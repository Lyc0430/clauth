//! The device list: its file, its checks, and the legacy import. Every test
//! that touches `~/.clauth` holds a [`HomeSandbox`], so nothing here reads or
//! writes the operator's real tree.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;

use crate::testutil::HomeSandbox;

/// A well-formed token no generator minted, for fixtures.
const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
/// A second one, for the tests that need two.
const OTHER: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

fn name(raw: &str) -> DeviceName {
    DeviceName::parse(raw).expect("a valid device name")
}

fn seed(name: &str, tier: Tier, token: &str) {
    seed_for_tests(name, tier, token).expect("seed a device");
}

fn seed_legacy(body: &str) {
    let path = legacy_path().expect("legacy path");
    crate::profile::mkdir_700(path.parent().expect("parent")).expect("mkdir");
    std::fs::write(&path, body).expect("seed auth_token.json");
}

/// An `auth_token.json` as the clauth before pairing wrote it; `tier: None` is
/// a file from before that field existed.
fn legacy_body(token: &str, tier: Option<&str>) -> String {
    let mut body = serde_json::json!({
        "schema": 1,
        "token": token,
        "created_at": "2026-01-02T03:04:05+00:00",
    });
    if let Some(tier) = tier {
        body["tier"] = tier.into();
    }
    body.to_string()
}

fn lines_containing(lines: &crate::logline::LogLines, needle: &str) -> usize {
    lines
        .snapshot()
        .iter()
        .filter(|line| line.contains(needle))
        .count()
}

/// What an import that makes `legacy` logs.
const IMPORTED: &str =
    "clauth daemon: device 'legacy' is imported (control); auth_token.json is deleted";
/// What an import of a token revoked since its import logs.
const REVOKED: &str = "clauth daemon: device 'legacy' was revoked since this token was imported, \
                       so it is not imported again; auth_token.json is deleted";

/// Run the import with every line it logs captured, and hold each line to the
/// never-log rule for the file the import read: no line carries its token or
/// its bytes.
fn import_logged() -> (anyhow::Result<()>, Vec<String>) {
    let body = std::fs::read_to_string(legacy_path().expect("path")).unwrap_or_default();
    let token = serde_json::from_str::<serde_json::Value>(&body)
        .ok()
        .and_then(|file| file["token"].as_str().map(str::to_string));
    let lines = crate::logline::LogLines::new();
    let capture = lines.capture_here();
    let result = import_legacy();
    drop(capture);
    let logged = lines.snapshot();
    for secret in [Some(body), token]
        .into_iter()
        .flatten()
        .filter(|secret| !secret.is_empty())
    {
        assert!(
            logged.iter().all(|line| !line.contains(&secret)),
            "a line the import logged carries the file's token or bytes"
        );
    }
    (result, logged)
}

// ── tokens ──────────────────────────────────────────────────────────────────

#[test]
fn a_generated_token_is_64_lowercase_hex() {
    let token = generate().expect("generate");
    assert_eq!(token.len(), 64);
    assert!(is_well_formed(&token), "{token} failed its own shape check");
}

#[test]
fn two_generations_differ() {
    // A wiring test, not a randomness one: a constant seed would pass every
    // other assertion in this file.
    assert_ne!(generate().expect("generate"), generate().expect("generate"));
}

#[test]
fn a_token_authenticates_only_as_itself() {
    let _home = HomeSandbox::new();
    seed("tray", Tier::Control, TOKEN);

    let found = authenticate(Some(TOKEN))
        .expect("read")
        .expect("the token must authenticate");
    assert_eq!((found.name.as_str(), &found.tier), ("tray", &Tier::Control));

    let mut near = TOKEN.to_string();
    near.pop();
    near.push('0');
    for wrong in [
        "",
        &TOKEN[..63],
        &format!("{TOKEN}0"),
        near.as_str(),
        &TOKEN.to_uppercase(),
    ] {
        assert!(
            authenticate(Some(wrong)).expect("read").is_none(),
            "{wrong:?} must not authenticate"
        );
    }
    assert!(
        authenticate(None).expect("read").is_none(),
        "no bearer is no device"
    );
}

/// The store holds the verifier and never the credential: a read of the file
/// yields nothing a client could present.
#[test]
fn the_store_holds_a_digest_and_never_the_token() {
    let _home = HomeSandbox::new();
    let token = add(&name("tray"), Tier::View).expect("add");
    let body = std::fs::read_to_string(store_path().expect("path")).expect("read the store");
    assert!(
        !body.contains(&token),
        "the plaintext token reached the store"
    );
    assert!(
        body.contains(&digest_hex(&token)),
        "the store must hold the token's digest to verify it"
    );
}

#[test]
fn a_device_rows_debug_never_renders_its_digest() {
    let device = Device::minted("tray", Tier::View, TOKEN, Joined::Add);
    let rendered = format!("{device:?}");
    assert!(!rendered.contains(&digest_hex(TOKEN)), "{rendered}");
    assert!(!rendered.contains(TOKEN), "{rendered}");
    assert!(rendered.contains("tray"), "{rendered}");
}

/// Unix-only: Windows has no mode bits, and `atomic_write_600` writes plainly
/// there, so there is no invariant left to assert.
#[cfg(unix)]
#[test]
fn the_store_and_its_dir_are_owner_only() {
    let _home = HomeSandbox::new();
    add(&name("tray"), Tier::View).expect("add");
    let dir = clauth_dir().expect("dir");
    assert!(
        store_path().expect("path").is_file(),
        "the store was written"
    );
    let loose = crate::testutil::owner_only_violations(&dir);
    assert!(
        loose.is_empty(),
        "the device list must inherit the 0600/0700 tree invariant; loose: {loose:#?}"
    );
}

// ── names ───────────────────────────────────────────────────────────────────

#[test]
fn a_device_name_takes_the_profile_charset_trimmed() {
    assert_eq!(name("  phone ").as_str(), "phone");
    assert_eq!(name("a.b-c_d@e+f").as_str(), "a.b-c_d@e+f");
    for bad in ["", "   ", "two words", ".hidden", "slash/y", "new\nline"] {
        assert!(DeviceName::parse(bad).is_err(), "{bad:?} must be refused");
    }
}

#[test]
fn the_legacy_name_is_reserved_in_any_case() {
    for reserved in ["legacy", "LEGACY", "Legacy"] {
        let err = DeviceName::parse(reserved).expect_err("the import owns this name");
        assert_eq!(
            err.to_string(),
            "'legacy' is the name clauth gives the token it imports from an older build; pick \
             another name"
        );
    }
}

#[test]
fn add_refuses_a_taken_name_in_any_case() {
    let _home = HomeSandbox::new();
    add(&name("Phone"), Tier::View).expect("first add");
    let err = add(&name("phone"), Tier::Control).expect_err("the name is taken");
    assert_eq!(
        err.to_string(),
        "a device named 'Phone' already exists; revoke it first: clauth devices revoke Phone"
    );
    assert_eq!(read_store().expect("read").devices.len(), 1);
}

// ── revoke ──────────────────────────────────────────────────────────────────

#[test]
fn a_revoked_device_no_longer_authenticates() {
    let _home = HomeSandbox::new();
    seed("tray", Tier::Control, TOKEN);
    seed("phone", Tier::View, OTHER);

    let removed = revoke("TRAY").expect("revoke folds case like the name check");
    assert_eq!(removed.name, "tray");
    assert!(authenticate(Some(TOKEN)).expect("read").is_none());
    assert!(
        authenticate(Some(OTHER)).expect("read").is_some(),
        "revoking one device leaves the others"
    );
}

#[test]
fn revoking_an_unknown_name_names_it() {
    let _home = HomeSandbox::new();
    let err = revoke("ghost").expect_err("nothing to revoke");
    assert_eq!(
        err.to_string(),
        "no device named 'ghost'; `clauth devices` lists the paired ones"
    );
}

// ── an unreadable store ─────────────────────────────────────────────────────

/// An unreadable list is refused, never read as empty: authenticating against
/// it would lock everyone out silently, and rewriting it would destroy the
/// rows it holds.
#[test]
fn an_unreadable_store_refuses_and_is_never_rewritten() {
    let _home = HomeSandbox::new();
    let path = store_path().expect("path");
    crate::profile::mkdir_700(path.parent().expect("parent")).expect("mkdir");
    std::fs::write(&path, b"{ not json").expect("damage the store");

    assert!(authenticate(Some(TOKEN)).is_err());
    assert!(add(&name("tray"), Tier::View).is_err());
    assert!(revoke("tray").is_err());
    assert_eq!(
        std::fs::read(&path).expect("read"),
        b"{ not json",
        "no writer may replace a store it could not read"
    );
}

/// A tier and a field this build does not know survive its rewrite: the row
/// was written by a newer clauth, and a downgrade adding a device must not
/// erase what that build meant.
#[test]
fn what_a_newer_build_wrote_survives_a_rewrite() {
    let _home = HomeSandbox::new();
    let path = store_path().expect("path");
    crate::profile::mkdir_700(path.parent().expect("parent")).expect("mkdir");
    let newer = serde_json::json!({
        "schema": 2,
        "future_top": "kept",
        "devices": [{
            "name": "wall",
            "tier": "readonly",
            "digest": digest_hex(TOKEN),
            "paired_at": "2026-01-02T03:04:05+00:00",
            "joined": "qr",
            "future_row": 7,
        }],
    });
    std::fs::write(&path, newer.to_string()).expect("seed");

    add(&name("tray"), Tier::View).expect("add");

    let back: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).expect("read")).expect("json");
    assert_eq!(
        back["schema"], 2,
        "a newer schema is never written back down"
    );
    assert_eq!(back["future_top"], "kept");
    let wall = &back["devices"][0];
    assert_eq!(
        (&wall["tier"], &wall["joined"], &wall["future_row"]),
        (
            &serde_json::json!("readonly"),
            &serde_json::json!("qr"),
            &serde_json::json!(7)
        )
    );
    let found = authenticate(Some(TOKEN))
        .expect("read")
        .expect("the row still verifies");
    assert_eq!(found.tier, Tier::Unknown("readonly".to_string()));
}

// ── legacy import ───────────────────────────────────────────────────────────

/// The upgrade path: the bytes the tray already holds authenticate as the
/// control device `legacy`, and the plaintext is gone from disk.
#[test]
fn the_legacy_token_becomes_the_legacy_control_device() {
    let _home = HomeSandbox::new();
    seed_legacy(&legacy_body(TOKEN, Some("control")));

    let (result, logged) = import_logged();
    result.expect("import");

    let device = authenticate(Some(TOKEN))
        .expect("read")
        .expect("the tray's bytes must still work");
    assert_eq!(
        (
            device.name.as_str(),
            &device.tier,
            &device.joined,
            device.paired_at.as_str()
        ),
        (
            "legacy",
            &Tier::Control,
            &Joined::Legacy,
            "2026-01-02T03:04:05+00:00"
        )
    );
    assert!(
        !legacy_path().expect("path").exists(),
        "the plaintext token must not outlive the import"
    );
    assert_eq!(logged, vec![IMPORTED]);
}

/// Every `auth_token.json` from before the `tier` field was a control token.
#[test]
fn a_legacy_file_from_before_the_tier_field_imports_as_control() {
    let _home = HomeSandbox::new();
    seed_legacy(&legacy_body(TOKEN, None));
    let (result, logged) = import_logged();
    result.expect("import");
    let device = authenticate(Some(TOKEN)).expect("read").expect("imported");
    assert_eq!(device.tier, Tier::Control);
    assert_eq!(logged, vec![IMPORTED]);
}

/// A file carrying any tier but `control` is neither imported nor served, and
/// stays where it is for the clauth that wrote it: `view` as much as a tier
/// this build does not know.
#[test]
fn a_legacy_file_of_any_tier_but_control_is_neither_imported_nor_served() {
    for tier in ["view", "readonly"] {
        let _home = HomeSandbox::new();
        let body = legacy_body(TOKEN, Some(tier));
        seed_legacy(&body);

        let (result, logged) = import_logged();
        result.expect("a refused tier is not a failed start");

        assert!(authenticate(Some(TOKEN)).expect("read").is_none(), "{tier}");
        assert!(
            !store_path().expect("path").exists(),
            "nothing was imported, so nothing was written"
        );
        assert_eq!(
            std::fs::read_to_string(legacy_path().expect("path")).expect("the file stays"),
            body
        );
        assert_eq!(
            logged,
            vec![format!(
                "clauth daemon: auth_token.json carries tier {tier:?} rather than control, so \
                 it is neither imported nor served; run the clauth that wrote it, or delete \
                 the file"
            )],
            "the operator is told once why the token stopped working"
        );
    }
}

#[test]
fn an_unusable_legacy_file_is_not_imported_and_says_so_once() {
    for bad in [
        "not json".to_string(),
        legacy_body("short", Some("control")),
        legacy_body(&TOKEN.to_uppercase(), Some("control")),
    ] {
        let _home = HomeSandbox::new();
        seed_legacy(&bad);

        let (result, logged) = import_logged();
        result.expect("an unusable file is not a failed start");

        assert!(
            !store_path().expect("path").exists(),
            "{bad:?} must import nothing"
        );
        assert!(legacy_path().expect("path").exists(), "{bad:?} stays put");
        assert_eq!(
            logged,
            vec![
                "clauth daemon: auth_token.json holds no usable token (bad JSON, or a token that \
                 is not 64 lowercase hex characters), so it is not imported; pair the client \
                 again with `clauth devices pair <name>` and delete the file"
            ],
            "{bad:?}"
        );
    }
}

/// A downgraded clauth minted a fresh `auth_token.json` after the import
/// deleted the old one; the next import hands `legacy` that token, the one the
/// client was given last.
#[test]
fn a_downgrade_minted_legacy_file_takes_over_the_legacy_device() {
    let _home = HomeSandbox::new();
    seed_legacy(&legacy_body(TOKEN, Some("control")));
    let (result, logged) = import_logged();
    result.expect("first import");
    assert_eq!(logged, vec![IMPORTED]);

    seed_legacy(&legacy_body(OTHER, Some("control")));
    let (result, logged) = import_logged();
    result.expect("second import");

    assert!(
        authenticate(Some(TOKEN)).expect("read").is_none(),
        "the old bytes are retired"
    );
    let device = authenticate(Some(OTHER))
        .expect("read")
        .expect("the downgrade's token works");
    assert_eq!(
        (device.name.as_str(), &device.tier),
        ("legacy", &Tier::Control)
    );
    assert_eq!(
        read_store().expect("read").devices.len(),
        1,
        "one legacy device, never two"
    );
    assert!(!legacy_path().expect("path").exists());
    assert_eq!(
        logged,
        vec![
            "clauth daemon: device 'legacy' now holds the token a downgraded clauth minted; \
             auth_token.json is deleted"
        ]
    );
}

/// The ordering: the list is on disk before the plaintext goes. A write that
/// fails must leave the client's only copy of its credential where it was.
#[test]
fn a_failed_store_write_keeps_the_legacy_file() {
    let _home = HomeSandbox::new();
    seed_legacy(&legacy_body(TOKEN, Some("control")));

    fail_next_write();
    let err = import_logged()
        .0
        .expect_err("the injected write failure propagates");
    assert!(
        format!("{err:#}").contains("injected failure writing the device list"),
        "{err:#}"
    );
    assert!(
        legacy_path().expect("path").exists(),
        "the plaintext must survive a write that did not land"
    );
    let (result, logged) = import_logged();
    result.expect("a later start retries");
    assert!(authenticate(Some(TOKEN)).expect("read").is_some());
    assert_eq!(logged, vec![IMPORTED]);
}

/// A crash between the write and the delete leaves both; the next import only
/// finishes the delete.
#[test]
fn an_interrupted_import_finishes_on_the_next_start() {
    let _home = HomeSandbox::new();
    let body = legacy_body(TOKEN, Some("control"));
    seed_legacy(&body);
    import_logged().0.expect("import");
    let store = std::fs::read(store_path().expect("path")).expect("read");
    seed_legacy(&body);

    let (result, logged) = import_logged();
    result.expect("re-import");

    assert_eq!(
        std::fs::read(store_path().expect("path")).expect("read"),
        store,
        "nothing to rewrite"
    );
    assert!(!legacy_path().expect("path").exists());
    assert_eq!(
        logged,
        vec!["clauth daemon: device 'legacy' already held its token; auth_token.json is deleted"]
    );
}

#[test]
fn no_legacy_file_is_no_import() {
    let _home = HomeSandbox::new();
    import_legacy().expect("nothing to import");
    assert!(!store_path().expect("path").exists());
}

// ── listing ─────────────────────────────────────────────────────────────────

#[test]
fn the_json_list_is_a_fixed_field_set_with_no_digest() {
    let _home = HomeSandbox::new();
    seed("tray", Tier::Control, TOKEN);
    let devices = read_store().expect("read").devices;
    let rows: serde_json::Value = serde_json::from_str(&list_json(&devices)).expect("json");
    assert_eq!(
        rows,
        serde_json::json!([{
            "name": "tray",
            "tier": "control",
            "paired_at": devices[0].paired_at,
            "joined": "add",
        }])
    );
}

#[test]
fn the_table_pairs_the_local_stamp_with_its_age() {
    let device = Device {
        paired_at: "2026-01-02T03:04:05+00:00".to_string(),
        ..Device::minted("phone", Tier::View, TOKEN, Joined::Pair)
    };
    let epoch = iso_to_epoch_secs(&device.paired_at).expect("parse");
    let stamp = crate::format::local_stamp(epoch).expect("stamp");
    let table = render_table(&[device], epoch + 3 * 3600 + 300);
    let cell = format!("{stamp} · 3h 5m ago");
    assert_eq!(
        table,
        format!(
            "{:<5}  {:<4}  {:<width$}  JOINED\nphone  view  {cell}  pair\n",
            "NAME",
            "TIER",
            "PAIRED AT",
            width = cell.chars().count()
        )
    );
}

#[test]
fn an_unparseable_stamp_renders_as_no_data() {
    assert_eq!(paired_cell("synthetic-fixture", 0), "-");
}

#[test]
fn an_empty_list_names_the_pair_command() {
    assert_eq!(
        render_table(&[], 0),
        "no devices are paired. `clauth devices pair <name>` pairs one.\n"
    );
}

#[test]
fn an_empty_store_is_announced_at_listener_start() {
    let _home = HomeSandbox::new();
    let lines = crate::logline::LogLines::new();
    let _capture = lines.capture_here();
    note_at_start();
    assert_eq!(lines_containing(&lines, "no device is paired yet"), 1);
}

/// A list that does not read is announced at listener start with the condition
/// that lifts the refusal, in the words the per-request line uses.
#[test]
fn an_unreadable_store_is_announced_at_listener_start() {
    let _home = HomeSandbox::new();
    let path = store_path().expect("path");
    crate::profile::mkdir_700(path.parent().expect("parent")).expect("mkdir");
    std::fs::write(&path, b"{ not json").expect("damage the store");
    let Err(err) = read_store() else {
        panic!("a damaged list must not read");
    };
    let lines = crate::logline::LogLines::new();
    let _capture = lines.capture_here();

    note_at_start();

    assert_eq!(
        lines.snapshot(),
        vec![format!(
            "clauth daemon: every REST request is refused until the device list reads: {err:#}"
        )]
    );
}

/// A legacy token revoked after its import stays revoked, even when the import
/// could not delete `auth_token.json`: the device list remembers which token it
/// imported, and a file still holding that token is not imported again. A
/// different token in the file is a downgrade's fresh mint, and imports.
#[test]
fn a_revoked_legacy_token_is_not_imported_again() {
    let _home = HomeSandbox::new();
    let body = legacy_body(TOKEN, Some("control"));
    seed_legacy(&body);
    import_logged().0.expect("import");
    // The state a failed delete leaves: the list holds the import and the
    // plaintext is still on disk.
    seed_legacy(&body);
    revoke("legacy").expect("revoke");

    let (result, logged) = import_logged();
    result.expect("the next start");

    assert!(
        authenticate(Some(TOKEN)).expect("read").is_none(),
        "a revoked token must stay revoked"
    );
    assert!(
        !legacy_path().expect("path").exists(),
        "the revoked plaintext is deleted"
    );
    assert_eq!(logged, vec![REVOKED]);

    seed_legacy(&legacy_body(OTHER, Some("control")));
    let (result, logged) = import_logged();
    result.expect("a downgrade's fresh token");
    let device = authenticate(Some(OTHER))
        .expect("read")
        .expect("the fresh token imports");
    assert_eq!(device.name, "legacy");
    assert_eq!(logged, vec![IMPORTED]);
}

/// The downgrade arm records the token it hands `legacy` too: once that token
/// is revoked, a copy of it a failed delete left behind is not imported again.
#[test]
fn a_revoked_token_a_downgrade_handed_legacy_is_not_imported_again() {
    let _home = HomeSandbox::new();
    seed_legacy(&legacy_body(TOKEN, Some("control")));
    import_logged().0.expect("the upgrade's import");
    let downgrade = legacy_body(OTHER, Some("control"));
    seed_legacy(&downgrade);
    import_logged().0.expect("the downgrade's token takes over");
    // The state a failed delete leaves: the list holds the downgrade's token
    // and its plaintext is still on disk.
    seed_legacy(&downgrade);
    revoke("legacy").expect("revoke");

    let (result, logged) = import_logged();
    result.expect("the next start");

    assert!(
        authenticate(Some(OTHER)).expect("read").is_none(),
        "a revoked token must stay revoked"
    );
    assert!(
        !legacy_path().expect("path").exists(),
        "the revoked plaintext is deleted"
    );
    assert_eq!(logged, vec![REVOKED]);
}
