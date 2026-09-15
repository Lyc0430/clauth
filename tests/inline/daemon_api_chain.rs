#![allow(clippy::unwrap_used, clippy::expect_used)]

//! The fallback-chain mutation routes: order, per-member threshold, wrap-off.
//!
//! Same sandbox model as the daemon route tests: every test holds a
//! [`HomeSandbox`], `keychain::enabled()` is false under `cfg(test)`, and no
//! network is reached.

#![cfg(unix)]

use crate::daemon::api::devices::Tier;
use crate::daemon::api::http::Response;
use crate::daemon::api::routes::API_PREFIX;
use crate::profile::{
    AppConfig, AppState, ConfigHandle, ProfileName, load_app_state, load_profile, save_app_state,
    save_profile,
};
use crate::testutil::{
    HomeSandbox, OTHER_TOKEN, TOKEN, body_json, call, ctx_with, req, seed_device, stored_profile,
    write_feed,
};

/// Three chain members plus one stored profile outside the chain, the fixture
/// the refusal arms need. Persisted, not just in memory, so the threshold
/// route's `is_configured` gate reads the roster back off disk.
fn seeded_chain() -> ConfigHandle {
    let alpha = stored_profile("alpha");
    let beta = stored_profile("beta");
    let gamma = stored_profile("gamma");
    let delta = stored_profile("delta");
    let state = AppState {
        active_profile: Some("alpha".into()),
        profiles: vec![
            "alpha".into(),
            "beta".into(),
            "gamma".into(),
            "delta".into(),
        ],
        fallback_chain: vec!["alpha".into(), "beta".into(), "gamma".into()],
        ..Default::default()
    };
    save_app_state(&state).expect("save app state");
    std::sync::Arc::new(crate::lockorder::RankedMutex::new(AppConfig {
        state,
        profiles: vec![alpha, beta, gamma, delta],
    }))
}

fn status_feed() -> serde_json::Value {
    let path = crate::profile::clauth_dir()
        .expect("clauth dir")
        .join("status.json");
    serde_json::from_slice(&std::fs::read(path).expect("status.json written"))
        .expect("feed is json")
}

fn feed_entry<'a>(feed: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
    feed["profiles"]
        .as_array()
        .expect("profiles")
        .iter()
        .find(|p| p["name"] == serde_json::json!(name))
        .unwrap_or_else(|| panic!("{name} is in the feed"))
}

// ------------------------------------------------------------------ order

#[test]
fn chain_order_reorders_persists_and_republishes() {
    let _home = HomeSandbox::new();
    let ctx = ctx_with(seeded_chain());

    let resp = call(
        &ctx,
        &req(
            "POST",
            "/api/v1/chain/order",
            Some(TOKEN),
            r#"{"members":["BETA","alpha","gamma"]}"#,
        ),
    );
    assert_eq!(resp.status, 200, "{}", String::from_utf8_lossy(&resp.body));
    let body = body_json(&resp);
    assert_eq!(body["ok"], serde_json::json!(true));
    assert_eq!(
        body["members"],
        serde_json::json!(["beta", "alpha", "gamma"])
    );

    let on_disk = load_app_state().expect("read profiles.toml");
    assert_eq!(
        on_disk.fallback_chain,
        vec![
            ProfileName::from("beta"),
            ProfileName::from("alpha"),
            ProfileName::from("gamma")
        ],
        "the order must land in profiles.toml, not just in the answer"
    );

    let feed = status_feed();
    assert_eq!(feed_entry(&feed, "beta")["fallback"]["position"], 1);
    assert_eq!(feed_entry(&feed, "alpha")["fallback"]["position"], 2);
    assert_eq!(feed_entry(&feed, "gamma")["fallback"]["position"], 3);
}

#[test]
fn chain_order_refusals_leave_the_chain_on_disk_unchanged() {
    let _home = HomeSandbox::new();
    let ctx = ctx_with(seeded_chain());

    let before = load_app_state().expect("read before").fallback_chain;
    let cases = [
        (
            r#"{"members":["alpha","beta"]}"#,
            "missing chain member 'gamma'",
        ),
        (
            r#"{"members":["alpha","beta","gamma","delta"]}"#,
            "extra chain member 'delta'",
        ),
        (
            r#"{"members":["alpha","beta","beta"]}"#,
            "duplicate chain member 'beta'",
        ),
        (
            r#"{"members":["alpha","beta","ghost"]}"#,
            "unknown chain member 'ghost'",
        ),
    ];
    for (body, reason) in cases {
        let resp = call(&ctx, &req("POST", "/api/v1/chain/order", Some(TOKEN), body));
        assert_eq!(resp.status, 400, "body {body:?}");
        let json = body_json(&resp);
        assert_eq!(
            json["error"],
            serde_json::json!("chain_order_invalid"),
            "body {body:?}"
        );
        assert_eq!(json["reason"], serde_json::json!(reason), "body {body:?}");
        assert_eq!(
            load_app_state().expect("read after").fallback_chain,
            before,
            "body {body:?} must not change the chain on disk"
        );
    }
}

// -------------------------------------------------------------- threshold

#[test]
fn chain_threshold_sets_persists_and_republishes() {
    let _home = HomeSandbox::new();
    let ctx = ctx_with(seeded_chain());

    let resp = call(
        &ctx,
        &req(
            "POST",
            "/api/v1/chain/threshold",
            Some(TOKEN),
            r#"{"profile":"BETA","threshold":90}"#,
        ),
    );
    assert_eq!(resp.status, 200, "{}", String::from_utf8_lossy(&resp.body));
    let body = body_json(&resp);
    assert_eq!(body["ok"], serde_json::json!(true));
    assert_eq!(body["profile"], serde_json::json!("beta"));
    assert_eq!(body["threshold"], serde_json::json!(90.0));

    let on_disk = load_profile(&ProfileName::from("beta")).expect("load beta");
    assert_eq!(on_disk.fallback_threshold, Some(90.0));

    let feed = status_feed();
    assert_eq!(feed_entry(&feed, "beta")["fallback"]["threshold"], 90.0);
}

#[test]
fn chain_threshold_refusals() {
    let _home = HomeSandbox::new();
    let ctx = ctx_with(seeded_chain());

    let unknown = call(
        &ctx,
        &req(
            "POST",
            "/api/v1/chain/threshold",
            Some(TOKEN),
            r#"{"profile":"ghost","threshold":90}"#,
        ),
    );
    assert_eq!(unknown.status, 404);
    assert_eq!(
        body_json(&unknown)["error"],
        serde_json::json!("profile_not_found")
    );

    let not_member = call(
        &ctx,
        &req(
            "POST",
            "/api/v1/chain/threshold",
            Some(TOKEN),
            r#"{"profile":"delta","threshold":90}"#,
        ),
    );
    assert_eq!(not_member.status, 409);
    let not_member_body = body_json(&not_member);
    assert_eq!(not_member_body["error"], serde_json::json!("not_a_member"));
    assert_eq!(
        not_member_body["reason"],
        serde_json::json!("'delta' is not in the fallback chain; add it on the Fallback tab first")
    );

    for body in [
        r#"{"profile":"alpha","threshold":100.5}"#,
        r#"{"profile":"alpha","threshold":-1}"#,
        r#"{"profile":"alpha","threshold":1e309}"#,
    ] {
        let resp = call(
            &ctx,
            &req("POST", "/api/v1/chain/threshold", Some(TOKEN), body),
        );
        assert_eq!(resp.status, 400, "body {body:?}");
        assert_eq!(
            body_json(&resp)["error"],
            serde_json::json!("bad_request"),
            "body {body:?}"
        );
    }
}

// ---------------------------------------------------------------- wrap-off

#[test]
fn chain_wrap_off_toggles_persists_and_republishes() {
    let _home = HomeSandbox::new();
    let ctx = ctx_with(seeded_chain());

    for (raw, want) in [("true", true), ("false", false), ("false", false)] {
        let body = format!(r#"{{"wrap_off":{raw}}}"#);
        let resp = call(
            &ctx,
            &req("POST", "/api/v1/chain/wrap-off", Some(TOKEN), &body),
        );
        assert_eq!(
            resp.status,
            200,
            "body {body:?}: {}",
            String::from_utf8_lossy(&resp.body)
        );
        let json = body_json(&resp);
        assert_eq!(json["ok"], serde_json::json!(true), "body {body:?}");
        assert_eq!(json["wrap_off"], serde_json::json!(want), "body {body:?}");
        assert_eq!(
            load_app_state().expect("read").switch_off_when_spent,
            want,
            "body {body:?}"
        );
        assert_eq!(
            status_feed()["wrap_off"],
            serde_json::json!(want),
            "body {body:?}"
        );
    }
}

// ---------------------------------------------------------------- access

#[test]
fn a_view_device_is_refused_every_chain_route() {
    let _home = HomeSandbox::new();
    let ctx = ctx_with(seeded_chain());
    seed_device("phone", Tier::View, OTHER_TOKEN);

    for (path, body) in [
        ("/chain/order", r#"{"members":["alpha","beta","gamma"]}"#),
        ("/chain/threshold", r#"{"profile":"alpha","threshold":90}"#),
        ("/chain/wrap-off", r#"{"wrap_off":true}"#),
    ] {
        let resp = call(
            &ctx,
            &req(
                "POST",
                &format!("{API_PREFIX}{path}"),
                Some(OTHER_TOKEN),
                body,
            ),
        );
        assert_eq!(resp.status, 403, "{path}");
        assert_eq!(
            body_json(&resp)["error"],
            serde_json::json!("control_required"),
            "{path}"
        );
    }
}

#[test]
fn a_held_chain_gate_refuses_each_route_with_409() {
    let _home = HomeSandbox::new();
    let ctx = ctx_with(seeded_chain());
    let before = load_app_state().expect("read before");
    let before_beta_threshold = load_profile(&ProfileName::from("beta"))
        .expect("load beta")
        .fallback_threshold;

    let (held_tx, held_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let holder = std::sync::Arc::clone(&ctx);
    std::thread::scope(|scope| {
        scope.spawn(move || {
            let _gate = holder.switch_gate.lock().expect("gate");
            held_tx.send(()).expect("signal held");
            let _ = release_rx.recv();
        });
        held_rx.recv().expect("gate taken");

        for (path, body) in [
            ("/chain/order", r#"{"members":["alpha","beta","gamma"]}"#),
            ("/chain/threshold", r#"{"profile":"alpha","threshold":90}"#),
            ("/chain/wrap-off", r#"{"wrap_off":true}"#),
        ] {
            let resp = call(
                &ctx,
                &req("POST", &format!("{API_PREFIX}{path}"), Some(TOKEN), body),
            );
            assert_eq!(resp.status, 409, "{path}");
            assert_eq!(
                body_json(&resp)["error"],
                serde_json::json!("edit_in_progress"),
                "{path}"
            );
        }
        let _ = release_tx.send(());
    });

    let after = load_app_state().expect("read after");
    assert_eq!(
        after.fallback_chain, before.fallback_chain,
        "a refused edit must not change the chain on disk"
    );
    assert_eq!(
        after.switch_off_when_spent, before.switch_off_when_spent,
        "a refused wrap-off must not change the flag on disk"
    );
    assert_eq!(
        load_profile(&ProfileName::from("beta"))
            .expect("load beta")
            .fallback_threshold,
        before_beta_threshold,
        "a refused threshold must not change the member on disk"
    );
}

#[test]
fn a_state_lock_timeout_is_503_on_each_chain_route() {
    let _home = HomeSandbox::new();
    let ctx = ctx_with(seeded_chain());
    let dir = crate::profile::clauth_dir().expect("clauth dir");
    let holder = crate::profile::open_state_file(&dir.join(crate::lock::LOCK_FILENAME))
        .expect("open holder handle");
    holder.lock().expect("hold the flock");
    crate::lock::set_state_lock_timeout_override(Some(std::time::Duration::from_millis(100)));

    for (path, body) in [
        ("/chain/order", r#"{"members":["alpha","beta","gamma"]}"#),
        ("/chain/threshold", r#"{"profile":"alpha","threshold":90}"#),
        ("/chain/wrap-off", r#"{"wrap_off":true}"#),
    ] {
        let resp = call(
            &ctx,
            &req("POST", &format!("{API_PREFIX}{path}"), Some(TOKEN), body),
        );
        assert_eq!(
            resp.status,
            503,
            "{path}: {}",
            String::from_utf8_lossy(&resp.body)
        );
        assert_eq!(
            body_json(&resp)["error"],
            serde_json::json!("state_locked"),
            "{path}"
        );
    }
    crate::lock::set_state_lock_timeout_override(None);
    drop(holder);
}

// ------------------------------------------------------- fresh-state re-reads

#[test]
fn an_order_edit_preserves_a_roster_row_registered_behind_its_back() {
    let _home = HomeSandbox::new();
    let ctx = ctx_with(seeded_chain());
    crate::testutil::register_names(&["epsilon"]);

    let resp = call(
        &ctx,
        &req(
            "POST",
            "/api/v1/chain/order",
            Some(TOKEN),
            r#"{"members":["beta","alpha","gamma"]}"#,
        ),
    );
    assert_eq!(resp.status, 200, "{}", String::from_utf8_lossy(&resp.body));

    let on_disk = load_app_state().expect("read profiles.toml");
    assert_eq!(
        on_disk.fallback_chain,
        vec![
            ProfileName::from("beta"),
            ProfileName::from("alpha"),
            ProfileName::from("gamma")
        ],
        "the reorder itself landed"
    );
    assert!(
        on_disk.profiles.iter().any(|n| n == "epsilon"),
        "a roster row written behind the daemon's back survives the edit"
    );
}

/// A member deleted at the machine inside the daemon's lag drops out of the
/// saved order, and the answer and the audit line carry what LANDED, never the
/// list the caller sent.
#[test]
fn an_order_edit_answers_the_order_that_landed_after_a_delete_behind_its_back() {
    let _home = HomeSandbox::new();
    let ctx = ctx_with(seeded_chain());
    let mut fresh = load_app_state().expect("read profiles.toml");
    fresh.profiles.retain(|n| n != "gamma");
    fresh.fallback_chain.retain(|n| n != "gamma");
    save_app_state(&fresh).expect("delete gamma behind the daemon's back");
    let lines = crate::logline::LogLines::new();
    let guard = lines.capture_here();

    let resp = call(
        &ctx,
        &req(
            "POST",
            "/api/v1/chain/order",
            Some(TOKEN),
            r#"{"members":["gamma","beta","alpha"]}"#,
        ),
    );
    drop(guard);
    assert_eq!(resp.status, 200, "{}", String::from_utf8_lossy(&resp.body));
    assert_eq!(
        body_json(&resp)["members"],
        serde_json::json!(["beta", "alpha"]),
        "the answer is the saved order, without the deleted member"
    );
    assert_eq!(
        load_app_state().expect("read after").fallback_chain,
        vec![ProfileName::from("beta"), ProfileName::from("alpha")]
    );
    assert_eq!(
        lines.snapshot(),
        vec!["clauth api: device 'test' reordered the chain to [beta, alpha]".to_string()],
        "the audit line records the order that landed"
    );
}

/// The membership check reads the FRESH chain: a member dropped from the chain
/// at the machine inside the daemon's lag is refused, and nothing is written.
#[test]
fn a_threshold_edit_refuses_a_member_dropped_from_the_chain_behind_its_back() {
    let _home = HomeSandbox::new();
    let ctx = ctx_with(seeded_chain());
    let mut fresh = load_app_state().expect("read profiles.toml");
    fresh.fallback_chain.retain(|n| n != "beta");
    save_app_state(&fresh).expect("drop beta from the chain behind the daemon's back");
    let before = load_profile(&ProfileName::from("beta"))
        .expect("read beta")
        .fallback_threshold;

    let resp = call(
        &ctx,
        &req(
            "POST",
            "/api/v1/chain/threshold",
            Some(TOKEN),
            r#"{"profile":"beta","threshold":90}"#,
        ),
    );
    assert_eq!(resp.status, 409, "{}", String::from_utf8_lossy(&resp.body));
    assert_eq!(body_json(&resp)["error"], serde_json::json!("not_a_member"));
    assert_eq!(
        load_profile(&ProfileName::from("beta"))
            .expect("read beta after")
            .fallback_threshold,
        before,
        "nothing was written for the dropped member"
    );
}

#[test]
fn a_wrap_off_edit_preserves_a_roster_row_registered_behind_its_back() {
    let _home = HomeSandbox::new();
    let ctx = ctx_with(seeded_chain());
    crate::testutil::register_names(&["epsilon"]);

    let resp = call(
        &ctx,
        &req(
            "POST",
            "/api/v1/chain/wrap-off",
            Some(TOKEN),
            r#"{"wrap_off":true}"#,
        ),
    );
    assert_eq!(resp.status, 200, "{}", String::from_utf8_lossy(&resp.body));

    let on_disk = load_app_state().expect("read profiles.toml");
    assert!(on_disk.switch_off_when_spent, "the wrap-off edit landed");
    assert!(
        on_disk.profiles.iter().any(|n| n == "epsilon"),
        "a roster row written behind the daemon's back survives the edit"
    );
}

#[test]
fn a_threshold_edit_preserves_a_member_field_written_behind_its_back() {
    let _home = HomeSandbox::new();
    let ctx = ctx_with(seeded_chain());
    let beta = ProfileName::from("beta");
    let mut fresh = load_profile(&beta).expect("load beta");
    fresh.max_auto_spend = Some(7.0);
    save_profile(&fresh).expect("save beta behind the daemon's back");

    let resp = call(
        &ctx,
        &req(
            "POST",
            "/api/v1/chain/threshold",
            Some(TOKEN),
            r#"{"profile":"beta","threshold":90}"#,
        ),
    );
    assert_eq!(resp.status, 200, "{}", String::from_utf8_lossy(&resp.body));

    let on_disk = load_profile(&beta).expect("load beta");
    assert_eq!(
        on_disk.fallback_threshold,
        Some(90.0),
        "the threshold landed"
    );
    assert_eq!(
        on_disk.max_auto_spend,
        Some(7.0),
        "a member field written behind the daemon's back survives the edit"
    );
}

#[test]
fn a_threshold_edit_for_a_member_deleted_from_disk_is_404_and_recreates_nothing() {
    let _home = HomeSandbox::new();
    let ctx = ctx_with(seeded_chain());
    let beta = ProfileName::from("beta");
    let mut state = load_app_state().expect("read before");
    state.profiles.retain(|n| n.as_str() != beta.as_str());
    state.fallback_chain.retain(|n| n.as_str() != beta.as_str());
    save_app_state(&state).expect("drop beta from disk");
    std::fs::remove_dir_all(crate::profile::profile_dir(&beta).expect("beta dir"))
        .expect("remove beta's profile dir");

    let resp = call(
        &ctx,
        &req(
            "POST",
            "/api/v1/chain/threshold",
            Some(TOKEN),
            r#"{"profile":"beta","threshold":90}"#,
        ),
    );
    assert_eq!(resp.status, 404, "{}", String::from_utf8_lossy(&resp.body));
    assert_eq!(
        body_json(&resp)["error"],
        serde_json::json!("profile_not_found")
    );
    assert!(
        !crate::profile::profile_dir(&beta)
            .expect("beta dir")
            .exists(),
        "a refused edit must not recreate the deleted member's profile dir"
    );
}

// -------------------------------------------------------------------- audit

#[test]
fn a_successful_chain_edit_logs_an_audit_line() {
    let _home = HomeSandbox::new();
    let ctx = ctx_with(seeded_chain());

    let lines = crate::logline::LogLines::new();
    let _guard = lines.capture_here();

    let order = call(
        &ctx,
        &req(
            "POST",
            "/api/v1/chain/order",
            Some(TOKEN),
            r#"{"members":["beta","alpha","gamma"]}"#,
        ),
    );
    assert_eq!(order.status, 200);
    let threshold = call(
        &ctx,
        &req(
            "POST",
            "/api/v1/chain/threshold",
            Some(TOKEN),
            r#"{"profile":"alpha","threshold":90}"#,
        ),
    );
    assert_eq!(threshold.status, 200);
    let wrap = call(
        &ctx,
        &req(
            "POST",
            "/api/v1/chain/wrap-off",
            Some(TOKEN),
            r#"{"wrap_off":true}"#,
        ),
    );
    assert_eq!(wrap.status, 200);

    drop(_guard);
    assert_eq!(
        lines.snapshot(),
        vec![
            "clauth api: device 'test' reordered the chain to [beta, alpha, gamma]".to_string(),
            "clauth api: device 'test' set 'alpha' threshold to 90".to_string(),
            "clauth api: device 'test' set wrap_off to true".to_string(),
        ]
    );
}

// ------------------------------------------------------------------ no-op

#[test]
fn a_noop_wrap_off_still_republishes_the_feed() {
    let _home = HomeSandbox::new();
    let ctx = ctx_with(seeded_chain());

    write_feed(
        &ctx,
        r#"{"schema":1,"generated_at":"2026-09-02T06:00:00+00:00","active_profile":"alpha","pending_switch":null,"wrap_off":true,"refresh_interval_ms":120000,"profiles":[]}"#,
    );

    let resp = call(
        &ctx,
        &req(
            "POST",
            "/api/v1/chain/wrap-off",
            Some(TOKEN),
            r#"{"wrap_off":false}"#,
        ),
    );
    assert_eq!(resp.status, 200, "{}", String::from_utf8_lossy(&resp.body));
    assert_eq!(
        status_feed()["wrap_off"],
        serde_json::json!(false),
        "the repeated value still republishes, moving the stale feed"
    );
}

// ---------------------------------------------------------------- edit failure

#[test]
fn a_chain_edit_failure_answers_500_edit_failed() {
    use std::os::unix::fs::PermissionsExt;

    let _home = HomeSandbox::new();
    let ctx = ctx_with(seeded_chain());
    let clauth_dir = crate::profile::clauth_dir().expect("clauth dir");

    // order and wrap-off save whole state into ~/.clauth; fail that dir.
    std::fs::set_permissions(&clauth_dir, std::fs::Permissions::from_mode(0o500))
        .expect("chmod clauth dir read-only");
    let answers: Vec<(&str, Response)> = [
        ("/chain/order", r#"{"members":["beta","alpha","gamma"]}"#),
        ("/chain/wrap-off", r#"{"wrap_off":true}"#),
    ]
    .into_iter()
    .map(|(path, body)| {
        (
            path,
            call(
                &ctx,
                &req("POST", &format!("{API_PREFIX}{path}"), Some(TOKEN), body),
            ),
        )
    })
    .collect();
    // Restore before any assertion so a red still lets the sandbox clean up.
    std::fs::set_permissions(&clauth_dir, std::fs::Permissions::from_mode(0o700))
        .expect("restore clauth dir perms");
    for (path, resp) in answers {
        assert_eq!(
            resp.status,
            500,
            "{path}: {}",
            String::from_utf8_lossy(&resp.body)
        );
        assert_eq!(
            body_json(&resp)["error"],
            serde_json::json!("edit_failed"),
            "{path}"
        );
        assert_eq!(
            body_json(&resp)["reason"],
            serde_json::json!("the chain edit failed; see daemon.log"),
            "{path}"
        );
    }

    // The threshold leg writes into the member's own dir, which ~/.clauth's
    // mode does not gate; fail it at the profile dir instead.
    let beta_dir = crate::profile::profile_dir(&ProfileName::from("beta")).expect("beta dir");
    std::fs::set_permissions(&beta_dir, std::fs::Permissions::from_mode(0o500))
        .expect("chmod beta dir read-only");
    let resp = call(
        &ctx,
        &req(
            "POST",
            "/api/v1/chain/threshold",
            Some(TOKEN),
            r#"{"profile":"beta","threshold":90}"#,
        ),
    );
    std::fs::set_permissions(&beta_dir, std::fs::Permissions::from_mode(0o700))
        .expect("restore beta dir perms");
    assert_eq!(resp.status, 500, "{}", String::from_utf8_lossy(&resp.body));
    assert_eq!(body_json(&resp)["error"], serde_json::json!("edit_failed"));
    assert_eq!(
        body_json(&resp)["reason"],
        serde_json::json!("the chain edit failed; see daemon.log")
    );
}

// --------------------------------------------------------------------- ghost

#[test]
fn a_chain_order_with_a_ghost_member_reorders_the_resolvable_members() {
    let _home = HomeSandbox::new();
    let ctx = ctx_with(seeded_chain());
    let mut state = load_app_state().expect("read before");
    state.fallback_chain = vec![
        ProfileName::from("alpha"),
        ProfileName::from("ghost"),
        ProfileName::from("beta"),
    ];
    save_app_state(&state).expect("put the ghost in the chain on disk");

    let resp = call(
        &ctx,
        &req(
            "POST",
            "/api/v1/chain/order",
            Some(TOKEN),
            r#"{"members":["beta","alpha"]}"#,
        ),
    );
    assert_eq!(resp.status, 200, "{}", String::from_utf8_lossy(&resp.body));
    assert_eq!(
        body_json(&resp)["members"],
        serde_json::json!(["beta", "alpha"])
    );
    assert_eq!(
        load_app_state().expect("read after").fallback_chain,
        vec![ProfileName::from("beta"), ProfileName::from("alpha")],
        "the saved order keeps the ghost out"
    );
}
