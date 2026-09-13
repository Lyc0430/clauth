#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Route behavior: who is let in, what the feed serves, and which switches are
//! refused.
//!
//! Everything runs against a [`HomeSandbox`] tempdir and `keychain::enabled()`
//! is false under `cfg(test)`, so the switch paths exercise the file/symlink
//! model only and never touch the operator's real `~/.clauth`, `~/.claude`, or
//! the Keychain. No network: tokens are minted without an expiry, so the
//! pre-install auth gate returns `Ready` without calling the refresher.

#![cfg(unix)]

use super::*;

use crate::profile::{
    AppConfig, AppState, ClaudeCredentials, ConfigHandle, DivergenceChoice, OAuthToken, Profile,
    save_app_state, save_profile,
};
use crate::testutil::HomeSandbox;

/// The bearer of the control device every context below pairs.
const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
/// The device [`TOKEN`] authenticates as.
const DEVICE: &str = "test";
/// The bearer of a second device, which the tests that need one pair.
const OTHER_TOKEN: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

fn creds(access: &str) -> ClaudeCredentials {
    ClaudeCredentials {
        claude_ai_oauth: Some(OAuthToken {
            access_token: access.to_string(),
            refresh_token: Some(format!("{access}-refresh")),
            expires_at: None,
            scopes: None,
            subscription_type: None,
            ..crate::profile::OAuthToken::default_extra()
        }),
    }
}

fn stored_profile(name: &str) -> Profile {
    let mut p = Profile::new(name.to_string(), None, None);
    p.credentials = Some(creds(name));
    save_profile(&p).expect("save profile");
    p
}

/// Two profiles, the first active, both with usable stored credentials.
fn seeded_config() -> ConfigHandle {
    let profiles = vec![stored_profile("alpha"), stored_profile("beta")];
    let state = AppState {
        active_profile: Some("alpha".into()),
        profiles: vec!["alpha".into(), "beta".into()],
        ..Default::default()
    };
    // Persisted, not just built in memory: `ensure_installable` gates on
    // `profile::is_configured`, which reads the roster back off disk so a target
    // deleted by a concurrent CLI bounces before any relink tears the live slot
    // down. A fixture that only holds the roster in memory reads as "not found".
    save_app_state(&state).expect("save app state");
    std::sync::Arc::new(crate::lockorder::RankedMutex::new(AppConfig {
        state,
        profiles,
    }))
}

/// A context over `config`, with [`TOKEN`] paired as the control device
/// [`DEVICE`].
fn ctx_with(config: ConfigHandle) -> std::sync::Arc<ApiContext> {
    seed_device(DEVICE, Tier::Control, TOKEN);
    let status_path = crate::profile::clauth_dir()
        .expect("clauth dir")
        .join("status.json");
    ApiContext::new(config, status_path, None)
}

/// The same context a running daemon builds: one that can see the scheduler's
/// in-memory stores.
fn ctx_with_live(
    config: ConfigHandle,
    live: crate::daemon::LiveStores,
) -> std::sync::Arc<ApiContext> {
    seed_device(DEVICE, Tier::Control, TOKEN);
    let status_path = crate::profile::clauth_dir()
        .expect("clauth dir")
        .join("status.json");
    ApiContext::new(config, status_path, Some(live))
}

/// A request as the HTTP layer would hand it to the router.
fn req(method: &str, path: &str, bearer: Option<&str>, body: &str) -> Request {
    let (path, query) = path.split_once('?').unwrap_or((path, ""));
    Request {
        method: method.to_string(),
        path: path.to_string(),
        query: query.to_string(),
        bearer: bearer.map(str::to_string),
        if_none_match: None,
        body: body.as_bytes().to_vec(),
        // Routing does not depend on this; the connection loop owns it.
        keep_alive: true,
    }
}

fn peer() -> SocketAddr {
    SocketAddr::from(([192, 0, 2, 7], 50_000))
}

/// The router as most of these tests drive it: one fixed peer, the answer
/// alone. A test about which device the answer went to calls [`handle`].
fn call(ctx: &ApiContext, req: &Request) -> Response {
    handle(ctx, req, peer()).response
}

fn seed_device(name: &str, tier: Tier, token: &str) {
    devices::seed_for_tests(name, tier, token).expect("seed a device");
}

fn route_path(route: &Route) -> String {
    format!("{API_PREFIX}{}", route.path)
}

/// A conditional GET, for the feed's 304 and `?wait` paths.
fn req_tagged(path: &str, bearer: Option<&str>, etag: &str) -> Request {
    Request {
        if_none_match: Some(etag.to_string()),
        ..req("GET", path, bearer, "")
    }
}

fn body_json(resp: &Response) -> serde_json::Value {
    serde_json::from_slice(&resp.body).expect("response body is json")
}

// ------------------------------------------------- status: waiting

/// A status feed body. `generated_at` is the field the daemon moves every tick
/// whether or not anything an operator can see has changed.
fn feed(active: &str, generated_at: &str) -> String {
    format!(
        r#"{{"schema":1,"generated_at":"{generated_at}","active_profile":"{active}","pending_switch":null,"wrap_off":false,"refresh_interval_ms":120000,"profiles":[]}}"#
    )
}

fn write_feed(ctx: &ApiContext, body: &str) {
    std::fs::write(&ctx.status_path, body).expect("write status.json");
}

/// The tag the daemon would hand out for what is on disk right now.
fn current_tag(ctx: &ApiContext) -> String {
    let resp = call(ctx, &req("GET", "/api/v1/status", Some(TOKEN), ""));
    assert_eq!(resp.status, 200);
    resp.etag.clone().expect("a 200 carries an entity tag")
}

/// The point of the whole thing: a reader parked on `?wait` is answered when
/// the accounts move, not when a timer fires. Without this the tray could only
/// be as current as its poll interval, which is what made a switch take
/// seconds to appear.
#[test]
fn a_wait_returns_as_soon_as_the_feed_changes() {
    let _home = HomeSandbox::new();
    let ctx = ctx_with(seeded_config());
    write_feed(&ctx, &feed("alpha", "2026-09-02T06:00:00+00:00"));
    let tag = current_tag(&ctx);

    let path = ctx.status_path.clone();
    let writer = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(300));
        std::fs::write(&path, feed("beta", "2026-09-02T06:00:05+00:00")).expect("republish");
    });

    let started = std::time::Instant::now();
    let resp = call(
        &ctx,
        &req_tagged("/api/v1/status?wait=10", Some(TOKEN), &tag),
    );
    let elapsed = started.elapsed();
    writer.join().expect("writer thread");

    assert_eq!(resp.status, 200, "the change is answered, not timed out");
    assert_eq!(body_json(&resp)["active_profile"], "beta");
    assert_ne!(
        resp.etag.as_deref(),
        Some(tag.as_str()),
        "and carries a new tag"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "answered on the change, not on the deadline: {elapsed:?}"
    );
}

/// The other half, and the reason the tag ignores `generated_at`: the daemon
/// rewrites the feed every tick, so on a quiet system that stamp is the only
/// thing moving. Waking a reader for it would turn every long poll into a
/// one-second one.
#[test]
fn a_wait_is_not_woken_by_the_timestamp_alone() {
    let _home = HomeSandbox::new();
    let ctx = ctx_with(seeded_config());
    write_feed(&ctx, &feed("alpha", "2026-09-02T06:00:00+00:00"));
    let tag = current_tag(&ctx);

    let path = ctx.status_path.clone();
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop = std::sync::Arc::clone(&done);
    let ticker = std::thread::spawn(move || {
        let mut second = 0;
        while !stop.load(std::sync::atomic::Ordering::Relaxed) {
            second += 1;
            let stamp = format!("2026-09-02T06:00:{second:02}+00:00");
            // The production write path, not a truncate-in-place: the daemon's
            // tick republishes through `atomic_write_600`, and a plain
            // `fs::write` racing the wait loop's reads can hand it a torn body
            // the fixture never meant to model.
            let _ = crate::profile::atomic_write_600(&path, feed("alpha", &stamp).as_bytes());
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    });

    let resp = call(
        &ctx,
        &req_tagged("/api/v1/status?wait=2", Some(TOKEN), &tag),
    );
    done.store(true, std::sync::atomic::Ordering::Relaxed);
    ticker.join().expect("ticker thread");

    assert_eq!(resp.status, 304, "a moving timestamp is not a change");
    assert_eq!(
        resp.etag.as_deref(),
        Some(tag.as_str()),
        "and the tag stands"
    );
}

/// A conditional read with no `wait` still answers at once — the first read of
/// a session has no tag, and a client that does have one must not be made to
/// block unless it asked to.
#[test]
fn a_conditional_read_without_wait_answers_immediately() {
    let _home = HomeSandbox::new();
    let ctx = ctx_with(seeded_config());
    write_feed(&ctx, &feed("alpha", "2026-09-02T06:00:00+00:00"));
    let tag = current_tag(&ctx);

    let started = std::time::Instant::now();
    let resp = call(&ctx, &req_tagged("/api/v1/status", Some(TOKEN), &tag));
    assert_eq!(resp.status, 304);
    assert!(started.elapsed() < std::time::Duration::from_secs(1));
}

/// A zero-wait conditional GET is a legitimate "has it moved?" probe: the feed
/// is read BEFORE the deadline is tested, so a feed that already differs from
/// the client's tag answers 200 at once. The loop used to test its deadline
/// first, which answered 304 without ever reading the file and delayed every
/// non-zero wait's first read by one poll interval.
#[test]
fn a_zero_wait_conditional_read_reads_before_deciding() {
    let _home = HomeSandbox::new();
    let ctx = ctx_with(seeded_config());
    write_feed(&ctx, &feed("alpha", "2026-09-02T06:00:00+00:00"));
    let held = current_tag(&ctx);

    // The feed moves; the reader holding the old tag must see it now, not on a
    // hypothetical next poll.
    write_feed(&ctx, &feed("beta", "2026-09-02T06:00:05+00:00"));
    let resp = call(
        &ctx,
        &req_tagged("/api/v1/status?wait=0", Some(TOKEN), &held),
    );
    assert_eq!(
        resp.status, 200,
        "a differing feed is a change, even at wait=0"
    );
    assert_eq!(body_json(&resp)["active_profile"], "beta");

    // A reader already current is told nothing changed.
    let now_tag = resp.etag.clone().expect("a 200 carries an entity tag");
    let resp = call(
        &ctx,
        &req_tagged("/api/v1/status?wait=0", Some(TOKEN), &now_tag),
    );
    assert_eq!(resp.status, 304);
}

/// The non-zero half of the same claim: a wait with a positive timeout serves
/// the FIRST read's freshness rather than blocking. The bound is one poll
/// interval, which is what separates the two failing shapes from the live
/// one: a loop that parks the caller for the whole wait answers at `wait`,
/// and one that delays its first read until after the first poll answers at
/// exactly [`WAIT_POLL`] — a sleep never undershoots — while the live loop
/// reads before its deadline test and answers in the time of one file read.
/// The zero-wait test above pins the same read-before-decide order at
/// `wait=0`, where the delayed shape answers 304 without ever reading.
#[test]
fn a_positive_wait_serves_the_first_reads_freshness_rather_than_parking() {
    let _home = HomeSandbox::new();
    let ctx = ctx_with(seeded_config());
    write_feed(&ctx, &feed("alpha", "2026-09-02T06:00:00+00:00"));
    let held = current_tag(&ctx);

    // The feed has already moved by the time the reader arrives.
    write_feed(&ctx, &feed("beta", "2026-09-02T06:00:05+00:00"));

    let started = std::time::Instant::now();
    let resp = call(
        &ctx,
        &req_tagged("/api/v1/status?wait=10", Some(TOKEN), &held),
    );
    let elapsed = started.elapsed();

    assert_eq!(resp.status, 200);
    assert_eq!(
        body_json(&resp)["active_profile"],
        serde_json::json!("beta")
    );
    assert!(
        elapsed < WAIT_POLL,
        "the first read is served before one poll interval could delay it, not \
         parked for the 10s wait: {elapsed:?}"
    );
}

/// A feed caught mid-replacement — a body that does not parse — is not a
/// change. The wait keeps going rather than answering the truncated bytes with
/// a tag fabricated from them, which is what the loop's own comment promises;
/// digesting raw bytes instead made a torn read answer 200 with the garbage.
#[test]
fn a_wait_skips_a_feed_that_does_not_parse() {
    let _home = HomeSandbox::new();
    let ctx = ctx_with(seeded_config());
    write_feed(&ctx, &feed("alpha", "2026-09-02T06:00:00+00:00"));
    let tag = current_tag(&ctx);

    // Half a feed: what a non-atomic writer leaves readable mid-write.
    write_feed(
        &ctx,
        r#"{"schema":1,"generated_at":"2026-09-02T06:00:00+00:00","active_prof"#,
    );

    let resp = call(
        &ctx,
        &req_tagged("/api/v1/status?wait=1", Some(TOKEN), &tag),
    );
    assert_eq!(resp.status, 304, "an unparseable body is not a change");
    assert!(
        resp.body.is_empty(),
        "the truncated bytes are never handed to the client"
    );
    assert_eq!(resp.etag.as_deref(), Some(tag.as_str()));
}

/// The plain conditional GET holds the same guard: a feed caught mid-replacement
/// is rebuilt from config rather than answered with the truncated bytes, so no
/// path serves a torn body. The 200 below is a REBUILT body (the seeded config's
/// `alpha` account), never the half-written file.
#[test]
fn a_plain_get_rebuilds_rather_than_serving_a_torn_feed() {
    let _home = HomeSandbox::new();
    let ctx = ctx_with(seeded_config());
    write_feed(&ctx, &feed("alpha", "2026-09-02T06:00:00+00:00"));
    let tag = current_tag(&ctx);

    // Half a feed: what a non-atomic writer leaves readable mid-write.
    write_feed(
        &ctx,
        r#"{"schema":1,"generated_at":"2026-09-02T06:00:00+00:00","active_prof"#,
    );

    let resp = call(&ctx, &req_tagged("/api/v1/status", Some(TOKEN), &tag));
    assert_eq!(resp.status, 200, "a torn feed is rebuilt, not skipped");
    // Parsed BEFORE the field asserts, so the pin's red under a regression is
    // the assertion on the answer, not a harness expect unwinding on garbage.
    let body: serde_json::Value =
        serde_json::from_slice(&resp.body).expect("the rebuilt body is whole, parseable JSON");
    assert_eq!(
        body["active_profile"], "alpha",
        "the answer is the rebuilt body, never the truncated file bytes"
    );
    assert_eq!(
        body["schema"],
        serde_json::json!(crate::daemon::SCHEMA_VERSION)
    );
}

// ---------------------------------------------------------------- auth

/// The table as shipped, row for row. A route's access is a security decision,
/// so a change to any row has to change this pin on purpose.
#[test]
fn the_route_table_is_exactly_this() {
    let rows: Vec<(&str, &str, Access)> = ROUTES
        .iter()
        .map(|route| (route.method, route.path, route.access))
        .collect();
    assert_eq!(
        rows,
        vec![
            ("GET", "/health", Access::View),
            ("HEAD", "/health", Access::View),
            ("GET", "/status", Access::View),
            ("HEAD", "/status", Access::View),
            ("POST", "/switch", Access::Control),
            ("POST", "/pair", Access::None),
        ]
    );
}

/// AU-1: every route but the pairing redemption refuses an unpaired caller and
/// challenges it, and a path in no row is refused the same way, so an unpaired
/// caller learns nothing about the table. The rows are picked by identity
/// rather than by access, so a row that stops asking for a bearer fails here
/// instead of dropping out of the loop.
#[test]
fn every_route_but_pair_refuses_an_unpaired_caller() {
    let _home = HomeSandbox::new();
    let ctx = ctx_with(seeded_config());
    let unpaired = "f".repeat(64);

    for route in ROUTES
        .iter()
        .filter(|route| (route.method, route.path) != ("POST", "/pair"))
    {
        for bearer in [None, Some(unpaired.as_str())] {
            let resp = call(&ctx, &req(route.method, &route_path(route), bearer, ""));
            assert_eq!(resp.status, 401, "{} {}", route.method, route.path);
            assert!(
                resp.challenge,
                "{} {} must challenge",
                route.method, route.path
            );
        }
    }
    for path in [
        "/api/v1/nope",
        "/api/v1/health/",
        "/api/v1//health",
        "/health",
        "/",
    ] {
        assert_eq!(
            call(&ctx, &req("GET", path, None, "")).status,
            401,
            "{path}"
        );
    }
}

/// The pairing redemption is the one route an unpaired caller reaches, and the
/// one row that reads no bearer; the same path under another method still
/// authenticates first.
#[test]
fn pair_is_the_one_route_an_unpaired_caller_reaches() {
    let open: Vec<(&str, &str)> = ROUTES
        .iter()
        .filter(|route| route.access == Access::None)
        .map(|route| (route.method, route.path))
        .collect();
    assert_eq!(open, vec![("POST", "/pair")]);

    let _home = HomeSandbox::new();
    let ctx = ctx_with(seeded_config());
    let resp = call(
        &ctx,
        &req("POST", "/api/v1/pair", None, r#"{"code":"ABCD-2345"}"#),
    );
    assert_eq!(resp.status, 403, "no code is live, and the route says so");
    assert_eq!(
        body_json(&resp)["error"],
        serde_json::json!("pairing_refused")
    );
    assert_eq!(
        call(&ctx, &req("GET", "/api/v1/pair", None, "")).status,
        401
    );
    assert_eq!(
        call(&ctx, &req("GET", "/api/v1/pair", Some(TOKEN), "")).status,
        405
    );
}

/// CT-1: each control route answers 403 to a view device. Derived from the
/// table, so a new mutating row is covered by being added; the refused switch
/// moved nothing, and the control device passes the same route.
#[test]
fn a_view_device_is_refused_every_control_route() {
    let _home = HomeSandbox::new();
    let config = seeded_config();
    let ctx = ctx_with(std::sync::Arc::clone(&config));
    seed_device("phone", Tier::View, OTHER_TOKEN);

    let control: Vec<&Route> = ROUTES
        .iter()
        .filter(|route| route.access == Access::Control)
        .collect();
    assert!(
        !control.is_empty(),
        "the table must hold a mutating route for this to guard"
    );
    for route in control {
        let resp = call(
            &ctx,
            &req(
                route.method,
                &route_path(route),
                Some(OTHER_TOKEN),
                r#"{"profile":"beta"}"#,
            ),
        );
        assert_eq!(
            (resp.status, body_json(&resp)),
            (
                403,
                serde_json::json!({
                    "ok": false,
                    "error": "control_required",
                    "reason": CONTROL_REQUIRED,
                })
            ),
            "{} {}",
            route.method,
            route.path
        );
    }
    assert_eq!(
        config
            .lock()
            .expect("config")
            .state
            .active_profile
            .as_deref(),
        Some("alpha"),
        "the refused switch moved nothing"
    );
    let resp = call(
        &ctx,
        &req(
            "POST",
            "/api/v1/switch",
            Some(TOKEN),
            r#"{"profile":"beta"}"#,
        ),
    );
    assert_eq!(resp.status, 200, "the control device passes the same route");
}

#[test]
fn a_view_device_reads_every_view_route() {
    let _home = HomeSandbox::new();
    let ctx = ctx_with(seeded_config());
    seed_device("phone", Tier::View, OTHER_TOKEN);
    for route in ROUTES.iter().filter(|route| route.access == Access::View) {
        let resp = call(
            &ctx,
            &req(route.method, &route_path(route), Some(OTHER_TOKEN), ""),
        );
        assert_eq!(resp.status, 200, "{} {}", route.method, route.path);
    }
}

/// A stored tier this build does not know: that device authenticates, every
/// route refuses it with the fix named, the log says so once, and the other
/// devices keep working.
#[test]
fn an_unknown_tier_device_is_refused_while_the_others_work() {
    let _home = HomeSandbox::new();
    let ctx = ctx_with(seeded_config());
    seed_device("wall", Tier::Unknown("readonly".to_string()), OTHER_TOKEN);
    let lines = crate::logline::LogLines::new();
    let _capture = lines.capture_here();

    for route in ROUTES.iter().filter(|route| route.access != Access::None) {
        let handled = handle(
            &ctx,
            &req(
                route.method,
                &route_path(route),
                Some(OTHER_TOKEN),
                r#"{"profile":"beta"}"#,
            ),
            peer(),
        );
        assert_eq!(
            (handled.response.status, body_json(&handled.response)),
            (
                403,
                serde_json::json!({
                    "ok": false,
                    "error": "device_tier_unknown",
                    "reason": TIER_UNKNOWN,
                })
            ),
            "{} {}",
            route.method,
            route.path
        );
        assert_eq!(
            handled.device.as_deref(),
            Some("wall"),
            "it authenticated; authorization is what refuses it"
        );
    }
    assert_eq!(
        call(&ctx, &req("GET", "/api/v1/health", Some(TOKEN), "")).status,
        200,
        "the other devices are unaffected"
    );
    assert_eq!(
        lines
            .snapshot()
            .iter()
            .filter(|line| line.contains("carries tier \"readonly\""))
            .count(),
        1
    );
}

/// TK-5: a revoked device is refused on its very next request, with no
/// restart, and the other devices keep working.
#[test]
fn a_revoked_device_is_refused_on_its_next_request() {
    let _home = HomeSandbox::new();
    let ctx = ctx_with(seeded_config());
    seed_device("phone", Tier::View, OTHER_TOKEN);
    let health = |bearer: &str| call(&ctx, &req("GET", "/api/v1/health", Some(bearer), "")).status;

    assert_eq!(health(OTHER_TOKEN), 200);
    devices::revoke("phone").expect("revoke");
    assert_eq!(health(OTHER_TOKEN), 401);
    assert_eq!(health(TOKEN), 200);
}

/// The list is read per request and fails closed: an unreadable one refuses
/// every request with a 500 said once in the log, never read as an empty list
/// and never as the last one that parsed.
#[test]
fn an_unreadable_device_list_refuses_every_request() {
    let _home = HomeSandbox::new();
    let ctx = ctx_with(seeded_config());
    std::fs::write(
        crate::profile::clauth_dir()
            .expect("dir")
            .join("devices.json"),
        b"{ not json",
    )
    .expect("damage the list");
    let lines = crate::logline::LogLines::new();
    let _capture = lines.capture_here();

    for _ in 0..2 {
        let resp = call(&ctx, &req("GET", "/api/v1/health", Some(TOKEN), ""));
        assert_eq!(
            (resp.status, body_json(&resp)),
            (500, serde_json::json!({"ok": false, "error": "internal"}))
        );
    }
    assert_eq!(
        lines
            .snapshot()
            .iter()
            .filter(|line| line.contains("until the device list reads"))
            .count(),
        1
    );
}

/// The router tells the serve loop which device each answer went to, for the
/// per-request audit line.
#[test]
fn the_router_reports_the_device_it_answered() {
    let _home = HomeSandbox::new();
    let ctx = ctx_with(seeded_config());
    let device = |bearer: Option<&str>, method: &str, path: &str| {
        handle(&ctx, &req(method, path, bearer, ""), peer()).device
    };
    assert_eq!(
        device(Some(TOKEN), "GET", "/api/v1/health").as_deref(),
        Some(DEVICE)
    );
    assert_eq!(
        device(Some(TOKEN), "GET", "/api/v1/nope").as_deref(),
        Some(DEVICE),
        "a 404 still went to the device"
    );
    assert_eq!(device(None, "GET", "/api/v1/health"), None);
    assert_eq!(
        device(None, "POST", "/api/v1/pair"),
        None,
        "the redemption reads no bearer"
    );
}

#[test]
fn a_wrong_token_is_rejected() {
    let _home = HomeSandbox::new();
    let ctx = ctx_with(seeded_config());
    let wrong = "f".repeat(64);

    let resp = call(&ctx, &req("GET", "/api/v1/health", Some(&wrong), ""));
    assert_eq!(resp.status, 401);
}

#[test]
fn health_reports_the_feed_schema() {
    let _home = HomeSandbox::new();
    let ctx = ctx_with(seeded_config());

    let resp = call(&ctx, &req("GET", "/api/v1/health", Some(TOKEN), ""));
    assert_eq!(resp.status, 200);
    let body = body_json(&resp);
    assert_eq!(body["ok"], serde_json::json!(true));
    assert_eq!(
        body["schema"],
        serde_json::json!(crate::daemon::SCHEMA_VERSION),
        "a client refuses a daemon newer than it knows off this number"
    );
}

#[test]
fn an_unknown_path_is_404_and_a_wrong_method_is_405() {
    let _home = HomeSandbox::new();
    let ctx = ctx_with(seeded_config());

    assert_eq!(
        call(&ctx, &req("GET", "/api/v1/nope", Some(TOKEN), "")).status,
        404
    );
    assert_eq!(
        call(&ctx, &req("POST", "/api/v1/status", Some(TOKEN), "")).status,
        405,
        "a known path with the wrong verb says which half is wrong"
    );
    assert_eq!(
        call(&ctx, &req("GET", "/api/v1/switch", Some(TOKEN), "")).status,
        405
    );
}

/// Methods are case-sensitive on the wire, so a lowercase verb is the wrong
/// verb: a plain client sending `get` at a known path is told which half is
/// wrong (405), never silently answered as `GET`. The parser-side half of this
/// pin lives in `daemon_api_http.rs` — the verb has to ARRIVE here lowercase
/// for this arm to be reachable from a real connection.
#[test]
fn a_lowercase_verb_is_a_method_error_not_a_silent_match() {
    let _home = HomeSandbox::new();
    let ctx = ctx_with(seeded_config());

    let resp = call(&ctx, &req("get", "/api/v1/status", Some(TOKEN), ""));
    assert_eq!(resp.status, 405);
    assert_eq!(
        body_json(&resp)["error"],
        serde_json::json!("method_not_allowed")
    );

    let control = call(&ctx, &req("GET", "/api/v1/status", Some(TOKEN), ""));
    assert_eq!(control.status, 200, "the uppercase spelling still serves");
}

/// HEAD routes like GET, at the router itself.
///
/// The route table maps HEAD onto its GET handlers (RFC 9110 §9.3), so this
/// seam answers a HEAD with the full GET response — status, body, and entity
/// tag. The body is stripped one layer up, in the connection loop, by the
/// method-level `Response::into_head` that covers the error arms too; the wire
/// half is pinned in the http tests. Pinning here that the ROUTER answers
/// HEAD as GET (and never 405) is what keeps the mapping from regressing.
#[test]
fn head_routes_like_get_at_the_router() {
    let _home = HomeSandbox::new();
    let ctx = ctx_with(seeded_config());

    let resp = call(&ctx, &req("HEAD", "/api/v1/health", Some(TOKEN), ""));
    assert_eq!(resp.status, 200);

    let status = call(&ctx, &req("HEAD", "/api/v1/status", Some(TOKEN), ""));
    assert_eq!(status.status, 200);

    // The disabled-accounts query is a GET arm too: its HEAD keeps the ETag a
    // conditional client re-arms from, and a matching If-None-Match answers
    // 304 with the tag.
    let tagged = call(&ctx, &req("HEAD", "/api/v1/status?all=1", Some(TOKEN), ""));
    assert_eq!(tagged.status, 200);
    let etag = tagged
        .etag
        .as_deref()
        .expect("the HEAD arm keeps the entity tag")
        .to_string();
    let mut conditional = req_tagged("/api/v1/status?all=1", Some(TOKEN), &etag);
    conditional.method = "HEAD".to_string();
    let not_modified = call(&ctx, &conditional);
    assert_eq!(not_modified.status, 304);
    assert!(not_modified.etag.is_some(), "the 304 repeats the tag");
}

/// The routes live under `/api/v1`, and nothing answers beside it.
///
/// Worth pinning because the prefix moved: an unversioned `/v1` was served
/// before, and a replica or script still dialling it must get a clean 404 rather
/// than a route that happens to still work. The token is valid in every case
/// here, so a 404 is the path being rejected and not the caller.
#[test]
fn only_the_api_v1_prefix_is_served() {
    let _home = HomeSandbox::new();
    let ctx = ctx_with(seeded_config());

    for path in ["/v1/health", "/v1/status", "/health", "/api/health"] {
        assert_eq!(
            call(&ctx, &req("GET", path, Some(TOKEN), "")).status,
            404,
            "{path} is outside the prefix and must not be served"
        );
    }

    assert_eq!(
        call(
            &ctx,
            &req(
                "GET",
                &format!("{}/health", crate::daemon::api::routes::API_PREFIX),
                Some(TOKEN),
                ""
            )
        )
        .status,
        200,
        "the prefix constant is what the table actually answers on"
    );
}

// -------------------------------------------------------------- status

/// `?all=1` answers from the scheduler's live stores, like the plain route.
///
/// It is the one status request that BUILDS a body instead of serving the file
/// the scheduler wrote, and it used to build with no live signals at all — so
/// `fetch_status`, `next_refresh_at`, `stale` and `pending_switch` came off a
/// file mtime while `GET /api/v1/status`, answered from the file, carried the
/// real ones. Same daemon, same second, four fields apart.
#[test]
fn all_equals_one_reads_the_live_stores_not_a_file_mtime() {
    let _home = HomeSandbox::new();
    let live = crate::daemon::LiveStores::default();
    live.usage_status
        .lock()
        .expect("status store")
        .insert("alpha".to_string(), crate::usage::FetchStatus::RateLimited);
    // The other store `LiveStores::snapshot`'s own comment names as the
    // regression: an `AuthExpired` third-party session writes no cache, so
    // before the snapshot carried this store the rebuild could only publish
    // the mtime derivation's `null` for it — indistinguishable from never
    // fetched. beta has no cache either, so only this store can answer.
    live.third_party_status
        .lock()
        .expect("third-party status store")
        .insert("beta".to_string(), crate::usage::FetchStatus::AuthExpired);
    let ctx = ctx_with_live(seeded_config(), live);

    let resp = call(&ctx, &req("GET", "/api/v1/status?all=1", Some(TOKEN), ""));
    assert_eq!(resp.status, 200);
    let body = body_json(&resp);
    let entry = |name: &str| {
        body["profiles"]
            .as_array()
            .expect("profiles")
            .iter()
            .find(|p| p["name"] == serde_json::json!(name))
            .unwrap_or_else(|| panic!("{name} is in the roster"))
            .clone()
    };
    let alpha = entry("alpha");
    assert_eq!(
        alpha["fetch_status"],
        serde_json::json!("RateLimited"),
        "the OAuth store's value has to win; nothing wrote a cache file for it to derive from"
    );
    let beta = entry("beta");
    assert_eq!(
        beta["fetch_status"],
        serde_json::json!("AuthExpired"),
        "the third-party store's verdict has to win; beta has no cache, so the \
         mtime derivation would publish null: {}",
        beta
    );
}

/// The published feed is passed through byte for byte: one writer, one shape.
#[test]
fn status_serves_the_on_disk_feed_verbatim() {
    let home = HomeSandbox::new();
    let ctx = ctx_with(seeded_config());
    let feed = r#"{"schema":1,"active_profile":"alpha","profiles":[]}"#;
    crate::profile::mkdir_700(&crate::profile::clauth_dir().expect("dir")).expect("mkdir");
    std::fs::write(&ctx.status_path, feed).expect("seed feed");
    let _ = home;

    let resp = call(&ctx, &req("GET", "/api/v1/status", Some(TOKEN), ""));
    assert_eq!(resp.status, 200);
    assert_eq!(
        String::from_utf8_lossy(&resp.body),
        feed,
        "the feed must not be re-serialized on the way out"
    );
}

/// A reader that connects during the daemon's first tick still gets a coherent
/// body rather than a 404 or an empty file.
#[test]
fn status_falls_back_to_a_built_body_when_the_feed_is_missing() {
    let _home = HomeSandbox::new();
    let ctx = ctx_with(seeded_config());
    assert!(!ctx.status_path.exists());

    let resp = call(&ctx, &req("GET", "/api/v1/status", Some(TOKEN), ""));
    assert_eq!(resp.status, 200);
    let body = body_json(&resp);
    assert_eq!(body["active_profile"], serde_json::json!("alpha"));
    assert_eq!(
        body["schema"],
        serde_json::json!(crate::daemon::SCHEMA_VERSION)
    );
}

/// The published feed always hides disabled accounts, so `?all=1` has to bypass
/// the passthrough and rebuild.
#[test]
fn all_reveals_disabled_accounts_that_the_plain_feed_hides() {
    let _home = HomeSandbox::new();
    let config = seeded_config();
    {
        let mut cfg = config.lock().expect("config");
        let beta = cfg
            .find_mut(&crate::profile::ProfileName::from("beta"))
            .expect("beta");
        beta.disabled = true;
        save_profile(beta).expect("save");
    }
    let ctx = ctx_with(config);

    let plain = body_json(&call(&ctx, &req("GET", "/api/v1/status", Some(TOKEN), "")));
    let all = body_json(&call(
        &ctx,
        &req("GET", "/api/v1/status?all=1", Some(TOKEN), ""),
    ));

    let names = |v: &serde_json::Value| -> Vec<String> {
        v["profiles"]
            .as_array()
            .expect("profiles")
            .iter()
            .map(|p| p["name"].as_str().unwrap_or_default().to_string())
            .collect()
    };
    assert!(!names(&plain).contains(&"beta".to_string()), "{plain}");
    assert!(names(&all).contains(&"beta".to_string()), "{all}");
}

/// `?all=1` is conditional like the plain route: its built body is tagged
/// through the same `etag_for`, a matching `If-None-Match` answered 304, a
/// moved feed answered 200 with a new tag. A client reusing its
/// conditional-request code against the query used to get the whole body
/// resent on every poll. `generated_at` moves on every rebuild and the tag
/// ignores it, so the 304 leg is not racing the clock.
#[test]
fn the_all_query_is_tagged_and_answers_304_to_a_matching_tag() {
    let _home = HomeSandbox::new();
    let config = seeded_config();
    let ctx = ctx_with(std::sync::Arc::clone(&config));

    let first = call(&ctx, &req("GET", "/api/v1/status?all=1", Some(TOKEN), ""));
    assert_eq!(first.status, 200);
    let tag = first
        .etag
        .clone()
        .expect("the ?all body carries an entity tag");

    let second = call(&ctx, &req_tagged("/api/v1/status?all=1", Some(TOKEN), &tag));
    assert_eq!(second.status, 304, "an unchanged roster is not resent");
    assert_eq!(second.etag.as_deref(), Some(tag.as_str()));

    // The feed moves: the active account changes, so the body a reader could
    // act on changes with it.
    config.lock().expect("config").state.active_profile = Some("beta".into());
    let third = call(&ctx, &req_tagged("/api/v1/status?all=1", Some(TOKEN), &tag));
    assert_eq!(third.status, 200, "a moved feed is answered, not 304'd");
    let moved = third.etag.clone().expect("a 200 carries an entity tag");
    assert_ne!(moved, tag, "and the feed's move is visible in the tag");

    let fourth = call(
        &ctx,
        &req_tagged("/api/v1/status?all=1", Some(TOKEN), &moved),
    );
    assert_eq!(fourth.status, 304, "the new tag is now the current one");
}

// -------------------------------------------------------------- switch

#[test]
fn switch_relinks_and_reports_the_previous_account() {
    let _home = HomeSandbox::new();
    let config = seeded_config();
    let ctx = ctx_with(std::sync::Arc::clone(&config));

    let resp = call(
        &ctx,
        &req(
            "POST",
            "/api/v1/switch",
            Some(TOKEN),
            r#"{"profile":"beta"}"#,
        ),
    );
    assert_eq!(resp.status, 200, "{}", String::from_utf8_lossy(&resp.body));
    let body = body_json(&resp);
    assert_eq!(body["ok"], serde_json::json!(true));
    assert_eq!(body["previous"], serde_json::json!("alpha"));
    assert_eq!(body["active"], serde_json::json!("beta"));
    assert_eq!(
        config
            .lock()
            .expect("config")
            .state
            .active_profile
            .as_deref(),
        Some("beta"),
        "the switch must land in state, not just in the response"
    );
}

/// The same case-insensitive resolution the CLI and MCP paths apply, and for
/// the same reason: an unresolved name reaching the relink would strip the live
/// credential symlink and leave nothing in its place.
#[test]
fn switch_resolves_the_name_case_insensitively() {
    let _home = HomeSandbox::new();
    let ctx = ctx_with(seeded_config());

    let resp = call(
        &ctx,
        &req(
            "POST",
            "/api/v1/switch",
            Some(TOKEN),
            r#"{"profile":"BeTa"}"#,
        ),
    );
    assert_eq!(resp.status, 200);
    assert_eq!(body_json(&resp)["active"], serde_json::json!("beta"));
}

#[test]
fn switch_to_an_unknown_profile_is_404_and_changes_nothing() {
    let _home = HomeSandbox::new();
    let config = seeded_config();
    let ctx = ctx_with(std::sync::Arc::clone(&config));

    let resp = call(
        &ctx,
        &req(
            "POST",
            "/api/v1/switch",
            Some(TOKEN),
            r#"{"profile":"ghost"}"#,
        ),
    );
    assert_eq!(resp.status, 404);
    assert_eq!(
        body_json(&resp)["error"],
        serde_json::json!("profile_not_found")
    );
    assert_eq!(
        config
            .lock()
            .expect("config")
            .state
            .active_profile
            .as_deref(),
        Some("alpha"),
    );
}

#[test]
fn switch_to_a_disabled_profile_is_refused() {
    let _home = HomeSandbox::new();
    let config = seeded_config();
    {
        let mut cfg = config.lock().expect("config");
        let beta = cfg
            .find_mut(&crate::profile::ProfileName::from("beta"))
            .expect("beta");
        beta.disabled = true;
        save_profile(beta).expect("save");
    }
    let ctx = ctx_with(std::sync::Arc::clone(&config));

    let resp = call(
        &ctx,
        &req(
            "POST",
            "/api/v1/switch",
            Some(TOKEN),
            r#"{"profile":"beta"}"#,
        ),
    );
    assert_eq!(resp.status, 409);
    assert_eq!(
        config
            .lock()
            .expect("config")
            .state
            .active_profile
            .as_deref(),
        Some("alpha"),
    );
}

#[test]
fn a_malformed_switch_body_is_400() {
    let _home = HomeSandbox::new();
    let ctx = ctx_with(seeded_config());

    for body in ["", "{}", "not json", r#"{"profile":7}"#] {
        let resp = call(&ctx, &req("POST", "/api/v1/switch", Some(TOKEN), body));
        assert_eq!(resp.status, 400, "body {body:?}");
    }
}

/// A switch already running means answer at once rather than parking the caller
/// on the cross-process flock for its full 25s deadline.
///
/// The gate is held on ANOTHER thread, which is the only shape that models the
/// real case: rank state is thread-local, so a same-thread re-entry would trip
/// the lock-order assertion instead of exercising this path.
#[test]
fn a_second_concurrent_switch_is_refused_immediately() {
    let _home = HomeSandbox::new();
    let ctx = ctx_with(seeded_config());

    let (held_tx, held_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();

    let holder = std::sync::Arc::clone(&ctx);
    std::thread::scope(|scope| {
        scope.spawn(move || {
            let _gate = holder.switch_gate.lock().expect("gate");
            held_tx.send(()).expect("signal held");
            // Hold it until the assertion below has run.
            let _ = release_rx.recv();
        });
        held_rx.recv().expect("gate taken");

        let resp = call(
            &ctx,
            &req(
                "POST",
                "/api/v1/switch",
                Some(TOKEN),
                r#"{"profile":"beta"}"#,
            ),
        );
        assert_eq!(resp.status, 409);
        assert_eq!(
            body_json(&resp)["error"],
            serde_json::json!("switch_in_progress")
        );
        let _ = release_tx.send(());
    });
}

/// The poisoned-gate half, pinned at the ROUTE rather than the primitive.
///
/// `RankedMutex::try_lock` recovers a poisoned mutex (its pin lives in
/// `tests/inline/lockorder.rs`), but only a test through `handle` reds on the
/// caller that matters: a future edit collapsing poison back into the lock
/// error would answer every later switch with a permanent `409
/// switch_in_progress`, and the primitive's pin would stay green while the
/// route wedged.
#[test]
fn a_poisoned_gate_does_not_wedge_the_switch_route() {
    let _home = HomeSandbox::new();
    let ctx = ctx_with(seeded_config());

    // Poison it the only way a mutex gets poisoned: panic while holding it.
    let holder = std::sync::Arc::clone(&ctx);
    let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _gate = holder.switch_gate.lock().expect("gate");
        panic!("a switch panicked under the gate");
    }));
    assert!(poisoned.is_err(), "precondition: the closure panicked");

    let resp = call(
        &ctx,
        &req(
            "POST",
            "/api/v1/switch",
            Some(TOKEN),
            r#"{"profile":"beta"}"#,
        ),
    );
    assert_eq!(
        resp.status,
        200,
        "a poisoned gate is recovered and the switch proceeds, not answered with a \
         permanent 409: {}",
        String::from_utf8_lossy(&resp.body)
    );
    assert_eq!(body_json(&resp)["active"], serde_json::json!("beta"));
    assert_eq!(
        ctx.config
            .lock()
            .expect("config")
            .state
            .active_profile
            .as_deref(),
        Some("beta"),
        "the switch must still land in state, not just in the response"
    );
}

/// The switch gate must not invert the lock order when the target's token has
/// already expired.
///
/// Every other case in this file mints `expires_at: None`, so `expiring()` is
/// false and `ensure_installable` short-circuits before it acquires a
/// `RotationGuard` — which is why the whole suite stayed green over a live
/// lock-order bug. With an expiry in the past the guard IS taken, entering
/// `rank::Rotation` while `rank::ApiSwitch` is held; at ApiSwitch's old 380 that
/// tripped the ordering assert and panicked the request out on any debug build.
///
/// What is asserted is the absence of that panic: the switch is expected to
/// FAIL — the chain here is synthetic — but to fail as an answer rather than by
/// unwinding through the gate. The token endpoint is pointed at a closed
/// loopback port so the refresh leg fails as transport without reaching the
/// network; without that the test would post a synthetic refresh token to
/// Anthropic on every run.
#[test]
fn a_switch_to_a_clock_expired_target_does_not_invert_the_lock_order() {
    let home = HomeSandbox::new();

    // Bound then dropped: the port is now closed, so a connect fails at once.
    let dead = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind");
    let port = dead.local_addr().expect("addr").port();
    drop(dead);
    // The RAII sandbox the other endpoint-override tests use, not a bare
    // `set_endpoint_overrides`: this test exists to catch a PANIC (the
    // lock-order assert), and a panic unwinds past a manual clear, leaving the
    // dead-port redirect installed for every sibling test in the binary.
    let _endpoints =
        crate::testutil::EndpointSandbox::new(&home, &format!("http://127.0.0.1:{port}"));

    let config = seeded_config();
    {
        let mut cfg = config.lock().expect("config");
        let beta = cfg
            .find_mut(&crate::profile::ProfileName::from("beta"))
            .expect("beta");
        // An hour in the past, in epoch ms, so `expiring()` is true however the
        // staleness window is spelled.
        if let Some(oauth) = beta
            .credentials
            .as_mut()
            .and_then(|c| c.claude_ai_oauth.as_mut())
        {
            oauth.expires_at = Some(crate::usage::now_ms() as i64 - 3_600_000);
        }
        save_profile(beta).expect("save");
    }
    let ctx = ctx_with(std::sync::Arc::clone(&config));

    let resp = call(
        &ctx,
        &req(
            "POST",
            "/api/v1/switch",
            Some(TOKEN),
            r#"{"profile":"beta"}"#,
        ),
    );

    assert_eq!(
        resp.status, 409,
        "an unrefreshable target is refused, not unwound through the gate"
    );
}

/// The switch is the same action `clauth <name>` and the MCP tool perform, so
/// it inherits their refusal sentences — not their anyhow chains. The IO arms
/// of a switch carry context strings that name absolute paths under the
/// operator's home (`failed to publish /home/…/credentials.json`); a reason
/// that reflects the open chain puts the operator's home layout in an HTTP
/// body, and the body is the one surface the daemon hands to a remote reader.
/// The failure is posed by making the live `.credentials.json` a directory:
/// the relink stages its symlink fine, and the rename onto a directory fails
/// `EISDIR` — the `failed to publish <home path>` arm itself.
#[test]
fn a_failed_switch_reflects_no_home_path() {
    let home = HomeSandbox::new();
    let config = seeded_config();
    {
        let mut cfg = config.lock().expect("config");
        // A diverged-looking live slot routes to the divergence machinery, so
        // the Discard default is what lets a headless switch reach the link
        // publish this fixture is built to fail.
        cfg.state.default_divergence = Some(DivergenceChoice::Discard);
    }
    std::fs::create_dir_all(
        crate::profile::claude_dir()
            .expect("claude dir")
            .join(".credentials.json"),
    )
    .expect("pose the wedge");
    let ctx = ctx_with(std::sync::Arc::clone(&config));

    let resp = call(
        &ctx,
        &req(
            "POST",
            "/api/v1/switch",
            Some(TOKEN),
            r#"{"profile":"beta"}"#,
        ),
    );
    let body = body_json(&resp);
    let reason = body["reason"].as_str().expect("reason is a string");
    let sandbox = home.home().display().to_string();
    assert_eq!(
        resp.status,
        500,
        "an IO failure answers switch_failed, body: {}",
        String::from_utf8_lossy(&resp.body)
    );
    assert_eq!(body["error"], serde_json::json!("switch_failed"));
    assert!(
        !reason.contains(&sandbox) && !reason.contains("/home/"),
        "the reflected reason must carry no home path, got: {reason}"
    );
    assert_eq!(
        config
            .lock()
            .expect("config")
            .state
            .active_profile
            .as_deref(),
        Some("alpha"),
        "a failed switch must leave the active profile unchanged"
    );
}

/// The 500 the failed switch answers is a fixed literal, so the context that
/// would name the home path has to live somewhere the operator can read: the
/// refusal logline, and only it. `Refused` renders a bare sentence, `Failed`
/// the full anyhow chain — a head-line-only copy would name neither the
/// failed operation nor its cause, and the body's "see daemon.log" would
/// point at a log that cannot answer.
#[test]
fn a_failed_switchs_context_reaches_the_log_but_not_the_body() {
    let _home = HomeSandbox::new();
    let config = seeded_config();
    {
        let mut cfg = config.lock().expect("config");
        cfg.state.default_divergence = Some(DivergenceChoice::Discard);
    }
    std::fs::create_dir_all(
        crate::profile::claude_dir()
            .expect("claude dir")
            .join(".credentials.json"),
    )
    .expect("pose the wedge");

    let lines = crate::logline::LogLines::new();
    let _capture = lines.capture_here();
    let ctx = ctx_with(std::sync::Arc::clone(&config));
    let resp = call(
        &ctx,
        &req(
            "POST",
            "/api/v1/switch",
            Some(TOKEN),
            r#"{"profile":"beta"}"#,
        ),
    );
    assert_eq!(resp.status, 500);

    let body = body_json(&resp);
    assert_eq!(
        body["reason"],
        serde_json::json!("the switch failed; see daemon.log"),
        "the body is the fixed literal, nothing else"
    );
    let joined = lines.snapshot().join("\n");
    let logged = joined
        .lines()
        .find(|line| line.contains("refused"))
        .expect("the refusal reached the log");
    assert!(
        logged.contains("failed to publish"),
        "the logline names the operation that failed: {logged}"
    );
    assert!(
        logged.contains("Is a directory"),
        "the logline carries the underlying cause, not the head line alone: {logged}"
    );
    let home = _home.home().display().to_string();
    assert!(
        !body["reason"].as_str().unwrap_or_default().contains(&home),
        "the home path lives in the log, never the body"
    );
}

/// The authored refusals — the closed diagnostic set `src/format.rs` renders
/// — reflect verbatim, so a remote reader gets the same actionable sentence
/// the CLI and MCP surfaces do, name and fix included.
#[test]
fn a_refused_switch_reflects_the_authored_sentence() {
    let _home = HomeSandbox::new();
    let config = seeded_config();
    {
        let mut cfg = config.lock().expect("config");
        let beta = cfg
            .find_mut(&crate::profile::ProfileName::from("beta"))
            .expect("beta");
        beta.disabled = true;
        save_profile(beta).expect("save");
    }
    let ctx = ctx_with(std::sync::Arc::clone(&config));

    let resp = call(
        &ctx,
        &req(
            "POST",
            "/api/v1/switch",
            Some(TOKEN),
            r#"{"profile":"beta"}"#,
        ),
    );
    let body = body_json(&resp);
    assert_eq!(resp.status, 409);
    assert_eq!(body["error"], serde_json::json!("switch_refused"));
    assert_eq!(
        body["reason"],
        serde_json::json!("'beta': account is disabled, run `clauth enable beta`")
    );
}

/// A config snapshot a tick old must not misfile a genuine refusal as an
/// unexpected failure. `ensure_switch_target_ok` re-reads the roster off disk
/// under the state flock precisely because the daemon holds a handle a
/// concurrent `clauth delete` can leave behind; the refusal it raises there is
/// still authored, still carries the fix, and must still answer 409 — the
/// route's own membership check passed a moment earlier, so answering 500 for
/// what the disk says a tick later mislabels a refusal the operator can act
/// on. Posed by the divergence itself: the handle still lists beta while the
/// saved roster does not.
#[test]
fn a_target_vanishing_mid_switch_answers_refused_not_failed() {
    let _home = HomeSandbox::new();
    let config = seeded_config();
    // seeded_config saved a roster carrying both profiles; take beta back off
    // the disk while the in-memory handle keeps it, which is exactly what a
    // delete racing the route's pre-check leaves behind.
    {
        let mut cfg = config.lock().expect("config");
        cfg.state.profiles.retain(|n| n != "beta");
        save_app_state(&cfg.state).expect("save roster");
    }
    let ctx = ctx_with(std::sync::Arc::clone(&config));

    let resp = call(
        &ctx,
        &req(
            "POST",
            "/api/v1/switch",
            Some(TOKEN),
            r#"{"profile":"beta"}"#,
        ),
    );
    let body = body_json(&resp);
    assert_eq!(
        resp.status,
        409,
        "a vanished target is a refusal, not an unexpected failure: {}",
        String::from_utf8_lossy(&resp.body)
    );
    assert_eq!(body["error"], serde_json::json!("switch_refused"));
    assert_eq!(
        body["reason"],
        serde_json::json!("profile 'beta' not found")
    );
}

/// A held state flock is the one retryable refusal, and its reason is the
/// closed `StateLockTimeout` Display — `~/.clauth/.lock` spelled as a literal,
/// never the sandbox's absolute home. Posed with the same independent open
/// file description `tests/inline/lock.rs` uses to stand in for a second
/// clauth process, plus the thread-local deadline override so the wait is
/// milliseconds, not 25 s.
#[test]
fn a_state_lock_timeout_is_503_with_a_path_free_reason() {
    let _home = HomeSandbox::new();
    // Seeded BEFORE the wedge: `seeded_config` takes the state flock itself.
    let ctx = ctx_with(seeded_config());
    let dir = crate::profile::clauth_dir().expect("clauth dir");
    let holder = crate::profile::open_state_file(&dir.join(crate::lock::LOCK_FILENAME))
        .expect("open holder handle");
    holder.lock().expect("hold the flock");
    crate::lock::set_state_lock_timeout_override(Some(std::time::Duration::from_millis(100)));

    let resp = call(
        &ctx,
        &req(
            "POST",
            "/api/v1/switch",
            Some(TOKEN),
            r#"{"profile":"beta"}"#,
        ),
    );
    crate::lock::set_state_lock_timeout_override(None);
    drop(holder);

    let body = body_json(&resp);
    assert_eq!(resp.status, 503, "{}", String::from_utf8_lossy(&resp.body));
    assert_eq!(body["error"], serde_json::json!("state_locked"));
    let reason = body["reason"].as_str().expect("reason is a string");
    assert!(
        !reason.contains("/home/") && !reason.contains("home"),
        "the reflected reason must carry no home path, got: {reason}"
    );
    assert!(
        reason.contains("state lock"),
        "the reason names the condition, got: {reason}"
    );
}

// --------------------------------------------------------------- audit

/// RE-1: the switch's own line names the device that asked.
#[test]
fn a_switch_line_names_the_device() {
    let _home = HomeSandbox::new();
    let ctx = ctx_with(seeded_config());
    let lines = crate::logline::LogLines::new();
    let _capture = lines.capture_here();

    let resp = call(
        &ctx,
        &req(
            "POST",
            "/api/v1/switch",
            Some(TOKEN),
            r#"{"profile":"beta"}"#,
        ),
    );
    assert_eq!(resp.status, 200);
    assert!(
        lines
            .snapshot()
            .contains(&"clauth api: device 'test' switched to 'beta'".to_string()),
        "{:#?}",
        lines.snapshot()
    );
}

#[test]
fn a_refused_switch_line_names_the_device() {
    let _home = HomeSandbox::new();
    let config = seeded_config();
    {
        let mut cfg = config.lock().expect("config");
        let beta = cfg
            .find_mut(&crate::profile::ProfileName::from("beta"))
            .expect("beta");
        beta.disabled = true;
        save_profile(beta).expect("save");
    }
    let ctx = ctx_with(std::sync::Arc::clone(&config));
    let lines = crate::logline::LogLines::new();
    let _capture = lines.capture_here();

    let resp = call(
        &ctx,
        &req(
            "POST",
            "/api/v1/switch",
            Some(TOKEN),
            r#"{"profile":"beta"}"#,
        ),
    );
    assert_eq!(resp.status, 409);
    assert!(
        lines
            .snapshot()
            .iter()
            .any(|line| line.starts_with("clauth api: device 'test' switch to 'beta' refused: ")),
        "{:#?}",
        lines.snapshot()
    );
}
