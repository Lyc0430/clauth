#![allow(clippy::unwrap_used, clippy::expect_used)]

//! `POST /api/v1/panes/{id}/prompt` and `POST /api/v1/panes/{id}/keys`: the
//! argv that reaches herdr, herdr's refusals mapped, the body shape judged
//! before herdr is asked, and the audit line that names sizes, never content.
//!
//! herdr is a recorded table behind the context's seam, so no test runs a
//! real one; every call's argv is recorded for the pins.

#![cfg(unix)]

use super::*;

use std::sync::{Arc, Mutex};

use crate::daemon::api::devices::Tier;
use crate::daemon::api::panes::PaneProbe;
use crate::testutil::{DEVICE, HomeSandbox, OTHER_TOKEN, TOKEN, body_json, call, req, seed_device};

/// herdr's error envelopes as measured on 0.9.0 for a bogus target: printed
/// on STDERR with an empty stdout, exit 1; `agent_blocked` and `timeout` are
/// the same envelope with the codes `herdr agent prompt --help` documents.
const AGENT_NOT_FOUND: &str = r#"{"error":{"code":"agent_not_found","message":"agent target w9:p99 not found"},"id":"cli:agent:prompt"}"#;
const PANE_NOT_FOUND_ENVELOPE: &str =
    r#"{"error":{"code":"pane_not_found","message":"pane w9:p99 not found"},"id":"cli:request"}"#;
const AGENT_BLOCKED_ENVELOPE: &str = r#"{"error":{"code":"agent_blocked","message":"agent w1N:p19 is blocked on a prompt"},"id":"cli:agent:prompt"}"#;
const TIMEOUT_ENVELOPE: &str = r#"{"error":{"code":"timeout","message":"no matching state within 5000ms"},"id":"cli:agent:prompt"}"#;
/// herdr's no-server refusal as measured on 0.9.0 with a bogus socket path,
/// the same stream as every other envelope.
const SERVER_NOT_RUNNING_STDERR: &str = r#"{"id":"cli:pane:list","error":{"code":"server_not_running","message":"no herdr server is running at /nonexistent/herdr.sock; run `herdr` to start or attach it"}}"#;

/// What the recorded table answers every call with.
#[derive(Clone, Copy)]
enum Answer {
    NotInstalled,
    NeverRan,
    Ran {
        success: bool,
        stdout: &'static str,
        stderr: &'static str,
    },
}

type Calls = Arc<Mutex<Vec<Vec<String>>>>;

/// A seam answering `answer` and recording every argv it was handed.
fn seam(answer: Answer) -> (PaneProbe, Calls) {
    let calls: Calls = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&calls);
    let probe: PaneProbe = Box::new(move |args, _deadline| {
        recorded
            .lock()
            .unwrap()
            .push(args.iter().map(|arg| arg.to_string()).collect());
        match answer {
            Answer::NotInstalled => HerdrProbeOut::NotInstalled,
            Answer::NeverRan => HerdrProbeOut::Ran(None),
            Answer::Ran {
                success,
                stdout,
                stderr,
            } => HerdrProbeOut::Ran(Some(HerdrOut {
                success,
                stdout: stdout.as_bytes().to_vec(),
                stderr: stderr.as_bytes().to_vec(),
            })),
        }
    });
    (probe, calls)
}

fn config() -> crate::profile::ConfigHandle {
    std::sync::Arc::new(crate::lockorder::RankedMutex::new(
        crate::profile::AppConfig {
            state: crate::profile::AppState::default(),
            profiles: Vec::new(),
        },
    ))
}

/// The control device every test pairs once, before its first context.
fn seed() {
    seed_device(DEVICE, Tier::Control, TOKEN);
}

/// A context over `answer`; the calls it saw.
fn ctx_over(answer: Answer) -> (std::sync::Arc<ApiContext>, Calls) {
    let status_path = crate::profile::clauth_dir()
        .expect("clauth dir")
        .join("status.json");
    let (probe, calls) = seam(answer);
    (
        ApiContext::for_tests(config(), status_path, None, probe),
        calls,
    )
}

fn calls_of(calls: &Calls) -> Vec<Vec<String>> {
    calls.lock().unwrap().clone()
}

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| part.to_string()).collect()
}

const PROMPT: &str = "/api/v1/panes/w1N:p19/prompt";
const KEYS: &str = "/api/v1/panes/w1N:p19/keys";
const PROMPT_BODY: &str = r#"{"text":"fix the tests"}"#;
const KEYS_BODY: &str = r#"{"keys":["y","enter"]}"#;

fn ok() -> Answer {
    Answer::Ran {
        success: true,
        stdout: "",
        stderr: "",
    }
}

/// A failure the way herdr emits one: whatever it printed on stderr, stdout
/// empty.
fn failed(stderr: &'static str) -> Answer {
    Answer::Ran {
        success: false,
        stdout: "",
        stderr,
    }
}

/// The prompt reaches herdr as `agent prompt <pane> <text>`, the answer is
/// the one-field ok, and the audit line carries the pane and the text's
/// length while the text itself reaches no line.
#[test]
fn a_prompt_runs_herdr_agent_prompt_and_logs_the_texts_length() {
    let _home = HomeSandbox::new();
    seed();
    let (ctx, calls) = ctx_over(ok());
    let lines = crate::logline::LogLines::new();
    let _capture = lines.capture_here();

    let resp = call(&ctx, &req("POST", PROMPT, Some(TOKEN), PROMPT_BODY));
    assert_eq!(
        (resp.status, body_json(&resp)),
        (200, serde_json::json!({"ok": true}))
    );
    assert_eq!(
        calls_of(&calls),
        vec![argv(&["agent", "prompt", "w1N:p19", "fix the tests"])]
    );
    assert_eq!(
        lines.snapshot(),
        vec!["clauth api: device 'test' prompted pane 'w1N:p19' text_len=13".to_string()]
    );
}

/// The keys reach herdr as `pane send-keys <pane> <key>…` in order, and the
/// audit line carries their count, never their names.
#[test]
fn keys_run_herdr_pane_send_keys_in_order_and_log_their_count() {
    let _home = HomeSandbox::new();
    seed();
    let (ctx, calls) = ctx_over(ok());
    let lines = crate::logline::LogLines::new();
    let _capture = lines.capture_here();

    let resp = call(&ctx, &req("POST", KEYS, Some(TOKEN), KEYS_BODY));
    assert_eq!(
        (resp.status, body_json(&resp)),
        (200, serde_json::json!({"ok": true}))
    );
    assert_eq!(
        calls_of(&calls),
        vec![argv(&["pane", "send-keys", "w1N:p19", "y", "enter"])]
    );
    assert_eq!(
        lines.snapshot(),
        vec!["clauth api: device 'test' sent keys to pane 'w1N:p19' keys=2".to_string()]
    );

    let many = call(
        &ctx,
        &req(
            "POST",
            "/api/v1/panes/wP:pAA/keys",
            Some(TOKEN),
            r#"{"keys":["ctrl+c","shift-tab","esc","F12","_"]}"#,
        ),
    );
    assert_eq!(many.status, 200);
    assert_eq!(
        calls_of(&calls)[1],
        argv(&[
            "pane",
            "send-keys",
            "wP:pAA",
            "ctrl+c",
            "shift-tab",
            "esc",
            "F12",
            "_"
        ])
    );
}

/// Both routes need the control tier: a view device is refused before herdr
/// is asked, with the fixed sentence.
#[test]
fn a_view_device_is_refused_both_routes_before_herdr_is_asked() {
    let _home = HomeSandbox::new();
    seed();
    let (ctx, calls) = ctx_over(ok());
    seed_device("phone", Tier::View, OTHER_TOKEN);
    for (path, body) in [(PROMPT, PROMPT_BODY), (KEYS, KEYS_BODY)] {
        let resp = call(&ctx, &req("POST", path, Some(OTHER_TOKEN), body));
        assert_eq!(resp.status, 403, "{path}");
        assert_eq!(
            body_json(&resp)["error"],
            serde_json::json!("control_required"),
            "{path}"
        );
    }
    assert!(calls_of(&calls).is_empty(), "herdr was never asked");
}

/// herdr's `agent_not_found` and `pane_not_found`, each on stderr with an
/// empty stdout as herdr prints them, answer 404 with the pane sentence on
/// either route.
#[test]
fn herdrs_not_found_answers_are_404_pane_not_found() {
    let _home = HomeSandbox::new();
    seed();
    let expected = serde_json::json!({
        "ok": false,
        "error": "pane_not_found",
        "reason": "no pane with that id in herdr's default session",
    });
    for answer in [failed(AGENT_NOT_FOUND), failed(PANE_NOT_FOUND_ENVELOPE)] {
        let (ctx, calls) = ctx_over(answer);
        for (path, body) in [(PROMPT, PROMPT_BODY), (KEYS, KEYS_BODY)] {
            let resp = call(&ctx, &req("POST", path, Some(TOKEN), body));
            assert_eq!(
                (resp.status, body_json(&resp)),
                (404, expected.clone()),
                "{path}"
            );
        }
        assert_eq!(
            calls_of(&calls).len(),
            2,
            "herdr answered both, so herdr was asked"
        );
    }
}

/// An agent waiting on a prompt of its own refuses a new prompt: 409 with the
/// sentence that names the way out. The keys route has no such answer — keys
/// are that way out — so there herdr's refusal is the logged catch-all.
#[test]
fn a_blocked_agent_is_409_on_the_prompt_route_alone() {
    let _home = HomeSandbox::new();
    seed();
    let (ctx, _) = ctx_over(failed(AGENT_BLOCKED_ENVELOPE));
    let resp = call(&ctx, &req("POST", PROMPT, Some(TOKEN), PROMPT_BODY));
    assert_eq!(
        (resp.status, body_json(&resp)),
        (
            409,
            serde_json::json!({
                "ok": false,
                "error": "agent_blocked",
                "reason": "the agent is waiting on a prompt of its own; answer it with keys or the terminal stream",
            })
        )
    );

    let lines = crate::logline::LogLines::new();
    let _capture = lines.capture_here();
    let keys = call(&ctx, &req("POST", KEYS, Some(TOKEN), KEYS_BODY));
    assert_eq!(
        (keys.status, body_json(&keys)["error"].clone()),
        (502, serde_json::json!("herdr_refused"))
    );
    assert_eq!(
        lines.snapshot(),
        vec![format!(
            "clauth api: device 'test' send-keys on pane 'w1N:p19' refused by herdr: {AGENT_BLOCKED_ENVELOPE}"
        )]
    );
}

/// herdr absent answers 503 with the panes route's fixed sentence for the
/// state, on both routes: not installed, a call that never ran, and a herdr
/// that ran and printed its `server_not_running` envelope on stderr.
#[test]
fn herdr_absent_is_503_with_the_panes_sentences() {
    let _home = HomeSandbox::new();
    seed();
    for (answer, reason) in [
        (Answer::NotInstalled, "herdr is not installed on this host"),
        (
            Answer::NeverRan,
            "herdr is installed but no server answered on its socket",
        ),
        (
            failed(SERVER_NOT_RUNNING_STDERR),
            "herdr is installed but no server answered on its socket",
        ),
    ] {
        let (ctx, _) = ctx_over(answer);
        for (path, body) in [(PROMPT, PROMPT_BODY), (KEYS, KEYS_BODY)] {
            let resp = call(&ctx, &req("POST", path, Some(TOKEN), body));
            assert_eq!(
                (resp.status, body_json(&resp)),
                (
                    503,
                    serde_json::json!({
                        "ok": false,
                        "error": "herdr_unavailable",
                        "reason": reason,
                    })
                ),
                "{path}"
            );
        }
    }
}

/// Any other non-zero exit is 502 with the fixed sentence; herdr's output
/// reaches the log through the sanitizer and never the body — stderr, where
/// herdr prints every envelope, or stdout should a herdr ever print there;
/// an exit with no output at all logs an empty tail.
#[test]
fn any_other_herdr_failure_is_502_with_its_output_in_the_log_not_the_body() {
    let _home = HomeSandbox::new();
    seed();
    let refused = serde_json::json!({
        "ok": false,
        "error": "herdr_refused",
        "reason": "herdr refused the request; see daemon.log",
    });
    let (ctx, _) = ctx_over(failed(TIMEOUT_ENVELOPE));
    let lines = crate::logline::LogLines::new();
    let _capture = lines.capture_here();
    let resp = call(&ctx, &req("POST", PROMPT, Some(TOKEN), PROMPT_BODY));
    assert_eq!((resp.status, body_json(&resp)), (502, refused.clone()));
    assert_eq!(
        lines.snapshot(),
        vec![format!(
            "clauth api: device 'test' prompt on pane 'w1N:p19' refused by herdr: {TIMEOUT_ENVELOPE}"
        )]
    );
    drop(_capture);

    let (ctx, _) = ctx_over(failed("not json\nsecond line"));
    let lines = crate::logline::LogLines::new();
    let _capture = lines.capture_here();
    let resp = call(&ctx, &req("POST", KEYS, Some(TOKEN), KEYS_BODY));
    assert_eq!((resp.status, body_json(&resp)), (502, refused.clone()));
    assert_eq!(
        lines.snapshot(),
        vec![
            "clauth api: device 'test' send-keys on pane 'w1N:p19' refused by herdr: not json second line"
                .to_string()
        ]
    );
    drop(_capture);

    let (ctx, _) = ctx_over(Answer::Ran {
        success: false,
        stdout: r#"{"id":"cli:agent:prompt","error":{"code":"agent_prompt_stalled","message":"no working or blocked state within 5000ms"}}"#,
        stderr: "",
    });
    let lines = crate::logline::LogLines::new();
    let _capture = lines.capture_here();
    let resp = call(&ctx, &req("POST", PROMPT, Some(TOKEN), PROMPT_BODY));
    assert_eq!((resp.status, body_json(&resp)), (502, refused.clone()));
    assert_eq!(
        lines.snapshot(),
        vec![
            r#"clauth api: device 'test' prompt on pane 'w1N:p19' refused by herdr: {"id":"cli:agent:prompt","error":{"code":"agent_prompt_stalled","message":"no working or blocked state within 5000ms"}}"#
                .to_string()
        ]
    );
    drop(_capture);

    let (ctx, _) = ctx_over(failed(""));
    let lines = crate::logline::LogLines::new();
    let _capture = lines.capture_here();
    let resp = call(&ctx, &req("POST", PROMPT, Some(TOKEN), PROMPT_BODY));
    assert_eq!((resp.status, body_json(&resp)), (502, refused));
    assert_eq!(
        lines.snapshot(),
        vec!["clauth api: device 'test' prompt on pane 'w1N:p19' refused by herdr: ".to_string()]
    );
}

/// A body that is not the one-field shape is 400 and herdr is never asked:
/// no text, empty text, a text carrying a NUL (no argv byte, so the spawn
/// would fail and read as herdr absent), a non-object; no keys, 33 keys, a
/// key of the wrong shape or length.
#[test]
fn a_bad_body_is_400_before_herdr_is_asked() {
    let _home = HomeSandbox::new();
    seed();
    let (ctx, calls) = ctx_over(ok());
    let bad = serde_json::json!({"ok": false, "error": "bad_request"});
    let thirty_three = serde_json::to_string(&serde_json::json!({"keys": vec!["y"; 33]})).unwrap();
    let long_key = serde_json::to_string(&serde_json::json!({"keys": ["a".repeat(33)]})).unwrap();
    for (path, body) in [
        (PROMPT, "{}"),
        (PROMPT, r#"{"text":""}"#),
        (PROMPT, r#"{"text":5}"#),
        (PROMPT, r#"{"text":"a\u0000b"}"#),
        (PROMPT, "[]"),
        (PROMPT, ""),
        (KEYS, "{}"),
        (KEYS, r#"{"keys":[]}"#),
        (KEYS, r#"{"keys":"y"}"#),
        (KEYS, r#"{"keys":["y", ""]}"#),
        (KEYS, r#"{"keys":["ctrl c"]}"#),
        (KEYS, r#"{"keys":["y;rm"]}"#),
        (KEYS, r#"{"keys":["é"]}"#),
        (KEYS, thirty_three.as_str()),
        (KEYS, long_key.as_str()),
    ] {
        let resp = call(&ctx, &req("POST", path, Some(TOKEN), body));
        assert_eq!(
            (resp.status, body_json(&resp)),
            (400, bad.clone()),
            "{path} {body}"
        );
    }
    assert!(calls_of(&calls).is_empty(), "herdr was never asked");

    let thirty_two = serde_json::to_string(&serde_json::json!({"keys": vec!["y"; 32]})).unwrap();
    let max_key = serde_json::to_string(&serde_json::json!({"keys": ["a".repeat(32)]})).unwrap();
    for body in [thirty_two.as_str(), max_key.as_str()] {
        assert_eq!(
            call(&ctx, &req("POST", KEYS, Some(TOKEN), body)).status,
            200,
            "the bounds are inclusive: {body}"
        );
    }
}

/// The pane id is the path segment percent-decoded once (a generated client
/// sends `w1N%3Ap19`) and passed to herdr as is when it is shaped like
/// herdr's (`<workspace>:<pane>`, each half an alphanumeric then
/// alphanumerics, `-` or `_`); any other shape is 404 before herdr is asked,
/// so `--help` and `-h` never reach herdr's TARGET slot, where they would
/// print help at exit 0 and read as a delivery, and a decoded `/` never
/// reaches it either. A malformed `%` sequence matches no route. A path with
/// no id, or more than one segment where the id goes, is not this route.
#[test]
fn the_pane_id_is_the_path_segment_decoded_once() {
    let _home = HomeSandbox::new();
    seed();
    let (ctx, calls) = ctx_over(ok());
    for (path, pane) in [
        ("/api/v1/panes/w9:p99/prompt", "w9:p99"),
        ("/api/v1/panes/w1N%3Ap19/prompt", "w1N:p19"),
        ("/api/v1/panes/w1N%3ap19/prompt", "w1N:p19"),
        ("/api/v1/panes/w-1_N:p_19/prompt", "w-1_N:p_19"),
    ] {
        let resp = call(&ctx, &req("POST", path, Some(TOKEN), PROMPT_BODY));
        assert_eq!(resp.status, 200, "{path}");
        assert_eq!(
            calls_of(&calls).last(),
            Some(&argv(&["agent", "prompt", pane, "fix the tests"])),
            "{path}"
        );
    }
    let keys = call(
        &ctx,
        &req(
            "POST",
            "/api/v1/panes/w1N%3Ap19/keys",
            Some(TOKEN),
            KEYS_BODY,
        ),
    );
    assert_eq!(keys.status, 200);
    assert_eq!(
        calls_of(&calls).last(),
        Some(&argv(&["pane", "send-keys", "w1N:p19", "y", "enter"]))
    );
    let delivered = calls_of(&calls).len();
    assert_eq!(delivered, 5);
    for path in [
        "/api/v1/panes/w1N%zzp19/prompt",
        "/api/v1/panes/w1N%3/prompt",
        "/api/v1/panes/w1N%/prompt",
        "/api/v1/panes/w1N%+1p19/prompt",
        "/api/v1/panes/%FF:p19/prompt",
        "/api/v1/panes//prompt",
        "/api/v1/panes/prompt",
        "/api/v1/panes/a/b/prompt",
        "/api/v1/panes/w1N:p19/prompt/",
    ] {
        let resp = call(&ctx, &req("POST", path, Some(TOKEN), PROMPT_BODY));
        assert_eq!(
            (resp.status, body_json(&resp)),
            (404, serde_json::json!({"ok": false, "error": "not_found"})),
            "{path} matches no route"
        );
    }
    assert_eq!(
        calls_of(&calls).len(),
        delivered,
        "no unmatched path reached herdr"
    );
    assert_eq!(
        call(&ctx, &req("GET", PROMPT, Some(TOKEN), "")).status,
        405,
        "the path is known; the verb is wrong"
    );
    let not_found = serde_json::json!({
        "ok": false,
        "error": "pane_not_found",
        "reason": "no pane with that id in herdr's default session",
    });
    for (path, body) in [
        ("/api/v1/panes/--help/prompt", PROMPT_BODY),
        ("/api/v1/panes/-h/keys", KEYS_BODY),
        ("/api/v1/panes/-h/prompt", PROMPT_BODY),
        ("/api/v1/panes/--help/keys", KEYS_BODY),
        ("/api/v1/panes/w1N/prompt", PROMPT_BODY),
        ("/api/v1/panes/:p19/keys", KEYS_BODY),
        ("/api/v1/panes/w1N:/prompt", PROMPT_BODY),
        ("/api/v1/panes/w1N:p19:x/keys", KEYS_BODY),
        ("/api/v1/panes/w1N:-p19/prompt", PROMPT_BODY),
        ("/api/v1/panes/-w1N:p19/keys", KEYS_BODY),
        ("/api/v1/panes/_w1N:p19/prompt", PROMPT_BODY),
        ("/api/v1/panes/w1N:p19%20/keys", KEYS_BODY),
        ("/api/v1/panes/w1N%2Fp19/prompt", PROMPT_BODY),
        ("/api/v1/panes/w1N%3Ap19%2Fx/keys", KEYS_BODY),
        ("/api/v1/panes/w1N%3Ap19%00/prompt", PROMPT_BODY),
        // Decoded once: a double-encoded id is the text `w1N%3Ap19`, which
        // fails the fence; a second decode pass would deliver it.
        ("/api/v1/panes/w1N%253Ap19/prompt", PROMPT_BODY),
        ("/api/v1/panes/w1N%253Ap19/keys", KEYS_BODY),
    ] {
        let resp = call(&ctx, &req("POST", path, Some(TOKEN), body));
        assert_eq!(
            (resp.status, body_json(&resp)),
            (404, not_found.clone()),
            "{path}"
        );
    }
    assert_eq!(
        calls_of(&calls).len(),
        delivered,
        "no shape-refused id reached herdr"
    );
}
