#![allow(clippy::unwrap_used, clippy::expect_used)]
//! The codex PKCE login, held against the values read from openai/codex at
//! tag rust-v0.145.0: the URL/claim shapes and the assembly as pure values,
//! the loopback callback over a real socket pair (the state check and the
//! closed-set `error` parse), the registered-port bind order, and the two
//! network legs (the code exchange, the api-key mint) against a local stub.

use super::*;

use std::net::TcpStream;

/// Feed one request through `handle_callback` over a real loopback socket
/// pair; returns its verdict and the raw HTTP response the "browser" received.
/// The request carries a complete header block, so the read loop ends at the
/// terminator instead of at its timeout.
fn callback_roundtrip(target: &str, expected_state: &str) -> (Result<Option<String>>, String) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let mut client = TcpStream::connect(addr).expect("connect");
    client
        .write_all(format!("GET {target} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())
        .expect("send request");
    let (server, _) = listener.accept().expect("accept");
    let verdict = handle_callback(server, expected_state);
    let mut response = String::new();
    client.read_to_string(&mut response).expect("read response");
    (verdict, response)
}

#[test]
fn the_callback_takes_the_code_only_under_the_expected_state() {
    let (verdict, response) =
        callback_roundtrip("/auth/callback?code=authcode-1&state=STATE", "STATE");
    assert_eq!(
        verdict.expect("valid callback").as_deref(),
        Some("authcode-1")
    );
    assert!(response.starts_with("HTTP/1.1 200 OK"), "got: {response}");

    let (verdict, _) = callback_roundtrip("/auth/callback?code=authcode-1&state=EVIL", "STATE");
    assert_eq!(
        verdict.expect_err("a state mismatch aborts").to_string(),
        "codex login state mismatch (possible CSRF); aborted"
    );

    let (verdict, _) = callback_roundtrip("/favicon.ico", "STATE");
    assert!(
        verdict.expect("an unrelated path keeps waiting").is_none(),
        "not the redirect"
    );
}

/// Bytes only the browser redirect could have supplied, shaped to forge a log
/// line and a TUI span if they were ever echoed: the wire form the query
/// carries, and the form `query_param` decodes it to. Neither is a string any
/// page copy or terminal line of this module can contain, so their absence is
/// the echo check, whichever form an echo would carry.
const CALLBACK_CANARY: &str = "CANARY%0Aclauth:%20forged%20line%20%60rm%20-rf%60";
const CALLBACK_CANARY_DECODED: &str = "CANARY\nclauth: forged line `rm -rf`";

/// An OAuth `error` param is fatal, and its bytes reach nothing: the code is
/// parsed into RFC 6749's closed set and the description is never read, so
/// the terminal line and the reply page are this module's own literals.
#[test]
fn the_callback_parses_an_error_into_the_closed_set_and_echoes_nothing() {
    let (verdict, response) = callback_roundtrip(
        &format!(
            "/auth/callback?state=STATE&error=access_denied&error_description={CALLBACK_CANARY}"
        ),
        "STATE",
    );
    let err = verdict.expect_err("an error param is fatal").to_string();
    assert_eq!(err, "you declined the authorization request");
    for injected in [CALLBACK_CANARY, CALLBACK_CANARY_DECODED] {
        assert!(!err.contains(injected), "echoed into the line: {err}");
        assert!(
            !response.contains(injected),
            "echoed onto the page: {response}"
        );
    }
    assert!(
        response.ends_with("close this tab; you can retry from clauth any time."),
        "the declined arm's own page: {response}"
    );

    // A code outside the spec's set is where the bytes are least trustworthy:
    // none are kept, not even into the line.
    let (verdict, response) = callback_roundtrip(
        &format!(
            "/auth/callback?state=STATE&error=made_up_code&error_description={CALLBACK_CANARY}"
        ),
        "STATE",
    );
    let err = verdict.expect_err("an error param is fatal").to_string();
    assert_eq!(err, "openai refused the login");
    assert!(
        !response.contains("made_up_code"),
        "echoed onto the page: {response}"
    );

    let (verdict, _) = callback_roundtrip("/auth/callback?state=STATE&error=server_error", "STATE");
    assert_eq!(
        verdict.expect_err("an error param is fatal").to_string(),
        "openai is having trouble"
    );

    // Neither a code nor an error: a fixed line with nothing interpolated.
    let (verdict, _) = callback_roundtrip("/auth/callback?state=STATE", "STATE");
    assert_eq!(
        verdict.expect_err("no code is fatal").to_string(),
        "codex login callback carried no code"
    );
}

/// The registered redirect set is two fixed ports, tried in order; a free
/// port elsewhere would not match a registered redirect_uri, so with both held
/// the login refuses instead of binding one.
#[test]
fn the_login_binds_the_registered_ports_in_order_and_refuses_with_both_held() {
    // The ports are real loopback ports: a box already holding one names the
    // skip instead of reading a foreign holder as the fn's own choice.
    for port in [PRIMARY_PORT, FALLBACK_PORT] {
        if let Err(e) = TcpListener::bind(("127.0.0.1", port)) {
            eprintln!(
                "SKIPPED the_login_binds_the_registered_ports_in_order_and_refuses_with_both_held: \
                 port {port} is in use on this box ({e})"
            );
            return;
        }
    }
    let (primary, port) = bind_registered_port().expect("the primary port is free");
    assert_eq!(port, PRIMARY_PORT);
    let (fallback, port) = bind_registered_port().expect("the fallback port is free");
    assert_eq!(
        port, FALLBACK_PORT,
        "the single fallback once the primary is held"
    );
    let err = bind_registered_port().expect_err("both held").to_string();
    assert_eq!(
        err,
        "codex's login ports (1455 and 1457) are both in use — close whatever holds them \
         (another codex or clauth login?) and retry"
    );
    drop(primary);
    drop(fallback);
}

/// The wire shape of the code exchange against a local stub: form-urlencoded
/// (the encoding that differs from the JSON refresh at the same endpoint),
/// exactly the five pairs, and the three-field reply parsed back.
#[test]
fn the_code_exchange_sends_the_five_form_pairs_and_parses_the_three_fields() {
    let (addr, handle) = crate::testutil::serve_endpoints_raw(2, |_path, _i| {
        (
            200,
            r#"{"id_token":"id.x","access_token":"at.x","refresh_token":"rt.x"}"#.to_string(),
        )
    });
    let tok = exchange_code_at(
        &format!("{addr}/oauth/token"),
        "the code",
        "the-verifier",
        "http://localhost:1455/auth/callback",
    )
    .expect("exchange succeeds");
    assert_eq!(tok.id_token, "id.x");
    assert_eq!(tok.access_token, "at.x");
    assert_eq!(tok.refresh_token, "rt.x");

    let seen = handle.join().expect("join stub");
    assert_eq!(seen.len(), 1, "one call");
    let raw = &seen[0];
    assert_eq!(crate::testutil::request_path(raw), "/oauth/token");
    assert_eq!(
        crate::testutil::request_header(raw, "content-type").as_deref(),
        Some("application/x-www-form-urlencoded")
    );
    assert_eq!(
        crate::testutil::request_body(raw),
        format!(
            "grant_type=authorization_code&code=the%20code\
             &redirect_uri=http%3A%2F%2Flocalhost%3A1455%2Fauth%2Fcallback\
             &client_id={CODEX_CLIENT_ID}&code_verifier=the-verifier"
        )
    );
}

/// A non-2xx exchange is an error naming the status, never a parse of the
/// error body.
#[test]
fn a_rejected_code_exchange_names_the_status() {
    let (addr, handle) = crate::testutil::serve_endpoints_raw(2, |_path, _i| {
        (400, r#"{"error":"invalid_grant"}"#.to_string())
    });
    // No `Debug` on the token-carrying reply, so no `expect_err`.
    let err = match exchange_code_at(
        &format!("{addr}/oauth/token"),
        "c",
        "v",
        "http://localhost:1455/auth/callback",
    ) {
        Ok(_) => panic!("a 400 is an error"),
        Err(e) => e.to_string(),
    };
    assert_eq!(err, "codex token exchange returned HTTP 400");
    assert_eq!(handle.join().expect("join stub").len(), 1);
}

/// The api-key mint is best-effort by contract: the key on a 2xx body that
/// carries one, `Ok(None)` on a 4xx, so a login that only wants the ChatGPT
/// chain still completes.
#[test]
fn the_api_key_exchange_is_best_effort() {
    let (addr, handle) = crate::testutil::serve_endpoints_raw(2, |_path, _i| {
        (200, r#"{"access_token":"sk-minted"}"#.to_string())
    });
    assert_eq!(
        exchange_api_key_at(&format!("{addr}/oauth/token"), "h.p.s").expect("2xx"),
        Some("sk-minted".to_string())
    );
    let seen = handle.join().expect("join stub");
    assert_eq!(seen.len(), 1);
    assert_eq!(
        crate::testutil::request_header(&seen[0], "content-type").as_deref(),
        Some("application/x-www-form-urlencoded")
    );
    assert_eq!(
        crate::testutil::request_body(&seen[0]),
        format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange\
             &client_id={CODEX_CLIENT_ID}&requested_token=openai-api-key\
             &subject_token=h.p.s&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aid_token"
        )
    );

    let (addr, handle) = crate::testutil::serve_endpoints_raw(2, |_path, _i| {
        (403, r#"{"error":"forbidden"}"#.to_string())
    });
    assert_eq!(
        exchange_api_key_at(&format!("{addr}/oauth/token"), "h.p.s")
            .expect("a 4xx is not an error"),
        None
    );
    assert_eq!(handle.join().expect("join stub").len(), 1);
}

#[test]
fn the_authorize_url_carries_the_verified_params() {
    let url = authorize_url("http://localhost:1455/auth/callback", "CHAL", "STATE");
    assert!(url.starts_with("https://auth.openai.com/oauth/authorize?"));
    for needle in [
        "response_type=code",
        &format!("client_id={CODEX_CLIENT_ID}"),
        "redirect_uri=http%3A%2F%2Flocalhost%3A1455%2Fauth%2Fcallback",
        "code_challenge=CHAL",
        "code_challenge_method=S256",
        "id_token_add_organizations=true",
        "codex_cli_simplified_flow=true",
        "state=STATE",
        "originator=codex_cli_rs",
    ] {
        assert!(url.contains(needle), "missing {needle} in {url}");
    }
    // The verified scope set, percent-encoded.
    assert!(
        url.contains("scope=openid%20profile%20email%20offline_access"),
        "scope: {url}"
    );
}

/// The account id is the `chatgpt_account_id` claim nested under the
/// id_token's `https://api.openai.com/auth` object — codex's exact nesting.
#[test]
fn the_account_id_comes_from_the_nested_claim() {
    let payload = crate::oauth_login::base64url_nopad(
        br#"{"https://api.openai.com/auth":{"chatgpt_account_id":"acc-123"}}"#,
    );
    let jwt = format!("h.{payload}.s");
    assert_eq!(chatgpt_account_id(&jwt).as_deref(), Some("acc-123"));

    // A flat claim (not nested) is NOT read — the nesting is the contract.
    let flat = crate::oauth_login::base64url_nopad(br#"{"chatgpt_account_id":"nope"}"#);
    assert_eq!(chatgpt_account_id(&format!("h.{flat}.s")), None);
}

/// The assembled auth.json: explicit `auth_mode` (codex infers ApiKey from a
/// bare key otherwise), the chain, the account id folded in, and no
/// OPENAI_API_KEY when the secondary exchange yielded none.
#[test]
fn the_auth_json_is_codexs_shape() {
    let payload = crate::oauth_login::base64url_nopad(
        br#"{"https://api.openai.com/auth":{"chatgpt_account_id":"acc-9"}}"#,
    );
    let tok = CodeExchange {
        id_token: format!("h.{payload}.s"),
        access_token: "at.x".into(),
        refresh_token: "rt.x".into(),
    };
    let outcome = assemble_auth_json(tok, None);
    let v: serde_json::Value = serde_json::from_slice(&outcome.auth_json).unwrap();
    assert_eq!(v["auth_mode"], "chatgpt", "explicit, never inferred");
    assert_eq!(v["tokens"]["access_token"], "at.x");
    assert_eq!(v["tokens"]["refresh_token"], "rt.x");
    assert_eq!(v["tokens"]["account_id"], "acc-9");
    assert!(v["last_refresh"].is_string());
    assert!(
        v.get("OPENAI_API_KEY").is_none(),
        "no api key when the exchange is skipped/offline"
    );
    assert_eq!(outcome.account_id.as_deref(), Some("acc-9"));
    // The chain reparses through the same model the runtime uses.
    let parsed = crate::codex_auth::CodexAuth::parse(&outcome.auth_json).expect("parse");
    assert_eq!(parsed.refresh_token(), Some("rt.x"));
    assert_eq!(parsed.account_id(), Some("acc-9"));
}

/// The encoding trap the spec pins: the authorization-code exchange is
/// form-urlencoded, while the refresh at the SAME endpoint is JSON. A
/// mutation swapping the exchange to JSON reds this.
#[test]
fn the_code_exchange_is_form_urlencoded_unlike_the_json_refresh() {
    let body = code_exchange_body(
        "the-code",
        "the-verifier",
        "http://localhost:1455/auth/callback",
    );
    assert!(body.starts_with("grant_type=authorization_code&"), "{body}");
    assert!(body.contains("&code=the-code&"), "{body}");
    assert!(body.contains("&code_verifier=the-verifier"), "{body}");
    assert!(
        !body.trim_start().starts_with('{'),
        "form, never JSON: {body}"
    );

    // The refresh body IS json, at the same endpoint — the two must not drift.
    let refresh = crate::codex_auth::CODEX_TOKEN_URL;
    assert_eq!(refresh, "https://auth.openai.com/oauth/token");
}
