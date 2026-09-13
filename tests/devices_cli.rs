//! `clauth devices` against the real binary: which stream carries what, and
//! what a signal or a newer code does to a waiting `pair`. Spawning is the only
//! way to see the bytes a shell would capture and the exit code it would get.
//!
//! Unix only, for the reason `tests/closed_reader.rs` gives: the child resolves
//! its home through `$HOME`, which only Unix lets a test point at a sandbox.
#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use sha2::Digest as _;

/// `clauth` with its home in `home` and nothing inherited that names another.
fn clauth(home: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_clauth"));
    cmd.env("HOME", home)
        .env_remove("CLAUDE_CONFIG_DIR")
        .stdin(Stdio::null());
    cmd
}

/// Start `clauth devices pair <name>` and read the code off its stdout, which
/// is printed only once the code is live.
fn start_pair(home: &Path, name: &str) -> (Child, BufReader<std::process::ChildStdout>, String) {
    let mut child = clauth(home)
        .args(["devices", "pair", name])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn clauth devices pair");
    let mut stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
    let mut line = String::new();
    stdout.read_line(&mut line).expect("read the code line");
    let code = line
        .strip_suffix('\n')
        .expect("the code ends its line")
        .to_string();
    (child, stdout, code)
}

/// The exit status, or a failure (and a killed child) past `limit`: a wait
/// that never ends must fail the test, not hang the suite.
fn wait_bounded(child: &mut Child, limit: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + limit;
    loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            return status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("clauth devices pair did not exit within {limit:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn read_stderr(child: &mut Child) -> String {
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("piped stderr")
        .read_to_string(&mut stderr)
        .expect("read stderr");
    stderr
}

fn is_display_code(code: &str) -> bool {
    let alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let (head, tail) = code.split_once('-').unwrap_or(("", ""));
    head.len() == 4
        && tail.len() == 4
        && head
            .chars()
            .chain(tail.chars())
            .all(|c| alphabet.contains(c))
}

/// `add` puts the token alone on stdout, so `$(clauth devices add tray)`
/// captures exactly it, and its one-time warning on stderr. The list keeps the
/// token's digest, and a listing never prints either back.
#[test]
fn add_prints_the_token_alone_on_stdout() {
    let home = tempfile::tempdir().expect("home");
    let out = clauth(home.path())
        .args(["devices", "add", "tray", "--control"])
        .output()
        .expect("run clauth devices add");
    assert_eq!(out.status.code(), Some(0));

    let stdout = String::from_utf8(out.stdout).expect("utf8 stdout");
    let token = stdout.strip_suffix('\n').unwrap_or_default();
    assert!(
        token.len() == 64
            && token
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "stdout must hold the token and nothing else"
    );
    assert_eq!(
        String::from_utf8(out.stderr).expect("utf8 stderr"),
        "clauth: added device 'tray' (control). That token is its only copy: clauth keeps just \
         a SHA-256 of it and cannot show it again.\n"
    );

    let list = std::fs::read_to_string(home.path().join(".clauth/devices.json")).expect("list");
    assert!(!list.contains(token), "the list must hold no token");
    assert!(
        list.contains(&hex::encode(sha2::Sha256::digest(token.as_bytes()))),
        "the list holds the token's digest"
    );

    let listed = clauth(home.path())
        .args(["devices", "--json"])
        .output()
        .expect("run clauth devices --json");
    assert_eq!(listed.status.code(), Some(0));
    let listed = String::from_utf8(listed.stdout).expect("utf8");
    assert!(
        !listed.contains(token),
        "a listing never prints a token back"
    );
    let rows: serde_json::Value = serde_json::from_str(&listed).expect("json rows");
    assert_eq!(
        (&rows[0]["name"], &rows[0]["tier"], &rows[0]["joined"]),
        (
            &serde_json::json!("tray"),
            &serde_json::json!("control"),
            &serde_json::json!("add")
        )
    );
}

/// Ctrl-C during `pair` withdraws the code, then exits 130; stdout held the
/// code alone.
#[test]
fn ctrl_c_during_pair_withdraws_the_code_and_exits_130() {
    let home = tempfile::tempdir().expect("home");
    let (mut child, mut stdout, code) = start_pair(home.path(), "phone");
    assert!(is_display_code(&code), "stdout opens with the code alone");
    let pairing = home.path().join(".clauth/pairing.json");
    assert!(pairing.exists(), "the code is live once it is printed");

    let sent = Command::new("kill")
        .args(["-INT", &child.id().to_string()])
        .status()
        .expect("run kill");
    assert!(sent.success());
    let status = wait_bounded(&mut child, Duration::from_secs(10));

    assert_eq!(status.code(), Some(130), "Ctrl-C exits 130: {status:?}");
    assert!(!pairing.exists(), "Ctrl-C withdraws the code");
    let mut rest = String::new();
    stdout.read_to_string(&mut rest).expect("rest of stdout");
    assert_eq!(rest, "", "stdout carried the code and nothing else");
    let stderr = read_stderr(&mut child);
    assert!(
        stderr.ends_with("clauth: pairing code withdrawn\n"),
        "{stderr}"
    );
}

/// A newer `pair` replaces the waiting code: the replaced waiter says so and
/// exits 1, and the newer code is the one left live.
#[test]
fn a_replaced_pair_says_so_and_exits_1() {
    let home = tempfile::tempdir().expect("home");
    let (mut first, _first_out, first_code) = start_pair(home.path(), "phone");
    let (mut second, _second_out, second_code) = start_pair(home.path(), "tablet");
    assert_ne!(first_code, second_code);

    let status = wait_bounded(&mut first, Duration::from_secs(10));
    assert_eq!(status.code(), Some(1), "{status:?}");
    let stderr = read_stderr(&mut first);
    assert!(
        stderr.ends_with(
            "Error: a newer `clauth devices pair` replaced this code before anyone entered it\n"
        ),
        "{stderr}"
    );
    assert!(
        home.path().join(".clauth/pairing.json").exists(),
        "the replaced waiter leaves the newer code alone"
    );

    Command::new("kill")
        .args(["-INT", &second.id().to_string()])
        .status()
        .expect("run kill");
    assert_eq!(
        wait_bounded(&mut second, Duration::from_secs(10)).code(),
        Some(130)
    );
}
