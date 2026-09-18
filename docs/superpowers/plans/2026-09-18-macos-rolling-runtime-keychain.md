# macOS Rolling Runtime Keychain Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keep each live macOS Claude runtime authenticated with its rolling profile's current refresh-less bearer, with clauth as the sole account-switching authority for managed sessions.

**Architecture:** The profile's `session-token.json` remains the source of truth. A focused reconciliation unit validates and updates a single namespaced Keychain item using a recorded installed-bearer fingerprint. Session start, fallback swap, and token re-stamp call that unit through a bounded per-session lock; the daemon runs multi-session reconciliation away from its watchdog-bounded tick. Per-session health is separate from profile auth health.

**Tech Stack:** Rust 2024, serde, sha2, existing `security` CLI wrapper, macOS Keychain, clauth's live-session registry and test harness.

**Spec:** `docs/superpowers/specs/2026-09-18-macos-rolling-runtime-keychain-design.md`

## Global Constraints

- Do not modify the installed `/Users/landon/.local/bin/clauth` or live `~/.clauth` data during development.
- Never distribute a refresh token to a rolling runtime, log a token, or overwrite an unrecognized non-empty Keychain login.
- Set `DISABLE_LOGIN_COMMAND=1` and `DISABLE_LOGOUT_COMMAND=1` only on macOS rolling-token Claude children launched by clauth; do not change bare Claude, other platforms, or other profile types.
- Never hold the global state flock across `/usr/bin/security` and never allow a Keychain stall to block the daemon's scheduler tick.
- Preserve existing Linux/Windows, endpoint, static-token, and non-rolling paths.
- A failed Claude turn or subagent is never automatically replayed.

## File map

- `src/runtime_keychain.rs`: macOS-only owned-item classification, single-item reconciliation, and bounded per-session lock.
- `src/keychain.rs`: expose the existing namespaced read/write and read-back primitives needed by the focused unit.
- `src/live_sessions.rs`: persistent installed-bearer fingerprint and runtime credential-health verdict.
- `src/runtime.rs`: start/swap call sites and runtime path derivation.
- `src/oauth.rs`, `src/usage/scheduler.rs`: trigger off-tick reconciliation after rolling sidecar changes.
- `src/daemon/status_json.rs`: report per-session runtime credential health separately from profile auth health.
- `tests/inline/runtime_keychain.rs`, `tests/inline/live_sessions.rs`, `tests/inline/runtime.rs`, `tests/inline/oauth.rs`, `tests/inline/daemon_status_json.rs`: focused regression tests.

---

### Task 1: Owned Keychain item contract

**Files:** Create `src/runtime_keychain.rs`, `tests/inline/runtime_keychain.rs`; modify `src/main.rs`, `src/keychain.rs` only to expose existing primitives.

**Interfaces:** Consumes `ClaudeCredentials`, `read_config_dir_item`, and `keychain_install_for_config_dir`. Produces `RuntimeCredentialHealth::{Ok,Stale,Foreign,Unreadable}` and `reconcile_item(runtime: &Path, prior_sha256: Option<&str>, incoming: &ClaudeCredentials) -> Result<RuntimeCredentialHealth>`.

- [ ] **Step 0: Prepare the build toolchain.** On this host `cargo` is absent. Install Homebrew Rust with `brew install rust`, then verify `cargo --version` and `rustc --version`; do not change the user's shell configuration.
- [ ] **Step 1: Write failing tests.** Use a throwaway Keychain service to cover absent, MCP-only, matching old bearer, already-current bearer, foreign non-empty bearer, read failure, and write read-back mismatch. Define local test helpers `sha256_hex(&str) -> String`, `bearer(&str) -> ClaudeCredentials`, and `item_access_token(&Path) -> Result<String>`; the central assertion is:

```rust
assert_eq!(reconcile_item(&runtime, Some(&sha256_hex("T1")), &bearer("T2"))?, RuntimeCredentialHealth::Ok);
assert_eq!(item_access_token(&runtime)?, "T2");
assert!(item_refresh_token(&runtime)?.is_none());
```

- [ ] **Step 2: Run the focused test and observe failure.** `cargo test runtime_keychain -- --nocapture` must fail because the module/interface does not yet exist.
- [ ] **Step 3: Add the minimal classifier and writer.** Compute SHA-256 of the existing item's access token; allow missing/shell, `prior_sha256`, or current token. Reject any other non-empty bearer as `Foreign`. Install the refresh-less incoming credential through the existing merge writer, re-read, and require exact incoming token identity. Return `Unreadable` on a read/write failure. Do not call the public `sign_out_at` on foreign items.
- [ ] **Step 4: Run `cargo test runtime_keychain -- --nocapture` to green; run `cargo fmt --check` and commit the unit.**

### Task 2: Session provenance and serialization

**Files:** Modify `src/live_sessions.rs`, `src/runtime.rs`; extend `tests/inline/live_sessions.rs`, `tests/inline/runtime.rs`.

**Interfaces:** Consumes Task 1's health enum. Produces session-owned `installed_bearer_sha256: Option<String>` and `credential_health: RuntimeCredentialHealth`, both serde-defaulted for old rows, plus `with_runtime_keychain_lock(session_id: &str, action: impl FnOnce() -> Result<T>) -> Result<T>`.

- [ ] **Step 1: Add failing row tests.** Serialize/deserialize an old row with neither new field and assert its health is unknown/stale, not `Ok`; update a session-owned field under the state lock and assert daemon-owned `intended_member` is preserved. Add a lock test where a swap and restamp cannot enter the same session's Keychain critical section together.
- [ ] **Step 2: Run `cargo test live_sessions -- --nocapture` and `cargo test runtime_keychain -- --nocapture`; capture the red tests.**
- [ ] **Step 3: Add serde-defaulted fields and session-only setters.** Store a SHA-256 hex digest, never token bytes. Use one bounded file lock per session. Do not take the global state lock while the Keychain lock is held across a subprocess; re-read the row after taking the per-session lock and use a separate short row update once the Keychain call has completed.
- [ ] **Step 4: Run the focused tests, format, and commit.**

### Task 3: Start and fallback swap use the same reconciliation

**Files:** Modify `src/runtime.rs`, `src/runtime_keychain.rs`; extend `tests/inline/runtime.rs`.

**Interfaces:** Consumes Tasks 1-2. Produces `reconcile_session(session_id: &str, expected_member: &str, new_bearer: &ClaudeCredentials) -> Result<RuntimeCredentialHealth>`; the function derives the existing runtime path and validates current membership under its session lock.

- [ ] **Step 1: Write failing tests** for a rolling start with a proven stale item, an unproven pre-patch item, an out-of-band foreign login, A→B swap racing with a B-side token change, and managed-child-only `DISABLE_LOGIN_COMMAND=1` / `DISABLE_LOGOUT_COMMAND=1`. Assert that a failed Keychain leg leaves an explicit degraded health verdict rather than `Ok`:

```rust
assert_eq!(row.current_member.as_deref(), Some("B"));
assert_eq!(row.credential_health, RuntimeCredentialHealth::Stale);
assert_ne!(row.installed_bearer_sha256, Some(sha256_hex("B-new")));
```

- [ ] **Step 2: Run `cargo test runtime -- --nocapture`; verify the new tests fail.**
- [ ] **Step 3: Replace rolling `SessionSeedArm::Skip` and `SwapItemArm::SignOut` call-site behavior with `reconcile_session`, preserving the existing non-rolling arms.** Set the two environment flags only on the rolling-token managed child spawn. A pre-patch row with an unknown non-empty item is not silently adopted; report the one-time controlled restart/resume. Check the current member again after acquiring the session Keychain lock; a moved row is a retryable stale-enumeration result.
- [ ] **Step 4: Run runtime and Keychain tests, format, and commit.**

### Task 4: Off-tick re-stamp fan-out and health status

**Files:** Modify `src/oauth.rs`, `src/usage/scheduler.rs`, `src/daemon/status_json.rs`; extend `tests/inline/oauth.rs`, `tests/inline/scheduler.rs`, `tests/inline/daemon_status_json.rs`.

**Interfaces:** Consumes `reconcile_session` and `LiveSession::credential_health`. Produces a bounded work queue keyed by `(session_id, bearer_sha256)` so repeated scheduler ticks coalesce instead of repeating Keychain writes, and an additive `live_sessions` status array with session ID, member, and `credential_health` only.

- [ ] **Step 1: Write failing tests** for two live sessions on one profile T1→T2, one locked Keychain item while the other succeeds, and one concurrent A→B swap. Assert profile auth stays `ok` while exactly one runtime reports `stale`:

```rust
assert_eq!(status.profiles[0].auth_status, "ok");
assert_eq!(status.live_sessions.iter().filter(|s| s.credential_health == "stale").count(), 1);
```

- [ ] **Step 2: Run focused OAuth, scheduler, and status tests to red.**
- [ ] **Step 3: Enqueue reconciliation after the sidecar has been durably stamped.** Run the queue on a separate bounded worker, not the daemon tick thread. A failed session is retried with backoff while the canonical sidecar remains intact. Read-back mismatch/foreign login is surfaced and not retried as an overwrite. Keep the existing global Keychain mirror behavior unchanged.
- [ ] **Step 4: Add the additive status shape and human-readable degraded message.** Do not claim `auth_status: ok` means the runtime is healthy. Run focused tests, format, and commit.

### Task 5: Acceptance and safe rollout

**Files:** Extend `tests/inline/runtime_keychain.rs` and docs for the new status field; no user configuration files.

- [ ] **Step 1: Run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-features`; record pass/fail counts.**
- [ ] **Step 2: On macOS, exercise a disposable runtime with a fake T1→T2 refresh and a Claude child using the same `CLAUDE_CONFIG_DIR`; prove the post-refresh request uses T2.** Never run the test against a live work transcript or rotate a real account's token just to induce failure.
- [ ] **Step 3: Verify a forced Keychain failure reports `stale` without leaking a token, and verify `--resume` retains the session ID without replaying the last prompt.**
- [ ] **Step 4: Review the diff for refresh-token fan-out, Keychain data loss, lock-order inversion, and token logging. Commit documentation and push the fork branch.** Do not install the fork binary or open an upstream PR until the user has reviewed the test evidence.

## Execution posture

Execute inline in this task; do not dispatch subagents. The live installed clauth remains untouched until all acceptance checks pass and the user separately approves a local rollout.
