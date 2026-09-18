# macOS rolling-token runtime Keychain reconciliation

## Problem and evidence

In clauth 0.15.2, a rolling profile's `credentials.json` and `session-token.json` can hold a valid, current OAuth access token while a live `clauth start` runtime's namespaced macOS Keychain item holds an older token that Anthropic has revoked. Claude Code reads the Keychain item before the runtime file, so requests and subagents fail with HTTP 401 even while `clauth status --json` reports the profile's `auth_status` as `ok`.

The observed distinction is a valid profile bearer (HTTP 200 from `/api/oauth/profile`) versus a revoked runtime Keychain bearer (HTTP 401), with both belonging to a session whose `current_member` is the profile. The session transcript remains intact. This design does not assume which process re-created the namespaced item after clauth signed it out; that writer is not established by the available logs.

The code currently makes a refresh-less sidecar a reason to skip a session-start Keychain write (`session_seed_arm`) or sign the item out once during a swap (`swap_item_arm`). `restamp_rolling_token` updates the sidecar and, on macOS, mirrors only the *global* active profile's Keychain item. There is no subsequent reconciliation of live per-runtime items. The upstream issue about refresh-token fan-out (#84) is related but describes a different state: rolling-token was not armed there.

## Goal and scope

Keep a live macOS `clauth start` session on the intended rolling profile as its bearer changes, without distributing a refresh token to Claude Code and without overwriting a genuine session-side `/login`. A failed reconciliation must be visible and actionable instead of allowing `auth_status: ok` to imply that every live runtime can authenticate.

Scope is clauth's OAuth rolling-token path on macOS. No change to Linux/Windows, endpoint/API-key profiles, non-rolling OAuth profiles, billing choices, Claude Desktop, or transcript contents. This patch does not automatically replay a prompt or failed subagent: replaying side-effecting work is a separate workflow decision.

## Approaches considered

1. **Recommended: reconcile each live runtime Keychain item on rolling bearer changes.** Keep clauth's profile credential as the sole refresh-token owner. Install the current refresh-less bearer into each owned runtime item, preserving unrelated MCP logins. Serialize this with that runtime's swap/start Keychain operations, and refuse to overwrite a foreign login. This preserves hot switching if Claude Code re-reads the item on the next request.
2. **Restart every Claude process on rotation.** Stronger against in-memory caching but interrupts tool calls and background agents roughly every token cycle. Useful as a recovery fallback, not the primary library behavior.
3. **Rely on a static `claude setup-token`.** Avoids short access-token rotations but changes scopes and plan-gated behavior, requires another account-specific mint, and does not repair the rolling-token contract. Not the default fix.

## State and ownership

For each live session, identify its existing runtime directory and namespaced Keychain service through clauth's own canonical-path derivation. `live_sessions` provides `current_member` and `launch_store`; the source of truth for a rolling member is its `session-token.json`. Persist a non-secret fingerprint of the last bearer clauth installed for that runtime. Never persist token bytes in the liveness record or logs.

The per-runtime Keychain item may be absent, an empty account shell with MCP logins, equal to the previously installed bearer, equal to the newly current bearer, unreadable, corrupt, or contain another login. For a runtime created by this patch, the first four states are clauth-owned and eligible for reconciliation. An unrecognized non-empty login is treated as a possible intentional `/login`: leave it untouched and report divergence.

Existing runtimes have no installed-bearer fingerprint. They cannot safely distinguish an old clauth bearer from an intentional session-side login if that bearer has already been revoked. Do not guess or overwrite them. Migrate such sessions by controlled termination and `--resume` into newly created runtime directories, preserving the transcript and never automatically resubmitting the last prompt. New runtime directory IDs must not reuse an old Keychain service while stale-runtime collection is pending.

## Transition and concurrency

On rolling sidecar re-stamp or refresh, capture the previous and new bearer identities. After the new sidecar is durable, enumerate live sessions currently on that member and reconcile their namespaced Keychain items. Do not hold the global state flock across `/usr/bin/security` subprocesses. Add a bounded per-session Keychain-operation lock shared by session start, swap, and re-stamp, so a swap cannot land between membership validation and Keychain replacement. Under that lock, re-read the live session record and current sidecar; do not use a stale enumeration result to install into a session that has moved accounts.

The Keychain write must carry **only** the refresh-less session bearer, never the profile's refresh token. Preserve MCP-server credential siblings using the existing merge path. Verify the write by reading back the item's bearer identity. If the item already equals the current bearer, do nothing. A missing or empty item is installed rather than assuming the file will remain authoritative forever; the daemon then owns keeping that installed item current.

Start and swap paths use the same reconciliation function. A refresh-less start must not silently `Skip` over an old non-empty Keychain item. A rolling swap must not report a healthy session solely because the credential-file symlink moved; completion includes the Keychain result or an explicit degraded verdict. Token rotation and swap may occur at any point while a Claude turn is running, so a brief server-side invalidation window cannot be eliminated entirely; the next request must see a current credential or a clear recovery instruction.

## Failure behavior and visibility

If the Keychain is locked, times out, rejects the write, or read-back disagrees, do not overwrite a foreign item or mark that runtime healthy. Record a per-session degraded reason in the status feed and one bounded, redacted log line naming the session ID and profile, never token material. Retain the new canonical sidecar, so other sessions are not rolled back. Offer a controlled process restart and `--resume <session-id>` when reconciliation cannot be completed; do not auto-resubmit the last prompt.

`auth_status` remains the health of the stored profile credential. Add a separate `credential_health` field to each live-session status row (`ok`, `stale`, `foreign`, or `unreadable`) so `profile ok` and `runtime stale` are not conflated. UI/CLI wording must explain that difference.

## Verification

Deterministic tests use a throwaway home and Keychain service, fake OAuth token endpoint, and mocked Claude child. Cover:

- start with rolling sidecar plus a matching, proven old bearer: reconcile before Claude launches;
- start with an unknown non-empty item or a pre-patch runtime lacking provenance: refuse to overwrite and provide the controlled-resume path;
- two live sessions on one member, T1 to T2 refresh: both items move to T2, neither contains a refresh token, profile chain advances once;
- swap A to B racing with B's refresh: the session ends on B's latest bearer, never A or an older B bearer;
- absent and MCP-only items, corrupt items, foreign `/login`, locked Keychain, timeout, partial write, and read-back mismatch;
- profile `ok` with one runtime stale: status exposes the runtime failure;
- background-agent child on the same `CLAUDE_CONFIG_DIR` after rotation: a request uses T2. Run this macOS integration check against Claude Code itself in a disposable session before declaring the hot path reliable;
- fail-safe recovery: after an injected 401, original session ID resumes in a new runtime without replaying any side-effecting prompt.

Run formatting, lint, Rust tests, and the macOS integration suite. A release candidate stays out of the user's installed `~/.local/bin/clauth` until the real-session smoke check passes. Preserve a rollback path to the upstream binary and existing `~/.clauth/` state.

## Acceptance and non-goals

Acceptance requires an active rolling session to survive a T1→T2 rotation and subsequent request without `/login`, including two concurrent sessions and a child agent. No test may assert success solely from `clauth status --json`; it must inspect the credential Claude actually sends or the resulting authenticated request. In a forced Keychain failure, the session must surface a degraded state rather than silently claim health.

This does not promise uninterrupted inference during network outages, complete account exhaustion, host restart, or a Keychain failure that prevents access. It does not solve automatic, exactly-once replay of in-flight tool calls.
