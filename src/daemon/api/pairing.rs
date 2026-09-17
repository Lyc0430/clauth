//! One-time pairing codes: how a device earns a token without holding one.
//!
//! `clauth devices pair <name>` parks a code in `~/.clauth/pairing.json` (its
//! SHA-256, never the code) with the name and tier the device will get, an
//! expiry, and an attempt budget, then waits for the outcome. `POST
//! /api/v1/pair` redeems it. The whole redemption runs inside one state-flock
//! hold, so however many requests race for one code, one mints a device.
//!
//! One code is live at a time: minting a new one replaces it.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::devices::{self, DeviceName, Tier};
use super::http::sanitize_for_log;
use crate::lock::with_state_lock;
use crate::logline::logline;
use crate::out::{Wrote, errln, write_chunk_result};
use crate::profile::{atomic_write_600, clauth_dir};
use crate::usage::{epoch_secs_to_iso, iso_to_epoch_secs, now_epoch_secs};

const PAIRING_FILE: &str = "pairing.json";
/// Bumped only on a breaking change to the file's shape, like `status.json`.
const SCHEMA: u64 = 1;
/// How long a code stays redeemable.
pub(crate) const CODE_TTL_SECS: i64 = 5 * 60;
/// Wrong tries a code survives; the last one deletes it.
pub(crate) const CODE_ATTEMPTS: u32 = 5;
/// Crockford's base32: the digits and the capitals without I, L, O and U.
pub(crate) const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const CODE_LEN: usize = 8;
/// How often the `pair` wait looks for an outcome.
const POLL: Duration = Duration::from_millis(200);

/// A code in canonical form: [`CODE_LEN`] characters of [`ALPHABET`].
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Code(String);

impl Code {
    /// 40 bits from the OS CSPRNG.
    fn generate() -> Result<Self> {
        let mut seed = [0u8; 5];
        getrandom::fill(&mut seed).map_err(|e| anyhow::anyhow!("CSPRNG failure: {e}"))?;
        Ok(Self::from_bits(
            seed.iter()
                .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte)),
        ))
    }

    /// The code spelling the low 40 bits of `bits`, five to a character, the
    /// most significant first.
    fn from_bits(bits: u64) -> Self {
        Self(
            (0..CODE_LEN)
                .rev()
                .map(|group| char::from(ALPHABET[((bits >> (group * 5)) & 0x1f) as usize]))
                .collect(),
        )
    }

    /// The canonical form of a code a person typed: case folded, `-` and
    /// whitespace dropped, and Crockford's look-alikes read as the digits they
    /// stand for (`O` as `0`, `I` and `L` as `1`). `None` when what is left is
    /// not a code at all.
    pub(crate) fn normalize(typed: &str) -> Option<Self> {
        let mut code = String::with_capacity(CODE_LEN);
        for c in typed.chars().filter(|c| *c != '-' && !c.is_whitespace()) {
            let c = match c.to_ascii_uppercase() {
                'O' => '0',
                'I' | 'L' => '1',
                c => c,
            };
            if !c.is_ascii() || !ALPHABET.contains(&(c as u8)) {
                return None;
            }
            code.push(c);
        }
        (code.len() == CODE_LEN).then_some(Self(code))
    }

    fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.0.as_bytes()).into()
    }
}

impl std::fmt::Display for Code {
    /// `XXXX-XXXX`, the dash for whoever reads it off a screen;
    /// [`Code::normalize`] drops it again.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-{}", &self.0[..4], &self.0[4..])
    }
}

impl std::fmt::Debug for Code {
    /// A live code is a credential, and a formatter is how one reaches a log
    /// line.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Code(<redacted>)")
    }
}

/// `~/.clauth/pairing.json`: the one live code.
#[derive(Serialize, Deserialize)]
struct PairingFile {
    schema: u64,
    /// The device name the code mints.
    name: String,
    tier: Tier,
    /// Whether the device the code mints may mint a session. A code written by
    /// a build before the field existed reads `false`.
    #[serde(default)]
    sessions: bool,
    /// SHA-256 of the canonical code, lowercase hex.
    digest: String,
    /// ISO-8601, from which on the code redeems nothing.
    expires_at: String,
    attempts_left: u32,
}

impl PairingFile {
    fn is_live(&self, now: i64) -> bool {
        iso_to_epoch_secs(&self.expires_at).is_some_and(|expiry| now < expiry)
    }

    /// Constant-time over the digests, so a wrong guess learns nothing from
    /// the timing.
    fn matches(&self, code: &Code) -> bool {
        let mut stored = [0u8; 32];
        hex::decode_to_slice(&self.digest, &mut stored).is_ok()
            && bool::from(stored.ct_eq(&code.digest()))
    }
}

fn pairing_path() -> Result<PathBuf> {
    Ok(clauth_dir()?.join(PAIRING_FILE))
}

/// The live code's record, or `None` when there is none. A file that does not
/// parse is no code: redeeming against it could only guess.
fn read_pairing(path: &Path) -> Result<Option<PairingFile>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(serde_json::from_slice(&bytes).ok()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("failed to read {}", path.display())),
    }
}

fn write_pairing(path: &Path, file: &PairingFile) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(file).context("failed to encode the pairing code")?;
    atomic_write_600(path, bytes).with_context(|| format!("failed to write {}", path.display()))
}

fn discard(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("failed to delete {}", path.display())),
    }
}

/// A code this process minted and is waiting on.
pub(crate) struct Pending {
    code: Code,
    name: DeviceName,
    digest: String,
    expires_at: i64,
}

impl Pending {
    pub(crate) fn code(&self) -> &Code {
        &self.code
    }
}

/// Mint a code for `name`, replacing whatever code was live. Refused while a
/// device already holds the name, so a redeemed code always adds a device.
pub(crate) fn begin(name: &DeviceName, tier: Tier, sessions: bool) -> Result<Pending> {
    begin_at(name, tier, sessions, now_epoch_secs())
}

/// [`begin`] at an explicit instant, so a test can mint a code that is already
/// past its expiry.
pub(crate) fn begin_at(name: &DeviceName, tier: Tier, sessions: bool, now: i64) -> Result<Pending> {
    with_state_lock(|_| {
        devices::refuse_taken(&devices::read_store()?, name)?;
        let code = Code::generate()?;
        let expires_at = now + CODE_TTL_SECS;
        let file = PairingFile {
            schema: SCHEMA,
            name: name.as_str().to_string(),
            tier,
            sessions,
            digest: hex::encode(code.digest()),
            expires_at: epoch_secs_to_iso(expires_at),
            attempts_left: CODE_ATTEMPTS,
        };
        write_pairing(&pairing_path()?, &file)?;
        Ok(Pending {
            code,
            name: name.clone(),
            digest: file.digest,
            expires_at,
        })
    })
}

/// What a redemption answered. The refusal carries no reason on purpose: a
/// wrong code, a spent one, an expired one and none at all look the same to
/// whoever is guessing.
pub(crate) enum Redeemed {
    Paired {
        name: String,
        tier: Tier,
        token: String,
    },
    Refused,
}

impl std::fmt::Debug for Redeemed {
    /// Never the token: the one place it may appear is the response that
    /// mints it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Paired { name, tier, .. } => f
                .debug_struct("Paired")
                .field("name", name)
                .field("tier", tier)
                .finish_non_exhaustive(),
            Self::Refused => f.write_str("Refused"),
        }
    }
}

/// Redeem `code` against the live pairing.
///
/// One state-flock hold covers the read, the expiry check, the compare, and
/// then either the attempt count or the mint, the append and the delete, so
/// two redemptions of one code cannot both mint. The device list reaches the
/// disk before `pairing.json` goes, so no crash can spend a code without
/// leaving its device behind.
pub(crate) fn redeem(code: &Code) -> Result<Redeemed> {
    redeem_at(code, now_epoch_secs())
}

/// [`redeem`] at an explicit instant, for the expiry boundary.
pub(crate) fn redeem_at(code: &Code, now: i64) -> Result<Redeemed> {
    // Checked before the flock: with no code waiting there is nothing to
    // redeem, and an unpaired peer must not be able to take a cross-process
    // lock to learn that. A code is only shown once its file exists.
    let path = pairing_path()?;
    if !path.exists() {
        return Ok(Redeemed::Refused);
    }
    with_state_lock(|held| {
        // A file that does not parse is no code. Deleting it keeps every later
        // probe on the lock-free path above.
        let Some(mut live) = read_pairing(&path)? else {
            discard(&path)?;
            return Ok(Redeemed::Refused);
        };
        if !live.is_live(now) {
            discard(&path)?;
            return Ok(Redeemed::Refused);
        }
        if !live.matches(code) {
            live.attempts_left = live.attempts_left.saturating_sub(1);
            if live.attempts_left == 0 {
                discard(&path)?;
                logline!(
                    "clauth api: the pairing code for '{}' was dropped after {CODE_ATTEMPTS} \
                     wrong tries",
                    sanitize_for_log(&live.name)
                );
            } else {
                write_pairing(&path, &live)?;
            }
            return Ok(Redeemed::Refused);
        }
        let token = devices::append_paired(held, &live.name, live.tier.clone(), live.sessions)?;
        discard(&path)?;
        match token {
            Some(token) => Ok(Redeemed::Paired {
                name: live.name,
                tier: live.tier,
                token,
            }),
            None => {
                logline!(
                    "clauth api: the pairing code for '{}' was refused: a device took that name \
                     first",
                    sanitize_for_log(&live.name)
                );
                Ok(Redeemed::Refused)
            }
        }
    })
}

/// How a `pair` wait ended.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// A device redeemed the code and holds this tier.
    Paired(Tier),
    /// A newer `pair` minted the live code.
    Replaced,
    /// The last wrong try deleted the code.
    Burned,
    /// Nobody redeemed it in time.
    Expired,
}

/// The outcome of `pending`'s wait, or `None` while the code is still live.
///
/// Read without the state flock: every writer replaces the files whole, and a
/// redemption writes the device before it deletes the code, so a code that is
/// gone while a device that joined by pairing holds its name reads as paired.
/// A second code for the same name, minted and redeemed between two polls,
/// would read the same; that takes two `pair` runs on one name inside one
/// poll.
pub(crate) fn observe(pending: &Pending, now: i64) -> Result<Option<Outcome>> {
    match read_pairing(&pairing_path()?)? {
        Some(file) if file.digest == pending.digest => {
            Ok((now >= pending.expires_at).then_some(Outcome::Expired))
        }
        Some(_) => Ok(Some(Outcome::Replaced)),
        None => {
            let store = devices::read_store()?;
            Ok(Some(match store.named(pending.name.as_str()) {
                Some(device) if device.joined == devices::Joined::Pair => {
                    Outcome::Paired(device.tier.clone())
                }
                _ if now >= pending.expires_at => Outcome::Expired,
                _ => Outcome::Burned,
            }))
        }
    }
}

/// Delete `pending`'s code if it is still the live one; a replacement belongs
/// to whoever minted it. Whether it was.
pub(crate) fn withdraw(pending: &Pending) -> Result<bool> {
    with_state_lock(|_| {
        let path = pairing_path()?;
        let live = read_pairing(&path)?.is_some_and(|file| file.digest == pending.digest);
        if live {
            discard(&path)?;
        }
        Ok(live)
    })
}

/// Refuse `name` while a live code is waiting to mint it. Without this, an
/// `add` under the same name would make the code's redemption fail, and its
/// waiter would read the added device as its own success.
pub(super) fn refuse_pending(name: &DeviceName) -> Result<()> {
    if let Some(file) = read_pairing(&pairing_path()?)?
        && file.is_live(now_epoch_secs())
        && file.name.eq_ignore_ascii_case(name.as_str())
    {
        bail!(
            "a pairing code for '{}' is waiting to be entered; let it finish or pick another name",
            file.name
        );
    }
    Ok(())
}

/// Why a [`wait_for`] returned.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Waited {
    Done(Outcome),
    /// A signal arrived before the wait saw an outcome; the code may still
    /// have reached one since its last look.
    Interrupted(i32),
}

/// Wait on `pending` until it reaches an [`Outcome`] or `caught` reports a
/// signal, looking once per `poll`.
pub(crate) fn wait_for(
    pending: &Pending,
    caught: impl Fn() -> Option<i32>,
    poll: Duration,
) -> Result<Waited> {
    loop {
        if let Some(signal) = caught() {
            return Ok(Waited::Interrupted(signal));
        }
        if let Some(outcome) = observe(pending, now_epoch_secs())? {
            return Ok(Waited::Done(outcome));
        }
        std::thread::sleep(poll);
    }
}

/// `clauth devices pair <name> [--control] [--sessions]`: the code alone on
/// stdout, the wait on stderr.
pub(crate) fn run_pair(name: &str, control: bool, sessions: bool) -> Result<()> {
    let name = DeviceName::parse(name)?;
    let tier = Tier::chosen(control);
    // Installed before the code exists, so no signal lands between minting it
    // and being able to withdraw it.
    let interrupt = Interrupt::install()?;
    let pending = begin(&name, tier.clone(), sessions)?;
    let lost = match write_chunk_result(
        &mut std::io::stdout().lock(),
        format_args!("{}", pending.code()),
        true,
    ) {
        Ok(Wrote::Yes) => None,
        Ok(Wrote::ReaderGone) => Some(None),
        Err(e) => Some(Some(e)),
    };
    if let Some(write_err) = lost {
        withdraw_lost(&pending, write_err)?;
    }
    errln!(
        "clauth: enter the code on the device within {} minutes to pair '{name}' ({tier}); \
         Ctrl-C withdraws it",
        CODE_TTL_SECS / 60
    );
    if tier == Tier::Control {
        errln!(
            "clauth: until it is used the code is a control credential: whoever enters it first \
             can switch this host's accounts"
        );
    }
    if sessions {
        errln!(
            "clauth: until it is used the code also grants sessions: whoever enters it first \
             can mint them through the API"
        );
    }
    if matches!(crate::daemon::singleton_held(), Ok(false)) {
        errln!(
            "clauth: no clauth daemon is running here, so nothing can redeem the code; start one \
             with `clauth daemon --listen`"
        );
    }
    let waited = wait_for(&pending, || interrupt.caught(), POLL);
    finish(&pending, waited)
}

/// Withdraw the code a lost line minted, naming the loss. `write_err` is
/// `Some(e)` when the write itself failed — a full disk behind a redirect —
/// rather than the reader closing the pipe, so the operator sees the cause.
/// `Ok(false)` from [`withdraw`] means a newer `pair` already replaced the code
/// before anyone read it, so the message says replaced, not withdrawn.
fn withdraw_lost(pending: &Pending, write_err: Option<std::io::Error>) -> Result<()> {
    let name = &pending.name;
    let cause = write_err.map(|e| format!(" ({e})")).unwrap_or_default();
    match withdraw(pending) {
        Ok(true) => {
            bail!("the pairing code for '{name}' never reached its reader{cause}; it was withdrawn")
        }
        Ok(false) => bail!(
            "the pairing code for '{name}' never reached its reader{cause}; a newer `clauth \
             devices pair` had already replaced it"
        ),
        Err(e) => bail!(
            "the pairing code for '{name}' never reached its reader{cause} and could not be \
             withdrawn: {e:#}; it stays redeemable until it expires in {} minutes",
            CODE_TTL_SECS / 60
        ),
    }
}

/// Turn a wait into what `pair` prints and exits with. Only a signal or an
/// error can leave the code live, so those two withdraw it first.
fn finish(pending: &Pending, waited: Result<Waited>) -> Result<()> {
    let name = &pending.name;
    match waited {
        Ok(Waited::Done(Outcome::Paired(tier))) => {
            errln!("paired '{name}' ({tier})");
            Ok(())
        }
        Ok(Waited::Done(Outcome::Replaced)) => {
            bail!("a newer `clauth devices pair` replaced this code before anyone entered it")
        }
        Ok(Waited::Done(Outcome::Burned)) => bail!(
            "the code was dropped after {CODE_ATTEMPTS} wrong tries; run `clauth devices pair \
             {name}` for a new one"
        ),
        Ok(Waited::Done(Outcome::Expired)) => {
            withdraw_or_say(pending);
            bail!("the code expired unused; run `clauth devices pair {name}` for a new one")
        }
        Ok(Waited::Interrupted(signal)) => match withdraw_or_say(pending) {
            Some(true) => {
                errln!("clauth: pairing code withdrawn");
                Err(crate::Interrupted(signal).into())
            }
            // Already gone when the signal was read: the code reached an
            // outcome between two polls, and that outcome is what happened.
            Some(false) => match observe(pending, now_epoch_secs()) {
                Ok(Some(outcome)) => finish(pending, Ok(Waited::Done(outcome))),
                Ok(None) => Err(crate::Interrupted(signal).into()),
                Err(e) => {
                    errln!(
                        "clauth: the pairing code was no longer waiting, and what became of it \
                         could not be read: {e:#}"
                    );
                    Err(crate::Interrupted(signal).into())
                }
            },
            None => Err(crate::Interrupted(signal).into()),
        },
        Err(e) => {
            withdraw_or_say(pending);
            Err(e)
        }
    }
}

/// [`withdraw`], saying so on stderr when it fails, since the code then stays
/// redeemable until it expires. Whether it removed the code, or `None` when it
/// could not tell.
fn withdraw_or_say(pending: &Pending) -> Option<bool> {
    match withdraw(pending) {
        Ok(removed) => Some(removed),
        Err(e) => {
            errln!(
                "clauth: could not withdraw the pairing code, which stays redeemable until it \
                 expires: {e:#}"
            );
            None
        }
    }
}

#[cfg(unix)]
const WITHDRAW_SIGNALS: [std::ffi::c_int; 3] = [
    signal_hook::consts::signal::SIGINT,
    signal_hook::consts::signal::SIGTERM,
    signal_hook::consts::signal::SIGHUP,
];
#[cfg(not(unix))]
const WITHDRAW_SIGNALS: [std::ffi::c_int; 2] = [
    signal_hook::consts::signal::SIGINT,
    signal_hook::consts::signal::SIGTERM,
];

/// The signals that end a `pair` wait, recorded instead of obeyed so the code
/// is withdrawn before the process exits. A second one exits at once, skipping
/// the withdrawal.
struct Interrupt {
    caught: Arc<AtomicUsize>,
}

impl Interrupt {
    fn install() -> Result<Self> {
        let caught = Arc::new(AtomicUsize::new(0));
        let armed = Arc::new(AtomicBool::new(false));
        for signal in WITHDRAW_SIGNALS {
            // Registered first so it runs first: the first signal finds it
            // unarmed and the next registration arms it.
            signal_hook::flag::register_conditional_shutdown(
                signal,
                128 + signal,
                Arc::clone(&armed),
            )
            .and_then(|_| signal_hook::flag::register(signal, Arc::clone(&armed)))
            .and_then(|_| {
                signal_hook::flag::register_usize(signal, Arc::clone(&caught), signal as usize)
            })
            .context("failed to install the signal handlers that withdraw the pairing code")?;
        }
        Ok(Self { caught })
    }

    fn caught(&self) -> Option<i32> {
        match self.caught.load(Ordering::SeqCst) {
            0 => None,
            signal => i32::try_from(signal).ok(),
        }
    }
}

#[cfg(test)]
#[path = "../../../tests/inline/daemon_api_pairing.rs"]
mod tests;
