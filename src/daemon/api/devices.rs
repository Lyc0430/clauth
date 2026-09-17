//! Paired devices: who may call `clauth daemon --listen`, and at which tier.
//!
//! `~/.clauth/devices.json` holds one row per device: its name, its tier, its
//! sessions grant, how it joined, and the SHA-256 of its bearer token. Never
//! the token itself, which exists on the device and in the one response that
//! mints it, so a read of the store yields nothing a client could present.
//!
//! Every request re-reads the store, so a revoke or a new device reaches a
//! running daemon at once. Every write runs under the state flock, through the
//! owner-only writer, and reaches the disk before anything that depends on it
//! moves ([`write_store`]).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::lock::{StateLockHeld, with_state_lock};
use crate::logline::logline;
use crate::out::{Wrote, errln, out, outln, write_chunk_result};
use crate::profile::{atomic_write_600, clauth_dir};
use crate::usage::{epoch_secs_to_iso, humanize_duration, iso_to_epoch_secs, now_epoch_secs};

const STORE_FILE: &str = "devices.json";
/// Where a clauth from before pairing kept its one global bearer token.
const LEGACY_FILE: &str = "auth_token.json";
/// Bumped only on a breaking change to the file's shape, like `status.json`.
const SCHEMA: u64 = 1;
/// Hex chars in a SHA-256 digest: the whole shape of a token.
const TOKEN_LEN: usize = 64;
/// The device the legacy import creates, and the one name `pair` and `add`
/// refuse, so the import never lands on a device someone named by hand.
pub(crate) const LEGACY_NAME: &str = "legacy";

/// What a device may do, fixed on this machine when its code or token is
/// minted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "String", into = "String")]
pub(crate) enum Tier {
    /// Read the status feed.
    View,
    /// Everything `View` may, plus switch accounts.
    Control,
    /// A tier a newer clauth wrote. Carried through every rewrite, so this
    /// build cannot erase it, and granted nothing: serving it as either known
    /// tier would guess at what the newer build meant by it.
    Unknown(String),
}

impl Tier {
    /// The tier a `--control` switch picks.
    pub(crate) fn chosen(control: bool) -> Self {
        if control { Self::Control } else { Self::View }
    }

    pub(crate) fn as_str(&self) -> &str {
        match self {
            Self::View => "view",
            Self::Control => "control",
            Self::Unknown(tier) => tier,
        }
    }
}

impl From<String> for Tier {
    fn from(tier: String) -> Self {
        match tier.as_str() {
            "view" => Self::View,
            "control" => Self::Control,
            _ => Self::Unknown(tier),
        }
    }
}

impl From<Tier> for String {
    fn from(tier: Tier) -> Self {
        match tier {
            Tier::View => "view".to_string(),
            Tier::Control => "control".to_string(),
            Tier::Unknown(tier) => tier,
        }
    }
}

impl std::fmt::Display for Tier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How a device came to be in the store.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "String", into = "String")]
pub(crate) enum Joined {
    /// Redeemed a pairing code.
    Pair,
    /// Minted by `clauth devices add` on this machine.
    Add,
    /// Imported from [`LEGACY_FILE`].
    Legacy,
    /// A value a newer clauth wrote, carried verbatim.
    Other(String),
}

impl Joined {
    pub(crate) fn as_str(&self) -> &str {
        match self {
            Self::Pair => "pair",
            Self::Add => "add",
            Self::Legacy => "legacy",
            Self::Other(joined) => joined,
        }
    }
}

impl From<String> for Joined {
    fn from(joined: String) -> Self {
        match joined.as_str() {
            "pair" => Self::Pair,
            "add" => Self::Add,
            "legacy" => Self::Legacy,
            _ => Self::Other(joined),
        }
    }
}

impl From<Joined> for String {
    fn from(joined: Joined) -> Self {
        joined.as_str().to_string()
    }
}

/// One row of the store.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Device {
    pub(crate) name: String,
    pub(crate) tier: Tier,
    /// SHA-256 of the device's bearer token, lowercase hex.
    digest: String,
    /// ISO-8601, when the device joined.
    pub(crate) paired_at: String,
    pub(crate) joined: Joined,
    /// The trusted-machine grant that lets this control device create sessions
    /// through the API once `[serve] session_creation` is on. A store written
    /// before the field existed loads `false`.
    #[serde(default)]
    pub(crate) sessions: bool,
    /// Fields a newer clauth added, kept through this build's rewrites.
    #[serde(flatten)]
    extra: serde_json::Map<String, serde_json::Value>,
}

impl std::fmt::Debug for Device {
    /// Never the digest. It is a verifier, and a formatter is how a verifier
    /// ends up in a log line.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Device")
            .field("name", &self.name)
            .field("tier", &self.tier)
            .field("paired_at", &self.paired_at)
            .field("joined", &self.joined)
            .field("sessions", &self.sessions)
            .finish_non_exhaustive()
    }
}

impl Device {
    fn minted(name: &str, tier: Tier, sessions: bool, token: &str, joined: Joined) -> Self {
        Self {
            name: name.to_string(),
            tier,
            digest: digest_hex(token),
            paired_at: epoch_secs_to_iso(now_epoch_secs()),
            joined,
            sessions,
            extra: serde_json::Map::new(),
        }
    }

    /// Whether `presented`, the SHA-256 of a presented bearer, is this
    /// device's. The compare runs over digests in constant time, so neither a
    /// token's length nor the position of its first wrong byte shows in the
    /// timing.
    fn verifies(&self, presented: &[u8; 32]) -> bool {
        let mut stored = [0u8; 32];
        hex::decode_to_slice(&self.digest, &mut stored).is_ok()
            && bool::from(stored.ct_eq(presented))
    }
}

/// `~/.clauth/devices.json`.
#[derive(Serialize, Deserialize)]
pub(super) struct Store {
    #[serde(default)]
    schema: u64,
    #[serde(default)]
    pub(super) devices: Vec<Device>,
    /// SHA-256 of the last `auth_token.json` this list imported, so a file
    /// still holding that token after `legacy` is revoked is never imported
    /// again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    legacy_digest: Option<String>,
    #[serde(flatten)]
    extra: serde_json::Map<String, serde_json::Value>,
}

impl Store {
    fn empty() -> Self {
        Self {
            schema: SCHEMA,
            devices: Vec::new(),
            legacy_digest: None,
            extra: serde_json::Map::new(),
        }
    }

    /// The index of the device holding `name`. Names are unique
    /// case-insensitively, so the lookup folds case and trims the same way, and
    /// a padded argv still resolves.
    fn index_named(&self, name: &str) -> Option<usize> {
        let name = name.trim();
        self.devices
            .iter()
            .position(|device| device.name.eq_ignore_ascii_case(name))
    }

    /// The device holding `name`.
    pub(super) fn named(&self, name: &str) -> Option<&Device> {
        self.index_named(name).map(|index| &self.devices[index])
    }
}

/// A device name, checked once where it enters: the profile-name charset, so a
/// name is one token in a log line and in the table, and never [`LEGACY_NAME`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DeviceName(String);

impl DeviceName {
    pub(crate) fn parse(raw: &str) -> Result<Self> {
        crate::actions::validate_name_chars(raw)?;
        let name = raw.trim();
        if name.eq_ignore_ascii_case(LEGACY_NAME) {
            bail!(
                "'{LEGACY_NAME}' is the name clauth gives the token it imports from an older \
                 build; pick another name"
            );
        }
        Ok(Self(name.to_string()))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for DeviceName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn store_path() -> Result<PathBuf> {
    Ok(clauth_dir()?.join(STORE_FILE))
}

fn legacy_path() -> Result<PathBuf> {
    Ok(clauth_dir()?.join(LEGACY_FILE))
}

/// A fresh token: 32 CSPRNG bytes through SHA-256, hex-encoded.
///
/// The hash is not there to protect the seed (nothing sees it); it fixes the
/// token at exactly 64 hex characters however the seed is drawn.
fn generate() -> Result<String> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| anyhow::anyhow!("CSPRNG failure: {e}"))?;
    Ok(hex::encode(<[u8; 32]>::from(Sha256::digest(seed))))
}

fn digest_hex(token: &str) -> String {
    hex::encode(<[u8; 32]>::from(Sha256::digest(token.as_bytes())))
}

/// True for the exact shape [`generate`] emits.
fn is_well_formed(token: &str) -> bool {
    token.len() == TOKEN_LEN
        && token
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The store as it is on disk now.
///
/// A missing file is an empty store, which is a legal start. A file that
/// cannot be read or parsed is an error, never an empty store: a caller that
/// took it for one would refuse nobody it should, or write a store over the
/// rows it could not read.
pub(super) fn read_store() -> Result<Store> {
    let path = store_path()?;
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Store::empty()),
        Err(e) => return Err(e).with_context(|| format!("failed to read {}", path.display())),
    };
    let mut store: Store = serde_json::from_slice(&bytes)
        .with_context(|| format!("{} is not a device list clauth can read", path.display()))?;
    store.schema = store.schema.max(SCHEMA);
    Ok(store)
}

/// Replace the store, and have it on disk before returning.
///
/// Durable because two callers delete something right after: the pairing
/// redemption deletes `pairing.json`, the legacy import deletes
/// `auth_token.json`. A crash that kept the deletion and lost the write would
/// take the credential away with nothing left to redeem or import.
fn write_store(_held: &StateLockHeld, store: &Store) -> Result<()> {
    #[cfg(test)]
    if FAIL_NEXT_WRITE.swap(false, std::sync::atomic::Ordering::AcqRel) {
        bail!("injected failure writing the device list");
    }
    let path = store_path()?;
    let bytes = serde_json::to_vec_pretty(store).context("failed to encode the device list")?;
    atomic_write_600(&path, bytes)
        .with_context(|| format!("failed to write {}", path.display()))?;
    sync_to_disk(&path).with_context(|| format!("failed to flush {} to disk", path.display()))
}

/// Test seam: fail the next [`write_store`] before it touches the disk, so a
/// test can hold each caller to writing the list before it deletes what the
/// list replaces. One-shot; every test that arms it holds a sandbox, whose lock
/// serializes them.
#[cfg(test)]
static FAIL_NEXT_WRITE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[cfg(test)]
pub(crate) fn fail_next_write() {
    FAIL_NEXT_WRITE.store(true, std::sync::atomic::Ordering::Release);
}

/// Test-only: put a device holding `token` in the store, for a test that needs
/// a device whose token it knows.
#[cfg(test)]
pub(crate) fn seed_for_tests(name: &str, tier: Tier, token: &str) -> Result<()> {
    with_state_lock(|held| {
        let mut store = read_store()?;
        store
            .devices
            .push(Device::minted(name, tier, false, token, Joined::Add));
        write_store(held, &store)
    })
}

fn sync_to_disk(path: &Path) -> std::io::Result<()> {
    // Opened for writing: `FlushFileBuffers` wants a writable handle on Windows.
    std::fs::OpenOptions::new()
        .write(true)
        .open(path)?
        .sync_all()?;
    // The rename lives in the directory entry, so only the directory's sync
    // makes it outlast a crash.
    #[cfg(unix)]
    if let Some(dir) = path.parent() {
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}

/// The device `presented` authenticates as, or `None`. A request with no
/// bearer reads nothing.
pub(crate) fn authenticate(presented: Option<&str>) -> Result<Option<Device>> {
    let Some(presented) = presented else {
        return Ok(None);
    };
    let digest: [u8; 32] = Sha256::digest(presented.as_bytes()).into();
    Ok(read_store()?
        .devices
        .into_iter()
        .find(|device| device.verifies(&digest)))
}

pub(super) fn refuse_taken(store: &Store, name: &DeviceName) -> Result<()> {
    if let Some(existing) = store.named(name.as_str()) {
        bail!(
            "a device named '{0}' already exists; revoke it first: clauth devices revoke {0}",
            existing.name
        );
    }
    Ok(())
}

/// Mint a token for `name` on this machine and store its digest. The token is
/// returned to be shown once; nothing can print it again.
pub(crate) fn add(name: &DeviceName, tier: Tier, sessions: bool) -> Result<String> {
    with_state_lock(|held| {
        let mut store = read_store()?;
        refuse_taken(&store, name)?;
        super::pairing::refuse_pending(name)?;
        let token = generate()?;
        store.devices.push(Device::minted(
            name.as_str(),
            tier,
            sessions,
            &token,
            Joined::Add,
        ));
        write_store(held, &store)?;
        Ok(token)
    })
}

/// Append the device a redeemed pairing code names, under the redemption's own
/// hold. `None` when the name was taken since the code was minted.
pub(super) fn append_paired(
    held: &StateLockHeld,
    name: &str,
    tier: Tier,
    sessions: bool,
) -> Result<Option<String>> {
    let mut store = read_store()?;
    if store.named(name).is_some() {
        return Ok(None);
    }
    let token = generate()?;
    store
        .devices
        .push(Device::minted(name, tier, sessions, &token, Joined::Pair));
    write_store(held, &store)?;
    Ok(Some(token))
}

/// The fixed sentence both name-lookup verbs use for a name the store does not
/// hold, so the two cannot drift apart.
fn missing_device(name: &str) -> anyhow::Error {
    anyhow::anyhow!("no device named '{name}'; `clauth devices` lists the paired ones")
}

/// Remove the device named `name`; its next request finds no row to verify.
pub(crate) fn revoke(name: &str) -> Result<Device> {
    with_state_lock(|held| {
        let mut store = read_store()?;
        let Some(index) = store.index_named(name) else {
            return Err(missing_device(name));
        };
        let removed = store.devices.remove(index);
        write_store(held, &store)?;
        Ok(removed)
    })
}

/// Grant the sessions flag to the control device named `name`. Returns the
/// device's canonical name and whether the grant was new (`false` = it already
/// held the flag, so the runner can say the no-op).
pub(crate) fn allow_sessions(name: &str) -> Result<(String, bool)> {
    with_state_lock(|held| {
        let mut store = read_store()?;
        let Some(index) = store.index_named(name) else {
            return Err(missing_device(name));
        };
        let canonical = store.devices[index].name.clone();
        if store.devices[index].tier != Tier::Control {
            bail!(
                "a device without the control tier cannot mint sessions; revoke '{canonical}' \
                 and re-pair it with --control"
            );
        }
        if store.devices[index].sessions {
            return Ok((canonical, false));
        }
        store.devices[index].sessions = true;
        write_store(held, &store)?;
        Ok((canonical, true))
    })
}

/// `~/.clauth/auth_token.json`, as the clauth before pairing wrote it.
#[derive(Deserialize)]
struct LegacyTokenFile {
    token: String,
    #[serde(default)]
    created_at: String,
    /// A file from before the field existed was a control token.
    #[serde(default = "control_tier")]
    tier: String,
}

fn control_tier() -> String {
    Tier::Control.as_str().to_string()
}

/// Fold `auth_token.json`, the one bearer a clauth before pairing served, into
/// the store as the control device [`LEGACY_NAME`], then delete the plaintext.
/// The client holding those bytes keeps working as that device.
///
/// A file carrying any tier but `control` stays where it is, neither imported
/// nor served: the import makes a control device, so importing it would
/// promote a token its writer restricted. So does a file holding no usable
/// token. A `legacy` device that already exists takes the file's digest,
/// because the file is newer than the import that made the device: a
/// downgraded clauth minted it after the import deleted the old one, and it is
/// the token the client was handed last.
pub(crate) fn import_legacy() -> Result<()> {
    with_state_lock(|held| {
        let path = legacy_path()?;
        let body = match std::fs::read_to_string(&path) {
            Ok(body) => body,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                logline!("clauth daemon: not importing {LEGACY_FILE}, which cannot be read: {e}");
                return Ok(());
            }
        };
        let legacy = match serde_json::from_str::<LegacyTokenFile>(&body) {
            Ok(legacy) if legacy.tier != Tier::Control.as_str() => {
                logline!(
                    "clauth daemon: {LEGACY_FILE} carries tier {:?} rather than control, so it is \
                     neither imported nor served; run the clauth that wrote it, or delete the \
                     file",
                    legacy.tier
                );
                return Ok(());
            }
            Ok(legacy) if is_well_formed(&legacy.token) => legacy,
            _ => {
                logline!(
                    "clauth daemon: {LEGACY_FILE} holds no usable token (bad JSON, or a token \
                     that is not 64 lowercase hex characters), so it is not imported; pair the \
                     client again with `clauth devices pair <name>` and delete the file"
                );
                return Ok(());
            }
        };
        let mut store = match read_store() {
            Ok(store) => store,
            Err(e) => {
                logline!(
                    "clauth daemon: not importing {LEGACY_FILE} while the device list is \
                     unreadable: {e:#}"
                );
                return Ok(());
            }
        };
        let digest = digest_hex(&legacy.token);
        let imported = match store.index_named(LEGACY_NAME) {
            Some(index) if store.devices[index].digest == digest => "already held its token",
            Some(index) => {
                store.devices[index].digest = digest.clone();
                store.devices[index].paired_at = legacy.created_at;
                store.legacy_digest = Some(digest);
                write_store(held, &store)?;
                "now holds the token a downgraded clauth minted"
            }
            // This list imported this very token and `legacy` is gone since:
            // it was revoked, and a file a failed delete left behind must not
            // undo that.
            None if store.legacy_digest.as_deref() == Some(digest.as_str()) => {
                "was revoked since this token was imported, so it is not imported again"
            }
            None => {
                store.devices.push(Device {
                    name: LEGACY_NAME.to_string(),
                    tier: Tier::Control,
                    digest: digest.clone(),
                    paired_at: legacy.created_at,
                    joined: Joined::Legacy,
                    sessions: false,
                    extra: serde_json::Map::new(),
                });
                store.legacy_digest = Some(digest);
                write_store(held, &store)?;
                "is imported (control)"
            }
        };
        match std::fs::remove_file(&path) {
            Ok(()) => logline!(
                "clauth daemon: device '{LEGACY_NAME}' {imported}; {LEGACY_FILE} is deleted"
            ),
            Err(e) => logline!(
                "clauth daemon: device '{LEGACY_NAME}' {imported}, but {LEGACY_FILE} could not be \
                 deleted ({e}); delete it by hand, it holds the plaintext token"
            ),
        }
        Ok(())
    })
}

/// One line when the listener starts on a store that refuses everyone: an
/// empty store is a legal start, and without the line the only symptom would
/// be a client's 401s.
pub(crate) fn note_at_start() {
    match read_store() {
        Ok(store) if store.devices.is_empty() => logline!(
            "clauth daemon: no device is paired yet, so every REST request but a pairing is \
             refused; pair one with `clauth devices pair <name>`"
        ),
        Ok(_) => {}
        Err(e) => logline!(
            "clauth daemon: every REST request is refused until the device list reads: {e:#}"
        ),
    }
}

/// `clauth devices [--json]`.
pub(crate) fn run_list(json: bool) -> Result<()> {
    let store = read_store()?;
    if json {
        outln!("{}", list_json(&store.devices));
    } else {
        out!("{}", render_table(&store.devices, now_epoch_secs()));
    }
    Ok(())
}

/// The `--json` rows: a fixed field set, which is why no digest can reach it.
fn list_json(devices: &[Device]) -> String {
    let rows: Vec<serde_json::Value> = devices
        .iter()
        .map(|device| {
            serde_json::json!({
                "name": device.name,
                "tier": device.tier.as_str(),
                "paired_at": device.paired_at,
                "joined": device.joined.as_str(),
                "sessions": device.sessions,
            })
        })
        .collect();
    serde_json::to_string_pretty(&rows).unwrap_or_else(|_| "[]".to_string())
}

fn render_table(devices: &[Device], now: i64) -> String {
    if devices.is_empty() {
        return "no devices are paired. `clauth devices pair <name>` pairs one.\n".to_string();
    }
    let paired: Vec<String> = devices
        .iter()
        .map(|device| paired_cell(&device.paired_at, now))
        .collect();
    let width = |header: &str, cells: &mut dyn Iterator<Item = &str>| {
        cells
            .map(|cell| cell.chars().count())
            .max()
            .unwrap_or(0)
            .max(header.chars().count())
    };
    let w_name = width("NAME", &mut devices.iter().map(|d| d.name.as_str()));
    let w_tier = width("TIER", &mut devices.iter().map(|d| d.tier.as_str()));
    let w_paired = width("PAIRED AT", &mut paired.iter().map(String::as_str));
    let w_joined = width("JOINED", &mut devices.iter().map(|d| d.joined.as_str()));
    let mut out = format!(
        "{:<w_name$}  {:<w_tier$}  {:<w_paired$}  {:<w_joined$}  SESSIONS\n",
        "NAME", "TIER", "PAIRED AT", "JOINED"
    );
    for (device, paired) in devices.iter().zip(&paired) {
        out.push_str(&format!(
            "{:<w_name$}  {:<w_tier$}  {:<w_paired$}  {:<w_joined$}  {}\n",
            device.name,
            device.tier.as_str(),
            paired,
            device.joined.as_str(),
            if device.sessions { "yes" } else { "no" },
        ));
    }
    out
}

/// The prose-stamp shape: local wall clock, paired with the age. `-` when the
/// stamp does not parse, never the raw text passed off as a time.
fn paired_cell(iso: &str, now: i64) -> String {
    let Some((epoch, stamp)) =
        iso_to_epoch_secs(iso).and_then(|epoch| Some((epoch, crate::format::local_stamp(epoch)?)))
    else {
        return "-".to_string();
    };
    // `humanize_duration` spells a non-positive span `now`, which ` ago` would
    // turn into `now ago`.
    let age = now - epoch;
    if age <= 0 {
        format!("{stamp} · now")
    } else {
        format!("{stamp} · {} ago", humanize_duration(age))
    }
}

/// `clauth devices add <name> [--control] [--sessions]`: the token alone on
/// stdout, so a `$(...)` capture holds exactly it, and everything else on stderr.
pub(crate) fn run_add(name: &str, control: bool, sessions: bool) -> Result<()> {
    let name = DeviceName::parse(name)?;
    let tier = Tier::chosen(control);
    let token = add(&name, tier.clone(), sessions)?;
    let lost =
        match write_chunk_result(&mut std::io::stdout().lock(), format_args!("{token}"), true) {
            Ok(Wrote::Yes) => None,
            Ok(Wrote::ReaderGone) => Some(None),
            Err(e) => Some(Some(e)),
        };
    if let Some(write_err) = lost {
        revoke_lost(&name, write_err)?;
    }
    errln!(
        "clauth: added device '{name}' ({tier}). That token is its only copy: clauth keeps just \
         a SHA-256 of it and cannot show it again."
    );
    if sessions {
        errln!("clauth: '{name}' may mint sessions");
    }
    Ok(())
}

/// Roll back the device a lost token line minted, naming the loss. `write_err`
/// is `Some(e)` when the write itself failed — a full disk behind a redirect —
/// rather than the reader closing the pipe, so the operator sees the cause.
fn revoke_lost(name: &DeviceName, write_err: Option<std::io::Error>) -> Result<()> {
    match revoke(name.as_str()) {
        Ok(_) => match write_err {
            Some(e) => {
                bail!(
                    "the token for '{name}' never reached its reader ({e}); the device was removed"
                )
            }
            None => {
                bail!("the token for '{name}' never reached its reader; the device was removed")
            }
        },
        Err(e) => match write_err {
            Some(write) => bail!(
                "the token for '{name}' never reached its reader ({write}) and the device could \
                 not be removed: {e:#}; remove it with `clauth devices revoke {name}`"
            ),
            None => bail!(
                "the token for '{name}' never reached its reader and the device could not be \
                 removed: {e:#}; remove it with `clauth devices revoke {name}`"
            ),
        },
    }
}

/// `clauth devices revoke <name>`.
pub(crate) fn run_revoke(name: &str) -> Result<()> {
    let removed = revoke(name)?;
    outln!(
        "clauth: revoked device '{}'; its next request is refused.",
        removed.name
    );
    Ok(())
}

/// `clauth devices allow-sessions <name>`.
pub(crate) fn run_allow_sessions(name: &str) -> Result<()> {
    let (name, granted) = allow_sessions(name)?;
    if granted {
        outln!("clauth: '{name}' may now mint sessions");
    } else {
        outln!("clauth: '{name}' already may mint sessions");
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../../tests/inline/daemon_api_devices.rs"]
mod tests;
