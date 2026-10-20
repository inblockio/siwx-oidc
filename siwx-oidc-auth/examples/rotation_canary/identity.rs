//! The persistent identity, one per environment, under
//! `~/.aqua-secrets/rotation-canary/<env>/`: `key.pem` (the canary account's
//! Ed25519 key, 0600), `client.json` (public: the registered client, the issuer
//! it belongs to, the logout route, the account's MXID), `devices.json` (the
//! devices the canary created and has not yet seen gone, the ones it is
//! finished with and when, the ones excused as unfinished sign-ins, and the
//! markers of sign-ins it started) and `.lock`.
//!
//! The directory is 0700 and `key.pem` is created 0600 by the `open(2)` that
//! creates it, so no byte of the key is ever in a file with wider modes. The
//! key is never overwritten (`create_new`), copied or backed up by this code.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use siwx_oidc_auth::SiwxKey;

use crate::hygiene::Secret;
use crate::report::Reason;

pub const KEY_FILE: &str = "key.pem";
pub const CLIENT_FILE: &str = "client.json";
pub const DEVICES_FILE: &str = "devices.json";
const LOCK_FILE: &str = ".lock";
const DIR_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;

/// `<home>/.aqua-secrets/rotation-canary`.
pub fn default_root() -> Option<PathBuf> {
    let home = std::env::var_os("HOME").filter(|h| !h.is_empty())?;
    Some(
        PathBuf::from(home)
            .join(".aqua-secrets")
            .join("rotation-canary"),
    )
}

/// Where the logout reaches siwx-oidc: through the homeserver's
/// `/_matrix/client/v3/logout` (probed at `init`), or, where the edge does not
/// route it, `/oauth2/revoke` on the issuer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogoutRoute {
    Matrix,
    Revoke,
}

impl LogoutRoute {
    pub fn word(self) -> &'static str {
        match self {
            LogoutRoute::Matrix => "matrix",
            LogoutRoute::Revoke => "revoke",
        }
    }
}

/// `client.json`. Nothing in it is a credential.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientRecord {
    pub version: u32,
    pub issuer: String,
    pub client_id: String,
    pub logout_route: LogoutRoute,
    pub mxid: String,
}

/// The environment's directory, created 0700 (with any missing parent) when
/// absent, and refused when it exists with wider modes or is not a plain
/// directory.
pub fn ensure_dir(root: &Path, env: &str) -> Result<PathBuf, Reason> {
    let dir = root.join(env);
    if !dir.exists() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(DIR_MODE)
            .create(&dir)
            .map_err(|_| Reason::IdentityWriteFailed)?;
    }
    check_dir(&dir)?;
    Ok(dir)
}

/// The environment's directory of an initialized identity: it must exist and be private.
pub fn existing_dir(root: &Path, env: &str) -> Result<PathBuf, Reason> {
    let dir = root.join(env);
    if fs::symlink_metadata(&dir).is_err() {
        return Err(Reason::NotInitialized);
    }
    check_dir(&dir)?;
    Ok(dir)
}

fn check_dir(dir: &Path) -> Result<(), Reason> {
    let meta = fs::symlink_metadata(dir).map_err(|_| Reason::IdentityUnreadable)?;
    if !meta.is_dir() || meta.mode() & 0o077 != 0 {
        return Err(Reason::PermsUnsafe);
    }
    Ok(())
}

pub fn key_exists(dir: &Path) -> bool {
    fs::symlink_metadata(dir.join(KEY_FILE)).is_ok()
}

pub fn client_exists(dir: &Path) -> bool {
    fs::symlink_metadata(dir.join(CLIENT_FILE)).is_ok()
}

/// Write a new key. The file is created 0600 and only then written; an
/// existing file of that name, whatever it is, is refused.
pub fn write_new_key(dir: &Path, pem: &Secret) -> Result<(), Reason> {
    check_dir(dir)?;
    let path = dir.join(KEY_FILE);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(FILE_MODE)
        .open(&path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                Reason::IdentityExists
            } else {
                Reason::IdentityWriteFailed
            }
        })?;
    let written = file
        .write_all(pem.expose().as_bytes())
        .and_then(|()| file.sync_all());
    if written.is_err() {
        // Nothing usable was stored: do not leave a truncated key behind.
        drop(file);
        let _ = fs::remove_file(&path);
        return Err(Reason::IdentityWriteFailed);
    }
    Ok(())
}

/// Load the key. Refused unless the directory and the file are private, the
/// file is a regular file (not a link) and the PEM is an Ed25519 key.
pub fn load_key(dir: &Path) -> Result<SiwxKey, Reason> {
    check_dir(dir)?;
    let path = dir.join(KEY_FILE);
    let meta = fs::symlink_metadata(&path).map_err(|_| Reason::NotInitialized)?;
    if !meta.is_file() || meta.mode() & 0o077 != 0 {
        return Err(Reason::PermsUnsafe);
    }
    let pem = Secret::new(fs::read_to_string(&path).map_err(|_| Reason::IdentityUnreadable)?);
    match SiwxKey::from_pem(pem.expose()) {
        Ok(key @ SiwxKey::Ed25519(_)) => Ok(key),
        _ => Err(Reason::IdentityUnreadable),
    }
}

pub fn read_client(dir: &Path) -> Result<ClientRecord, Reason> {
    let path = dir.join(CLIENT_FILE);
    let meta = fs::symlink_metadata(&path).map_err(|_| Reason::NotInitialized)?;
    if !meta.is_file() {
        return Err(Reason::PermsUnsafe);
    }
    let text = fs::read_to_string(&path).map_err(|_| Reason::IdentityUnreadable)?;
    serde_json::from_str(&text).map_err(|_| Reason::IdentityUnreadable)
}

/// Replace `name` atomically (a temporary file in the same directory, 0600,
/// then `rename`), so a crash leaves the old content or the new one.
fn write_private_atomic(dir: &Path, name: &str, text: &str) -> Result<(), Reason> {
    let tmp = dir.join(format!("{name}.tmp"));
    let _ = fs::remove_file(&tmp);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(FILE_MODE)
        .open(&tmp)
        .map_err(|_| Reason::IdentityWriteFailed)?;
    file.write_all(text.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|_| Reason::IdentityWriteFailed)?;
    fs::rename(&tmp, dir.join(name)).map_err(|_| Reason::IdentityWriteFailed)
}

pub fn write_client(dir: &Path, record: &ClientRecord) -> Result<(), Reason> {
    let text = serde_json::to_string_pretty(record).map_err(|_| Reason::IdentityWriteFailed)?;
    write_private_atomic(dir, CLIENT_FILE, &text)
}

/// A sign-in the canary started. The server creates the Synapse device at
/// `/sign_in`, before the code is exchanged, so a sign-in that failed or was
/// killed afterwards leaves a device the canary never saw an id for. The
/// marker is written before the sign-in and dropped once the run knows its own
/// device; one still there at the next run says "one device of this kind may
/// be unrecorded".
///
/// A marker is a licence to excuse one device, so it does not last: see
/// [`ATTEMPT_MAX_AGE_SECS`] and [`ATTEMPT_CAP`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attempt {
    pub id: String,
    /// Unix seconds on this host's clock when the sign-in started.
    pub at: i64,
}

/// How long a marker can excuse a device: three days. A run that died leaves
/// its marker for the next run, which is a person or a job a few hours to a
/// weekend away (a Friday evening failure and a Monday run are about 64 hours
/// apart). A marker older than that belongs to a run nobody is waiting for any
/// more, and the longer it stays valid the longer it can cover a device
/// somebody else made. An expired marker explains nothing: its device reads as
/// a stranger and fires the tripwire, the safe direction.
pub const ATTEMPT_MAX_AGE_SECS: i64 = 3 * 24 * 60 * 60;

/// The most markers that count, and the most the ledger keeps (the oldest are
/// dropped first). Each run that fails between its `/authorize` probe and its
/// `whoami` leaves one, and an operator chasing a broken token endpoint may
/// retry a dozen times, so the cap is above that. Without a cap the number of
/// devices the canary excuses would grow with every failed run, and the
/// tripwire would get looser the longer the deployment is unhealthy.
pub const ATTEMPT_CAP: usize = 16;

/// A marker dated this far ahead of this host's clock is still believed (the
/// clock is not exact); one dated further ahead is not, so a clock set back
/// cannot keep a marker alive past its age limit.
const ATTEMPT_FUTURE_SLACK_SECS: i64 = 300;

impl Attempt {
    /// Whether the marker may still explain a device at `now` (unix seconds).
    pub fn is_live(&self, now: i64) -> bool {
        self.at <= now.saturating_add(ATTEMPT_FUTURE_SLACK_SECS)
            && now.saturating_sub(self.at) <= ATTEMPT_MAX_AGE_SECS
    }
}

/// How far a device's `last_seen_ts` may lie past the time the canary last used
/// the device and still be the canary's own use: the server's clock against this
/// host's (the skew C3 tolerates is `checks::MAX_SKEW_SECS`, 30 s), so twice
/// that. A longer slack would let a stranger who signs in on a retired id
/// right after the canary's logout, and uses it once, pass for the canary.
pub const LAST_SEEN_SLACK_SECS: i64 = 60;

/// The time recorded for a device whose logout time is unknown (a ledger written
/// before the times were kept): earlier than any `last_seen_ts`, so such a device
/// passes only while it has never been seen in use.
const TIME_UNKNOWN: i64 = i64::MIN;

/// The devices the canary has finished with: each id with the unix seconds, on
/// this host's clock, taken after the canary's last request with the device's
/// token. A device on it that is still listed at a later run is the canary's own
/// only if it carries the canary's display name and its `last_seen_ts` is no
/// later than that time plus [`LAST_SEEN_SLACK_SECS`] (see
/// `flow::Device::is_survivor`): siwx-oidc lets a client propose a device id and
/// recreates a deleted one, so an id alone proves nothing.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "LoggedOutRepr", into = "BTreeMap<String, i64>")]
pub struct LoggedOut(BTreeMap<String, i64>);

/// What `devices.json` may hold under `logged_out`: the map, or the bare list
/// of ids of the version that did not keep the times.
#[derive(Deserialize)]
#[serde(untagged)]
enum LoggedOutRepr {
    Timed(BTreeMap<String, i64>),
    Bare(BTreeSet<String>),
}

impl From<LoggedOutRepr> for LoggedOut {
    fn from(repr: LoggedOutRepr) -> Self {
        LoggedOut(match repr {
            LoggedOutRepr::Timed(map) => map,
            LoggedOutRepr::Bare(ids) => ids.into_iter().map(|id| (id, TIME_UNKNOWN)).collect(),
        })
    }
}

impl From<LoggedOut> for BTreeMap<String, i64> {
    fn from(logged_out: LoggedOut) -> Self {
        logged_out.0
    }
}

impl LoggedOut {
    pub fn contains(&self, id: &str) -> bool {
        self.0.contains_key(id)
    }

    /// The time recorded for `id`.
    pub fn at(&self, id: &str) -> Option<i64> {
        self.0.get(id).copied()
    }

    /// Record `id` as finished with at `at` (replacing an earlier time).
    pub fn insert(&mut self, id: String, at: i64) {
        self.0.insert(id, at);
    }

    pub fn remove(&mut self, id: &str) {
        self.0.remove(id);
    }

    pub fn retain(&mut self, mut keep: impl FnMut(&str) -> bool) {
        self.0.retain(|id, _| keep(id));
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn ids(&self) -> BTreeSet<String> {
        self.0.keys().cloned().collect()
    }
}

/// `devices.json`: what the canary knows about the devices it made. Only this
/// program writes the file, so a stranger's device is never in it. An
/// unreadable ledger reads as empty: the tripwire gets stricter, never looser.
///
/// A device leaves every list only when a reading shows it gone, never on the
/// strength of an answer: siwx-oidc deletes a Synapse device best-effort and
/// answers 200 whether or not that worked.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ledger {
    /// Devices created by a run of the canary and not yet seen gone: this run's
    /// own where the logout may leave it (`/oauth2/revoke`, an unproven logout)
    /// and the device of a run that died after learning it. Tolerated at the
    /// next run whatever they look like, and deleted.
    #[serde(default)]
    pub pending: BTreeSet<String>,
    /// Devices the canary is finished with at a known time: the ones whose
    /// logout a run proved (the refresh token was refused after it) and the ones
    /// it deleted. The proof is about the grant, not the device, so one of these
    /// may still be listed at the next run. It is then reported under its own
    /// reason and deleted, not taken for a stranger, provided it still looks
    /// like the canary's (see [`LoggedOut`]); otherwise it fires the tripwire.
    #[serde(default)]
    pub logged_out: LoggedOut,
    /// Devices a run excused as the leftover of an unfinished sign-in. The
    /// canary never used their tokens, so they stay excused only while they are
    /// still never seen in use: one that has been used since was used by
    /// somebody else and fires the tripwire.
    #[serde(default)]
    pub unfinished: BTreeSet<String>,
    /// Sign-ins started and not finished, oldest first.
    #[serde(default)]
    pub attempts: Vec<Attempt>,
}

impl Ledger {
    /// How many unfinished sign-ins of earlier runs (not `own`, this run's)
    /// can still explain a device at `now`: the live markers, at most
    /// [`ATTEMPT_CAP`].
    pub fn live_attempts(&self, now: i64, own: &str) -> usize {
        self.attempts
            .iter()
            .filter(|a| a.id != own && a.is_live(now))
            .count()
            .min(ATTEMPT_CAP)
    }

    /// Add a marker: the expired ones are dropped first and, when the cap would
    /// be passed, the oldest live ones after them.
    pub fn record_attempt(&mut self, attempt: Attempt, now: i64) {
        self.attempts.retain(|a| a.is_live(now));
        self.attempts.push(attempt);
        let excess = self.attempts.len().saturating_sub(ATTEMPT_CAP);
        self.attempts.drain(..excess);
    }
}

pub fn read_ledger(dir: &Path) -> Ledger {
    fs::read_to_string(dir.join(DEVICES_FILE))
        .ok()
        .and_then(|text| serde_json::from_str::<Ledger>(&text).ok())
        .unwrap_or_default()
}

pub fn write_ledger(dir: &Path, ledger: &Ledger) -> Result<(), Reason> {
    let text = serde_json::to_string_pretty(ledger).map_err(|_| Reason::IdentityWriteFailed)?;
    write_private_atomic(dir, DEVICES_FILE, &text)
}

/// Read the ledger, change it, write it back.
pub fn update_ledger(dir: &Path, change: impl FnOnce(&mut Ledger)) -> Result<(), Reason> {
    let mut ledger = read_ledger(dir);
    change(&mut ledger);
    write_ledger(dir, &ledger)
}

/// Remove the old identity's files (after its account was erased).
pub fn remove_identity(dir: &Path) -> Result<(), Reason> {
    for name in [KEY_FILE, CLIENT_FILE, DEVICES_FILE] {
        match fs::remove_file(dir.join(name)) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(Reason::IdentityWriteFailed),
        }
    }
    Ok(())
}

/// The per-environment run lock (`flock(2)` through `File::try_lock`): runs of
/// one environment never overlap, because the logout tripwire of one would see
/// the other's device. Released when dropped, and by the kernel when the
/// process dies.
#[derive(Debug)]
pub struct RunLock {
    _file: File,
}

pub async fn acquire_lock(dir: &Path, wait: Duration) -> Result<RunLock, Reason> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(FILE_MODE)
        .open(dir.join(LOCK_FILE))
        .map_err(|_| Reason::LockFailed)?;
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(RunLock { _file: file }),
            Err(fs::TryLockError::WouldBlock) => {
                if tokio::time::Instant::now() >= deadline {
                    return Err(Reason::LockBusy);
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            Err(fs::TryLockError::Error(_)) => return Err(Reason::LockFailed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Scratch {
            let mut root = std::env::temp_dir();
            root.push(format!("rotation-canary-test-{tag}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&root);
            Scratch(root)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn mode(path: &Path) -> u32 {
        fs::symlink_metadata(path).unwrap().mode() & 0o777
    }

    #[test]
    fn the_directory_is_0700_and_the_key_is_0600_and_never_overwritten() {
        let scratch = Scratch::new("key");
        let dir = ensure_dir(&scratch.0, "dev").unwrap();
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&scratch.0), 0o700, "a created parent is private too");
        let key = SiwxKey::generate_ed25519();
        let pem = Secret::new(key.to_pem().unwrap());
        write_new_key(&dir, &pem).unwrap();
        assert_eq!(mode(&dir.join(KEY_FILE)), 0o600);
        // Refuses to overwrite, and leaves the first key untouched.
        let other = Secret::new(SiwxKey::generate_ed25519().to_pem().unwrap());
        assert_eq!(write_new_key(&dir, &other), Err(Reason::IdentityExists));
        assert_eq!(
            fs::read_to_string(dir.join(KEY_FILE)).unwrap(),
            pem.expose()
        );
        // And loads back as the same account.
        assert_eq!(load_key(&dir).unwrap().did(), key.did());
    }

    #[test]
    fn the_key_file_is_private_from_its_first_byte_even_under_a_loose_umask() {
        // `mode(0o600)` on `open` is not widened by any umask; the file is never
        // created with wider modes and tightened afterwards.
        let scratch = Scratch::new("umask");
        let dir = ensure_dir(&scratch.0, "dev").unwrap();
        // SAFETY: a test-only umask change in a test that creates one file.
        let old = unsafe { libc::umask(0) };
        let pem = Secret::new(SiwxKey::generate_ed25519().to_pem().unwrap());
        let result = write_new_key(&dir, &pem);
        unsafe { libc::umask(old) };
        result.unwrap();
        assert_eq!(mode(&dir.join(KEY_FILE)), 0o600);
    }

    #[test]
    fn a_loose_directory_or_key_is_refused_not_repaired() {
        use std::os::unix::fs::PermissionsExt;
        let scratch = Scratch::new("loose");
        let dir = ensure_dir(&scratch.0, "dev").unwrap();
        write_new_key(
            &dir,
            &Secret::new(SiwxKey::generate_ed25519().to_pem().unwrap()),
        )
        .unwrap();
        fs::set_permissions(dir.join(KEY_FILE), fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(load_key(&dir).err(), Some(Reason::PermsUnsafe));
        assert_eq!(
            mode(&dir.join(KEY_FILE)),
            0o640,
            "refused, not chmod-ed behind the operator's back"
        );
        fs::set_permissions(dir.join(KEY_FILE), fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(load_key(&dir).err(), Some(Reason::PermsUnsafe));
        assert_eq!(
            ensure_dir(&scratch.0, "dev").unwrap_err(),
            Reason::PermsUnsafe
        );
    }

    #[test]
    fn a_key_that_is_not_ed25519_or_not_a_key_is_unreadable() {
        let scratch = Scratch::new("kind");
        let dir = ensure_dir(&scratch.0, "dev").unwrap();
        write_new_key(
            &dir,
            &Secret::new(SiwxKey::generate_p256().to_pem().unwrap()),
        )
        .unwrap();
        assert_eq!(load_key(&dir).err(), Some(Reason::IdentityUnreadable));
        let dir = ensure_dir(&scratch.0, "other").unwrap();
        write_new_key(&dir, &Secret::new("not a pem".to_string())).unwrap();
        assert_eq!(load_key(&dir).err(), Some(Reason::IdentityUnreadable));
        let dir = ensure_dir(&scratch.0, "empty").unwrap();
        assert_eq!(load_key(&dir).err(), Some(Reason::NotInitialized));
    }

    #[test]
    fn client_json_round_trips_atomically_and_is_private() {
        let scratch = Scratch::new("client");
        let dir = ensure_dir(&scratch.0, "dev").unwrap();
        assert_eq!(read_client(&dir).unwrap_err(), Reason::NotInitialized);
        let record = ClientRecord {
            version: 1,
            issuer: "https://siwx.example.org".to_string(),
            client_id: "client-1".to_string(),
            logout_route: LogoutRoute::Revoke,
            mxid: "@canary:example.org".to_string(),
        };
        write_client(&dir, &record).unwrap();
        assert_eq!(mode(&dir.join(CLIENT_FILE)), 0o600);
        assert_eq!(read_client(&dir).unwrap(), record);
        let newer = ClientRecord {
            client_id: "client-2".to_string(),
            ..record
        };
        write_client(&dir, &newer).unwrap();
        assert_eq!(read_client(&dir).unwrap().client_id, "client-2");
        assert!(!dir.join("client.json.tmp").exists());
        let text = fs::read_to_string(dir.join(CLIENT_FILE)).unwrap();
        assert!(text.contains("\"logout_route\": \"revoke\""), "{text}");
    }

    #[test]
    fn the_device_ledger_round_trips_and_an_unreadable_one_reads_as_empty() {
        let scratch = Scratch::new("ledger");
        let dir = ensure_dir(&scratch.0, "dev").unwrap();
        assert_eq!(read_ledger(&dir), Ledger::default());
        let mut logged_out = LoggedOut::default();
        logged_out.insert("SIWX_c".to_string(), 1_700_000_100);
        let ledger = Ledger {
            pending: BTreeSet::from(["SIWX_a".to_string(), "SIWX_b".to_string()]),
            logged_out,
            unfinished: BTreeSet::from(["SIWX_d".to_string()]),
            attempts: vec![Attempt {
                id: "abc".to_string(),
                at: 1_700_000_000,
            }],
        };
        write_ledger(&dir, &ledger).unwrap();
        assert_eq!(mode(&dir.join(DEVICES_FILE)), 0o600);
        assert_eq!(read_ledger(&dir), ledger);
        update_ledger(&dir, |l| {
            l.pending.remove("SIWX_a");
            l.attempts.clear();
        })
        .unwrap();
        assert_eq!(
            read_ledger(&dir).pending,
            BTreeSet::from(["SIWX_b".to_string()])
        );
        assert!(read_ledger(&dir).attempts.is_empty());
        fs::write(dir.join(DEVICES_FILE), b"{ not json").unwrap();
        assert_eq!(
            read_ledger(&dir),
            Ledger::default(),
            "stricter, never looser"
        );
    }

    #[test]
    fn a_ledger_of_the_first_version_without_attempts_still_reads() {
        let scratch = Scratch::new("ledger-v1");
        let dir = ensure_dir(&scratch.0, "dev").unwrap();
        fs::write(dir.join(DEVICES_FILE), br#"{"pending":["SIWX_old"]}"#).unwrap();
        let ledger = read_ledger(&dir);
        assert_eq!(ledger.pending, BTreeSet::from(["SIWX_old".to_string()]));
        assert!(ledger.attempts.is_empty());
        assert!(ledger.logged_out.is_empty());
    }

    #[test]
    fn a_ledger_without_logged_out_devices_still_reads() {
        let scratch = Scratch::new("ledger-v2");
        let dir = ensure_dir(&scratch.0, "dev").unwrap();
        fs::write(
            dir.join(DEVICES_FILE),
            br#"{"pending":[],"attempts":[{"id":"abc","at":1700000000}]}"#,
        )
        .unwrap();
        let ledger = read_ledger(&dir);
        assert_eq!(ledger.attempts.len(), 1);
        assert!(ledger.logged_out.is_empty());
    }

    #[test]
    fn the_logout_times_are_kept_and_a_list_of_ids_from_before_reads_as_time_unknown() {
        let scratch = Scratch::new("ledger-times");
        let dir = ensure_dir(&scratch.0, "dev").unwrap();
        update_ledger(&dir, |l| {
            l.logged_out.insert("SIWX_a".to_string(), 1_700_000_000)
        })
        .unwrap();
        let text = fs::read_to_string(dir.join(DEVICES_FILE)).unwrap();
        assert!(text.contains("\"SIWX_a\": 1700000000"), "{text}");
        assert_eq!(
            read_ledger(&dir).logged_out.at("SIWX_a"),
            Some(1_700_000_000)
        );
        assert_eq!(read_ledger(&dir).logged_out.at("SIWX_b"), None);

        // The version that kept a bare list: every id is there, at no known time.
        fs::write(
            dir.join(DEVICES_FILE),
            br#"{"pending":[],"logged_out":["SIWX_old"],"attempts":[]}"#,
        )
        .unwrap();
        let ledger = read_ledger(&dir);
        assert!(ledger.logged_out.contains("SIWX_old"));
        assert_eq!(ledger.logged_out.at("SIWX_old"), Some(i64::MIN));
        assert!(ledger.unfinished.is_empty());
        // It round-trips as a map.
        write_ledger(&dir, &ledger).unwrap();
        assert_eq!(read_ledger(&dir), ledger);
    }

    fn attempt(id: &str, at: i64) -> Attempt {
        Attempt {
            id: id.to_string(),
            at,
        }
    }

    const NOW: i64 = 1_800_000_000;

    #[test]
    fn a_marker_explains_a_device_only_for_three_days() {
        assert!(attempt("a", NOW).is_live(NOW));
        assert!(attempt("a", NOW - ATTEMPT_MAX_AGE_SECS).is_live(NOW));
        assert!(!attempt("a", NOW - ATTEMPT_MAX_AGE_SECS - 1).is_live(NOW));
        assert!(!attempt("a", 1).is_live(NOW), "a marker from 1970 is spent");
    }

    #[test]
    fn a_marker_from_the_future_is_believed_a_little_and_not_for_ever() {
        assert!(attempt("a", NOW + 60).is_live(NOW), "a clock a minute off");
        assert!(
            !attempt("a", NOW + 3_600).is_live(NOW),
            "an hour ahead is not a clock error; a marker set that far ahead would never age"
        );
        assert!(!attempt("a", i64::MAX).is_live(NOW));
        assert!(!attempt("a", i64::MIN).is_live(NOW));
    }

    #[test]
    #[ignore = "known gap, tracked in #84 (item 2)"]
    fn audit_a7_a_clock_set_back_does_not_keep_a_marker_alive_past_its_age_limit() {
        // Recorded 3 days and 1 hour ago; this host's clock is now 2 hours slow.
        let marker = attempt("a", NOW - ATTEMPT_MAX_AGE_SECS - 3_600);
        assert!(!marker.is_live(NOW - 7_200), "expired by the true clock");
    }

    #[test]
    fn only_live_markers_of_other_runs_count() {
        let ledger = Ledger {
            attempts: vec![
                attempt("old", NOW - ATTEMPT_MAX_AGE_SECS - 10),
                attempt("fresh", NOW - 10),
                attempt("mine", NOW - 1),
            ],
            ..Ledger::default()
        };
        assert_eq!(ledger.live_attempts(NOW, "mine"), 1);
        assert_eq!(ledger.live_attempts(NOW, "nobody"), 2);
    }

    #[test]
    fn the_markers_that_count_are_capped_even_in_a_ledger_that_holds_more() {
        let ledger = Ledger {
            attempts: (0..ATTEMPT_CAP + 5)
                .map(|n| attempt(&format!("m{n}"), NOW - 10))
                .collect(),
            ..Ledger::default()
        };
        assert_eq!(ledger.live_attempts(NOW, "mine"), ATTEMPT_CAP);
    }

    #[test]
    fn recording_a_marker_drops_expired_ones_and_keeps_at_most_the_cap_newest() {
        let mut ledger = Ledger {
            attempts: vec![attempt("old", 1)],
            ..Ledger::default()
        };
        ledger.record_attempt(attempt("a", NOW), NOW);
        assert_eq!(ledger.attempts, vec![attempt("a", NOW)], "expired is gone");
        for n in 0..ATTEMPT_CAP + 3 {
            ledger.record_attempt(attempt(&format!("n{n}"), NOW), NOW);
        }
        assert_eq!(ledger.attempts.len(), ATTEMPT_CAP);
        assert_eq!(
            ledger.attempts.last().unwrap().id,
            format!("n{}", ATTEMPT_CAP + 2),
            "the newest is kept"
        );
        assert!(
            ledger.attempts.iter().all(|a| a.id != "a" && a.id != "n0"),
            "the oldest go first"
        );
    }

    #[test]
    fn remove_identity_deletes_the_key_and_the_client_and_nothing_else() {
        let scratch = Scratch::new("remove");
        let dir = ensure_dir(&scratch.0, "dev").unwrap();
        write_new_key(
            &dir,
            &Secret::new(SiwxKey::generate_ed25519().to_pem().unwrap()),
        )
        .unwrap();
        fs::write(dir.join("keep.txt"), b"x").unwrap();
        remove_identity(&dir).unwrap();
        assert!(!key_exists(&dir));
        assert!(dir.join("keep.txt").exists());
        remove_identity(&dir).unwrap();
    }

    #[tokio::test]
    async fn a_second_run_of_one_environment_waits_and_then_gives_up() {
        let scratch = Scratch::new("lock");
        let dir = ensure_dir(&scratch.0, "dev").unwrap();
        let first = acquire_lock(&dir, Duration::from_secs(1)).await.unwrap();
        let second = acquire_lock(&dir, Duration::from_millis(300)).await;
        assert_eq!(second.unwrap_err(), Reason::LockBusy);
        drop(first);
        assert!(acquire_lock(&dir, Duration::from_secs(1)).await.is_ok());
        // Another environment is not blocked by it.
        let other = ensure_dir(&scratch.0, "prod").unwrap();
        let _held = acquire_lock(&dir, Duration::from_secs(1)).await.unwrap();
        assert!(acquire_lock(&other, Duration::from_millis(100))
            .await
            .is_ok());
    }
}
