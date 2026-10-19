//! The persistent identity, one per environment, under
//! `~/.aqua-secrets/rotation-canary/<env>/`: `key.pem` (the canary account's
//! Ed25519 key, 0600), `client.json` (public: the registered client, the issuer
//! it belongs to, the logout route, the account's MXID), `devices.json` (the
//! devices the canary created and has not yet seen gone) and `.lock`.
//!
//! The directory is 0700 and `key.pem` is created 0600 by the `open(2)` that
//! creates it, so no byte of the key is ever in a file with wider modes. The
//! key is never overwritten (`create_new`), copied or backed up by this code.

use std::collections::BTreeSet;
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

#[derive(Default, Serialize, Deserialize)]
struct DeviceLedger {
    #[serde(default)]
    pending: BTreeSet<String>,
}

/// The devices this canary created and has not yet seen gone (`devices.json`).
/// A run that dies before its logout, or a deployment whose logout leaves the
/// device behind, would otherwise make the next run's tripwire fire on the
/// canary's own leftover. Only this program writes the file, so a stranger's
/// device is never in it. An unreadable ledger reads as empty: the tripwire
/// gets stricter, never looser.
pub fn read_pending(dir: &Path) -> BTreeSet<String> {
    fs::read_to_string(dir.join(DEVICES_FILE))
        .ok()
        .and_then(|text| serde_json::from_str::<DeviceLedger>(&text).ok())
        .map(|ledger| ledger.pending)
        .unwrap_or_default()
}

pub fn write_pending(dir: &Path, pending: &BTreeSet<String>) -> Result<(), Reason> {
    let text = serde_json::to_string_pretty(&DeviceLedger {
        pending: pending.clone(),
    })
    .map_err(|_| Reason::IdentityWriteFailed)?;
    write_private_atomic(dir, DEVICES_FILE, &text)
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
        assert!(read_pending(&dir).is_empty());
        let pending = BTreeSet::from(["SIWX_a".to_string(), "SIWX_b".to_string()]);
        write_pending(&dir, &pending).unwrap();
        assert_eq!(mode(&dir.join(DEVICES_FILE)), 0o600);
        assert_eq!(read_pending(&dir), pending);
        fs::write(dir.join(DEVICES_FILE), b"{ not json").unwrap();
        assert!(read_pending(&dir).is_empty(), "stricter, never looser");
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
