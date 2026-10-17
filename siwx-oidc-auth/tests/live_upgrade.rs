//! Upgrade continuity of a live deployment: sessions minted on one build of
//! siwx-oidc are checked on the build that replaces it.
//!
//! The suite runs in stages around the switch, chosen by `QUALIFY_STAGE`:
//!
//! - `mint`, against the build that runs before the switch: signs in with
//!   freshly generated Ed25519 keys and creates one throwaway account per
//!   session shape below, then writes the sessions (keys and tokens) to
//!   `$QUALIFY_STATE_DIR/live_upgrade.json`. Switch the server, keeping its
//!   Redis.
//! - `check`, against the build after the switch: one test per check. Each
//!   check uses its own session and deactivates that account when it is
//!   done, also when it failed.
//! - `cleanup`: deactivates every account the mint created that no check
//!   deactivated (a filtered, aborted or never-run check), verifies that each
//!   account refuses a new sign-in, and removes the state.
//!
//! Each test belongs to one stage and is named after it, so run a stage with
//! its name and an underscore as the filter:
//!
//! ```text
//! export SIWX_SERVER=https://siwx.example.org SIWX_HOMESERVER=https://matrix.example.org
//! export QUALIFY_STATE_DIR=$HOME/.cache/qualify/live-upgrade
//! QUALIFY_STAGE=mint    cargo test -p siwx-oidc-auth --test live_upgrade -- --ignored --nocapture mint_
//! # switch the server
//! QUALIFY_STAGE=check   cargo test -p siwx-oidc-auth --test live_upgrade -- --ignored --nocapture check_
//! QUALIFY_STAGE=cleanup cargo test -p siwx-oidc-auth --test live_upgrade -- --ignored --nocapture cleanup_
//! ```
//!
//! The session shapes are the ones a deployment holds at an upgrade:
//!
//! | Shape | What it is |
//! |---|---|
//! | `agent` | an agent with a stable `AQUA_…` device |
//! | `registration-deleted` | the same, whose client registration is then deleted with its registration access token (RFC 7592), as an expired one is gone |
//! | `element-x` | a 43-character device id with `/` and `+`, as Element X mints them |
//! | `matrix-refresh` | refreshed at `POST /_matrix/client/v3/refresh` on the homeserver instead of `POST /token` |
//! | `access-token` | an access token minted and never presented before the switch |
//! | `device-delete` | two devices of one account, one Element X shaped, deleted through `DELETE /_matrix/client/v3/devices/{id}` |
//! | `rotated-before-switch` | rotated at the very end of the mint, its previous refresh token kept as a client whose refresh response was lost |
//!
//! Targets come only from `SIWX_SERVER` and `SIWX_HOMESERVER`, never from this
//! file, and must be the same at every stage. A missing variable, a missing
//! state, a test run in another stage than its own, or a check that cannot
//! judge (the access-token check after the token's 300 s) fails under
//! `E2E_STRICT_SKIPS` (the default); with `E2E_STRICT_SKIPS=0` it prints
//! `E2E_SKIP` and passes.
//!
//! `QUALIFY_STATE_DIR` holds private keys and refresh tokens: the mint creates
//! it with mode 0700 and every stage refuses a directory others may read; the
//! state file is 0600. Nothing here prints a token.
//!
//! `SIWX_DEVICE_DELETE_BASE` (default `SIWX_HOMESERVER`) is where
//! `DELETE /_matrix/client/v3/devices/{id}` is sent. Under delegated
//! authentication Synapse does not delete devices on that route, so the edge in
//! front of the homeserver must route it to siwx-oidc, which answers it with no
//! user-interactive authentication (the bearer's account, any of its
//! devices). Element Web and Element X delete devices through the account page
//! (MSC4191) instead; this route serves clients that call the client-server API.
//! On a deployment whose edge does not route it, point the variable at the
//! siwx-oidc URL: the check then proves siwx-oidc's handling, not the edge's.

mod live;

use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use live::{
    deactivate, delete_registration, element_x_device_id, env_url, handle, is_access_token,
    is_legacy_refresh_token, is_refresh_token, matrix_refresh, now, random_upper,
    register_public_client, shape, strict, target_from_env, token_refresh, whoami, Failure, Pair,
    Target, REDIRECT_URI,
};
use serde::{Deserialize, Serialize};
use siwx_oidc_auth::{authenticate_with_device, AuthTokens, SiwxKey};

const STATE_FILE: &str = "live_upgrade.json";
const CLIENT_NAME: &str = "siwx-oidc-auth live upgrade test";
/// A state older than this is from another run, not one switch ago.
const STATE_MAX_AGE_SECS: i64 = 86_400;
/// An access token needs this much of its lifetime left to be judged.
const ACCESS_MARGIN_SECS: i64 = 10;
/// The access token lifetime when the answer does not say.
const ACCESS_TTL_DEFAULT_SECS: i64 = 300;

// ---------------------------------------------------------------------------
// Skips, stages and the state directory
// ---------------------------------------------------------------------------

/// A leg that cannot run: a failure under `E2E_STRICT_SKIPS`, else a loud skip.
fn skip_or_fail(test: &str, why: &str) {
    eprintln!("E2E_SKIP: live_upgrade::{test}: {why}");
    if strict() {
        panic!(
            "{test}: {why}. This is a FAILURE, not a skip, because a skipped check reads as a \
             pass. Fix it, or set E2E_STRICT_SKIPS=0 to accept an unverified run."
        );
    }
}

/// The target and the state directory when `test` belongs to the stage that
/// `QUALIFY_STAGE` names; `None` after a skip.
fn stage(test: &str, own: &str) -> Option<(Target, PathBuf)> {
    let stage = std::env::var("QUALIFY_STAGE").unwrap_or_default();
    if stage != own {
        skip_or_fail(
            test,
            &format!(
                "QUALIFY_STAGE is {stage:?}; this test belongs to stage {own:?} (run a stage \
                 with its name as the test filter: `-- --ignored {own}_`)"
            ),
        );
        return None;
    }
    let target = match target_from_env() {
        Ok(target) => target,
        Err(why) => {
            skip_or_fail(test, &why);
            return None;
        }
    };
    let Some(dir) = env_url("QUALIFY_STATE_DIR") else {
        skip_or_fail(test, "QUALIFY_STATE_DIR must name the state directory");
        return None;
    };
    Some((target, PathBuf::from(dir)))
}

/// A directory or file no one but its owner may read.
fn private(mode: u32) -> bool {
    mode & 0o077 == 0
}

/// Refuse a state directory that others may read; create it (0700) only when
/// `create` (the mint).
fn state_dir(dir: &Path, create: bool) -> anyhow::Result<()> {
    if !dir.exists() {
        anyhow::ensure!(
            create,
            "QUALIFY_STATE_DIR {} does not exist: run the mint first",
            dir.display()
        );
        std::fs::create_dir_all(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    let meta = std::fs::metadata(dir)?;
    anyhow::ensure!(meta.is_dir(), "{} is not a directory", dir.display());
    let mode = meta.permissions().mode() & 0o777;
    anyhow::ensure!(
        private(mode),
        "QUALIFY_STATE_DIR {} has mode {mode:o}: it holds keys and refresh tokens, so it must \
         be 0700",
        dir.display()
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// The state
// ---------------------------------------------------------------------------

/// The refresh token format the mint received.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Format {
    /// `mcr_` + 32 base62: a build before the grant record.
    Legacy,
    /// `mcr_{handle}_{secret}`.
    Current,
}

fn format_of(refresh_token: &str) -> Option<Format> {
    if is_refresh_token(refresh_token) {
        Some(Format::Current)
    } else if is_legacy_refresh_token(refresh_token) {
        Some(Format::Legacy)
    } else {
        None
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct Device {
    device_id: String,
    access_token: String,
    /// When the access token was issued (taken before the request) and its
    /// lifetime.
    access_issued_at: i64,
    access_expires_in: i64,
    refresh_token: String,
    /// `rotated-before-switch`: the refresh token the rotation superseded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    previous_refresh_token: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
struct Session {
    shape: String,
    /// PKCS#8 PEM of the throwaway key: it deactivates the account.
    key_pem: String,
    did: String,
    client_id: String,
    mxid: String,
    devices: Vec<Device>,
}

#[derive(Serialize, Deserialize)]
struct State {
    server: String,
    homeserver: String,
    /// When the mint finished.
    minted_at: i64,
    minted_format: Format,
    sessions: Vec<Session>,
}

fn state_path(dir: &Path) -> PathBuf {
    dir.join(STATE_FILE)
}

/// The marker a deactivated account leaves, so the cleanup knows it is done.
fn marker_path(dir: &Path, shape: &str) -> PathBuf {
    dir.join(format!("deactivated-{shape}"))
}

fn write_private(path: &Path, contents: &[u8]) -> anyhow::Result<()> {
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents)?;
    Ok(())
}

fn read_state(dir: &Path, target: &Target) -> anyhow::Result<State> {
    state_dir(dir, false)?;
    let path = state_path(dir);
    anyhow::ensure!(
        path.exists(),
        "{} does not exist: run the mint first",
        path.display()
    );
    let mode = std::fs::metadata(&path)?.permissions().mode() & 0o777;
    anyhow::ensure!(
        private(mode),
        "{} has mode {mode:o}: it must be 0600",
        path.display()
    );
    let state: State = serde_json::from_slice(&std::fs::read(&path)?)?;
    anyhow::ensure!(
        state.server == target.server && state.homeserver == target.homeserver,
        "the state was minted against another deployment ({} / {})",
        state.server,
        state.homeserver
    );
    Ok(state)
}

impl State {
    fn session(&self, shape: &str) -> anyhow::Result<&Session> {
        self.sessions
            .iter()
            .find(|s| s.shape == shape)
            .ok_or_else(|| anyhow::anyhow!("the state has no {shape} session"))
    }
}

impl Session {
    fn key(&self) -> anyhow::Result<SiwxKey> {
        SiwxKey::from_pem(&self.key_pem)
    }
}

// ---------------------------------------------------------------------------
// Checks
// ---------------------------------------------------------------------------

/// The outcome of every check, printed as it is made, prefixed with the
/// session's shape (the checks run in parallel).
#[derive(Default)]
struct Checks {
    shape: String,
    failed: Vec<String>,
}

impl Checks {
    fn of(shape: &str) -> Self {
        Checks {
            shape: shape.to_string(),
            failed: Vec::new(),
        }
    }
    fn check(&mut self, ok: bool, what: &str, detail: impl std::fmt::Display) {
        if ok {
            eprintln!("ok      [{}] {what}", self.shape);
        } else {
            eprintln!("FAILED  [{}] {what}: {detail}", self.shape);
            self.failed.push(format!("{what}: {detail}"));
        }
    }
    fn note(&self, what: impl std::fmt::Display) {
        eprintln!("        [{}] {what}", self.shape);
    }
}

/// A pair in the current format: `mat_…` and `mcr_{handle}_{secret}`.
fn check_current_pair(checks: &mut Checks, what: &str, pair: &Pair) {
    checks.check(
        is_access_token(&pair.access_token),
        &format!("{what}: the access token is mat_ + 32 base62"),
        shape(&pair.access_token),
    );
    checks.check(
        is_refresh_token(&pair.refresh_token),
        &format!("{what}: the refresh token is in the current format mcr_{{handle}}_{{secret}}"),
        shape(&pair.refresh_token),
    );
}

/// whoami names the minted account and device.
async fn check_whoami(
    checks: &mut Checks,
    target: &Target,
    what: &str,
    access_token: &str,
    mxid: &str,
    device_id: &str,
) {
    match whoami(target, access_token).await {
        Ok(me) => checks.check(
            me.user_id == mxid && me.device_id.as_deref() == Some(device_id),
            &format!("{what}: whoami names the same account and device"),
            format!("{} {:?}", me.user_id, me.device_id),
        ),
        Err(e) => checks.check(false, &format!("{what}: whoami answers"), e),
    }
}

/// Refresh at `/token` (or the Matrix endpoint), check the format and the
/// account, then rotate once more: the chain goes on.
async fn check_refresh_chain(
    checks: &mut Checks,
    target: &Target,
    session: &Session,
    device: &Device,
    at_matrix: bool,
) -> anyhow::Result<Pair> {
    let endpoint = if at_matrix {
        "POST /_matrix/client/v3/refresh"
    } else {
        "POST /token"
    };
    let refresh = |rt: String| async move {
        if at_matrix {
            matrix_refresh(target, &rt).await
        } else {
            token_refresh(target, &session.client_id, &rt).await
        }
    };
    let first = refresh(device.refresh_token.clone())
        .await
        .map_err(|e| anyhow::anyhow!("the minted refresh token refreshes at {endpoint}: {e}"))?;
    checks.check(
        true,
        &format!("the minted refresh token refreshes at {endpoint}"),
        "",
    );
    check_current_pair(checks, "the first refresh", &first);
    check_whoami(
        checks,
        target,
        "the refreshed access token",
        &first.access_token,
        &session.mxid,
        &device.device_id,
    )
    .await;
    let second = refresh(first.refresh_token.clone())
        .await
        .map_err(|e| anyhow::anyhow!("the refreshed token rotates at {endpoint}: {e}"))?;
    check_current_pair(checks, "the second refresh", &second);
    checks.check(
        handle(&first.refresh_token).is_some()
            && handle(&first.refresh_token) == handle(&second.refresh_token),
        "the second refresh keeps the grant's handle",
        format!(
            "{} -> {}",
            shape(&first.refresh_token),
            shape(&second.refresh_token)
        ),
    );
    Ok(second)
}

/// Deactivate the session's account, mark it, and check that its latest
/// refresh token is refused afterwards.
async fn deactivate_session(
    checks: &mut Checks,
    target: &Target,
    dir: &Path,
    session: &Session,
    latest: Option<&str>,
) {
    let key = match session.key() {
        Ok(key) => key,
        Err(e) => {
            checks.check(false, "the session's key is readable", e);
            return;
        }
    };
    match deactivate(target, &key).await {
        Ok(()) => {
            checks.check(true, "the throwaway account is deactivated", "");
            if let Err(e) = write_private(&marker_path(dir, &session.shape), b"deactivated\n") {
                eprintln!("warning: could not write the deactivation marker: {e}");
            }
            if let Some(rt) = latest {
                let after = token_refresh(target, &session.client_id, rt).await;
                checks.check(
                    matches!(&after, Err(Failure::Refused { code, .. }) if code == "invalid_grant"),
                    "after deactivation the latest refresh token is refused",
                    match &after {
                        Ok(_) => "a token pair".to_string(),
                        Err(e) => e.to_string(),
                    },
                );
            }
        }
        Err(e) => checks.check(false, "the throwaway account is deactivated", e),
    }
}

/// Run one check on its session and deactivate the account afterwards,
/// whatever the check found. `body` returns the latest refresh token it holds
/// (to prove the deactivation refuses it) or the error that stopped it.
async fn run_check<F, Fut>(test: &str, shape_name: &str, body: F)
where
    F: FnOnce(Target, Session, State) -> Fut,
    Fut: std::future::Future<Output = (Checks, anyhow::Result<Option<String>>)>,
{
    let Some((target, dir)) = stage(test, "check") else {
        return;
    };
    let state = read_state(&dir, &target).unwrap_or_else(|e| panic!("{test}: {e:#}"));
    let age = now() - state.minted_at;
    let session = state
        .session(shape_name)
        .unwrap_or_else(|e| panic!("{test}: {e:#}"))
        .clone();
    if marker_path(&dir, shape_name).exists() {
        panic!(
            "{test}: the {shape_name} account was already deactivated by an earlier check run; \
             mint again"
        );
    }
    eprintln!(
        "        {shape_name}: minted {age} s ago in the {:?} format, account {}",
        state.minted_format, session.mxid
    );
    let too_old = age > STATE_MAX_AGE_SECS;
    let (mut checks, outcome) = if too_old {
        (Checks::of(shape_name), Ok(None))
    } else {
        body(target.clone(), session.clone(), state).await
    };
    let latest = outcome.as_ref().ok().cloned().flatten();
    deactivate_session(&mut checks, &target, &dir, &session, latest.as_deref()).await;
    if too_old {
        skip_or_fail(
            test,
            &format!("the state is {age} s old, more than {STATE_MAX_AGE_SECS} s: mint again"),
        );
        return;
    }
    if let Err(e) = outcome {
        panic!(
            "{test}: stopped early: {e:#}; failed checks before that: {:?}",
            checks.failed
        );
    }
    assert!(
        checks.failed.is_empty(),
        "{test}: {} check(s) failed: {:#?}",
        checks.failed.len(),
        checks.failed
    );
}

// ---------------------------------------------------------------------------
// Mint
// ---------------------------------------------------------------------------

/// A key and the account it signed into, kept so a failed mint can clean up.
struct Minting {
    key: SiwxKey,
    signed_in: bool,
}

async fn sign_in(
    target: &Target,
    client_id: &str,
    key: &SiwxKey,
    device_id: &str,
) -> anyhow::Result<(Device, AuthTokens)> {
    let issued_at = now();
    let tokens = authenticate_with_device(
        &target.server,
        client_id,
        REDIRECT_URI,
        key,
        Some(device_id),
    )
    .await?;
    let refresh_token = tokens
        .refresh_token
        .clone()
        .ok_or_else(|| anyhow::anyhow!("the code exchange issued no refresh token"))?;
    Ok((
        Device {
            device_id: device_id.to_string(),
            access_token: tokens.access_token.clone(),
            access_issued_at: issued_at,
            access_expires_in: tokens
                .expires_in
                .map_or(ACCESS_TTL_DEFAULT_SECS, |s| s as i64),
            refresh_token,
            previous_refresh_token: None,
        },
        tokens,
    ))
}

/// Sign in a new identity on `devices` (in order) and record the account.
/// The account's MXID comes from whoami with the first device's access token;
/// `whoami_all` also checks every other device (the `access-token` shape
/// keeps its second access token unused).
async fn mint_session(
    target: &Target,
    minting: &mut Vec<Minting>,
    shape_name: &str,
    devices: &[String],
    whoami_all: bool,
) -> anyhow::Result<(Session, String)> {
    let key = SiwxKey::generate_ed25519();
    let did = key.did();
    let key_pem = key.to_pem()?;
    minting.push(Minting {
        key: SiwxKey::from_pem(&key_pem)?,
        signed_in: false,
    });
    let reg = register_public_client(target, CLIENT_NAME).await?;
    let mut minted = Vec::new();
    let mut mxid: Option<String> = None;
    for (i, device_id) in devices.iter().enumerate() {
        let (device, _) = sign_in(target, &reg.client_id, &key, device_id).await?;
        minting.last_mut().unwrap().signed_in = true;
        if i == 0 || whoami_all {
            let me = whoami(target, &device.access_token)
                .await
                .map_err(|e| anyhow::anyhow!("{shape_name}: whoami answered {e}"))?;
            anyhow::ensure!(
                me.device_id.as_deref() == Some(device_id.as_str()),
                "{shape_name}: whoami names device {:?}, not the one signed in",
                me.device_id
            );
            anyhow::ensure!(
                mxid.as_ref().is_none_or(|m| *m == me.user_id),
                "{shape_name}: two devices of one key landed on two accounts"
            );
            mxid = Some(me.user_id);
        }
        minted.push(device);
    }
    let format = minted
        .first()
        .and_then(|d| format_of(&d.refresh_token))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "{shape_name}: the refresh token has an unknown format: {}",
                shape(&minted[0].refresh_token)
            )
        })?;
    eprintln!("ok      minted {shape_name} ({format:?} format)");
    Ok((
        Session {
            shape: shape_name.to_string(),
            key_pem,
            did,
            client_id: reg.client_id,
            mxid: mxid.expect("one device at least"),
            devices: minted,
        },
        reg.registration_access_token,
    ))
}

async fn mint_all(target: &Target, minting: &mut Vec<Minting>) -> anyhow::Result<State> {
    let agent_device = || format!("AQUA_{}", random_upper(12));
    let mut sessions = Vec::new();

    let (agent, _) = mint_session(target, minting, "agent", &[agent_device()], false).await?;
    let minted_format = format_of(&agent.devices[0].refresh_token).expect("checked by the mint");
    sessions.push(agent);

    let (gone, registration_access_token) = mint_session(
        target,
        minting,
        "registration-deleted",
        &[agent_device()],
        false,
    )
    .await?;
    delete_registration(
        target,
        &live::Registration {
            client_id: gone.client_id.clone(),
            registration_access_token,
        },
    )
    .await?;
    eprintln!("ok      the registration-deleted session's client registration is deleted");
    sessions.push(gone);

    let (ex, _) = mint_session(
        target,
        minting,
        "element-x",
        &[element_x_device_id()],
        false,
    )
    .await?;
    sessions.push(ex);

    let (matrix, _) = mint_session(
        target,
        minting,
        "matrix-refresh",
        &[random_upper(10)],
        false,
    )
    .await?;
    sessions.push(matrix);

    // The second device's access token is never presented before the check:
    // the homeserver caches an introspection for two minutes, so a token it
    // had seen would be answered from its cache instead of by the new build.
    let (access, _) = mint_session(
        target,
        minting,
        "access-token",
        &[agent_device(), agent_device()],
        false,
    )
    .await?;
    sessions.push(access);

    let (delete, _) = mint_session(
        target,
        minting,
        "device-delete",
        &[element_x_device_id(), agent_device()],
        true,
    )
    .await?;
    sessions.push(delete);

    let (mut rotated, _) = mint_session(
        target,
        minting,
        "rotated-before-switch",
        &[agent_device()],
        false,
    )
    .await?;

    for s in &sessions {
        for d in &s.devices {
            anyhow::ensure!(
                format_of(&d.refresh_token) == Some(minted_format),
                "{}: one mint received two refresh token formats",
                s.shape
            );
        }
    }

    // Last: the rotation whose response a client could lose at the switch.
    let device = &mut rotated.devices[0];
    let issued_at = now();
    let pair = token_refresh(target, &rotated.client_id, &device.refresh_token)
        .await
        .map_err(|e| anyhow::anyhow!("rotated-before-switch: the rotation answered {e}"))?;
    device.previous_refresh_token = Some(std::mem::replace(
        &mut device.refresh_token,
        pair.refresh_token,
    ));
    device.access_token = pair.access_token;
    device.access_issued_at = issued_at;
    device.access_expires_in = pair
        .expires_in
        .map_or(ACCESS_TTL_DEFAULT_SECS, |s| s as i64);
    eprintln!("ok      rotated-before-switch rotated; its previous refresh token is kept");
    sessions.push(rotated);

    Ok(State {
        server: target.server.clone(),
        homeserver: target.homeserver.clone(),
        minted_at: now(),
        minted_format,
        sessions,
    })
}

/// `mint`: one throwaway account per session shape, written to the state.
#[tokio::test]
#[ignore = "live: QUALIFY_STAGE=mint; creates throwaway accounts on SIWX_SERVER/SIWX_HOMESERVER"]
async fn mint_sessions_in_every_shape() {
    let test = "mint_sessions_in_every_shape";
    let Some((target, dir)) = stage(test, "mint") else {
        return;
    };
    state_dir(&dir, true).unwrap_or_else(|e| panic!("{test}: {e:#}"));
    if state_path(&dir).exists() {
        if let Ok(old) =
            serde_json::from_slice::<State>(&std::fs::read(state_path(&dir)).unwrap_or_default())
        {
            let active: Vec<&str> = old
                .sessions
                .iter()
                .filter(|s| !marker_path(&dir, &s.shape).exists())
                .map(|s| s.shape.as_str())
                .collect();
            assert!(
                active.is_empty(),
                "{test}: the state of an earlier mint still has active accounts {active:?}: \
                 run QUALIFY_STAGE=cleanup against {} first",
                old.server
            );
        }
    }
    for entry in std::fs::read_dir(&dir).unwrap().flatten() {
        if entry
            .file_name()
            .to_string_lossy()
            .starts_with("deactivated-")
        {
            std::fs::remove_file(entry.path()).ok();
        }
    }

    let mut minting = Vec::new();
    match mint_all(&target, &mut minting).await {
        Ok(state) => {
            write_private(
                &state_path(&dir),
                &serde_json::to_vec_pretty(&state).unwrap(),
            )
            .unwrap_or_else(|e| panic!("{test}: writing the state: {e:#}"));
            eprintln!(
                "ok      {} sessions minted in the {:?} format; switch the server and run \
                 QUALIFY_STAGE=check",
                state.sessions.len(),
                state.minted_format
            );
        }
        Err(e) => {
            for m in minting.iter().filter(|m| m.signed_in) {
                match deactivate(&target, &m.key).await {
                    Ok(()) => {
                        eprintln!("ok      deactivated {} after the failed mint", m.key.did())
                    }
                    Err(d) => eprintln!(
                        "FAILED  could not deactivate {} after the failed mint: {d:#}",
                        m.key.did()
                    ),
                }
            }
            panic!("{test}: {e:#}");
        }
    }
}

// ---------------------------------------------------------------------------
// Check
// ---------------------------------------------------------------------------

/// An agent's legacy refresh token refreshes at `POST /token` into the current
/// format, for the same account and device, and the chain goes on.
#[tokio::test]
#[ignore = "live: QUALIFY_STAGE=check; deactivates the account it checks"]
async fn check_agent_session_refreshes_into_the_current_format() {
    run_check(
        "check_agent_session_refreshes_into_the_current_format",
        "agent",
        |target, session, _| async move {
            let mut checks = Checks::of(&session.shape);
            let device = session.devices[0].clone();
            let outcome = check_refresh_chain(&mut checks, &target, &session, &device, false)
                .await
                .map(|pair| Some(pair.refresh_token));
            (checks, outcome)
        },
    )
    .await;
}

/// The same for an agent whose client registration is gone (R2: most refresh
/// tokens a deployment holds outlive their registration).
#[tokio::test]
#[ignore = "live: QUALIFY_STAGE=check; deactivates the account it checks"]
async fn check_session_whose_registration_was_deleted_refreshes_into_the_current_format() {
    run_check(
        "check_session_whose_registration_was_deleted_refreshes_into_the_current_format",
        "registration-deleted",
        |target, session, _| async move {
            let mut checks = Checks::of(&session.shape);
            let device = session.devices[0].clone();
            let outcome = check_refresh_chain(&mut checks, &target, &session, &device, false)
                .await
                .map(|pair| Some(pair.refresh_token));
            (checks, outcome)
        },
    )
    .await;
}

/// An Element X device id (43 characters with `/` and `+`) refreshes into the
/// current format and whoami names exactly that device (R3).
#[tokio::test]
#[ignore = "live: QUALIFY_STAGE=check; deactivates the account it checks"]
async fn check_element_x_device_refreshes_and_keeps_its_device_id() {
    run_check(
        "check_element_x_device_refreshes_and_keeps_its_device_id",
        "element-x",
        |target, session, _| async move {
            let mut checks = Checks::of(&session.shape);
            let device = session.devices[0].clone();
            let outcome = check_refresh_chain(&mut checks, &target, &session, &device, false)
                .await
                .map(|pair| Some(pair.refresh_token));
            (checks, outcome)
        },
    )
    .await;
}

/// A refresh token refreshes at `POST /_matrix/client/v3/refresh` on the
/// homeserver (routed to the provider by the edge) into the current format.
#[tokio::test]
#[ignore = "live: QUALIFY_STAGE=check; deactivates the account it checks"]
async fn check_matrix_refresh_endpoint_refreshes_into_the_current_format() {
    run_check(
        "check_matrix_refresh_endpoint_refreshes_into_the_current_format",
        "matrix-refresh",
        |target, session, _| async move {
            let mut checks = Checks::of(&session.shape);
            let device = session.devices[0].clone();
            let outcome = check_refresh_chain(&mut checks, &target, &session, &device, true)
                .await
                .map(|pair| Some(pair.refresh_token));
            (checks, outcome)
        },
    )
    .await;
}

/// An access token minted before the switch and never presented is still
/// accepted after it, for the same account and device, while it lives (300 s).
/// Later than that the check cannot judge: a skip, a failure under
/// `E2E_STRICT_SKIPS`.
#[tokio::test]
#[ignore = "live: QUALIFY_STAGE=check; deactivates the account it checks"]
async fn check_access_token_minted_before_the_switch_is_still_accepted() {
    let test = "check_access_token_minted_before_the_switch_is_still_accepted";
    let mut too_late = None;
    run_check(test, "access-token", |target, session, _| {
        let too_late = &mut too_late;
        async move {
            let mut checks = Checks::of(&session.shape);
            let device = session.devices[1].clone();
            let left = device.access_issued_at + device.access_expires_in - now();
            if left < ACCESS_MARGIN_SECS {
                *too_late = Some(format!(
                    "the access token was issued {} s ago and has {left} s left of its {} s: \
                     run the check within {} s of the mint",
                    now() - device.access_issued_at,
                    device.access_expires_in,
                    device.access_expires_in - ACCESS_MARGIN_SECS
                ));
                return (checks, Ok(Some(device.refresh_token)));
            }
            checks.note(format!("the access token has {left} s left"));
            check_whoami(
                &mut checks,
                &target,
                "the access token minted before the switch",
                &device.access_token,
                &session.mxid,
                &device.device_id,
            )
            .await;
            (checks, Ok(Some(device.refresh_token)))
        }
    })
    .await;
    if let Some(why) = too_late {
        skip_or_fail(test, &why);
    }
}

/// `GET /_matrix/client/v3/devices` with `access_token`: the device ids.
async fn list_devices(target: &Target, access_token: &str) -> Result<Vec<String>, Failure> {
    let body = live::classify(
        live::http()
            .get(format!("{}/_matrix/client/v3/devices", target.homeserver))
            .bearer_auth(access_token)
            .send()
            .await,
    )
    .await?;
    Ok(body
        .get("devices")
        .and_then(|d| d.as_array())
        .map(|devices| {
            devices
                .iter()
                .filter_map(|d| d.get("device_id")?.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default())
}

/// `DELETE /_matrix/client/v3/devices/{id}` on the homeserver (or on
/// `SIWX_DEVICE_DELETE_BASE`) from the account's other device removes the
/// Element X shaped device: Synapse no longer lists it, its refresh token is
/// refused, and the other device keeps working.
#[tokio::test]
#[ignore = "live: QUALIFY_STAGE=check; deactivates the account it checks"]
async fn check_device_deletion_through_the_homeserver_removes_the_device() {
    run_check(
        "check_device_deletion_through_the_homeserver_removes_the_device",
        "device-delete",
        |target, session, _| async move {
            let mut checks = Checks::of(&session.shape);
            let outcome = async {
                let (doomed, own) = (&session.devices[0], &session.devices[1]);
                let doomed_pair = token_refresh(&target, &session.client_id, &doomed.refresh_token)
                    .await
                    .map_err(|e| anyhow::anyhow!("the Element X device refreshes: {e}"))?;
                check_current_pair(&mut checks, "the Element X device's refresh", &doomed_pair);
                let own_pair = token_refresh(&target, &session.client_id, &own.refresh_token)
                    .await
                    .map_err(|e| anyhow::anyhow!("the other device refreshes: {e}"))?;
                check_current_pair(&mut checks, "the other device's refresh", &own_pair);

                let base =
                    env_url("SIWX_DEVICE_DELETE_BASE").unwrap_or_else(|| target.homeserver.clone());
                checks.note(format!(
                    "DELETE /_matrix/client/v3/devices/{{id}} goes to {base}"
                ));
                let encoded = urlencoding::encode(&doomed.device_id);
                let deleted = live::classify(
                    live::http()
                        .delete(format!("{base}/_matrix/client/v3/devices/{encoded}"))
                        .bearer_auth(&own_pair.access_token)
                        .json(&serde_json::json!({}))
                        .send()
                        .await,
                )
                .await;
                checks.check(
                    deleted.is_ok(),
                    "DELETE /devices/{id} answers 200 with no user-interactive authentication",
                    match &deleted {
                        Err(Failure::Refused { status: 404, code }) if code == "M_UNRECOGNIZED" => {
                            "404 M_UNRECOGNIZED: Synapse answered, so the edge does not route \
                             this request to siwx-oidc (set SIWX_DEVICE_DELETE_BASE to test \
                             siwx-oidc alone)"
                                .to_string()
                        }
                        Err(Failure::Refused { status: 401, code }) if code.is_empty() => {
                            "401 with flows: Synapse asked for user-interactive authentication, \
                             so the edge does not route this request to siwx-oidc"
                                .to_string()
                        }
                        Err(e) => e.to_string(),
                        Ok(_) => String::new(),
                    },
                );
                match list_devices(&target, &own_pair.access_token).await {
                    Ok(ids) => {
                        checks.check(
                            !ids.contains(&doomed.device_id),
                            "the homeserver no longer lists the deleted device",
                            format!("{} device(s) listed, the deleted one among them", ids.len()),
                        );
                        checks.check(
                            ids.contains(&own.device_id),
                            "the homeserver still lists the other device",
                            format!("{} device(s) listed", ids.len()),
                        );
                    }
                    Err(e) => checks.check(false, "GET /devices answers", e),
                }
                let after =
                    token_refresh(&target, &session.client_id, &doomed_pair.refresh_token).await;
                checks.check(
                    matches!(&after, Err(Failure::Refused { code, .. }) if code == "invalid_grant"),
                    "the deleted device's refresh token is refused",
                    match &after {
                        Ok(_) => "a token pair".to_string(),
                        Err(e) => e.to_string(),
                    },
                );
                let own_next =
                    token_refresh(&target, &session.client_id, &own_pair.refresh_token).await;
                checks.check(
                    own_next.is_ok(),
                    "the other device still refreshes",
                    own_next
                        .as_ref()
                        .err()
                        .map(|e| e.to_string())
                        .unwrap_or_default(),
                );
                Ok(own_next.ok().map(|p| p.refresh_token))
            }
            .await;
            (checks, outcome)
        },
    )
    .await;
}

/// A client that lost the response of the rotation just before the switch and
/// presents its previous refresh token after it. Across the switch from a
/// build before the grant record (a legacy mint) the previous build's grace
/// pointer is not read: the token is refused and the client signs in again,
/// to the same account and device (the documented outcome). Without such a
/// switch (a current-format mint) the token is a lost response and gets the
/// same successor pair back (I4).
#[tokio::test]
#[ignore = "live: QUALIFY_STAGE=check; deactivates the account it checks"]
async fn check_refresh_response_lost_before_the_switch_has_the_documented_outcome() {
    run_check(
        "check_refresh_response_lost_before_the_switch_has_the_documented_outcome",
        "rotated-before-switch",
        |target, session, state| async move {
            let mut checks = Checks::of(&session.shape);
            let device = session.devices[0].clone();
            let previous = device
                .previous_refresh_token
                .clone()
                .expect("the mint keeps the previous refresh token");
            checks.note(format!(
                "the rotation ran {} s before this check",
                now() - state.minted_at
            ));
            let replay = token_refresh(&target, &session.client_id, &previous).await;
            let outcome = match state.minted_format {
                Format::Legacy => {
                    checks.check(
                        matches!(&replay, Err(Failure::Refused { code, .. }) if code == "invalid_grant"),
                        "the previous build's superseded refresh token is refused after the switch",
                        match &replay {
                            Ok(_) => "a token pair: the grace of the previous build still \
                                      applies (no switch, or within its 60 s)"
                                .to_string(),
                            Err(e) => e.to_string(),
                        },
                    );
                    match session.key() {
                        Ok(key) => match sign_in(
                            &target,
                            &session.client_id,
                            &key,
                            &device.device_id,
                        )
                        .await
                        {
                            Ok((again, _)) => {
                                checks.check(
                                    is_refresh_token(&again.refresh_token),
                                    "the sign-in again issues a current-format refresh token",
                                    shape(&again.refresh_token),
                                );
                                check_whoami(
                                    &mut checks,
                                    &target,
                                    "the sign-in again",
                                    &again.access_token,
                                    &session.mxid,
                                    &device.device_id,
                                )
                                .await;
                                Ok(Some(again.refresh_token))
                            }
                            Err(e) => Err(anyhow::anyhow!("the client signs in again: {e:#}")),
                        },
                        Err(e) => Err(e),
                    }
                }
                Format::Current => {
                    checks.check(
                        matches!(&replay, Ok(pair)
                            if pair.refresh_token == device.refresh_token
                                && pair.access_token == device.access_token),
                        "with no switch across the grant record, the lost response is \
                         answered with the same successor pair",
                        match &replay {
                            Ok(_) => "a different pair".to_string(),
                            Err(e) => e.to_string(),
                        },
                    );
                    Ok(Some(device.refresh_token.clone()))
                }
            };
            (checks, outcome)
        },
    )
    .await;
}

// ---------------------------------------------------------------------------
// Cleanup
// ---------------------------------------------------------------------------

/// `cleanup`: every account the mint created is deactivated (here, if no
/// check did it) and refuses a new sign-in; then the state is removed.
#[tokio::test]
#[ignore = "live: QUALIFY_STAGE=cleanup; deactivates every account the mint created"]
async fn cleanup_every_account_is_deactivated_and_refuses_sign_in() {
    let test = "cleanup_every_account_is_deactivated_and_refuses_sign_in";
    let Some((target, dir)) = stage(test, "cleanup") else {
        return;
    };
    let state = read_state(&dir, &target).unwrap_or_else(|e| panic!("{test}: {e:#}"));
    let mut checks = Checks::of("cleanup");
    for session in &state.sessions {
        let key = match session.key() {
            Ok(key) => key,
            Err(e) => {
                checks.check(false, &format!("{}: the key is readable", session.shape), e);
                continue;
            }
        };
        if !marker_path(&dir, &session.shape).exists() {
            match deactivate(&target, &key).await {
                Ok(()) => {
                    eprintln!("ok      {}: deactivated by the cleanup", session.shape);
                    write_private(&marker_path(&dir, &session.shape), b"deactivated\n").ok();
                }
                Err(e) => {
                    checks.check(false, &format!("{}: deactivated", session.shape), e);
                    continue;
                }
            }
        }
        let refused = match register_public_client(&target, CLIENT_NAME).await {
            Ok(reg) => authenticate_with_device(
                &target.server,
                &reg.client_id,
                REDIRECT_URI,
                &key,
                Some(&session.devices[0].device_id),
            )
            .await
            .is_err(),
            Err(e) => {
                checks.check(false, "a client registers for the sign-in probe", e);
                continue;
            }
        };
        checks.check(
            refused,
            &format!(
                "{}: the deactivated account refuses a new sign-in",
                session.shape
            ),
            "the sign-in succeeded",
        );
    }
    assert!(
        checks.failed.is_empty(),
        "{test}: {} check(s) failed, the state is kept: {:#?}",
        checks.failed.len(),
        checks.failed
    );
    for session in &state.sessions {
        std::fs::remove_file(marker_path(&dir, &session.shape)).ok();
    }
    std::fs::remove_file(state_path(&dir)).unwrap();
    eprintln!(
        "ok      all {} accounts are deactivated; the state is removed",
        state.sessions.len()
    );
}

// ---------------------------------------------------------------------------
// Pure checks of the helpers (run in every `cargo test`)
// ---------------------------------------------------------------------------

#[test]
fn the_element_x_device_id_has_the_shape_element_x_mints() {
    for _ in 0..50 {
        let id = element_x_device_id();
        assert_eq!(id.len(), 43, "{id}");
        assert!(id.contains('/') && id.contains('+'), "{id}");
        assert!(
            id.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'/' || b == b'+'),
            "{id}"
        );
    }
}

#[test]
fn the_refresh_token_formats_are_told_apart() {
    let legacy = format!("mcr_{}", "a".repeat(32));
    let current = format!("mcr_{}_{}", "b".repeat(22), "c".repeat(32));
    assert_eq!(format_of(&legacy), Some(Format::Legacy));
    assert_eq!(format_of(&current), Some(Format::Current));
    assert_eq!(format_of("mcr_short"), None);
    assert_eq!(format_of(&format!("mat_{}", "a".repeat(32))), None);
    assert_eq!(handle(&current), Some("b".repeat(22).as_str()));
}

#[test]
fn a_state_directory_others_may_read_is_refused() {
    assert!(private(0o700));
    assert!(private(0o600));
    for open in [0o750, 0o705, 0o755, 0o777, 0o640, 0o604] {
        assert!(!private(open), "{open:o}");
    }
}
