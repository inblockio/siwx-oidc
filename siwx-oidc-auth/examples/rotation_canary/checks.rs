//! `check`: the six checks, in order, and the summary.
//!
//! | # | check | name |
//! |---|---|---|
//! | C1 | discovery | `discovery` |
//! | C2 | jwks | `jwks` |
//! | C3 | sign-in | `sign_in` |
//! | C4 | whoami | `whoami` |
//! | C5 | did proof | `did_proof` |
//! | C6 | logout | `logout` |
//!
//! A check that cannot run is recorded as skipped with the reason, so six
//! outcomes are always printed and the summary can say what ran.

use std::collections::BTreeSet;
use std::path::Path;
use std::time::Duration;

use siwx_oidc_auth::{verify_did_assertion, SiwxKey, DID_PROFILE_FIELD};

use crate::cli::{CheckConfig, Matrix};
use crate::flow::{self, Probe, Tokens, RETRY_PAUSE};
use crate::hygiene::{self, Secret};
use crate::identity::{self, ClientRecord};
use crate::jose::{
    check_times, header_kid, issuers_match, judge_jwks, parse_jwks, verify_id_token, Expect,
    JwkEntry,
};
use crate::net::send;
use crate::report::{self, Outcome, Reason, Verdict};

/// The stated clock skew: an ID token's `iat` may differ from the server's
/// `Date` by this many seconds. Printed with the measured skew.
pub const MAX_SKEW_SECS: i64 = 30;
/// A server being recreated answers 502 to 504 for a while.
const DISCOVERY_PATIENCE: Duration = Duration::from_secs(60);
/// A second run of the environment waits this long for the first.
const LOCK_WAIT: Duration = Duration::from_secs(120);

type Fields = Vec<(&'static str, String)>;

#[derive(Default)]
struct Run {
    outcomes: Vec<Outcome>,
}

impl Run {
    fn record(&mut self, check: &'static str, verdict: Verdict, reason: Reason, fields: Fields) {
        report::emit(check, verdict, reason, &fields);
        self.outcomes.push(Outcome {
            check,
            verdict,
            reason,
        });
    }

    fn ok(&mut self, check: &'static str, fields: Fields) {
        self.record(check, Verdict::Ok, Reason::Ok, fields);
    }

    fn fail(&mut self, check: &'static str, reason: Reason, fields: Fields) {
        self.record(check, Verdict::Fail, reason, fields);
    }

    fn skip(&mut self, check: &'static str, reason: Reason, fields: Fields) {
        self.record(check, Verdict::Skip, reason, fields);
    }
}

fn list(items: &[String]) -> String {
    items.join(",")
}

/// A refusal before any check ran: one line, no summary.
fn refuse(check: &str, reason: Reason, code: i32) -> i32 {
    report::emit(check, Verdict::Fail, reason, &[]);
    code
}

struct Discovery {
    jwks_uri: String,
}

struct Session {
    tokens: Tokens,
    /// The server's `Date` at this run's `/authorize` response.
    server_date: Option<i64>,
}

struct WhoAmI {
    mxid: String,
    device: Option<String>,
}

struct Cx {
    http: reqwest::Client,
    cfg: CheckConfig,
    dir: std::path::PathBuf,
    key: SiwxKey,
    record: ClientRecord,
    jwks: Option<Vec<JwkEntry>>,
}

pub async fn run(cfg: CheckConfig, root: &Path) -> i32 {
    let dir = match identity::existing_dir(root, &cfg.env) {
        Ok(dir) => dir,
        Err(reason) => return refuse("identity", reason, 2),
    };
    let _lock = match identity::acquire_lock(&dir, LOCK_WAIT).await {
        Ok(lock) => lock,
        Err(reason) => return refuse("lock", reason, 1),
    };
    let key = match identity::load_key(&dir) {
        Ok(key) => key,
        Err(reason) => return refuse("identity", reason, 2),
    };
    let record = match identity::read_client(&dir) {
        Ok(record) => record,
        Err(reason) => return refuse("identity", reason, 2),
    };
    if !issuers_match(&record.issuer, &cfg.issuer) {
        return refuse("identity", Reason::StoredIssuerDiffers, 2);
    }
    let http = match flow::http() {
        Ok(http) => http,
        Err(reason) => return refuse("client", reason, 1),
    };
    let mut cx = Cx {
        http,
        cfg,
        dir,
        key,
        record,
        jwks: None,
    };
    let mut run = Run::default();

    let discovery = cx.discovery(&mut run).await;
    cx.jwks(&mut run, discovery).await;
    let session = cx.sign_in(&mut run).await;
    match (session, cx.cfg.matrix.clone()) {
        (None, _) => {
            for check in ["whoami", "did_proof", "logout"] {
                run.skip(check, Reason::NoSignIn, vec![]);
            }
        }
        (Some(session), None) => {
            run.skip("whoami", Reason::NoMatrix, vec![]);
            run.skip("did_proof", Reason::NoMatrix, vec![]);
            // No Matrix side to log out of: still leave no live grant.
            let revoked = flow::revoke_quietly(&cx.http, &cx.cfg.issuer, &session.tokens).await;
            run.skip(
                "logout",
                Reason::NoMatrix,
                vec![("revoked", if revoked { "yes" } else { "no" }.to_string())],
            );
        }
        (Some(session), Some(matrix)) => {
            let me = cx.whoami(&mut run, &session, &matrix).await;
            cx.did_proof(&mut run, &session, &matrix, me.as_ref()).await;
            cx.logout(&mut run, &session, &matrix, me.as_ref()).await;
        }
    }

    let summary = report::summarize(&run.outcomes, &cx.cfg.env, hygiene::taint_tripped());
    hygiene::print_line(report::render_summary(&summary), "summary");
    report::exit_code(&run.outcomes, &summary)
}

fn same_origin(a: &str, b: &str) -> bool {
    match (url::Url::parse(a), url::Url::parse(b)) {
        (Ok(a), Ok(b)) => a.origin() == b.origin() && a.origin().is_tuple(),
        _ => false,
    }
}

impl Cx {
    /// C1: 200 (502 to 504 and no answer retried for up to a minute: the
    /// server may be recreating); `issuer` equals `--issuer` after trimming one
    /// trailing slash; `jwks_uri` on the issuer's origin.
    async fn discovery(&self, run: &mut Run) -> Option<Discovery> {
        const CHECK: &str = "discovery";
        let url = format!("{}/.well-known/openid-configuration", self.cfg.issuer);
        let deadline = tokio::time::Instant::now() + DISCOVERY_PATIENCE;
        let mut attempts = 0u32;
        let result = loop {
            attempts += 1;
            let result = send(self.http.get(&url)).await;
            let retry = match &result {
                Ok(reply) => reply.is_unavailable(),
                Err(_) => true,
            };
            if !retry || tokio::time::Instant::now() + RETRY_PAUSE > deadline {
                break result;
            }
            tokio::time::sleep(RETRY_PAUSE).await;
        };
        let attempts_field = ("attempts", attempts.to_string());
        let reply = match result {
            Ok(reply) => reply,
            Err(_) => {
                run.fail(CHECK, Reason::DiscoveryUnreachable, vec![attempts_field]);
                return None;
            }
        };
        if reply.status != 200 {
            run.fail(
                CHECK,
                Reason::DiscoveryStatus,
                vec![("status", reply.status.to_string()), attempts_field],
            );
            return None;
        }
        let (Some(issuer), Some(jwks_uri)) =
            (reply.str_field("issuer"), reply.str_field("jwks_uri"))
        else {
            run.fail(CHECK, Reason::DiscoveryMalformed, vec![attempts_field]);
            return None;
        };
        if !issuers_match(issuer, &self.cfg.issuer) {
            run.fail(
                CHECK,
                Reason::IssuerMismatch,
                vec![
                    ("got_issuer", issuer.to_string()),
                    ("want_issuer", self.cfg.issuer.clone()),
                ],
            );
            return None;
        }
        if !same_origin(jwks_uri, &self.cfg.issuer) {
            run.fail(CHECK, Reason::JwksOrigin, vec![attempts_field]);
            return None;
        }
        run.ok(
            CHECK,
            vec![
                ("issuer", self.cfg.issuer.clone()),
                ("status", "200".to_string()),
                attempts_field,
                ("jwks_origin", "same".to_string()),
            ],
        );
        Some(Discovery {
            jwks_uri: jwks_uri.to_string(),
        })
    }

    /// C2: the kid set equals `--expect-kids` exactly, no `--dropped-kids`
    /// member is published, and every kid is the one derived from its own key.
    async fn jwks(&mut self, run: &mut Run, discovery: Option<Discovery>) {
        const CHECK: &str = "jwks";
        let Some(discovery) = discovery else {
            run.skip(CHECK, Reason::BlockedByDiscovery, vec![]);
            return;
        };
        let reply = match send(self.http.get(&discovery.jwks_uri)).await {
            Ok(reply) => reply,
            Err(_) => return run.fail(CHECK, Reason::JwksUnreachable, vec![]),
        };
        if reply.status != 200 {
            return run.fail(
                CHECK,
                Reason::JwksStatus,
                vec![("status", reply.status.to_string())],
            );
        }
        let Some(entries) = reply.json.as_ref().and_then(parse_jwks) else {
            return run.fail(CHECK, Reason::JwksMalformed, vec![]);
        };
        let verdict = judge_jwks(&entries, &self.cfg.expect, &self.cfg.dropped);
        let fields = vec![
            (
                "kids",
                list(&entries.iter().map(|e| e.kid.clone()).collect::<Vec<_>>()),
            ),
            ("count", entries.len().to_string()),
            ("missing", list(&verdict.missing)),
            ("extra", list(&verdict.extra)),
            ("dropped_present", list(&verdict.dropped_present)),
            ("not_derived", list(&verdict.not_derived)),
        ];
        self.jwks = Some(entries);
        match verdict.reason() {
            Reason::Ok => run.ok(CHECK, fields),
            reason => run.fail(CHECK, reason, fields),
        }
    }

    /// C3: the stored key and client, a PKCE sign-in, and the ID token judged
    /// by hand-written ES256 code against the `/jwk` entry of its header kid.
    /// Tokens obtained are handed on even when their verification failed: C6
    /// must still end the session.
    async fn sign_in(&mut self, run: &mut Run) -> Option<Session> {
        const CHECK: &str = "sign_in";
        let issuer = self.cfg.issuer.clone();
        let mut client = "reused";
        let mut probe = flow::probe_authorize(&self.http, &issuer, &self.record.client_id).await;
        if probe == Probe::ClientRefused && self.cfg.baseline {
            // The run before a rotation is the one that may replace a client
            // the server forgot (a dynamic client expires). After a rotation
            // the baseline's client must still work: that is what a client's
            // stored registration (Element's) would see.
            match flow::register_client(&self.http, &issuer).await {
                Ok(client_id) => {
                    self.record.client_id = client_id;
                    if identity::write_client(&self.dir, &self.record).is_err() {
                        run.fail(
                            CHECK,
                            Reason::IdentityWriteFailed,
                            vec![("client", "registered".to_string())],
                        );
                        return None;
                    }
                    client = "registered";
                    probe =
                        flow::probe_authorize(&self.http, &issuer, &self.record.client_id).await;
                }
                Err(reason) => {
                    run.fail(CHECK, reason, vec![("client", "refused".to_string())]);
                    return None;
                }
            }
        }
        let server_date = match probe {
            Probe::Valid { date } => date,
            Probe::ClientRefused => {
                run.fail(
                    CHECK,
                    Reason::ClientRefused,
                    vec![("client", "refused".to_string())],
                );
                return None;
            }
            Probe::Unavailable => {
                run.fail(
                    CHECK,
                    Reason::SignInUnavailable,
                    vec![("client", client.to_string())],
                );
                return None;
            }
            Probe::Unexpected => {
                run.fail(
                    CHECK,
                    Reason::AuthorizeUnexpected,
                    vec![("client", client.to_string())],
                );
                return None;
            }
        };
        // Seconds on this host's monotonic clock since the server's `Date`.
        let since_probe = std::time::Instant::now();
        let tokens =
            match flow::sign_in(&self.http, &issuer, &self.record.client_id, &self.key).await {
                Ok(tokens) => tokens,
                Err(reason) => {
                    run.fail(CHECK, reason, vec![("client", client.to_string())]);
                    return None;
                }
            };
        let elapsed = since_probe.elapsed().as_secs() as i64 + 1;
        let did = self.key.did();
        let verified = (|| {
            let jwks = self.jwks.as_ref().ok_or(Reason::JwksUnavailable)?;
            let id_token = tokens.id_token.as_ref().ok_or(Reason::IdTokenMissing)?;
            let facts = verify_id_token(
                id_token.expose(),
                jwks,
                &Expect {
                    live_kid: &self.cfg.live_kid,
                    issuer: &issuer,
                    client_id: &self.record.client_id,
                    did: &did,
                },
            )?;
            let date = server_date.ok_or(Reason::ServerDateMissing)?;
            let skew = check_times(facts.iat, facts.exp, date, elapsed, MAX_SKEW_SECS)?;
            Ok::<_, Reason>((facts, skew))
        })();
        match verified {
            Ok((facts, skew)) => run.ok(
                CHECK,
                vec![
                    ("client", client.to_string()),
                    ("alg", "ES256".to_string()),
                    ("kid", facts.kid),
                    ("sig", "verified".to_string()),
                    ("skew", skew.to_string()),
                    ("max_skew", MAX_SKEW_SECS.to_string()),
                    ("lifetime", (facts.exp - facts.iat).to_string()),
                ],
            ),
            Err(reason) => {
                let got_kid = tokens
                    .id_token
                    .as_ref()
                    .and_then(|t| header_kid(t.expose()))
                    .unwrap_or_default();
                run.fail(
                    CHECK,
                    reason,
                    vec![
                        ("client", client.to_string()),
                        ("got_kid", got_kid),
                        ("want_kid", self.cfg.live_kid.clone()),
                    ],
                );
            }
        }
        Some(Session {
            tokens,
            server_date,
        })
    }

    /// C4: the access token works at the homeserver and names a user on `--server-name`.
    async fn whoami(&self, run: &mut Run, session: &Session, matrix: &Matrix) -> Option<WhoAmI> {
        const CHECK: &str = "whoami";
        let reply = send(
            self.http
                .get(format!(
                    "{}/_matrix/client/v3/account/whoami",
                    matrix.homeserver
                ))
                .bearer_auth(session.tokens.access.expose()),
        )
        .await;
        let reply = match reply {
            Ok(reply) => reply,
            Err(_) => {
                run.fail(CHECK, Reason::WhoamiUnreachable, vec![]);
                return None;
            }
        };
        if reply.status != 200 {
            run.fail(
                CHECK,
                Reason::WhoamiStatus,
                vec![("status", reply.status.to_string())],
            );
            return None;
        }
        let Some(mxid) = reply.str_field("user_id").map(str::to_string) else {
            run.fail(CHECK, Reason::WhoamiMalformed, vec![]);
            return None;
        };
        let device = reply.str_field("device_id").map(str::to_string);
        let on_server =
            mxid.starts_with('@') && mxid.ends_with(&format!(":{}", matrix.server_name));
        let fields = vec![
            ("mxid", mxid.clone()),
            ("device", device.clone().unwrap_or_default()),
        ];
        // The device is on the ledger from the moment it is known: if this run
        // dies before its logout, the next run's tripwire knows it for ours.
        if let Some(device) = &device {
            let mut pending = identity::read_pending(&self.dir);
            if pending.insert(device.clone()) {
                let _ = identity::write_pending(&self.dir, &pending);
            }
        }
        if on_server {
            run.ok(CHECK, fields);
        } else {
            run.fail(CHECK, Reason::ServerNameMismatch, fields);
        }
        Some(WhoAmI { mxid, device })
    }

    /// C5: the DID proof on the account's profile, fetched once; its header kid
    /// is the live kid; `verify_did_assertion` verifies that same proof; it is
    /// the key's DID; and it is not older than this run's `/authorize` answer
    /// (the proof is minted at every sign-in).
    async fn did_proof(
        &self,
        run: &mut Run,
        session: &Session,
        matrix: &Matrix,
        me: Option<&WhoAmI>,
    ) {
        const CHECK: &str = "did_proof";
        let Some(me) = me else {
            return run.skip(CHECK, Reason::BlockedByWhoami, vec![]);
        };
        let url = format!(
            "{}/_matrix/client/v3/profile/{}/{}",
            matrix.homeserver,
            urlencoding::encode(&me.mxid),
            DID_PROFILE_FIELD
        );
        let reply = match send(self.http.get(url)).await {
            Ok(reply) => reply,
            Err(_) => return run.fail(CHECK, Reason::ProfileUnreachable, vec![]),
        };
        if reply.status == 404 {
            return run.fail(CHECK, Reason::DidFieldAbsent, vec![]);
        }
        if reply.status != 200 {
            return run.fail(
                CHECK,
                Reason::ProfileStatus,
                vec![("status", reply.status.to_string())],
            );
        }
        let field = reply.json.as_ref().and_then(|j| j.get(DID_PROFILE_FIELD));
        let Some(field) = field.filter(|f| !f.is_null()) else {
            return run.fail(CHECK, Reason::DidFieldAbsent, vec![]);
        };
        // A bare string is the legacy shape: it carries no proof.
        let Some(proof) = field
            .get("proof")
            .and_then(|p| p.as_str())
            .filter(|p| !p.is_empty())
            .map(|p| Secret::new(p.to_string()))
        else {
            return run.fail(CHECK, Reason::DidProofAbsent, vec![]);
        };
        let proof_kid = header_kid(proof.expose()).unwrap_or_default();
        let verified = verify_did_assertion(&self.cfg.issuer, proof.expose(), &me.mxid).await;
        let (reason, age, verify) = match &verified {
            _ if proof_kid != self.cfg.live_kid => (Reason::DidKidMismatch, None, verified.is_ok()),
            Err(_) => (Reason::DidProofInvalid, None, false),
            Ok(v) if v.did() != self.key.did() => (Reason::DidSubMismatch, None, true),
            Ok(v) => {
                let age = session.server_date.map(|since| v.issued_at() - since);
                match age {
                    Some(age) if age < 0 => (Reason::DidProofStale, Some(age), true),
                    None => (Reason::ServerDateMissing, None, true),
                    Some(age) => (Reason::Ok, Some(age), true),
                }
            }
        };
        let fields = vec![
            ("kid", proof_kid),
            ("want_kid", self.cfg.live_kid.clone()),
            ("verify", if verify { "ok" } else { "failed" }.to_string()),
            (
                "iat_after_authorize",
                age.map(|a| a.to_string()).unwrap_or_default(),
            ),
        ];
        match reason {
            Reason::Ok => run.ok(CHECK, fields),
            reason => run.fail(CHECK, reason, fields),
        }
    }

    /// C6: the tripwire (the account has no rooms and no device but this
    /// run's, leftovers of earlier runs of the canary excepted), then the logout
    /// by the recorded route, passing only when this run's refresh token is then
    /// refused. Always attempted once C3 signed in.
    async fn logout(&self, run: &mut Run, session: &Session, matrix: &Matrix, me: Option<&WhoAmI>) {
        const CHECK: &str = "logout";
        let own_device = me.and_then(|m| m.device.as_deref());
        let pending = identity::read_pending(&self.dir);
        let reading =
            flow::read_account(&self.http, &matrix.homeserver, &session.tokens.access).await;
        let judged = reading
            .as_ref()
            .map(|r| flow::judge(r, own_device, &pending));
        // Forget the canary's own leftovers, but never touch anything while the
        // tripwire is fired: the evidence stays.
        let mut cleaned = BTreeSet::new();
        if let Some(judged) = judged.as_ref().filter(|j| !j.fired) {
            for id in &judged.leftovers {
                if flow::delete_device(&self.http, &matrix.homeserver, &session.tokens.access, id)
                    .await
                {
                    cleaned.insert(id.clone());
                }
            }
        }
        // The session is ended whatever the tripwire says: it is this run's.
        let report = flow::logout_and_prove(
            &self.http,
            &self.cfg.issuer,
            Some(&matrix.homeserver),
            self.record.logout_route,
            &self.record.client_id,
            &session.tokens,
        )
        .await;
        // The ledger keeps this run's device (its deletion cannot be read back
        // with a revoked token) and every earlier one still listed.
        let ledger = reading.as_ref().map(|r| {
            let mut keep: BTreeSet<String> = pending
                .iter()
                .filter(|id| r.listed.contains(id) && !cleaned.contains(*id))
                .cloned()
                .collect();
            keep.extend(own_device.map(str::to_string));
            keep
        });
        let ledger_word = match ledger {
            Some(keep) => match identity::write_pending(&self.dir, &keep) {
                Ok(()) => "ok",
                Err(_) => "failed",
            },
            None => "unchanged",
        };
        let (tripwire, reason_if_fired) = match &judged {
            Some(j) if j.fired => ("fired", Some(Reason::IdentityCompromised)),
            Some(_) => ("clean", None),
            None => ("unavailable", None),
        };
        let mut fields: Fields = vec![
            ("route", report.route.word().to_string()),
            ("tripwire", tripwire.to_string()),
            (
                "rooms",
                reading
                    .as_ref()
                    .map(|r| r.rooms.to_string())
                    .unwrap_or_default(),
            ),
            (
                "devices",
                reading
                    .as_ref()
                    .map(|r| r.listed.len().to_string())
                    .unwrap_or_default(),
            ),
            (
                "logout_status",
                report
                    .logout_status
                    .map(|s| s.to_string())
                    .unwrap_or_default(),
            ),
            ("refresh", report.refresh.to_string()),
            ("ledger", ledger_word.to_string()),
        ];
        if let Some(j) = &judged {
            if !j.leftovers.is_empty() {
                fields.push(("leftovers", list(&j.leftovers)));
                fields.push(("cleaned", cleaned.len().to_string()));
            }
            if !j.strangers.is_empty() {
                fields.push(("strangers", list(&j.strangers)));
            }
        }
        if let Some(cleanup) = report.cleanup {
            fields.push(("cleanup", cleanup.to_string()));
        }
        let reason = match (reason_if_fired, judged.is_none(), report.reason) {
            (Some(fired), _, _) => fired,
            (None, true, Reason::Ok) => Reason::TripwireUnavailable,
            (None, _, reason) => reason,
        };
        match reason {
            Reason::Ok => run.ok(CHECK, fields),
            reason => run.fail(CHECK, reason, fields),
        }
    }
}
