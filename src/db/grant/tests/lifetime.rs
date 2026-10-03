//! Absolute expiry (I6): the cap a grant gets, the access-token clamp, grants
//! written without a cap, cap changes, the lift, and the H5 property test.
//!
//! Time moves only by ageing a grant's fields in Redis ([`age`]); no clock in
//! the product is overridden.

use super::*;
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::sync::Arc;

async fn redis_now(client: &RedisClient) -> i64 {
    let (secs, _micros): (String, String) = raw(client, &["TIME"]).await;
    secs.parse().expect("TIME")
}

/// Shift a grant's `auth_time`, `auth_ms`, `absolute_exp` (when present) and
/// `last_used` `ARGV[1]` seconds into the past, as if that much time had passed.
const AGE_LUA: &str = r#"
for _, f in ipairs({'auth_time', 'absolute_exp', 'last_used'}) do
  if redis.call('HEXISTS', KEYS[1], f) == 1 then
    redis.call('HINCRBY', KEYS[1], f, -tonumber(ARGV[1]))
  end
end
if redis.call('HEXISTS', KEYS[1], 'auth_ms') == 1 then
  redis.call('HINCRBY', KEYS[1], 'auth_ms', -1000 * tonumber(ARGV[1]))
end
return 1
"#;

async fn age(client: &RedisClient, id: &GrantId, secs: i64) {
    let _: i64 = raw(
        client,
        &["EVAL", AGE_LUA, "1", &grant_key(id), &secs.to_string()],
    )
    .await;
}

/// Caps under which `client_id`'s grants get `cap` (`None`: no cap), set as
/// the global value or as the client's own, beside values that never bind it
/// (a larger global value, a smaller value for another client).
fn caps(client_id: &str, cap: Option<u64>, via_global: bool) -> GrantLifetime {
    let mut per_client = HashMap::from([("another-client".to_string(), 60)]);
    let global_secs = match cap {
        None => None,
        Some(cap) if via_global => Some(cap),
        Some(cap) => {
            per_client.insert(client_id.to_string(), cap);
            Some(cap + 3_600)
        }
    };
    GrantLifetime {
        global_secs,
        per_client_secs: Arc::new(per_client),
    }
}

fn grant_for(client_id: &str, device_id: &str, auth_time: i64) -> NewGrant {
    let mut g = matrix_grant(&format!("life{}", nonce()), device_id);
    g.client_id = client_id.to_string();
    if device_id.is_empty() {
        g.kind = GrantKind::Oidc;
    }
    g.auth_ms = Some(auth_time * 1000);
    g
}

async fn ttl(client: &RedisClient, key: &str) -> i64 {
    raw(client, &["TTL", key]).await
}

/// The cap of a grant is its client's operator value when one is set, else
/// the global default (D1, provisional): a per-client value replaces the
/// global one, longer or shorter, so an operator can give one client (say
/// Element) a longer cap than a short global default.
#[test]
fn a_per_client_cap_overrides_the_global_default() {
    assert_eq!(GrantLifetime::default().cap_for("a"), None);
    let global = GrantLifetime {
        global_secs: Some(7_200),
        ..Default::default()
    };
    assert_eq!(global.cap_for("a"), Some(7_200));
    let per_client = GrantLifetime {
        global_secs: None,
        per_client_secs: Arc::new(HashMap::from([("a".to_string(), 3_600)])),
    };
    assert_eq!(per_client.cap_for("a"), Some(3_600));
    assert_eq!(per_client.cap_for("b"), None, "another client is uncapped");
    let both = GrantLifetime {
        global_secs: Some(7_200),
        per_client_secs: Arc::new(HashMap::from([
            ("a".to_string(), 3_600),
            ("b".to_string(), 10_800),
        ])),
    };
    assert_eq!(both.cap_for("a"), Some(3_600), "a shorter per-client value");
    assert_eq!(
        both.cap_for("b"),
        Some(10_800),
        "a longer per-client value replaces the global default"
    );
    assert_eq!(both.cap_for("c"), Some(7_200), "the global default");
}

/// The access token's `exp` is the earlier of its own lifetime and the
/// grant's absolute expiry, at issue and at rotation, and the stored entries
/// expire with it; a token is refused once its grant is past the absolute
/// expiry, whatever its own `exp` says.
#[tokio::test]
async fn an_access_token_never_outlives_its_grants_absolute_expiry() {
    let Some(base) = crate::test_support::redis().await else {
        return;
    };
    let client_id = format!("clamp-{}", nonce());
    let client = base
        .clone()
        .with_grant_lifetime(caps(&client_id, Some(7_200), false));
    // Authenticated 7,100 s ago: 100 s of the cap left, less than one access lifetime.
    let auth = redis_now(&client).await - 7_100;
    let abs = auth + 7_200;
    let issued = issue(&client, &grant_for(&client_id, "CLAMPDEV", auth)).await;
    assert_eq!(issued.access_exp, abs, "the first access token is clamped");
    let g = hgetall(&client, &grant_key(&issued.grant_id)).await;
    assert_eq!(g.get("absolute_exp"), Some(&abs.to_string()));
    for key in [at_key(&issued.access_token), grant_key(&issued.grant_id)] {
        let t = ttl(&client, &key).await;
        assert!(
            t > 0 && t <= 100,
            "{key} lives until the absolute expiry, got {t}"
        );
    }
    let access = client
        .lookup_access_token(&issued.access_token)
        .await
        .unwrap()
        .expect("accepted before the absolute expiry");
    assert_eq!(access.exp, abs);

    let next = rotated(rotate(&client, issued.refresh_token.as_deref().unwrap()).await);
    assert_eq!(
        next.pair.access_exp, abs,
        "a rotated access token is clamped"
    );
    let t = ttl(&client, &at_key(&next.pair.access_token)).await;
    assert!(t > 0 && t <= 100, "got {t}");

    age(&client, &issued.grant_id, 200).await;
    assert!(
        client
            .lookup_access_token(&next.pair.access_token)
            .await
            .unwrap()
            .is_none(),
        "a grant past its absolute expiry accepts no access token"
    );
}

/// A grant written while no cap applied has no `absolute_exp`. Once a cap is
/// configured it counts from the grant's `auth_time`: the access check refuses
/// past it, the rotation script refuses and deletes, and a rotation inside it
/// writes the deadline.
#[tokio::test]
async fn a_grant_written_without_a_cap_is_capped_from_its_auth_time() {
    let Some(base) = crate::test_support::redis().await else {
        return;
    };
    let client_id = format!("uncapped-{}", nonce());
    let uncapped = base.clone();
    let capped = base
        .clone()
        .with_grant_lifetime(caps(&client_id, Some(3_600), true));
    let now = redis_now(&base).await;

    let live = issue(&uncapped, &grant_for(&client_id, "", now)).await;
    let g = hgetall(&base, &grant_key(&live.grant_id)).await;
    assert!(!g.contains_key("absolute_exp"), "no cap, no absolute_exp");
    let access = capped
        .lookup_access_token(&live.access_token)
        .await
        .unwrap()
        .expect("inside the cap");
    assert!(access.exp <= now + 3_600);
    let next = rotated(rotate(&capped, live.refresh_token.as_deref().unwrap()).await);
    let g = hgetall(&base, &grant_key(&live.grant_id)).await;
    assert_eq!(g.get("absolute_exp"), Some(&(now + 3_600).to_string()));
    assert!(next.pair.access_exp <= now + 3_600);

    let old = issue(&uncapped, &grant_for(&client_id, "OLDDEV", now)).await;
    age(&base, &old.grant_id, 3_600).await;
    assert!(
        uncapped
            .lookup_access_token(&old.access_token)
            .await
            .unwrap()
            .is_some(),
        "without a cap nothing ends the grant"
    );
    assert!(
        capped
            .lookup_access_token(&old.access_token)
            .await
            .unwrap()
            .is_none(),
        "the access check applies the cap from auth_time"
    );
    let outcome = rotate(&capped, old.refresh_token.as_deref().unwrap()).await;
    assert!(
        matches!(outcome, RotateOutcome::Invalid(InvalidReason::Expired)),
        "got {outcome:?}"
    );
    assert_eq!(
        raw::<i64>(&base, &["EXISTS", &grant_key(&old.grant_id)]).await,
        0,
        "an expired grant is deleted"
    );
}

/// A lowered cap applies at the next rotation; raising the cap, or removing
/// it, never moves a written absolute expiry later.
#[tokio::test]
async fn a_lowered_cap_applies_at_the_next_rotation_and_a_raised_one_never_extends() {
    let Some(base) = crate::test_support::redis().await else {
        return;
    };
    let client_id = format!("change-{}", nonce());
    let at = |cap| {
        base.clone()
            .with_grant_lifetime(caps(&client_id, cap, false))
    };
    let now = redis_now(&base).await;
    let issued = issue(&at(Some(14_400)), &grant_for(&client_id, "CHDEV", now)).await;
    let abs = |client: &RedisClient, id: &GrantId| {
        let (client, key) = (client.clone(), grant_key(id));
        async move { hgetall(&client, &key).await.get("absolute_exp").cloned() }
    };
    assert_eq!(
        abs(&base, &issued.grant_id).await,
        Some((now + 14_400).to_string())
    );
    let p1 = rotated(rotate(&at(Some(3_600)), issued.refresh_token.as_deref().unwrap()).await);
    assert_eq!(
        abs(&base, &issued.grant_id).await,
        Some((now + 3_600).to_string()),
        "a lowered cap moves the absolute expiry earlier at the next rotation"
    );
    let p2 = rotated(rotate(&at(Some(28_800)), &p1.pair.refresh_token).await);
    let p3 = rotated(rotate(&at(None), &p2.pair.refresh_token).await);
    assert_eq!(
        abs(&base, &issued.grant_id).await,
        Some((now + 3_600).to_string()),
        "raising or removing the cap never extends the grant"
    );
    age(&base, &issued.grant_id, 3_600).await;
    let outcome = rotate(&at(None), &p3.pair.refresh_token).await;
    assert!(
        matches!(outcome, RotateOutcome::Invalid(InvalidReason::Expired)),
        "got {outcome:?}"
    );
}

/// A lifted legacy grant counts its cap from the legacy entry's issue time
/// (the last legacy rotation), clamps its first access token, and a legacy
/// token already past the cap is refused and left as it is.
#[tokio::test]
async fn a_lifted_grant_counts_its_cap_from_the_legacy_issue_time() {
    let Some(base) = crate::test_support::redis().await else {
        return;
    };
    let user = format!("liftcap{}", nonce());
    let (legacy_rt, meta) =
        seed_legacy(&base, &user, "LIFTDEV", REFRESH_TOKEN_TTL as i64, true).await;
    // The legacy entry was issued 60 s ago: a 200 s cap leaves 140 s.
    let client = base
        .clone()
        .with_grant_lifetime(caps(&meta.client_id, Some(200), false));
    let legacy = peek_legacy(&client, &legacy_rt).await;
    let lifted = rotated(
        client
            .lift_legacy_refresh_token(&request(&legacy_rt), &legacy, false)
            .await
            .unwrap(),
    );
    let g = hgetall(&base, &grant_key(&lifted.grant_id)).await;
    assert_eq!(g.get("absolute_exp"), Some(&(meta.iat + 200).to_string()));
    assert_eq!(lifted.pair.access_exp, meta.iat + 200);

    let (old_rt, old_meta) = seed_legacy(
        &base,
        &format!("liftold{}", nonce()),
        "",
        REFRESH_TOKEN_TTL as i64,
        true,
    )
    .await;
    let short = base
        .clone()
        .with_grant_lifetime(caps(&old_meta.client_id, Some(30), true));
    let old = peek_legacy(&short, &old_rt).await;
    let outcome = short
        .lift_legacy_refresh_token(&request(&old_rt), &old, false)
        .await
        .unwrap();
    assert!(
        matches!(outcome, RotateOutcome::Invalid(InvalidReason::Expired)),
        "got {outcome:?}"
    );
    assert_eq!(
        raw::<i64>(&base, &["EXISTS", &format!("token/{old_rt}")]).await,
        1,
        "a refused legacy token stays as it is"
    );
}

fn min_cap(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    [a, b].into_iter().flatten().min()
}

/// Real-time slack for second-granular Redis `TIME` and the test's own runtime.
const MARGIN: i64 = 3;
const SEQUENCES: usize = 64;
const STEPS: usize = 40;
const CAPS: [u64; 5] = [1_800, 3_600, 7_200, 14_400, 28_800];

/// H5: with a cap configured, no sequence of rotations, replays,
/// introspections, cap changes and elapsed time yields an accepted access
/// token or a successful refresh at or past `auth_time` + cap. The cap of a
/// refresh is the earliest cap written into the grant (at issue and at every
/// rotation) and the cap in force; an access token answers to the written one,
/// or to the cap in force for a grant written without one. So a lowered cap
/// applies at the next rotation and a raised one never extends a grant.
/// Liveness half: inside the cap the current token rotates, the previous one
/// replays while its successor is unused, and live access tokens are accepted.
///
/// Seeded and reproducible: the seed is printed, and `H5_SEED=<seed>` replays it.
#[tokio::test]
async fn h5_no_sequence_outlives_the_absolute_expiry() {
    let Some(base) = crate::test_support::redis().await else {
        return;
    };
    let seed: u64 = std::env::var("H5_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64
        });
    eprintln!("h5 seed {seed} (H5_SEED={seed} replays it)");
    let mut rng = StdRng::seed_from_u64(seed);
    let (mut rotations, mut replays, mut accepted, mut expiries) = (0, 0, 0, 0);

    for seq in 0..SEQUENCES {
        let client_id = format!("h5-{}", nonce());
        let via_global = rng.gen_bool(0.5);
        let pick = |rng: &mut StdRng| CAPS[rng.gen_range(0..CAPS.len())];
        let mut cap = if rng.gen_bool(0.2) {
            None
        } else {
            Some(pick(&mut rng))
        };
        let at = |cap| {
            base.clone()
                .with_grant_lifetime(caps(&client_id, cap, via_global))
        };
        let device = if rng.gen_bool(0.5) { "H5DEV" } else { "" };
        let auth = redis_now(&base).await;
        let issued = issue(&at(cap), &grant_for(&client_id, device, auth)).await;
        let id = issued.grant_id.clone();
        // Seconds of simulated time since authentication, at a real instant.
        let mut shift: i64 = 0;
        let elapsed = |shift: i64| {
            let base = base.clone();
            async move { shift + redis_now(&base).await - auth }
        };
        let mut written = cap; // the earliest cap written into the grant
        let mut current = issued.refresh_token.clone().expect("refresh token");
        let mut previous: Option<String> = None;
        let mut successor_unused = false;
        let mut generation = 0u64;
        let mut tokens = vec![(issued.access_token.clone(), 0u64, issued.access_exp)];
        let mut ended = false;

        for step in 0..STEPS {
            let tag = format!("seed {seed} sequence {seq} step {step}");
            let refresh_limit = min_cap(written, cap).map(|c| c as i64);
            let access_limit = written.or(cap).map(|c| c as i64);
            let before = elapsed(shift).await;
            match rng.gen_range(0..7) {
                0..=2 => {
                    let replay = rng.gen_bool(0.3) && previous.is_some();
                    let presented = if replay {
                        previous.clone().unwrap()
                    } else {
                        current.clone()
                    };
                    let outcome = rotate(&at(cap), &presented).await;
                    let after = elapsed(shift).await;
                    let inside = refresh_limit.is_none_or(|l| after + MARGIN < l);
                    match outcome {
                        RotateOutcome::Rotated(p) if !replay => {
                            assert!(
                                refresh_limit.is_none_or(|l| before < l),
                                "{tag}: rotated at {before} s, cap {refresh_limit:?}"
                            );
                            written = min_cap(written, cap);
                            if let Some(l) = written {
                                let deadline = auth - shift + l as i64;
                                assert!(
                                    p.pair.access_exp <= deadline,
                                    "{tag}: access exp {} past the absolute expiry {deadline}",
                                    p.pair.access_exp
                                );
                            }
                            previous = Some(std::mem::replace(&mut current, p.pair.refresh_token));
                            successor_unused = true;
                            generation = p.generation;
                            tokens.push((p.pair.access_token, p.generation, p.pair.access_exp));
                            rotations += 1;
                        }
                        RotateOutcome::Replayed(p) if replay => {
                            assert!(successor_unused, "{tag}: replayed after use");
                            assert!(
                                refresh_limit.is_none_or(|l| before < l),
                                "{tag}: replayed at {before} s, cap {refresh_limit:?}"
                            );
                            assert_eq!(p.pair.refresh_token, current, "{tag}");
                            replays += 1;
                        }
                        RotateOutcome::Reuse(_) if replay => {
                            assert!(!successor_unused || !inside, "{tag}: reuse while unused");
                        }
                        RotateOutcome::Invalid(InvalidReason::Expired) => {
                            assert!(
                                !inside,
                                "{tag}: expired at {after} s, cap {refresh_limit:?}"
                            );
                            expiries += 1;
                            ended = true;
                        }
                        other => panic!("{tag}: unexpected {other:?} (replay {replay})"),
                    }
                }
                3 | 4 => {
                    let (token, gen, exp) = tokens[rng.gen_range(0..tokens.len())].clone();
                    let answer = at(cap).lookup_access_token(&token).await.unwrap();
                    let after = elapsed(shift).await;
                    let real_now = redis_now(&base).await;
                    match answer {
                        Some(a) => {
                            assert!(
                                access_limit.is_none_or(|l| before < l),
                                "{tag}: access token accepted at {before} s, cap {access_limit:?}"
                            );
                            if let Some(l) = access_limit {
                                assert!(a.exp <= auth - shift + l, "{tag}: exp past the expiry");
                            }
                            if gen == generation {
                                successor_unused = false;
                            }
                            accepted += 1;
                        }
                        None => {
                            let inside = access_limit.is_none_or(|l| after + MARGIN < l);
                            assert!(
                                !inside || exp <= real_now + MARGIN,
                                "{tag}: a live access token was refused at {after} s, cap {access_limit:?}"
                            );
                        }
                    }
                }
                5 => {
                    let d = rng.gen_range(0..=3_000);
                    age(&base, &id, d).await;
                    shift += d;
                }
                _ => {
                    cap = if rng.gen_bool(0.15) {
                        None
                    } else {
                        Some(pick(&mut rng))
                    };
                }
            }
            if ended {
                break;
            }
        }

        // Every sequence ends past its cap: nothing is accepted any more.
        let tag = format!("seed {seed} sequence {seq} end");
        if !ended {
            if min_cap(written, cap).is_none() {
                cap = Some(CAPS[0]);
            }
            let limit = [min_cap(written, cap), written.or(cap)]
                .into_iter()
                .flatten()
                .max()
                .unwrap() as i64;
            let now = elapsed(shift).await;
            if now <= limit {
                let d = limit - now + 1;
                age(&base, &id, d).await;
            }
            for (token, _, _) in &tokens {
                assert!(
                    at(cap).lookup_access_token(token).await.unwrap().is_none(),
                    "{tag}: an access token was accepted past the cap"
                );
            }
            let outcome = rotate(&at(cap), &current).await;
            assert!(
                matches!(outcome, RotateOutcome::Invalid(InvalidReason::Expired)),
                "{tag}: the current token past the cap gave {outcome:?}"
            );
            expiries += 1;
        }
        assert_eq!(
            raw::<i64>(&base, &["EXISTS", &grant_key(&id)]).await,
            0,
            "{tag}: an expired grant is deleted"
        );
    }
    eprintln!(
        "h5: {rotations} rotations, {replays} replays, {accepted} access checks accepted, {expiries} expiries"
    );
    assert!(rotations > SEQUENCES && replays > 0 && accepted > SEQUENCES);
    assert_eq!(expiries, SEQUENCES, "every sequence reached its expiry");
}
