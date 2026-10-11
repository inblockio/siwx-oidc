//! The guest room template audited at mint (design 01 §4.3, 04 GP-SEC-07 and GP-SEC-28; work
//! package S2a).
//!
//! The host's own client creates the meeting room; siwx-oidc never does. Before it mints
//! an invitation into that room it reads the room's state and refuses a room a joined
//! guest could reshape. Everything here is pure: [`audit_room`] takes the parsed state
//! and the hosts' Matrix user ids, so every rule is tested without a Synapse.
//!
//! Power is computed with the room-version rule, never read from the `users` map alone:
//! in room versions 10 and 11 the `users` map and `users_default` decide; in version 12
//! the `m.room.create` sender and every `additional_creators` entry hold unlimited power
//! and never appear in `users` (MSC4289).

use serde_json::Value;
use std::collections::HashMap;

/// The state type that marks a room as open to guests. The P4 module confines a guest to
/// rooms that carry it, so only a host may set it.
pub const GUEST_ROOM_STATE: &str = "io.inblock.guest_room";

/// The call-member state types, stable and unstable. They must sit at power 0 so a guest
/// can join the call.
pub const CALL_MEMBER_TYPES: [&str; 4] = [
    "org.matrix.msc3401.call.member",
    "m.call.member",
    "org.matrix.msc4143.rtc.member",
    "m.rtc.member",
];

/// Non-state event types a call needs from every participant (keys, ring and decline,
/// reactions, redacting one's own). They may sit below 50; every other type may not.
pub const CALL_EVENT_TYPES: [&str; 7] = [
    "io.element.call.encryption_keys",
    "io.element.call.reaction",
    "org.matrix.msc4075.rtc.notification",
    "m.rtc.notification",
    "org.matrix.msc4310.rtc.decline",
    "m.reaction",
    "m.room.redaction",
];

/// Non-state event types that may also sit below 50 (F14-R07): the encrypted message
/// event, so registered participants can chat in the encrypted room. `events_default`
/// stays 50, and the Synapse guest-policy module still refuses a guest's messages. Allowed,
/// never required.
pub const CHAT_EVENT_TYPES: [&str; 1] = ["m.room.encrypted"];

/// The lowest power a guarded action may require (`invite`, `kick`, `ban`, `redact`,
/// `state_default`, `events_default` and every per-type override).
const GUARDED: i64 = 50;

/// The Matrix identifier length limit, in bytes.
const MAX_ROOM_ID_BYTES: usize = 255;

/// One way a room misses the template. The reason code is what the host is told.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Violation {
    /// No `m.room.create` event in the state.
    CreateMissing,
    /// A room version the audit has no power rule for (only 10, 11 and 12 pass).
    RoomVersion(String),
    /// `m.federate` is not `false` in the creation content.
    Federates,
    /// The join rule is not `knock`.
    JoinRule,
    /// No `m.room.encryption` event.
    Unencrypted,
    /// History visibility is not `joined`.
    HistoryVisibility,
    /// Guest access is set and is not `forbidden`.
    GuestAccess,
    /// No `m.room.power_levels` event.
    PowerLevelsMissing,
    /// A power level field is not an integer.
    PowerLevelType(String),
    /// A guarded action (`invite`, `kick`, `ban`, `redact`, `state_default`,
    /// `events_default`) requires less than 50.
    PowerTooLow(&'static str),
    /// `users_default` is not 0.
    UsersDefault,
    /// A per-type override below 50 for a type that is neither a call type nor
    /// `m.room.encrypted`.
    EventOverride(String),
    /// A call-member type is not at 0.
    CallMemberPower(&'static str),
    /// No `io.inblock.guest_room` state event, or one sent by a non-host.
    GuestRoomFlag,
    /// A non-host has the power to set `io.inblock.guest_room`.
    GuestRoomPower(String),
    /// A room version 12 `additional_creators` entry is not a host.
    AdditionalCreator(String),
    /// The room has a topic or an avatar (both are readable without authentication).
    TopicOrAvatar,
}

impl Violation {
    /// The fixed reason code the host sees. Never a Synapse body.
    pub fn code(&self) -> &'static str {
        match self {
            Violation::CreateMissing | Violation::RoomVersion(_) => "room_version",
            Violation::Federates => "room_federates",
            Violation::JoinRule => "room_join_rule",
            Violation::Unencrypted => "room_unencrypted",
            Violation::HistoryVisibility => "room_history_visibility",
            Violation::GuestAccess => "room_guest_access",
            Violation::PowerLevelsMissing
            | Violation::PowerLevelType(_)
            | Violation::PowerTooLow(_)
            | Violation::UsersDefault
            | Violation::EventOverride(_)
            | Violation::CallMemberPower(_) => "room_power_levels",
            Violation::GuestRoomFlag => "room_guest_flag",
            Violation::GuestRoomPower(_) | Violation::AdditionalCreator(_) => "room_creators",
            Violation::TopicOrAvatar => "room_metadata",
        }
    }
}

/// Whether `room_id` matches the room id grammar (04 GP-SEC-07, the single definition).
///
/// `!`, then one or more ASCII letters, digits, `-`, `_` or `.`, then optionally `:` and
/// a server part that equals `server_name` byte for byte. At most 255 bytes. Room version
/// 12 ids have no server part (MSC4291), so none is required.
pub fn valid_room_id(room_id: &str, server_name: &str) -> bool {
    if room_id.len() > MAX_ROOM_ID_BYTES {
        return false;
    }
    let Some(rest) = room_id.strip_prefix('!') else {
        return false;
    };
    let (opaque, server) = match rest.split_once(':') {
        Some((o, s)) => (o, Some(s)),
        None => (rest, None),
    };
    let opaque_ok = !opaque.is_empty()
        && opaque
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
    opaque_ok && server.is_none_or(|s| s == server_name)
}

/// The room state, keyed by `(type, state_key)`, as the admin API returns it.
pub struct RoomState {
    events: HashMap<(String, String), StateEvent>,
}

struct StateEvent {
    sender: String,
    content: Value,
}

impl RoomState {
    /// Parse the `state` array of `GET /_synapse/admin/v1/rooms/{id}/state`. An entry
    /// without a string `type` or `state_key` is skipped: it cannot be addressed by the
    /// rules, and every rule treats a missing event as a violation.
    pub fn from_events(events: &[Value]) -> Self {
        let events = events
            .iter()
            .filter_map(|e| {
                let kind = e.get("type")?.as_str()?.to_string();
                let key = e.get("state_key")?.as_str()?.to_string();
                let sender = e.get("sender").and_then(Value::as_str).unwrap_or("");
                let content = e.get("content").cloned().unwrap_or(Value::Null);
                Some((
                    (kind, key),
                    StateEvent {
                        sender: sender.to_string(),
                        content,
                    },
                ))
            })
            .collect();
        Self { events }
    }

    fn get(&self, kind: &str) -> Option<&StateEvent> {
        self.events.get(&(kind.to_string(), String::new()))
    }

    fn content_str(&self, kind: &str, field: &str) -> Option<&str> {
        self.get(kind)?.content.get(field)?.as_str()
    }

    /// Whether `user_id` is joined (its `m.room.member` state is `join`).
    pub fn is_joined(&self, user_id: &str) -> bool {
        self.events
            .get(&("m.room.member".to_string(), user_id.to_string()))
            .and_then(|e| e.content.get("membership")?.as_str())
            == Some("join")
    }
}

/// Effective power under the room-version rule.
struct Power<'a> {
    /// Version 12 creators (the create sender and `additional_creators`): unlimited.
    creators: Vec<&'a str>,
    users: HashMap<&'a str, i64>,
    users_default: i64,
}

impl Power<'_> {
    fn of(&self, user_id: &str) -> i64 {
        if self.creators.contains(&user_id) {
            return i64::MAX;
        }
        self.users
            .get(user_id)
            .copied()
            .unwrap_or(self.users_default)
    }
}

/// Read an integer power field. Room versions 10 and later refuse non-integer power
/// levels, so anything else is a violation rather than something to coerce.
fn int(v: &Value, field: &str, problems: &mut Vec<Violation>) -> Option<i64> {
    match v {
        Value::Number(n) if n.is_i64() => n.as_i64(),
        _ => {
            problems.push(Violation::PowerLevelType(field.to_string()));
            None
        }
    }
}

/// Audit `state` against the template. `hosts` are the Matrix user ids of `guest_hosts`.
/// Returns every violation found, not only the first.
pub fn audit_room(state: &RoomState, hosts: &[String]) -> Result<(), Vec<Violation>> {
    let mut problems = Vec::new();
    let is_host = |u: &str| hosts.iter().any(|h| h == u);

    // Creation: version, federation, version 12 creators.
    let mut creators: Vec<&str> = Vec::new();
    let mut version_ok = false;
    match state.get("m.room.create") {
        None => problems.push(Violation::CreateMissing),
        Some(create) => {
            // The spec default for a missing `room_version` is "1".
            let version = create
                .content
                .get("room_version")
                .and_then(Value::as_str)
                .unwrap_or("1");
            match version {
                "10" | "11" => version_ok = true,
                "12" => {
                    version_ok = true;
                    creators.push(create.sender.as_str());
                    if let Some(extra) = create
                        .content
                        .get("additional_creators")
                        .and_then(Value::as_array)
                    {
                        for c in extra.iter().filter_map(Value::as_str) {
                            creators.push(c);
                            if !is_host(c) {
                                problems.push(Violation::AdditionalCreator(c.to_string()));
                            }
                        }
                    }
                }
                other => problems.push(Violation::RoomVersion(other.to_string())),
            }
            // `m.federate` defaults to true, so it must be present and false.
            if create.content.get("m.federate") != Some(&Value::Bool(false)) {
                problems.push(Violation::Federates);
            }
        }
    }

    if state.content_str("m.room.join_rules", "join_rule") != Some("knock") {
        problems.push(Violation::JoinRule);
    }
    if state.get("m.room.encryption").is_none() {
        problems.push(Violation::Unencrypted);
    }
    if state.content_str("m.room.history_visibility", "history_visibility") != Some("joined") {
        problems.push(Violation::HistoryVisibility);
    }
    // An absent `m.room.guest_access` means `forbidden` (client-server spec).
    if state
        .get("m.room.guest_access")
        .is_some_and(|e| e.content.get("guest_access").and_then(Value::as_str) != Some("forbidden"))
    {
        problems.push(Violation::GuestAccess);
    }
    let has = |kind: &str, field: &str| {
        state
            .content_str(kind, field)
            .is_some_and(|s| !s.trim().is_empty())
    };
    if has("m.room.topic", "topic") || has("m.room.avatar", "url") {
        problems.push(Violation::TopicOrAvatar);
    }

    // The flag must be there and come from a host.
    if !state
        .get(GUEST_ROOM_STATE)
        .is_some_and(|e| is_host(&e.sender))
    {
        problems.push(Violation::GuestRoomFlag);
    }

    let Some(pl) = state.get("m.room.power_levels").map(|e| &e.content) else {
        problems.push(Violation::PowerLevelsMissing);
        return Err(problems);
    };
    // Spec defaults for absent fields: `state_default` 50 when the event exists,
    // `events_default` and `users_default` 0, `invite` 0, `kick`/`ban`/`redact` 50.
    let field = |name: &'static str, default: i64, problems: &mut Vec<Violation>| match pl.get(name)
    {
        None => Some(default),
        Some(v) => int(v, name, problems),
    };
    for (name, default) in [
        ("invite", 0),
        ("kick", 50),
        ("ban", 50),
        ("redact", 50),
        ("state_default", 50),
        ("events_default", 0),
    ] {
        if let Some(level) = field(name, default, &mut problems) {
            if level < GUARDED {
                problems.push(Violation::PowerTooLow(name));
            }
        }
    }
    let state_default = field("state_default", 50, &mut problems).unwrap_or(GUARDED);
    let users_default = field("users_default", 0, &mut problems).unwrap_or(0);
    if users_default != 0 {
        problems.push(Violation::UsersDefault);
    }

    let empty = serde_json::Map::new();
    let overrides = pl
        .get("events")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let mut levels: HashMap<&str, i64> = HashMap::new();
    for (kind, v) in overrides {
        if let Some(level) = int(v, kind, &mut problems) {
            levels.insert(kind.as_str(), level);
        }
    }
    for (kind, level) in &levels {
        let allowed = CALL_MEMBER_TYPES.contains(kind)
            || CALL_EVENT_TYPES.contains(kind)
            || CHAT_EVENT_TYPES.contains(kind);
        if *level < GUARDED && !allowed {
            problems.push(Violation::EventOverride((*kind).to_string()));
        }
    }
    for kind in CALL_MEMBER_TYPES {
        // Absent means `state_default`, so a guest could not join the call.
        if levels.get(kind).copied().unwrap_or(state_default) != 0 {
            problems.push(Violation::CallMemberPower(kind));
        }
    }

    // Only a host may set the flag: its required power must exceed every non-host's.
    if version_ok {
        let users = pl.get("users").and_then(Value::as_object).unwrap_or(&empty);
        let mut power = Power {
            creators,
            users: HashMap::new(),
            users_default,
        };
        for (user, v) in users {
            if let Some(level) = int(v, user, &mut problems) {
                power.users.insert(user.as_str(), level);
            }
        }
        let flag_level = levels
            .get(GUEST_ROOM_STATE)
            .copied()
            .unwrap_or(state_default);
        let mut holders: Vec<&str> = power.users.keys().copied().collect();
        holders.extend(power.creators.iter().copied());
        holders.sort_unstable();
        holders.dedup();
        for user in holders {
            if !is_host(user) && power.of(user) >= flag_level {
                problems.push(Violation::GuestRoomPower(user.to_string()));
            }
        }
        if users_default >= flag_level {
            problems.push(Violation::GuestRoomPower("users_default".to_string()));
        }
    }

    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems)
    }
}

/// Whether `user_id` is joined to the room with at least `invite` power, computed with
/// the room-version rule (design 01 step A3): a version 12 creator passes with no
/// `users` entry. `None` when the state cannot say (no create or power levels event).
pub fn may_invite(state: &RoomState, user_id: &str) -> Option<bool> {
    if !state.is_joined(user_id) {
        return Some(false);
    }
    let create = state.get("m.room.create")?;
    let pl = &state.get("m.room.power_levels")?.content;
    let num = |v: Option<&Value>, d: i64| v.map_or(Some(d), Value::as_i64);
    let version = create.content.get("room_version").and_then(Value::as_str);
    if version == Some("12") {
        let extra = create
            .content
            .get("additional_creators")
            .and_then(Value::as_array);
        let is_creator = create.sender == user_id
            || extra.is_some_and(|a| a.iter().any(|c| c.as_str() == Some(user_id)));
        if is_creator {
            return Some(true);
        }
    }
    let invite = num(pl.get("invite"), 0)?;
    let users_default = num(pl.get("users_default"), 0)?;
    let own = num(pl.get("users").and_then(|u| u.get(user_id)), users_default)?;
    Some(own >= invite)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const HOST: &str = "@host:example.org";
    const OTHER_HOST: &str = "@cohost:example.org";
    const STRANGER: &str = "@mallory:example.org";

    fn hosts() -> Vec<String> {
        vec![HOST.to_string(), OTHER_HOST.to_string()]
    }

    fn ev(kind: &str, key: &str, sender: &str, content: Value) -> Value {
        json!({"type": kind, "state_key": key, "sender": sender, "content": content})
    }

    /// A room that passes, for `version`: what a compliant portal creates.
    fn baseline(version: &str) -> Vec<Value> {
        let mut events = json!({
            "m.room.name": 50, "m.room.topic": 50, "m.room.avatar": 50,
            "m.room.pinned_events": 50,
        });
        for t in CALL_MEMBER_TYPES.iter().chain(CALL_EVENT_TYPES.iter()) {
            events[t] = json!(0);
        }
        // Version 12 refuses a `users` entry for a creator.
        let users = if version == "12" {
            json!({})
        } else {
            json!({ HOST: 100 })
        };
        vec![
            ev(
                "m.room.create",
                "",
                HOST,
                json!({"room_version": version, "m.federate": false}),
            ),
            ev("m.room.member", HOST, HOST, json!({"membership": "join"})),
            ev(
                "m.room.power_levels",
                "",
                HOST,
                json!({
                    "users": users, "users_default": 0,
                    "events_default": 50, "state_default": 50,
                    "invite": 50, "kick": 50, "ban": 50, "redact": 50,
                    "events": events,
                }),
            ),
            ev("m.room.join_rules", "", HOST, json!({"join_rule": "knock"})),
            ev(
                "m.room.history_visibility",
                "",
                HOST,
                json!({"history_visibility": "joined"}),
            ),
            ev(
                "m.room.guest_access",
                "",
                HOST,
                json!({"guest_access": "forbidden"}),
            ),
            ev(
                "m.room.encryption",
                "",
                HOST,
                json!({"algorithm": "m.megolm.v1.aes-sha2"}),
            ),
            ev("m.room.name", "", HOST, json!({"name": "Meeting"})),
            ev(GUEST_ROOM_STATE, "", HOST, json!({"version": 1})),
        ]
    }

    fn audit(events: &[Value]) -> Result<(), Vec<Violation>> {
        audit_room(&RoomState::from_events(events), &hosts())
    }

    /// Replace (or with `None`, drop) the state event `(kind, "")`.
    fn with(mut events: Vec<Value>, kind: &str, replacement: Option<Value>) -> Vec<Value> {
        events.retain(|e| !(e["type"] == kind && e["state_key"] == ""));
        events.extend(replacement);
        events
    }

    /// Edit the power-levels content in place.
    fn pl(mut events: Vec<Value>, edit: impl Fn(&mut Value)) -> Vec<Value> {
        let e = events
            .iter_mut()
            .find(|e| e["type"] == "m.room.power_levels")
            .unwrap();
        edit(&mut e["content"]);
        events
    }

    fn create(mut events: Vec<Value>, edit: impl Fn(&mut Value)) -> Vec<Value> {
        let e = events
            .iter_mut()
            .find(|e| e["type"] == "m.room.create")
            .unwrap();
        edit(e);
        events
    }

    fn refused_with(events: &[Value], expected: Violation) {
        let problems = audit(events).expect_err("the room must be refused");
        assert!(
            problems.contains(&expected),
            "expected {expected:?}, got {problems:?}"
        );
    }

    const VERSIONS: [&str; 3] = ["10", "11", "12"];

    #[test]
    fn the_baseline_passes_on_every_audited_version() {
        for v in VERSIONS {
            assert_eq!(audit(&baseline(v)), Ok(()), "room version {v}");
        }
    }

    #[test]
    fn an_unaudited_room_version_is_refused() {
        for v in ["9", "13", "org.example.custom"] {
            let room = create(baseline("11"), |e| e["content"]["room_version"] = json!(v));
            refused_with(&room, Violation::RoomVersion(v.to_string()));
        }
        let room = create(baseline("11"), |e| {
            e["content"].as_object_mut().unwrap().remove("room_version");
        });
        refused_with(&room, Violation::RoomVersion("1".to_string()));
        refused_with(
            &with(baseline("11"), "m.room.create", None),
            Violation::CreateMissing,
        );
    }

    #[test]
    fn each_template_item_missing_is_refused_on_every_version() {
        for v in VERSIONS {
            let b = || baseline(v);
            refused_with(
                &create(b(), |e| e["content"]["m.federate"] = json!(true)),
                Violation::Federates,
            );
            refused_with(
                &create(b(), |e| {
                    e["content"].as_object_mut().unwrap().remove("m.federate");
                }),
                Violation::Federates,
            );
            for rule in ["public", "invite", "restricted"] {
                refused_with(
                    &with(
                        b(),
                        "m.room.join_rules",
                        Some(ev(
                            "m.room.join_rules",
                            "",
                            HOST,
                            json!({"join_rule": rule}),
                        )),
                    ),
                    Violation::JoinRule,
                );
            }
            refused_with(&with(b(), "m.room.join_rules", None), Violation::JoinRule);
            refused_with(
                &with(b(), "m.room.encryption", None),
                Violation::Unencrypted,
            );
            for hv in ["shared", "invited", "world_readable"] {
                refused_with(
                    &with(
                        b(),
                        "m.room.history_visibility",
                        Some(ev(
                            "m.room.history_visibility",
                            "",
                            HOST,
                            json!({"history_visibility": hv}),
                        )),
                    ),
                    Violation::HistoryVisibility,
                );
            }
            refused_with(
                &with(b(), "m.room.history_visibility", None),
                Violation::HistoryVisibility,
            );
            refused_with(
                &with(
                    b(),
                    "m.room.guest_access",
                    Some(ev(
                        "m.room.guest_access",
                        "",
                        HOST,
                        json!({"guest_access": "can_join"}),
                    )),
                ),
                Violation::GuestAccess,
            );
            refused_with(
                &with(b(), "m.room.power_levels", None),
                Violation::PowerLevelsMissing,
            );
            for name in [
                "invite",
                "kick",
                "ban",
                "redact",
                "state_default",
                "events_default",
            ] {
                refused_with(
                    &pl(b(), |c| c[name] = json!(49)),
                    Violation::PowerTooLow(name),
                );
            }
            // Spec defaults: an absent `invite` or `events_default` is 0.
            for name in ["invite", "events_default"] {
                refused_with(
                    &pl(b(), |c| {
                        c.as_object_mut().unwrap().remove(name);
                    }),
                    Violation::PowerTooLow(name),
                );
            }
            refused_with(
                &pl(b(), |c| c["users_default"] = json!(1)),
                Violation::UsersDefault,
            );
            refused_with(
                &pl(b(), |c| c["state_default"] = json!("50")),
                Violation::PowerLevelType("state_default".into()),
            );
            refused_with(
                &pl(b(), |c| c["events"]["m.room.join_rules"] = json!(0)),
                Violation::EventOverride("m.room.join_rules".into()),
            );
            refused_with(
                &pl(b(), |c| c["events"]["m.room.message"] = json!(0)),
                Violation::EventOverride("m.room.message".into()),
            );
            refused_with(
                &with(
                    b(),
                    "m.room.topic",
                    Some(ev(
                        "m.room.topic",
                        "",
                        HOST,
                        json!({"topic": "Board meeting"}),
                    )),
                ),
                Violation::TopicOrAvatar,
            );
            refused_with(
                &with(
                    b(),
                    "m.room.avatar",
                    Some(ev("m.room.avatar", "", HOST, json!({"url": "mxc://x/y"}))),
                ),
                Violation::TopicOrAvatar,
            );
            refused_with(&with(b(), GUEST_ROOM_STATE, None), Violation::GuestRoomFlag);
        }
    }

    /// F14-R07: `m.room.encrypted` at 0 is allowed (never required), with `events_default`
    /// at 50; every other override below 50 still fails as `room_power_levels`.
    #[test]
    fn the_encrypted_event_may_sit_at_zero_and_nothing_else_may() {
        for v in VERSIONS {
            let room = pl(baseline(v), |c| c["events"]["m.room.encrypted"] = json!(0));
            assert_eq!(audit(&room), Ok(()), "room version {v}: encrypted at 0");
            // Not required: the baseline has no such override and passes (above).
            let at_default = pl(baseline(v), |c| {
                c["events"]["m.room.encrypted"] = json!(50);
            });
            assert_eq!(audit(&at_default), Ok(()), "room version {v}: at 50");
        }
        // Allowing it moves nothing else: `events_default` below 50 and the neighbours fail.
        let room = pl(baseline("11"), |c| {
            c["events"]["m.room.encrypted"] = json!(0);
            c["events"]["m.room.message"] = json!(0);
        });
        let problems = audit(&room).expect_err("m.room.message at 0 is refused");
        assert_eq!(
            problems,
            vec![Violation::EventOverride("m.room.message".into())]
        );
        assert_eq!(problems[0].code(), "room_power_levels");
        let room = pl(baseline("11"), |c| {
            c["events"]["m.room.encrypted"] = json!(0);
            c["events_default"] = json!(0);
        });
        let problems = audit(&room).expect_err("events_default at 0 is refused");
        assert_eq!(problems, vec![Violation::PowerTooLow("events_default")]);
    }

    #[test]
    fn an_absent_guest_access_means_forbidden_and_an_empty_topic_is_none() {
        let room = with(baseline("11"), "m.room.guest_access", None);
        assert_eq!(audit(&room), Ok(()));
        let room = with(
            baseline("11"),
            "m.room.topic",
            Some(ev("m.room.topic", "", HOST, json!({"topic": ""}))),
        );
        assert_eq!(audit(&room), Ok(()));
    }

    #[test]
    fn call_member_types_must_sit_at_zero() {
        for v in VERSIONS {
            for t in CALL_MEMBER_TYPES {
                refused_with(
                    &pl(baseline(v), |c| c["events"][t] = json!(50)),
                    Violation::CallMemberPower(t),
                );
                // Absent falls back to `state_default` (50): a guest could not join.
                refused_with(
                    &pl(baseline(v), |c| {
                        c["events"].as_object_mut().unwrap().remove(t);
                    }),
                    Violation::CallMemberPower(t),
                );
            }
        }
    }

    #[test]
    fn the_guest_room_flag_must_come_from_a_host() {
        for v in VERSIONS {
            let room = with(
                baseline(v),
                GUEST_ROOM_STATE,
                Some(ev(GUEST_ROOM_STATE, "", STRANGER, json!({"version": 1}))),
            );
            refused_with(&room, Violation::GuestRoomFlag);
        }
    }

    #[test]
    fn only_hosts_may_have_the_power_to_set_the_flag() {
        for v in VERSIONS {
            // A non-host at state_default can set it.
            let room = pl(baseline(v), |c| c["users"][STRANGER] = json!(50));
            refused_with(&room, Violation::GuestRoomPower(STRANGER.into()));
            // A lowered override for the flag puts it within a guest's reach.
            let room = pl(baseline(v), |c| c["events"][GUEST_ROOM_STATE] = json!(0));
            refused_with(&room, Violation::GuestRoomPower("users_default".into()));
            // A second host at 100 is fine.
            let room = pl(baseline(v), |c| c["users"][OTHER_HOST] = json!(100));
            assert_eq!(audit(&room), Ok(()), "room version {v}");
        }
    }

    #[test]
    fn a_version_12_creator_holds_unlimited_power() {
        // The create sender is not a host: unlimited power, so it could set the flag.
        let room = create(baseline("12"), |e| e["sender"] = json!(STRANGER));
        refused_with(&room, Violation::GuestRoomPower(STRANGER.into()));
        // In version 11 the same sender has only its `users` entry (here none: 0).
        let room = create(baseline("11"), |e| e["sender"] = json!(STRANGER));
        assert_eq!(audit(&room), Ok(()));
    }

    #[test]
    fn a_version_12_additional_creator_must_be_a_host() {
        let room = create(baseline("12"), |e| {
            e["content"]["additional_creators"] = json!([OTHER_HOST])
        });
        assert_eq!(audit(&room), Ok(()));
        let room = create(baseline("12"), |e| {
            e["content"]["additional_creators"] = json!([STRANGER])
        });
        refused_with(&room, Violation::AdditionalCreator(STRANGER.into()));
        let room = create(baseline("12"), |e| {
            e["content"]["additional_creators"] = json!([])
        });
        assert_eq!(audit(&room), Ok(()));
    }

    #[test]
    fn may_invite_uses_the_room_version_rule() {
        // Version 12: the creator has no `users` entry and still passes.
        let s = RoomState::from_events(&baseline("12"));
        assert_eq!(may_invite(&s, HOST), Some(true));
        // Version 11: the `users` entry decides.
        let s = RoomState::from_events(&baseline("11"));
        assert_eq!(may_invite(&s, HOST), Some(true));
        let s = RoomState::from_events(&pl(baseline("11"), |c| c["users"][HOST] = json!(10)));
        assert_eq!(may_invite(&s, HOST), Some(false));
        // Not joined: never.
        let mut room: Vec<Value> = baseline("12")
            .into_iter()
            .filter(|e| e["type"] != "m.room.member")
            .collect();
        room.push(ev(
            "m.room.member",
            HOST,
            HOST,
            json!({"membership": "leave"}),
        ));
        assert_eq!(
            may_invite(&RoomState::from_events(&room), HOST),
            Some(false)
        );
        // A joined non-creator in version 12 falls back to `users_default`.
        let mut room = baseline("12");
        room.push(ev(
            "m.room.member",
            STRANGER,
            STRANGER,
            json!({"membership": "join"}),
        ));
        assert_eq!(
            may_invite(&RoomState::from_events(&room), STRANGER),
            Some(false)
        );
    }

    #[test]
    fn the_room_id_grammar() {
        let server = "example.org";
        let hash = "A".repeat(43);
        for ok in [
            "!abcdefghijklmnopqr:example.org".to_string(),
            format!("!{hash}"),
            "!a-b_c.d".to_string(),
        ] {
            assert!(valid_room_id(&ok, server), "{ok} must be accepted");
        }
        let long = format!("!{}", "a".repeat(255));
        for bad in [
            "!a:other.example",
            "!a/b",
            "!a%2fb",
            "!a b",
            "a:example.org",
            "!",
            "!:example.org",
            "!a?b",
            "!a#b",
            "!a\nb",
            "!a..b/..",
            "!é",
            long.as_str(),
        ] {
            assert!(!valid_room_id(bad, server), "{bad:?} must be refused");
        }
        assert_eq!(format!("!{}", "a".repeat(254)).len(), 255);
        assert!(valid_room_id(&format!("!{}", "a".repeat(254)), server));
    }

    #[test]
    fn every_violation_has_a_fixed_reason_code() {
        let room = with(baseline("11"), "m.room.encryption", None);
        let problems = audit(&room).unwrap_err();
        assert_eq!(problems[0].code(), "room_unencrypted");
    }
}
