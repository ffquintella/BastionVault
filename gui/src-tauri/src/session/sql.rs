//! SQL browser sessions, host side (features/sql-browser.md §10, T125 Phase 4).
//!
//! The session lives in the `dbms-management` plugin on the server. The host
//! keeps the plugin mount it resolved, the plugin's session id and the
//! namespace, keyed by a local token. The webview holds only that token:
//! never the vault token, the plugin session id or a database credential.
//! Paths are the resolved mount plus validated or escaped segments.

use serde_json::{Map, Value};

use super::{SessionCleanup, SessionCleanupKind};

/// The host's record of one SQL session (one `connect_sessions` entry).
#[derive(Debug, Clone)]
pub struct SqlSessionState {
    /// The plugin mount, e.g. `dbms/` (always ends with `/`).
    pub mount: String,
    /// The plugin's session id, checked by [`plugin_session_id_ok`].
    pub session_id: String,
    /// The namespace active at open (`None` = root). Every later call is
    /// pinned to it, as the plugin binds the session to it.
    pub namespace: Option<String>,
    pub resource: String,
    /// The database (catalog) the session is connected to.
    pub catalog: String,
    /// UTC date (`YYYY-MM-DD`) the session was opened on, for the journal.
    pub opened_on: String,
}

impl SqlSessionState {
    /// The close hook the drop path hands back: `DELETE` the plugin session.
    pub fn cleanup(&self) -> SessionCleanup {
        SessionCleanup {
            kind: SessionCleanupKind::SqlSessionClose {
                mount: self.mount.clone(),
                session_id: self.session_id.clone(),
                namespace: self.namespace.clone(),
            },
        }
    }

    /// `<mount>v2/sessions/<id>` plus `suffix` (no leading `/`).
    pub fn path(&self, suffix: &str) -> String {
        session_path(&self.mount, &self.session_id, suffix)
    }
}

/// `<mount>v2/sessions/<id>[/<suffix>]`.
pub fn session_path(mount: &str, session_id: &str, suffix: &str) -> String {
    if suffix.is_empty() {
        format!("{mount}v2/sessions/{session_id}")
    } else {
        format!("{mount}v2/sessions/{session_id}/{suffix}")
    }
}

/// The plugin's session id shape (`ids::session_id`): 16 hex, `-`, 64 hex,
/// lowercase. Checked before the host stores an id or builds a path with it.
pub fn plugin_session_id_ok(id: &str) -> bool {
    let Some((prefix, rest)) = id.split_once('-') else { return false };
    prefix.len() == 16
        && rest.len() == 64
        && prefix.bytes().chain(rest.bytes()).all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A run id from an `execute` reply (`r<n>` today): short and plain.
pub fn run_id_ok(id: &str) -> bool {
    !id.is_empty() && id.len() <= 32 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// A journal date segment, `YYYY-MM-DD`.
pub fn journal_date_ok(s: &str) -> bool {
    s.len() == 10 && s.bytes().enumerate().all(|(i, b)| if i == 4 || i == 7 { b == b'-' } else { b.is_ascii_digit() })
}

/// Longest schema or object name the browser sends.
pub const MAX_OBJECT_NAME_BYTES: usize = 256;

/// Percent-encode one object-browser path segment: every byte outside the
/// unreserved set is escaped, so no name can change the path. The plugin
/// decodes it strictly. Empty, over-long and control-character names fail.
pub fn encode_segment(name: &str, what: &str) -> Result<String, String> {
    if name.is_empty() {
        return Err(format!("{what} name is empty"));
    }
    if name.len() > MAX_OBJECT_NAME_BYTES {
        return Err(format!("{what} name is longer than {MAX_OBJECT_NAME_BYTES} bytes"));
    }
    if name.chars().any(char::is_control) {
        return Err(format!("{what} name contains a control character"));
    }
    let mut out = String::with_capacity(name.len());
    for b in name.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'~' | b'-') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    Ok(out)
}

/// `objects`, `objects/<schema>` or `objects/<schema>/<object>`.
pub fn objects_suffix(schema: Option<&str>, object: Option<&str>) -> Result<String, String> {
    match (schema, object) {
        (None, None) => Ok("objects".to_string()),
        (Some(s), None) => Ok(format!("objects/{}", encode_segment(s, "schema")?)),
        (Some(s), Some(o)) => Ok(format!("objects/{}/{}", encode_segment(s, "schema")?, encode_segment(o, "object")?)),
        (None, Some(_)) => Err("an object needs its schema".to_string()),
    }
}

/// `catalog/schema/object` for `resources/v2/sql/privileges/<r>?objects=`
/// (the encoding `lib/sqlPrivileges.ts::encodeSqlObjectTriple` uses).
pub fn privileges_triple(catalog: &str, schema: &str, object: &str) -> String {
    let enc = |s: &str| s.replace('%', "%25").replace('/', "%2F").replace(',', "%2C");
    format!("{}/{}/{}", enc(catalog), enc(schema), enc(object))
}

/// The body of `POST v2/sessions`: only the plugin's four fields. Values are
/// the plugin's to check; the host refuses only what is never valid.
pub fn open_body(
    resource: &str,
    profile: Option<&str>,
    catalog: Option<&str>,
    mfa_ticket: Option<&str>,
) -> Result<Map<String, Value>, String> {
    let text = |v: &str, what: &str, max: usize| -> Result<Value, String> {
        if v.is_empty() || v.len() > max || v.chars().any(char::is_control) {
            return Err(format!("`{what}` must be 1-{max} printable characters"));
        }
        Ok(Value::String(v.to_string()))
    };
    let mut body = Map::new();
    body.insert("resource".into(), text(resource, "resource", 256)?);
    if let Some(p) = profile.filter(|p| !p.is_empty()) {
        body.insert("profile".into(), text(p, "profile", 128)?);
    }
    if let Some(c) = catalog.filter(|c| !c.is_empty()) {
        body.insert("catalog".into(), text(c, "catalog", 63)?);
    }
    if let Some(t) = mfa_ticket.filter(|t| !t.is_empty()) {
        body.insert("mfa_ticket".into(), text(t, "mfa_ticket", 256)?);
    }
    Ok(body)
}

/// Keys `POST v2/sessions/<id>/rows` accepts.
const EDIT_KEYS: [&str; 5] = ["object", "op", "key", "values", "original"];

/// Check a structured grid edit before forwarding it: exactly the plugin's
/// shape (`rows.rs`). Unknown keys are refused, so no SQL text rides along.
pub fn check_edit(edit: &Map<String, Value>) -> Result<(), String> {
    if let Some(k) = edit.keys().find(|k| !EDIT_KEYS.contains(&k.as_str())) {
        return Err(format!("unknown field `{k}` in a grid edit"));
    }
    let object = edit.get("object").and_then(Value::as_object).ok_or("a grid edit needs `object` {schema, name}")?;
    if object.len() != 2 || !["schema", "name"].iter().all(|k| object.get(*k).is_some_and(Value::is_string)) {
        return Err("`object` must be exactly {schema, name}".to_string());
    }
    match edit.get("op").and_then(Value::as_str) {
        Some("insert" | "update" | "delete") => {}
        _ => return Err("`op` is insert, update or delete".to_string()),
    }
    for k in ["key", "values", "original"] {
        match edit.get(k) {
            None | Some(Value::Null) | Some(Value::Object(_)) => {}
            Some(_) => return Err(format!("`{k}` must be an object of column → value")),
        }
    }
    Ok(())
}

/// A plugin status reply without the plugin's session id.
pub fn scrub_status(mut v: Map<String, Value>) -> Map<String, Value> {
    v.remove("session_id");
    v
}

/// Exactly one reachable mount of a plugin declaring `sql_console`. None or
/// several is an explicit error: the host never guesses where SQL goes.
pub fn pick_console_mount(candidates: &[(String, String)]) -> Result<String, String> {
    match candidates {
        [] => Err("no SQL browser is available: no mount you can reach is served by a plugin declaring \
                   `sql_console` (register and mount dbms-management, features/sql-browser.md)"
            .to_string()),
        [(mount, _)] => {
            let mount = mount.trim_start_matches('/');
            if mount.is_empty() || mount.contains("..") {
                return Err(format!("the SQL console mount `{mount}` is not a mount path"));
            }
            Ok(if mount.ends_with('/') { mount.to_string() } else { format!("{mount}/") })
        }
        many => Err(format!(
            "more than one SQL console mount is reachable ({}); refusing to pick one",
            many.iter().map(|(m, p)| format!("{m} ({p})")).collect::<Vec<_>>().join(", ")
        )),
    }
}

/// `(mount, plugin)` for every `plugin:<name>` mount of a
/// `sys/internal/ui/mounts` secret map, sorted.
pub fn plugin_mounts(map: &Map<String, Value>) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = map
        .iter()
        .filter_map(|(path, entry)| {
            let ty = entry.get("type").and_then(Value::as_str)?;
            let plugin = ty.strip_prefix("plugin:")?;
            (!plugin.is_empty()).then(|| (path.clone(), plugin.to_string()))
        })
        .collect();
    out.sort();
    out
}

/// Operator-facing label of a SQL session.
pub fn label(resource: &str, profile: &str, catalog: &str) -> String {
    if catalog.is_empty() {
        format!("sql {resource} · {profile}")
    } else {
        format!("sql {resource}/{catalog} · {profile}")
    }
}

/// UTC `YYYY-MM-DD` of a Unix time in ms (the journal's day bucket).
pub fn utc_date(unix_ms: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(unix_ms)
        .map(|d| d.format("%Y-%m-%d").to_string())
        .unwrap_or_default()
}

/// The days either side of `date`, for a record the plugin's clock put on
/// the other side of midnight.
pub fn adjacent_dates(date: &str) -> Vec<String> {
    let Ok(d) = chrono::NaiveDate::parse_from_str(date, "%Y-%m-%d") else { return Vec::new() };
    [d.pred_opt(), d.succ_opt()].into_iter().flatten().map(|d| d.format("%Y-%m-%d").to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SID: &str = "0123456789abcdef-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn plugin_session_ids_must_have_the_plugins_shape() {
        assert!(plugin_session_id_ok(SID));
        for bad in [
            "",
            "x-y",
            &SID[..SID.len() - 1],
            &SID.to_uppercase(),
            "0123456789abcdef-../../sys/seal0123456789abcdef0123456789abcdef0123456",
            "0123456789abcdef-0123456789abcdef0123456789abcdef0123456789abcdeg",
        ] {
            assert!(!plugin_session_id_ok(bad), "{bad}");
        }
    }

    #[test]
    fn paths_stay_under_the_session() {
        assert_eq!(session_path("dbms/", SID, ""), format!("dbms/v2/sessions/{SID}"));
        assert_eq!(session_path("dbms/", SID, "runs/r1"), format!("dbms/v2/sessions/{SID}/runs/r1"));
        assert!(run_id_ok("r12"));
        for bad in ["", "../x", "r1/cancel", "r 1", &"r".repeat(33)] {
            assert!(!run_id_ok(bad), "{bad}");
        }
        assert!(journal_date_ok("2026-10-29"));
        for bad in ["2026-1-29", "2026/10/29", "../../all", "2026-10-29x"] {
            assert!(!journal_date_ok(bad), "{bad}");
        }
    }

    #[test]
    fn object_segments_are_escaped_not_trusted() {
        assert_eq!(objects_suffix(None, None).unwrap(), "objects");
        assert_eq!(objects_suffix(Some("public"), None).unwrap(), "objects/public");
        assert_eq!(
            objects_suffix(Some("my schema"), Some("a/b?c#d%e")).unwrap(),
            "objects/my%20schema/a%2Fb%3Fc%23d%25e"
        );
        assert_eq!(encode_segment("tábua", "object").unwrap(), "t%C3%A1bua");
        assert!(objects_suffix(None, Some("t")).is_err());
        assert!(encode_segment("", "schema").is_err());
        assert!(encode_segment("a\nb", "schema").is_err());
        assert!(encode_segment(&"x".repeat(MAX_OBJECT_NAME_BYTES + 1), "schema").is_err());
    }

    #[test]
    fn the_open_body_carries_only_the_plugins_fields() {
        let b = open_body("db1", Some("ro"), None, Some("tkt")).unwrap();
        assert_eq!(Value::Object(b), json!({"resource": "db1", "profile": "ro", "mfa_ticket": "tkt"}));
        let b = open_body("db1", Some(""), Some(""), None).unwrap();
        assert_eq!(Value::Object(b), json!({"resource": "db1"}));
        assert!(open_body("", None, None, None).is_err());
        assert!(open_body("db1", Some("a\u{0}b"), None, None).is_err());
        assert!(open_body("db1", None, Some(&"c".repeat(64)), None).is_err());
    }

    #[test]
    fn grid_edits_are_structured_and_never_sql() {
        let ok = |v: Value| check_edit(v.as_object().unwrap());
        assert!(ok(json!({"object": {"schema": "s", "name": "t"}, "op": "update", "key": {"id": 1},
            "values": {"a": "x"}, "original": {"a": "y"}}))
        .is_ok());
        assert!(ok(json!({"object": {"schema": "s", "name": "t"}, "op": "delete", "key": {"id": 1}})).is_ok());
        for bad in [
            json!({"object": {"schema": "s", "name": "t"}, "op": "update", "sql": "DROP TABLE t"}),
            json!({"object": {"schema": "s", "name": "t"}, "op": "merge"}),
            json!({"object": {"schema": "s"}, "op": "insert", "values": {"a": 1}}),
            json!({"object": {"schema": "s", "name": "t", "catalog": "x"}, "op": "insert"}),
            json!({"object": "s.t", "op": "insert"}),
            json!({"object": {"schema": "s", "name": "t"}, "op": "insert", "values": [1]}),
        ] {
            assert!(ok(bad.clone()).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_console_mount_is_one_or_an_error() {
        let one = vec![("dbms/".to_string(), "dbms-management".to_string())];
        assert_eq!(pick_console_mount(&one).unwrap(), "dbms/");
        let bare = vec![("sql".to_string(), "dbms-management".to_string())];
        assert_eq!(pick_console_mount(&bare).unwrap(), "sql/");
        assert!(pick_console_mount(&[]).unwrap_err().contains("sql_console"));
        let two = vec![("a/".to_string(), "p1".to_string()), ("b/".to_string(), "p2".to_string())];
        assert!(pick_console_mount(&two).unwrap_err().contains("more than one"));
        assert!(pick_console_mount(&[("../x/".to_string(), "p".to_string())]).is_err());
    }

    #[test]
    fn plugin_mounts_are_read_from_the_mount_types() {
        let map = json!({
            "secret/": {"type": "kv"},
            "dbms/": {"type": "plugin:dbms-management"},
            "acc/": {"type": "plugin:self-accounts"},
            "odd/": {"type": "plugin:"},
            "bad/": {}
        });
        assert_eq!(
            plugin_mounts(map.as_object().unwrap()),
            vec![
                ("acc/".to_string(), "self-accounts".to_string()),
                ("dbms/".to_string(), "dbms-management".to_string())
            ]
        );
    }

    #[test]
    fn status_replies_lose_the_plugin_session_id() {
        let v = json!({"session_id": SID, "resource": "db1", "privileges": ["sql_select"]});
        let out = scrub_status(v.as_object().unwrap().clone());
        assert!(!out.contains_key("session_id"));
        assert_eq!(out["resource"], "db1");
    }

    #[test]
    fn journal_dates_and_labels() {
        assert_eq!(utc_date(0), "1970-01-01");
        assert_eq!(adjacent_dates("2026-03-01"), vec!["2026-02-28".to_string(), "2026-03-02".to_string()]);
        assert!(adjacent_dates("nope").is_empty());
        assert_eq!(label("db1", "ro", "app"), "sql db1/app · ro");
        assert_eq!(privileges_triple("app", "pub,lic", "a/b%"), "app/pub%2Clic/a%2Fb%25");
    }

    #[test]
    fn the_cleanup_deletes_exactly_this_session() {
        let s = SqlSessionState {
            mount: "dbms/".into(),
            session_id: SID.into(),
            namespace: Some("team".into()),
            resource: "db1".into(),
            catalog: "app".into(),
            opened_on: "2026-10-29".into(),
        };
        match s.cleanup().kind {
            SessionCleanupKind::SqlSessionClose { mount, session_id, namespace } => {
                assert_eq!(session_path(&mount, &session_id, ""), format!("dbms/v2/sessions/{SID}"));
                assert_eq!(namespace.as_deref(), Some("team"));
            }
            other => panic!("unexpected cleanup {other:?}"),
        }
    }
}
