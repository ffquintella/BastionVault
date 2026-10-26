//! Authorization questions an engine is allowed to ask.
//!
//! Not an ACL handle. The policy engine's `ACL`, `Policy`, `PermissionsEntry`
//! and `Capability` types are the evaluator's internals; an engine that could
//! name them could also build one, and a second place that decides what a
//! caller may do is a second place to get it wrong. So this trait exposes the
//! four *questions* the engines actually ask, each answered by the same
//! evaluator the request pipeline uses:
//!
//! | question | asked by |
//! |---|---|
//! | may this caller open a session to this target? | rustion, resource connect-MFA |
//! | which of these objects may this caller see? | rustion, resource listing |
//! | does this caller hold `sudo` here? | rustion raw `session/open` |
//! | which of these SQL privileges does this caller hold on a resource? | the SQL browser host calls (features/sql-browser.md §3.4) |
//!
//! All of them take the caller's own `Request` rather than a synthesized one.
//! That is load-bearing and was a real bug once: the identity-less
//! `Request::default()` probe reports "denied" for every share-grantee,
//! because scope-gated rules resolve owner and share qualifiers off the
//! request. See `PolicyStore::may_connect_target`.

use bv_errors::RvError;
use bv_logical::Request;

pub use sql::{
    canonical_resource, sql_check_path, SqlCapability, SqlCheck, SqlPurpose, SqlTarget, SqlVerdict, SQL_MAX_CHECKS,
    SQL_MAX_NAME_LEN,
};

#[maybe_async::maybe_async]
pub trait PolicyGate: Send + Sync {
    /// May the caller behind `req` open a session to `target_prefix`?
    ///
    /// Asks for the `connect` capability explicitly, and resolves owner and
    /// share qualifiers off `req` — so an owner or a `connect`-share grantee
    /// passes, and a read-only share does not.
    ///
    /// Fails closed: any evaluation error is `false`.
    async fn may_connect_target(&self, req: &Request, target_prefix: &str) -> bool;

    /// Which of `targets` may the caller behind `req` read?
    ///
    /// Returns one verdict per target, in order. Share- and owner-aware.
    async fn readable_targets(&self, req: &Request, targets: &[String]) -> Vec<bool>;

    /// Does the caller behind `req` hold `sudo` on `path` (or root)?
    ///
    /// `Err` when no ACL can be built for the caller — the caller should treat
    /// that as a refusal, never as a pass.
    async fn caller_has_sudo(&self, req: &Request, path: &str) -> Result<bool, RvError>;

    /// Which of `checks` does the caller behind `req` hold on `resource`?
    ///
    /// One verdict per check, in order. Each is a capability probe on
    /// [`sql_check_path`] with the owner, share and asset-group qualifiers of
    /// `(resource, <resource>)` resolved off `req`. Nothing implies a SQL
    /// capability except the root token, and an applying `deny` revokes it.
    /// `Err` refuses the whole batch: treat it as a refusal, never as a pass.
    async fn sql_privileges(
        &self,
        req: &Request,
        purpose: SqlPurpose<'_>,
        resource: &str,
        checks: &[SqlCheck],
    ) -> Result<Vec<SqlVerdict>, RvError>;
}

/// The SQL browser's privilege vocabulary and the synthetic paths it is
/// evaluated on (features/sql-browser.md §3). Pure types and path building;
/// the decision is `PolicyGate::sql_privileges`.
pub mod sql {
    use bv_errors::RvError;

    /// Upper bound on the checks in one [`super::PolicyGate::sql_privileges`]
    /// batch. A larger batch is refused, not truncated.
    pub const SQL_MAX_CHECKS: usize = 1024;

    /// Longest resource name, catalog, schema or object name (in bytes) that
    /// is placed in a synthetic path. A longer resource name is refused; a
    /// longer object name is unaddressable (see [`SqlTarget::is_addressable`]).
    pub const SQL_MAX_NAME_LEN: usize = 512;

    /// One of the eleven SQL capabilities. Probe-only, like `connect`: no
    /// request operation maps to one, no other capability implies one, and
    /// none implies another.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum SqlCapability {
        Select,
        Insert,
        Update,
        Delete,
        Alter,
        Create,
        Drop,
        Execute,
        Admin,
        Export,
        Script,
    }

    impl SqlCapability {
        /// Every SQL capability, in policy-language order.
        pub const ALL: [SqlCapability; 11] = [
            SqlCapability::Select,
            SqlCapability::Insert,
            SqlCapability::Update,
            SqlCapability::Delete,
            SqlCapability::Alter,
            SqlCapability::Create,
            SqlCapability::Drop,
            SqlCapability::Execute,
            SqlCapability::Admin,
            SqlCapability::Export,
            SqlCapability::Script,
        ];

        /// The name as policies and shares spell it (`sql_select`, …).
        pub const fn as_str(self) -> &'static str {
            match self {
                SqlCapability::Select => "sql_select",
                SqlCapability::Insert => "sql_insert",
                SqlCapability::Update => "sql_update",
                SqlCapability::Delete => "sql_delete",
                SqlCapability::Alter => "sql_alter",
                SqlCapability::Create => "sql_create",
                SqlCapability::Drop => "sql_drop",
                SqlCapability::Execute => "sql_execute",
                SqlCapability::Admin => "sql_admin",
                SqlCapability::Export => "sql_export",
                SqlCapability::Script => "sql_script",
            }
        }

        /// The capability spelled exactly `s`, or `None`. Case-sensitive,
        /// like every other capability name.
        pub fn parse(s: &str) -> Option<Self> {
            Self::ALL.into_iter().find(|c| c.as_str() == s)
        }
    }

    impl std::fmt::Display for SqlCapability {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(self.as_str())
        }
    }

    /// What a check is about: the database server, or one object in it.
    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    pub enum SqlTarget {
        /// `…/sql/server`: statements that name no object, `sql_admin`,
        /// `sql_script`, and opening a session.
        Server,
        /// `…/sql/objects/<catalog>/<schema>/<object>`, names already
        /// resolved and case-normalized by the caller (§4.4).
        Object { catalog: String, schema: String, object: String },
    }

    impl SqlTarget {
        /// Whether every name can be placed in a path segment. A name that is
        /// empty, too long, `.` / `..`, or contains `/`, `*`, `+` or a control
        /// character is not: such an object is checked on the objects root
        /// (`…/sql/objects/`), which only grants covering every object match,
        /// so no object-scoped rule can ever apply to it (fail closed).
        pub fn is_addressable(&self) -> bool {
            match self {
                SqlTarget::Server => true,
                SqlTarget::Object { catalog, schema, object } => {
                    [catalog, schema, object].into_iter().all(|s| addressable_segment(s))
                }
            }
        }
    }

    fn addressable_segment(s: &str) -> bool {
        !s.is_empty()
            && s.len() <= SQL_MAX_NAME_LEN
            && s != "."
            && s != ".."
            && !s.chars().any(|c| c == '/' || c == '*' || c == '+' || c.is_control())
    }

    /// One privilege to decide.
    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    pub struct SqlCheck {
        pub capability: SqlCapability,
        pub target: SqlTarget,
    }

    /// The decision for one [`SqlCheck`].
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct SqlVerdict {
        pub capability: SqlCapability,
        pub target: SqlTarget,
        /// The synthetic ACL path the check was evaluated on.
        pub path: String,
        pub allowed: bool,
        /// A `deny` that governs or applies decided the refusal.
        pub denied_by_deny: bool,
    }

    /// Why the caller asks, which decides what is recorded.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum SqlPurpose<'a> {
        /// A session or statement is allowed or refused on this answer. Every
        /// refused check is written to the denial store, naming `plugin`.
        Enforce { plugin: &'a str },
        /// The caller's own privileges, for display (the GUI's chips). Nothing
        /// is recorded, and nothing may be enforced from the answer.
        Display,
    }

    /// The canonical form of a resource name in a synthetic path: trimmed and
    /// lower-cased, as the resource engine stores new names and as owner,
    /// share and asset-group records key them. `Err` when it cannot address
    /// exactly one resource.
    pub fn canonical_resource(resource: &str) -> Result<String, RvError> {
        let r = resource.trim().to_lowercase();
        if !addressable_segment(&r) {
            return Err(RvError::ErrResponseStatus(
                400,
                format!("invalid resource name for a SQL privilege check: {:?}", truncate(resource)),
            ));
        }
        Ok(r)
    }

    fn truncate(s: &str) -> String {
        s.chars().take(64).collect()
    }

    /// The synthetic ACL path a check on `resource` is evaluated on, prefixed
    /// with `namespace` (`""` for root). Never routed; it exists only for
    /// evaluation. An unaddressable object maps to the objects root.
    pub fn sql_check_path(namespace: &str, resource: &str, target: &SqlTarget) -> Result<String, RvError> {
        let resource = canonical_resource(resource)?;
        let ns = namespace.trim().trim_matches('/');
        let mut path = if ns.is_empty() { String::new() } else { format!("{ns}/") };
        path.push_str("resources/resources/");
        path.push_str(&resource);
        path.push_str("/sql/");
        match target {
            SqlTarget::Server => path.push_str("server"),
            SqlTarget::Object { catalog, schema, object } if target.is_addressable() => {
                path.push_str(&format!("objects/{catalog}/{schema}/{object}"));
            }
            SqlTarget::Object { .. } => path.push_str("objects/"),
        }
        Ok(path)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn object(c: &str, s: &str, o: &str) -> SqlTarget {
            SqlTarget::Object { catalog: c.into(), schema: s.into(), object: o.into() }
        }

        #[test]
        fn names_round_trip() {
            for c in SqlCapability::ALL {
                assert_eq!(SqlCapability::parse(c.as_str()), Some(c));
                assert!(c.as_str().starts_with("sql_"));
            }
            assert_eq!(SqlCapability::parse("SQL_SELECT"), None);
            assert_eq!(SqlCapability::parse("select"), None);
        }

        #[test]
        fn paths_are_built_under_the_resource() {
            assert_eq!(
                sql_check_path("", "netrisk-db", &SqlTarget::Server).unwrap(),
                "resources/resources/netrisk-db/sql/server"
            );
            assert_eq!(
                sql_check_path("dti/esi/", " NetRisk-DB ", &object("def", "netrisk", "users")).unwrap(),
                "dti/esi/resources/resources/netrisk-db/sql/objects/def/netrisk/users"
            );
        }

        /// A name that could escape its segment, or widen the match, never
        /// reaches an object-scoped path: it is checked on the objects root.
        #[test]
        fn unaddressable_objects_fall_back_to_the_objects_root() {
            let long = "x".repeat(SQL_MAX_NAME_LEN + 1);
            for t in [
                object("def", "netrisk", "a/b"),
                object("def", "net*", "t"),
                object("def", "netrisk", "+"),
                object("", "netrisk", "t"),
                object("def", "..", "t"),
                object("def", "netrisk", "t\n"),
                object("def", "netrisk", long.as_str()),
            ] {
                assert!(!t.is_addressable(), "{t:?}");
                assert_eq!(sql_check_path("", "db", &t).unwrap(), "resources/resources/db/sql/objects/");
            }
            assert!(object("def", "public", "Mixed Case \"t\"").is_addressable());
        }

        #[test]
        fn unaddressable_resources_are_refused() {
            for r in ["", "  ", "a/b", "*", "+", "..", ".", "db\u{0}", &"r".repeat(SQL_MAX_NAME_LEN + 1)] {
                assert!(sql_check_path("", r, &SqlTarget::Server).is_err(), "{r:?}");
            }
        }
    }
}
