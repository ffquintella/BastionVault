//! The entries the directory serves, built from Phase 1 records only:
//! `<base_dn>`, `ou=people` (`uid=<login>`: top, account, posixAccount) and
//! `ou=groups` (`cn=<login>`, the user-private group, and `cn=gid.<n>`, one
//! per supplementary gid; both top, posixGroup). `gid.<n>` cannot collide
//! with a login, which never contains `.`. No attribute holds a credential.

use super::{dn::Dn, proto::OID_STARTTLS};
use crate::{entitlement::gate::IssueGrant, posix::model::WorkforceIdentity};

/// Attributes a filter may name; anything else is Undefined.
const KNOWN_ATTRIBUTES: &[&str] = &[
    "objectclass",
    "uid",
    "cn",
    "uidnumber",
    "gidnumber",
    "homedirectory",
    "loginshell",
    "gecos",
    "memberuid",
    "ou",
    "dc",
    "o",
    "namingcontexts",
    "supportedldapversion",
    "supportedextension",
    "supportedsaslmechanisms",
];

pub fn is_known_attribute(lower: &str) -> bool {
    KNOWN_ATTRIBUTES.contains(&lower)
}

pub fn is_integer_attribute(lower: &str) -> bool {
    matches!(lower, "uidnumber" | "gidnumber" | "supportedldapversion")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub dn: Dn,
    pub attrs: Vec<(&'static str, Vec<String>)>,
}

impl Entry {
    /// The values of an attribute, by case-insensitive name.
    pub fn values(&self, lower: &str) -> Option<&[String]> {
        self.attrs.iter().find(|(n, _)| n.eq_ignore_ascii_case(lower)).map(|(_, v)| v.as_slice())
    }

    /// The attributes a search asked for: none for `1.1`, every one for an
    /// empty list or `*`, otherwise those named (unknown names are ignored).
    pub fn select(&self, requested: &[String]) -> Vec<(&'static str, &[String])> {
        let all = requested.is_empty() || requested.iter().any(|a| a == "*");
        self.attrs
            .iter()
            .filter(|(n, _)| all || requested.iter().any(|r| r.eq_ignore_ascii_case(n)))
            .map(|(n, v)| (*n, v.as_slice()))
            .collect()
    }
}

/// Where entries live and the two attributes the records do not hold.
#[derive(Debug, Clone)]
pub struct Layout {
    pub base: Dn,
    pub home_base: String,
    pub shell: String,
}

/// What a person entry is built from: a gate grant (served) or an identity
/// record (the provisional entry a filter is tried on first).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Person {
    pub entity_id: String,
    pub login: String,
    pub uid: u32,
    pub gid: u32,
    pub gids: Vec<u32>,
    pub display_name: String,
}

impl From<&IssueGrant> for Person {
    fn from(g: &IssueGrant) -> Self {
        Self {
            entity_id: g.entity_id.clone(),
            login: g.login.clone(),
            uid: g.uid,
            gid: g.primary_gid,
            gids: g.gids.clone(),
            display_name: g.display_name.clone(),
        }
    }
}

impl From<&WorkforceIdentity> for Person {
    fn from(w: &WorkforceIdentity) -> Self {
        Self {
            entity_id: w.entity_id.clone(),
            login: w.login.clone(),
            uid: w.uid,
            gid: w.primary_gid,
            gids: w.gids.clone(),
            display_name: w.display_name.clone(),
        }
    }
}

fn one(v: impl Into<String>) -> Vec<String> {
    vec![v.into()]
}

pub fn supplementary_group_name(gid: u32) -> String {
    format!("gid.{gid}")
}

impl Layout {
    pub fn people(&self) -> Dn {
        self.base.child("ou", "people")
    }

    pub fn groups(&self) -> Dn {
        self.base.child("ou", "groups")
    }

    pub fn person_dn(&self, login: &str) -> Dn {
        self.people().child("uid", login)
    }

    /// The login a bind DN names: exactly `uid=<login>,ou=people,<base>`.
    pub fn login_for_dn(&self, dn: &Dn) -> Option<String> {
        if dn.parent()? != self.people() {
            return None;
        }
        match dn.leaf()? {
            ("uid", login) => Some(login.to_string()),
            _ => None,
        }
    }

    /// The base entry and the two organisational units.
    pub fn structural(&self) -> Vec<Entry> {
        let mut base_attrs = vec![("objectClass", one("top"))];
        let naming = match self.base.leaf() {
            Some(("dc", v)) => Some(("dc", v)),
            Some(("o", v)) => Some(("o", v)),
            Some(("ou", v)) => Some(("ou", v)),
            _ => None,
        };
        if let Some((name, v)) = naming {
            base_attrs.push((name, one(v)));
        }
        let ou = |name: &str, dn: Dn| Entry {
            dn,
            attrs: vec![("objectClass", vec!["top".into(), "organizationalUnit".into()]), ("ou", one(name))],
        };
        vec![
            Entry { dn: self.base.clone(), attrs: base_attrs },
            ou("people", self.people()),
            ou("groups", self.groups()),
        ]
    }

    /// `posixAccount`. `cn` is the display name, or the login without one.
    pub fn person(&self, p: &Person) -> Entry {
        let cn = if p.display_name.is_empty() { p.login.clone() } else { p.display_name.clone() };
        let mut attrs = vec![
            ("objectClass", vec!["top".into(), "account".into(), "posixAccount".into()]),
            ("uid", one(&p.login)),
            ("cn", one(cn)),
            ("uidNumber", one(p.uid.to_string())),
            ("gidNumber", one(p.gid.to_string())),
            ("homeDirectory", one(format!("{}/{}", self.home_base, p.login))),
            ("loginShell", one(&self.shell)),
        ];
        if !p.display_name.is_empty() {
            attrs.push(("gecos", one(&p.display_name)));
        }
        Entry { dn: self.person_dn(&p.login), attrs }
    }

    /// The user-private group: its gid is the person's primary gid, and,
    /// like the host helper's group line, it lists no members.
    pub fn private_group(&self, p: &Person) -> Entry {
        Entry {
            dn: self.groups().child("cn", &p.login),
            attrs: vec![
                ("objectClass", vec!["top".into(), "posixGroup".into()]),
                ("cn", one(&p.login)),
                ("gidNumber", one(p.gid.to_string())),
            ],
        }
    }

    pub fn supplementary_group(&self, gid: u32, members: Vec<String>) -> Entry {
        let name = supplementary_group_name(gid);
        Entry {
            dn: self.groups().child("cn", &name),
            attrs: vec![
                ("objectClass", vec!["top".into(), "posixGroup".into()]),
                ("cn", one(&name)),
                ("gidNumber", one(gid.to_string())),
                ("memberUid", members),
            ],
        }
    }

    /// The root DSE: what a client reads to learn the naming context.
    pub fn root_dse(&self, tls: bool, starttls_offered: bool) -> Entry {
        let mut attrs = vec![
            ("objectClass", one("top")),
            ("namingContexts", one(self.base.to_string())),
            ("supportedLDAPVersion", one("3")),
        ];
        if starttls_offered && !tls {
            attrs.push(("supportedExtension", one(OID_STARTTLS)));
        }
        if tls {
            attrs.push(("supportedSASLMechanisms", one("EXTERNAL")));
        }
        Entry { dn: Dn::root(), attrs }
    }
}
