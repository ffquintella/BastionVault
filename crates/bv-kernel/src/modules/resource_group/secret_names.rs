//! The asset-group key of a KV secret: its own name (T507).
//!
//! A format 1 member, and the key a request looks up once switched, is the
//! secret's own `<mount>/<name>` relative to its namespace, derived through the
//! mount table exactly as `policy::kv_target` derives owner keys. A path no KV
//! mount serves keys on itself. Format 0 used `legacy_secret_key` instead.

use std::collections::BTreeSet;

use super::group_store::{ResourceGroupEntry, ResourceGroupStore};
use crate::{
    errors::RvError,
    modules::policy::{kv_target::KvItem, policy_store::looks_like_kv_path},
    router::Router,
};

/// The 503 for a change to which KV secrets a group lists, or a delete of a
/// listed one, while the T507 switch is pending: retriable once it is done.
pub(crate) fn pending_refusal() -> RvError {
    RvError::ErrResponseStatus(
        503,
        "asset-group KV-secret members are being re-keyed on each secret's own name and the switch is pending, so \
         changes to which secrets a group lists, and deletes of a listed secret, are refused until a pass \
         completes (at unseal, or by its background retry) (docs/api.md, \"Asset-group key switch pending\")"
            .to_string(),
    )
}

/// What a namespace-relative path is to the member keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Target {
    /// No mount serves it.
    NoMount,
    /// A mount that is not a KV engine serves it: it keys on itself.
    NotKv,
    /// A KV path that names no secret (T506) or an ambiguous name: no key.
    NoKey,
    /// A KV secret by its own name; `acts_on_data` for a `destroy/` or
    /// `undelete/` request, which looked its secret up by the `data/` path.
    Secret { name: String, acts_on_data: bool },
}

/// `sub`, the path below the namespace-relative `mount` of engine `ty`.
fn item_target(mount: &str, ty: &str, sub: &str) -> Target {
    if !matches!(ty, "kv" | "kv-v2") {
        return Target::NotKv;
    }
    match KvItem::from_route(mount, ty, sub) {
        Ok(Some(item)) => match item.key() {
            Some(name) => Target::Secret { name, acts_on_data: item.acts_on_data() },
            None => Target::NoKey,
        },
        Ok(None) | Err(_) => Target::NoKey,
    }
}

/// `path` without its leading `/`s and its namespace prefix.
pub(crate) fn ns_relative<'a>(path: &'a str, ns: Option<&str>) -> &'a str {
    let p = path.trim_start_matches('/');
    match ns.map(|n| n.trim().trim_matches('/')).filter(|n| !n.is_empty()) {
        Some(n) => p.strip_prefix(n).and_then(|r| r.strip_prefix('/')).unwrap_or(p),
        None => p,
    }
}

/// The namespace-qualified form of the namespace-relative `rel`.
pub(crate) fn qualify(rel: &str, ns: Option<&str>) -> String {
    match ns.map(|n| n.trim().trim_matches('/')).filter(|n| !n.is_empty()) {
        Some(n) => format!("{n}/{}", rel.trim_start_matches('/')),
        None => rel.trim_start_matches('/').to_string(),
    }
}

/// `path` (namespace prefix included) through the router, as a request to
/// it resolves; the secret's name relative to namespace `ns`.
pub(crate) fn router_target(router: &Router, path: &str, ns: Option<&str>) -> Result<Target, RvError> {
    let path = path.trim_start_matches('/');
    let mount = router.matching_mount(path)?;
    let Some(entry) = (!mount.is_empty()).then(|| router.matching_mount_entry(&mount)).transpose()?.flatten() else {
        return Ok(Target::NoMount);
    };
    let ty = entry.read()?.logical_type.clone();
    let ns_mount = ns_relative(&mount, ns);
    Ok(item_target(ns_mount, &ty, &path[mount.len()..]))
}

/// A namespace's logical mounts `(path, engine)`, as its stored mount table
/// lists them, resolved like the router: the longest mount path a path
/// starts with. Used by the migration, which runs before any request.
#[derive(Debug, Default)]
pub(crate) struct NsMounts(pub Vec<(String, String)>);

impl NsMounts {
    pub(crate) fn target(&self, rel: &str) -> Target {
        let rel = rel.trim_start_matches('/');
        let best =
            self.0.iter().filter(|(m, _)| !m.is_empty() && rel.starts_with(m.as_str())).max_by_key(|(m, _)| m.len());
        match best {
            Some((mount, ty)) => item_target(mount, ty, &rel[mount.len()..]),
            None => Target::NoMount,
        }
    }
}

/// The key a request to `path` (namespace prefix included) looks up once
/// switched: a KV secret's own name, the namespace-relative path where no KV
/// mount serves it, none for a KV path that names no secret or a fault.
pub(crate) fn request_key(router: &Router, path: &str, ns: Option<&str>) -> Option<String> {
    match router_target(router, path, ns) {
        Ok(Target::Secret { name, .. }) => Some(name),
        Ok(Target::NoMount | Target::NotKv) => ResourceGroupStore::checked_secret_name(ns_relative(path, ns)),
        Ok(Target::NoKey) | Err(_) => None,
    }
}

/// The paths a request to the format 1 member `name` can take whose key is
/// that member: for a kv-v2 secret its `data/` path and, unless it reads as
/// another secret, its short form. Namespace prefix included. For read probes.
pub(crate) fn member_paths(router: &Router, name: &str, ns: Option<&str>) -> Vec<String> {
    let full = qualify(name, ns);
    let mut out = vec![full.clone()];
    if let Ok(mount) = router.matching_mount(&full) {
        let kv_v2 = router
            .matching_mount_entry(&mount)
            .ok()
            .flatten()
            .is_some_and(|e| e.read().map(|e| e.logical_type == "kv-v2").unwrap_or(false));
        if kv_v2 && !mount.is_empty() {
            out.push(format!("{mount}data/{}", &full[mount.len()..]));
        }
    }
    out.retain(|p| request_key(router, p, ns).as_deref() == Some(name));
    out
}

/// How the T507 migration read a format 0 member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reading {
    /// It reached one secret (or one path): its own name.
    One,
    /// It reached several: each keeps the membership; operators prune.
    Several,
    /// No lookup reaches it with the current mounts: kept as written.
    Unresolved,
}

/// A format 0 member as format 1 reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conversion {
    /// Every key a pre-T507 lookup could reach the member by, sorted.
    pub keys: Vec<String>,
    pub reading: Reading,
}

/// The paths whose pre-T507 lookup gave `member`: itself unless its second
/// segment is `data` or `metadata`, and it with either inserted there.
pub(crate) fn preimages(member: &str) -> Vec<String> {
    let member = member.trim_matches('/');
    let (head, rest) = match member.split_once('/') {
        Some((head, rest)) => (head, Some(rest)),
        None => (member, None),
    };
    let mut out = Vec::new();
    if !matches!(rest.and_then(|r| r.split('/').next()), Some("data" | "metadata")) {
        out.push(member.to_string());
    }
    for inserted in ["data", "metadata"] {
        out.push(match rest {
            Some(rest) => format!("{head}/{inserted}/{rest}"),
            None => format!("{head}/{inserted}"),
        });
    }
    out
}

/// Read the format 0 `member` as every key a pre-T507 lookup reached it by,
/// resolving each such path with `target`: the access it gave, exactly.
pub(crate) fn convert_member(
    member: &str,
    target: impl Fn(&str) -> Result<Target, RvError>,
) -> Result<Conversion, RvError> {
    let mut keys = BTreeSet::new();
    for path in preimages(member) {
        if !looks_like_kv_path(&path, None) {
            continue;
        }
        match target(&path)? {
            Target::Secret { name, acts_on_data: false } => keys.insert(name),
            Target::NotKv => keys.insert(path),
            Target::Secret { acts_on_data: true, .. } | Target::NoKey | Target::NoMount => false,
        };
    }
    let reading = match keys.len() {
        0 => Reading::Unresolved,
        1 => Reading::One,
        _ => Reading::Several,
    };
    if keys.is_empty() {
        keys.extend(ResourceGroupStore::checked_secret_name(member));
    }
    Ok(Conversion { keys: keys.into_iter().collect(), reading })
}

/// The format 1 members of `g` through `target`; `g` itself when format 1.
pub(crate) fn own_members(
    g: &ResourceGroupEntry,
    target: impl Fn(&str) -> Result<Target, RvError>,
) -> Result<Vec<String>, RvError> {
    if g.secrets_format > 0 {
        return Ok(g.secrets.clone());
    }
    let mut keys = BTreeSet::new();
    for member in &g.secrets {
        keys.extend(convert_member(member, &target)?.keys);
    }
    Ok(keys.into_iter().collect())
}

/// The path a pre-T507 lookup of the secret a client names by its own `name`
/// used (namespace-relative): its `data/` path on kv-v2, else `name`. Looked
/// up through `groups_for_legacy_secret` while the switch is pending.
pub(crate) fn legacy_path_of_name(router: &Router, name: &str, ns: Option<&str>) -> String {
    let full = qualify(name, ns);
    let kv_v2 = |mount: &str| {
        let entry = router.matching_mount_entry(mount).ok().flatten();
        entry.is_some_and(|e| e.read().map(|e| e.logical_type == "kv-v2").unwrap_or(false))
    };
    match router.matching_mount(&full) {
        Ok(mount) if !mount.is_empty() && kv_v2(&mount) => {
            ns_relative(&format!("{mount}data/{}", &full[mount.len()..]), ns).to_string()
        }
        _ => ns_relative(&full, ns).to_string(),
    }
}

/// The KV-secret members of `g` read as format 1 through `router`, in
/// namespace `ns`: a format 0 record found once switched (a raw `.bvx`
/// import) converted as the migration would, `g`'s own list otherwise.
pub(crate) fn own_members_via(
    router: &Router,
    g: &ResourceGroupEntry,
    ns: Option<&str>,
) -> Result<Vec<String>, RvError> {
    own_members(g, |p| router_target(router, &qualify(p, ns), ns))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The mounts of the classification table in the T507 report.
    fn mounts() -> NsMounts {
        let m = [
            ("secret/", "kv-v2"),
            ("kv/", "kv"),
            ("team/kv/", "kv-v2"),
            ("a/b/", "kv"),
            ("apps/data/", "kv-v2"),
            ("transit/", "transit"),
        ];
        NsMounts(m.iter().map(|(p, t)| (p.to_string(), t.to_string())).collect())
    }

    fn convert(member: &str) -> (Vec<String>, Reading) {
        let c = convert_member(member, |p| Ok(mounts().target(p))).unwrap();
        (c.keys, c.reading)
    }

    #[test]
    fn the_paths_a_pre_t507_lookup_turned_into_a_member() {
        assert_eq!(preimages("kv/x"), ["kv/x", "kv/data/x", "kv/metadata/x"]);
        assert_eq!(preimages("secret/data/y"), ["secret/data/data/y", "secret/metadata/data/y"]);
        assert_eq!(preimages("secret"), ["secret", "secret/data", "secret/metadata"]);
        for member in ["kv/x", "secret/data/y", "a/b/c", "team/kv/data/z"] {
            for path in preimages(member) {
                assert_eq!(ResourceGroupStore::legacy_secret_key(&path).as_deref(), Some(member), "{path}");
            }
        }
    }

    /// The classification table (T507 report): `(stored member, own names,
    /// reading)` with the mounts above.
    #[test]
    fn each_kind_of_stored_member_converts_to_the_access_it_gave() {
        let one = Reading::One;
        let cases: [(&str, &[&str], Reading); 12] = [
            ("secret/x", &["secret/x"], one),
            ("secret/data/y", &["secret/data/y"], one),
            ("secret/destroy/x", &["secret/destroy/x"], one),
            ("secret/config", &["secret/config"], one),
            ("kv/x", &["kv/data/x", "kv/metadata/x", "kv/x"], Reading::Several),
            ("kv/data/x", &["kv/data/data/x", "kv/metadata/data/x"], Reading::Several),
            ("team/kv/data/z", &["team/kv/z"], one),
            ("team/kv/z", &["team/kv/z"], one),
            ("a/b/c", &["a/b/c"], one),
            ("apps/x", &["apps/data/x"], one),
            ("transit/keys/k", &["transit/data/keys/k", "transit/keys/k", "transit/metadata/keys/k"], Reading::Several),
            ("gone/x", &["gone/x"], Reading::Unresolved),
        ];
        for (member, keys, reading) in cases {
            assert_eq!(convert(member), (keys.iter().map(|k| k.to_string()).collect(), reading), "{member}");
        }
        assert_eq!(convert("sys/x"), (vec!["sys/x".to_string()], Reading::Unresolved), "never looked up");
    }

    #[test]
    fn a_namespaced_mount_resolves_relative_to_its_namespace() {
        assert_eq!(ns_relative("/team/kv/data/x", Some("team")), "kv/data/x");
        assert_eq!(ns_relative("kv/data/x", None), "kv/data/x");
        assert_eq!(qualify("kv/x", Some("/team/")), "team/kv/x");
        assert_eq!(qualify("kv/x", None), "kv/x");
        let ns = NsMounts(vec![("kv/".into(), "kv".into())]);
        assert_eq!(ns.target("kv/data/x"), Target::Secret { name: "kv/data/x".into(), acts_on_data: false });
        assert_eq!(ns.target("nomount/x"), Target::NoMount);
    }
}
