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
    /// Two stored mounts share the router key that serves it (a root mount
    /// `a/secret/` and namespace `a`'s `secret/`): which one the router
    /// keeps is not knowable here.
    MountConflict,
    /// A KV secret by its own name; `acts_on_data` for a `destroy/` or
    /// `undelete/` request, which looked its secret up by the `data/` path;
    /// `routes`, the paths a pre-T507 lookup of any request to it used.
    Secret { name: String, acts_on_data: bool, routes: Vec<String> },
}

/// `sub`, the path below the namespace-relative `mount` of engine `ty`.
fn item_target(mount: &str, ty: &str, sub: &str) -> Target {
    if !matches!(ty, "kv" | "kv-v2") {
        return Target::NotKv;
    }
    let item = match KvItem::from_route(mount, ty, sub) {
        Ok(Some(item)) => item,
        Ok(None) | Err(_) => return Target::NoKey,
    };
    let Some(name) = item.key() else {
        return Target::NoKey;
    };
    Target::Secret { routes: lookup_routes(mount, ty, &name), name, acts_on_data: item.acts_on_data() }
}

/// The paths a pre-T507 group lookup used for the requests to the secret
/// `name` (`<mount><secret>`): kv one; kv-v2 its `data/` path (`destroy/`
/// and `undelete/` too), `metadata/` path and, when it reads back as that
/// secret, its version 2 short form.
fn lookup_routes(mount: &str, ty: &str, name: &str) -> Vec<String> {
    let secret = &name[mount.len()..];
    if ty != "kv-v2" {
        return vec![name.to_string()];
    }
    let mut routes = vec![format!("{mount}data/{secret}"), format!("{mount}metadata/{secret}")];
    let short = KvItem::from_route(mount, ty, secret).ok().flatten();
    if short.is_some_and(|i| !i.acts_on_data() && i.key().as_deref() == Some(name)) {
        routes.push(name.to_string());
    }
    routes
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

/// Every namespace's logical mounts `(router key, engine)` from the stored
/// tables, a namespace's keyed `<namespace path>/<mount>` as the shared
/// router keys them, so a scope reaches its descendants' mounts by path,
/// and an ancestor's mount covering its path, exactly as a request does.
#[derive(Debug, Default)]
pub(crate) struct AllMounts(pub Vec<(String, String)>);

impl AllMounts {
    /// `rel`, a path of scope `scope`, as a request in that scope resolves:
    /// the longest router key its full path starts with; a conflict when two
    /// stored mounts share that key.
    pub(crate) fn target(&self, scope: &str, rel: &str) -> Target {
        let ns = (!scope.is_empty()).then_some(scope);
        let full = qualify(rel, ns);
        let serving: Vec<&(String, String)> =
            self.0.iter().filter(|(m, _)| !m.is_empty() && full.starts_with(m.as_str())).collect();
        let Some(longest) = serving.iter().map(|(m, _)| m.len()).max() else {
            return Target::NoMount;
        };
        match serving.iter().filter(|(m, _)| m.len() == longest).collect::<Vec<_>>().as_slice() {
            [(mount, ty)] => item_target(ns_relative(mount, ns), ty, &full[mount.len()..]),
            _ => Target::MountConflict,
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
        // The router keeps one entry per key, so it never reports a conflict.
        Ok(Target::NoKey | Target::MountConflict) | Err(_) => None,
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
    /// It reached a kv-v2 secret through some of its routes only: the own
    /// name would cover them all, so it is kept with the pre-T507 rule.
    KeptRouteSpecific,
    /// No lookup reaches it with the current mounts: kept with the pre-T507
    /// rule, which a mount created later would still follow.
    KeptNoMount,
    /// Two stored mounts share the router key of one of its paths: which
    /// secret it reached is not knowable, so it is kept with the old rule.
    KeptMountConflict,
}

impl Reading {
    /// Kept as written and matched by the pre-T507 rule, not by own name.
    pub fn kept(self) -> bool {
        matches!(self, Self::KeptRouteSpecific | Self::KeptNoMount | Self::KeptMountConflict)
    }
}

/// A format 0 member as format 1 reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conversion {
    /// Every own name a pre-T507 lookup reached the member by, sorted; for
    /// a kept member, the member itself.
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

/// Read the format 0 `member` as every own name a pre-T507 lookup reached it
/// by, resolving each such path with `target`, when that is exact: a member
/// that reached a kv-v2 secret through only some of its routes, or nothing,
/// is kept and keeps matching by the pre-T507 rule (Ruling BB: no widening).
pub(crate) fn convert_member(
    member: &str,
    target: impl Fn(&str) -> Result<Target, RvError>,
) -> Result<Conversion, RvError> {
    let mut keys = BTreeSet::new();
    let (mut route_specific, mut conflict) = (false, false);
    for path in preimages(member) {
        if !looks_like_kv_path(&path, None) {
            continue;
        }
        match target(&path)? {
            Target::Secret { name, acts_on_data: false, routes } => {
                let legacy = |r: &String| ResourceGroupStore::legacy_secret_key(r);
                route_specific |= routes.iter().any(|r| legacy(r).as_deref() != Some(member));
                keys.insert(name);
            }
            Target::NotKv => {
                keys.insert(path);
            }
            Target::MountConflict => conflict = true,
            Target::Secret { acts_on_data: true, .. } | Target::NoKey | Target::NoMount => {}
        }
    }
    let reading = match keys.len() {
        _ if conflict => Reading::KeptMountConflict,
        _ if route_specific => Reading::KeptRouteSpecific,
        0 => Reading::KeptNoMount,
        1 => Reading::One,
        _ => Reading::Several,
    };
    if reading.kept() {
        keys = ResourceGroupStore::checked_secret_name(member).into_iter().collect();
    }
    Ok(Conversion { keys: keys.into_iter().collect(), reading })
}

/// The format 1 lists `(own names, kept members)` of `g` through `target`;
/// `g`'s own lists when it is format 1 already.
pub(crate) fn split_members(
    g: &ResourceGroupEntry,
    target: impl Fn(&str) -> Result<Target, RvError>,
) -> Result<(Vec<String>, Vec<String>), RvError> {
    if g.secrets_format > 0 {
        return Ok((g.secrets.clone(), g.secrets_legacy_kept.clone()));
    }
    let (mut own, mut kept) = (BTreeSet::new(), BTreeSet::new());
    for member in &g.secrets {
        let c = convert_member(member, &target)?;
        match c.reading.kept() {
            true => kept.extend(c.keys),
            false => own.extend(c.keys),
        }
    }
    Ok((own.into_iter().collect(), kept.into_iter().collect()))
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

/// [`split_members`] through `router`, in namespace `ns`: a format 0 record
/// found once switched (a raw `.bvx` import) read as the migration would.
pub(crate) fn split_members_via(
    router: &Router,
    g: &ResourceGroupEntry,
    ns: Option<&str>,
) -> Result<(Vec<String>, Vec<String>), RvError> {
    split_members(g, |p| router_target(router, &qualify(p, ns), ns))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The mounts of the classification table in the T507 report, by router
    /// key: root mounts, `secret/` in namespace `team` and `kv/` in `a/b`.
    fn mounts() -> AllMounts {
        let m = [
            ("secret/", "kv-v2"),
            ("kv/", "kv"),
            ("team/kv/", "kv-v2"),
            ("x/y/", "kv"),
            ("apps/data/", "kv-v2"),
            ("transit/", "transit"),
            ("team/secret/", "kv-v2"),
            ("a/b/kv/", "kv"),
        ];
        AllMounts(m.iter().map(|(p, t)| (p.to_string(), t.to_string())).collect())
    }

    fn convert_in(scope: &str, member: &str) -> (Vec<String>, Reading) {
        let c = convert_member(member, |p| Ok(mounts().target(scope, p))).unwrap();
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

    /// The classification table (T507 report): `(scope, stored member, keys
    /// after, reading)` with the mounts above. A kept member keeps itself.
    #[test]
    fn each_kind_of_stored_member_converts_to_the_access_it_gave() {
        let (one, several) = (Reading::One, Reading::Several);
        let (route, none) = (Reading::KeptRouteSpecific, Reading::KeptNoMount);
        let cases: [(&str, &str, &[&str], Reading); 22] = [
            ("", "secret/x", &["secret/x"], one),
            ("", "secret/data/y", &["secret/data/y"], one),
            ("", "secret/destroy/x", &["secret/destroy/x"], one),
            ("", "secret/config", &["secret/config"], one),
            ("", "kv/x", &["kv/data/x", "kv/metadata/x", "kv/x"], several),
            ("", "kv/data/x", &["kv/data/data/x", "kv/metadata/data/x"], several),
            ("", "team/kv/data/z", &["team/kv/data/z"], route),
            ("", "team/kv/metadata/z", &["team/kv/metadata/z"], route),
            ("", "team/kv/z", &["team/kv/z"], route),
            ("", "x/y/c", &["x/y/c"], one),
            ("", "apps/x", &["apps/x"], route),
            ("", "apps/data/x", &["apps/data/x"], route),
            ("", "transit/keys/k", &["transit/data/keys/k", "transit/keys/k", "transit/metadata/keys/k"], several),
            ("", "gone/x", &["gone/x"], none),
            ("", "sys/x", &["sys/x"], none),
            // A namespace's mounts seen from root by path: kv-v2 is
            // multi-segment there, kv (v1) one route per secret.
            ("", "team/secret/data/x", &["team/secret/data/x"], route),
            ("", "team/secret/x", &["team/secret/x"], route),
            ("", "a/b/kv/data/x", &["a/b/kv/data/x"], one),
            // A namespace's own one-segment kv-v2 mount: exact.
            ("team", "secret/x", &["secret/x"], one),
            ("team", "secret/data/y", &["secret/data/y"], one),
            // A scope reaching its child's mount (`a/b`'s `kv/` from `a`).
            ("a", "b/kv/data/x", &["b/kv/data/x"], one),
            ("a", "b/kv/x", &["b/kv/x"], one),
        ];
        for (scope, member, keys, reading) in cases {
            let want = (keys.iter().map(|k| k.to_string()).collect::<Vec<_>>(), reading);
            assert_eq!(convert_in(scope, member), want, "{member} in {scope:?}");
        }
    }

    /// A root mount `a/secret/` and namespace `a`'s `secret/` share a router
    /// key: whichever the router kept, the member keeps the old rule.
    #[test]
    fn a_member_behind_two_mounts_with_one_router_key_is_kept() {
        let m = AllMounts(vec![("a/secret/".into(), "kv".into()), ("a/secret/".into(), "kv-v2".into())]);
        assert_eq!(m.target("", "a/secret/x"), Target::MountConflict);
        assert_eq!(m.target("a", "secret/x"), Target::MountConflict, "from the namespace too");
        for (scope, member) in [("", "a/secret/x"), ("a", "secret/x"), ("", "a/secret/data/x")] {
            let c = convert_member(member, |p| Ok(m.target(scope, p))).unwrap();
            assert_eq!((c.keys, c.reading), (vec![member.to_string()], Reading::KeptMountConflict), "{member}");
        }
    }

    #[test]
    fn a_path_resolves_like_the_router_relative_to_its_scope() {
        assert_eq!(ns_relative("/team/kv/data/x", Some("team")), "kv/data/x");
        assert_eq!(ns_relative("kv/data/x", None), "kv/data/x");
        assert_eq!(qualify("kv/x", Some("/team/")), "team/kv/x");
        assert_eq!(qualify("kv/x", None), "kv/x");
        let m = mounts();
        let secret = |name: &str, routes: &[&str]| Target::Secret {
            name: name.into(),
            acts_on_data: false,
            routes: routes.iter().map(|r| r.to_string()).collect(),
        };
        assert_eq!(m.target("", "kv/data/x"), secret("kv/data/x", &["kv/data/x"]));
        assert_eq!(m.target("a", "b/kv/x"), secret("b/kv/x", &["b/kv/x"]), "a child's mount");
        let in_team = secret("secret/x", &["secret/data/x", "secret/metadata/x", "secret/x"]);
        assert_eq!(m.target("team", "secret/x"), in_team, "its own mount");
        assert_eq!(m.target("", "nomount/x"), Target::NoMount);
        assert_eq!(m.target("team", "transit/x"), Target::NoMount, "a root mount does not cover team's paths");
    }
}
