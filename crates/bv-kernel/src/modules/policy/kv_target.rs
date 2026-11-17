//! The KV secret a request path addresses (T499, T504).
//!
//! Owner and share records key a KV secret on `<router mount><name>`. The name
//! is derived once, from the request and the mount's engine: a kv-v2 path loses
//! exactly one sub-command segment, a kv path none. A key is never derived
//! again, so a secret literally named `data/x` keeps a key of its own.

use crate::{errors::RvError, modules::identity::owner_store::OwnerStore, router::Router};

/// Prefixes `Router::handle_request` leaves alone at API version 2 (it prepends
/// `data/` to anything else on a kv-v2 mount). Mirrored here; keep in step.
const KV_V2_ROUTER_PREFIXES: [&str; 6] = ["data/", "metadata/", "metadata", "destroy/", "undelete/", "config"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Engine {
    V1,
    V2,
}

/// The kv-v2 sub-command a request goes through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KvSub {
    Data,
    Metadata,
    Destroy,
    Undelete,
}

/// A KV secret (or, for a list, a folder) a request addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KvItem {
    engine: Engine,
    /// Router mount key, namespace prefix included, ending in `/`.
    mount: String,
    /// `None` on a kv (v1) mount.
    sub: Option<KvSub>,
    /// The secret's name without surrounding `/`; empty only for a list of
    /// the mount's root.
    name: String,
    /// The request path ended in `/` (a list).
    folder: bool,
    /// Byte offset of the name in the request path (after its leading `/`).
    name_at: usize,
}

impl KvItem {
    /// The item behind `rel`, the path below `mount` as requested; `None`
    /// when the mount is not a KV engine or `rel` names no secret (kv-v2
    /// `config`, an unroutable sub-command). Independent of the API version:
    /// a version 2 short form `x` is the version 1 `data/x`. A name with an
    /// empty or `..` segment or surrounding whitespace is an error: trimmed,
    /// it would name another secret than the one the engine stores.
    pub(crate) fn from_route(mount: &str, logical_type: &str, rel: &str) -> Result<Option<Self>, RvError> {
        let (engine, sub, raw) = match logical_type {
            "kv" => (Engine::V1, None, rel),
            "kv-v2" => match classify_v2(rel) {
                Some((sub, raw)) => (Engine::V2, Some(sub), raw),
                None => return Ok(None),
            },
            _ => return Ok(None),
        };
        // One trailing `/` marks a list; any other empty segment is not one.
        let folder = raw.ends_with('/');
        let name = raw.strip_suffix('/').unwrap_or(raw);
        let bad_segment = !name.is_empty() && name.split('/').any(|s| s.is_empty() || s == "..");
        if raw == "/" || bad_segment || name.trim() != name {
            return Err(ambiguous());
        }
        if name.is_empty() && sub != Some(KvSub::Metadata) {
            return Ok(None);
        }
        let name_at = mount.len() + rel.len() - raw.len();
        let (mount, name) = (mount.to_string(), name.to_string());
        Ok(Some(Self { engine, mount, sub, folder: folder || name.is_empty(), name, name_at }))
    }

    /// The request path ended in `/`: only a list may address a folder.
    pub(crate) fn folder(&self) -> bool {
        self.folder && !self.name.is_empty()
    }

    /// Byte offset of the secret's name in the request path.
    pub(crate) fn name_at(&self) -> usize {
        self.name_at
    }

    /// The owner and share key: `<mount><name>`. `None` for a mount-root list.
    pub(crate) fn key(&self) -> Option<String> {
        (!self.name.is_empty()).then(|| format!("{}{}", self.mount, self.name))
    }

    /// The key the pre-T499 code used for this item: `legacy(path)`, except that
    /// a kv-v2 `destroy/` or `undelete/` request keys on its secret, as its
    /// `data/` request does (it keyed on a secret named `destroy/<name>`).
    pub(crate) fn legacy_key(&self, path: &str, ns: Option<&str>) -> Option<String> {
        match self.sub {
            Some(KvSub::Destroy | KvSub::Undelete) => OwnerStore::legacy_kv_key(&self.data_path(), ns),
            _ => OwnerStore::legacy_kv_key(path, ns),
        }
    }

    /// The version 1 data path of the secret, `<mount>data/<name>` on kv-v2.
    pub(crate) fn data_path(&self) -> String {
        match self.engine {
            Engine::V1 => format!("{}{}", self.mount, self.name),
            Engine::V2 => format!("{}data/{}", self.mount, self.name),
        }
    }

    /// Whether a group lookup should use [`Self::data_path`] instead of the
    /// request path: a kv-v2 `destroy/` or `undelete/` acts on the secret.
    pub(crate) fn acts_on_data(&self) -> bool {
        matches!(self.sub, Some(KvSub::Destroy | KvSub::Undelete))
    }

    /// The two ACL paths that name this kv-v2 secret's data, `<mount><name>`
    /// and `<mount>data/<name>` (a folder's for a `list`), each with the
    /// offset of the name in it (T504). Empty on a kv (v1) mount.
    pub(crate) fn deny_aliases(&self, list: bool) -> Vec<(String, usize)> {
        if self.engine != Engine::V2 {
            return Vec::new();
        }
        let tail = if (self.folder || list) && !self.name.is_empty() { "/" } else { "" };
        let (mount, name) = (&self.mount, &self.name);
        vec![(format!("{mount}{name}{tail}"), mount.len()), (format!("{mount}data/{name}{tail}"), mount.len() + 5)]
    }
}

/// The sub-command and the rest of a kv-v2 path, as the router and the
/// engine's routes read it. `None` for `config`, the `metadata` list root
/// without its `/`, and paths no route serves.
fn classify_v2(rel: &str) -> Option<(KvSub, &str)> {
    if rel == "metadata" {
        return Some((KvSub::Metadata, ""));
    }
    let subs = [("data/", KvSub::Data), ("metadata/", KvSub::Metadata), ("destroy/", KvSub::Destroy)];
    for (prefix, sub) in subs.into_iter().chain([("undelete/", KvSub::Undelete)]) {
        if let Some(rest) = rel.strip_prefix(prefix) {
            return Some((sub, rest));
        }
    }
    if rel.is_empty() || KV_V2_ROUTER_PREFIXES.iter().any(|p| rel.starts_with(p)) {
        return None;
    }
    Some((KvSub::Data, rel))
}

/// The text of [`ambiguous`]'s 400.
const AMBIGUOUS: &str = "invalid KV path: an empty segment or surrounding whitespace in the name";

/// The 400 for a KV path whose name is ambiguous (see [`KvItem::from_route`]).
pub(crate) fn ambiguous() -> RvError {
    RvError::ErrResponseStatus(400, AMBIGUOUS.into())
}

/// Whether `e` is [`ambiguous`]'s refusal, the only error [`resolve`] gives
/// that is not a router fault.
pub(crate) fn is_ambiguous(e: &RvError) -> bool {
    matches!(e, RvError::ErrResponseStatus(400, message) if message == AMBIGUOUS)
}

/// What a request path is to the owner, share and asset-group lookups.
#[derive(Debug)]
pub(crate) enum KvTarget {
    /// No KV engine serves the path.
    NotKv,
    /// A KV engine serves it, but it names no secret: a kv-v2 mount's
    /// `config`, a sub-command without a name, a mount root (T506).
    NoSecret,
    /// The secret, or for a list the folder, it addresses.
    Item(KvItem),
}

/// [`resolve`], telling a path no KV engine serves from a KV path that names
/// no secret. A mount-root list is an [`KvTarget::Item`] without a key.
pub(crate) fn target(router: &Router, path: &str) -> Result<KvTarget, RvError> {
    let path = path.trim_start_matches('/');
    let mount = router.matching_mount(path)?;
    let Some(rel) = path.strip_prefix(mount.as_str()).filter(|_| !mount.is_empty()) else {
        return Ok(KvTarget::NotKv);
    };
    let Some(entry) = router.matching_mount_entry(&mount)? else {
        return Ok(KvTarget::NotKv);
    };
    let logical_type = entry.read()?.logical_type.clone();
    if !matches!(logical_type.as_str(), "kv" | "kv-v2") {
        return Ok(KvTarget::NotKv);
    }
    Ok(match KvItem::from_route(&mount, &logical_type, rel)? {
        Some(item) => KvTarget::Item(item),
        None => KvTarget::NoSecret,
    })
}

/// The KV item a request to `path` addresses, through the router's mount
/// table as `Router::handle_request` resolves it, after the leading `/`s the
/// ACL ignores too. An ambiguous name is an error (no key is derived).
pub(crate) fn resolve(router: &Router, path: &str) -> Result<Option<KvItem>, RvError> {
    Ok(match target(router, path)? {
        KvTarget::Item(item) => Some(item),
        KvTarget::NotKv | KvTarget::NoSecret => None,
    })
}

/// Whether `path` is a KV path that names no secret: [`KvTarget::NoSecret`]
/// or a mount-root list. Nobody owns it and no share or group reaches it (T506).
pub(crate) fn names_no_secret(router: &Router, path: &str) -> bool {
    match target(router, path) {
        Ok(KvTarget::NoSecret) => true,
        Ok(KvTarget::Item(item)) => item.key().is_none(),
        Ok(KvTarget::NotKv) | Err(_) => false,
    }
}

/// Whether `item`'s owner and share key, as a request to `path` derives it,
/// changes when the T499 switch happens (T511): a record written under the old
/// key before then would be left behind. See `docs/api.md` for which names.
pub(crate) fn key_moves(item: &KvItem, path: &str, ns: Option<&str>) -> bool {
    owner_key(Some(item), path, ns, false) != owner_key(Some(item), path, ns, true)
}

/// The owner and share key of the secret `path` addresses. With `split` (the
/// T499 datafix has run) it is [`KvItem::key`]; before that, and for any
/// path that is not a KV secret, the pre-T499 key, so records keep resolving.
pub(crate) fn owner_key(item: Option<&KvItem>, path: &str, ns: Option<&str>, split: bool) -> Option<String> {
    match item {
        Some(item) if split => item.key().or_else(|| OwnerStore::legacy_kv_key(path, ns)),
        Some(item) => item.legacy_key(path, ns),
        None => OwnerStore::legacy_kv_key(path, ns),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v2(rel: &str) -> Option<KvItem> {
        KvItem::from_route("secret/", "kv-v2", rel).unwrap()
    }

    #[test]
    fn a_kv_v2_path_loses_exactly_one_sub_command() {
        let cases = [
            ("data/x", "secret/x"),
            ("x", "secret/x"),
            ("metadata/x", "secret/x"),
            ("destroy/x", "secret/x"),
            ("undelete/x", "secret/x"),
            ("data/data/x", "secret/data/x"),
            ("metadata/data/x", "secret/data/x"),
            ("data/metadata/x", "secret/metadata/x"),
            ("data/data/data/x", "secret/data/data/x"),
            ("metadata/team/", "secret/team"),
            ("data/delete/x", "secret/delete/x"),
            ("delete/x", "secret/delete/x"),
        ];
        for (rel, key) in cases {
            assert_eq!(v2(rel).and_then(|i| i.key()).as_deref(), Some(key), "{rel}");
        }
        for rel in ["config", "metadatafoo", "configs/x", "", "data/"] {
            assert_eq!(v2(rel).and_then(|i| i.key()), None, "{rel}");
        }
        for rel in ["metadata/", "metadata"] {
            assert!(v2(rel).is_some_and(|i| i.key().is_none()), "{rel}: the root list is an item without a key");
        }
    }

    // A name the engine would store under another spelling than its trimmed
    // form gets no key: an empty or `..` segment, a doubled trailing `/`,
    // surrounding whitespace.
    #[test]
    fn an_ambiguous_name_is_refused() {
        for rel in ["data//x", "/x", "data/x//", "data/a//b", "data/a/../b", "metadata//", "data/x ", " x", "data//"] {
            assert!(KvItem::from_route("secret/", "kv-v2", rel).is_err(), "kv-v2 {rel:?}");
        }
        for rel in ["/x", "x//", "a//b", "x ", "/"] {
            let refusal = KvItem::from_route("kv/", "kv", rel).unwrap_err();
            assert!(is_ambiguous(&refusal), "kv {rel:?}: {refusal:?}");
        }
        assert!(!is_ambiguous(&RvError::ErrRwLockReadPoison));
        assert!(!is_ambiguous(&RvError::ErrResponseStatus(400, "another 400".into())));
        let list = v2("metadata/team/").unwrap();
        assert!(list.folder() && list.key().as_deref() == Some("secret/team"));
        assert!(KvItem::from_route("kv/", "kv", "").unwrap().is_none(), "the kv root list names no secret");
    }

    /// Which request paths move at the T499 switch, as `docs/api.md` lists
    /// them: `(router mount, engine, rel, namespace, moves)`.
    #[test]
    fn the_keys_that_move_at_the_switch() {
        let cases = [
            ("secret/", "kv-v2", "data/x", None, false),
            ("secret/", "kv-v2", "x", None, false),
            ("secret/", "kv-v2", "data/data/x", None, true),
            ("secret/", "kv-v2", "metadata/metadata/x", None, true),
            ("secret/", "kv-v2", "destroy/data/x", None, true),
            ("secret/", "kv-v2", "data/data", None, true),
            ("secret/", "kv-v2", "data/database/x", None, false),
            ("team/kv/", "kv-v2", "data/x", None, true),
            ("team/kv/", "kv-v2", "metadata/x", None, true),
            ("team/kv/", "kv-v2", "undelete/x", None, true),
            ("team/kv/", "kv-v2", "x", None, false),
            ("team/secret/", "kv-v2", "data/data/x", Some("team"), false),
            ("team/kv/x/", "kv-v2", "data/y", Some("team"), true),
            ("team/data/secret/", "kv-v2", "x", Some("team/data"), true),
            ("team/data/secret/", "kv-v2", "data/x", Some("team/data"), true),
            ("kv/", "kv", "x", None, false),
            ("kv/", "kv", "data/x", None, true),
            ("team/kv/", "kv", "data/x", Some("team"), true),
            ("a/b/", "kv", "data/x", None, false),
        ];
        for (mount, engine, rel, ns, moves) in cases {
            let item = KvItem::from_route(mount, engine, rel).unwrap().unwrap();
            assert_eq!(key_moves(&item, &format!("{mount}{rel}"), ns), moves, "{mount}{rel} in {ns:?}");
        }
    }

    #[test]
    fn a_kv_v1_path_is_the_name_verbatim() {
        for (rel, key) in [("x", "kv/x"), ("data/x", "kv/data/x"), ("metadata/data/x", "kv/metadata/data/x")] {
            let item = KvItem::from_route("kv/", "kv", rel).unwrap().unwrap();
            assert_eq!(item.key().as_deref(), Some(key));
            assert!(item.deny_aliases(false).is_empty());
        }
        assert_eq!(KvItem::from_route("transit/", "transit", "keys/x").unwrap(), None);
    }

    // Every spelling of one secret gives one key, `<mount><name>`, and two
    // secrets never share one: `data/x` is not `x`.
    #[test]
    fn one_key_per_secret() {
        for name in ["x", "team/x", "delete/x", "data/x", "metadata/x", "data/data/x"] {
            let key = format!("secret/{name}");
            for rel in [format!("data/{name}"), format!("metadata/{name}"), format!("destroy/{name}")] {
                assert_eq!(v2(&rel).unwrap().key().as_deref(), Some(key.as_str()), "{rel}");
            }
        }
        assert_ne!(v2("data/data/x").unwrap().key(), v2("data/x").unwrap().key());
    }

    #[test]
    fn the_legacy_key_is_the_pre_t499_one_except_for_destroy_and_undelete() {
        let legacy = |rel: &str| v2(rel).unwrap().legacy_key(&format!("secret/{rel}"), None);
        assert_eq!(legacy("data/data/x").as_deref(), Some("secret/x"), "the collision the datafix resolves");
        assert_eq!(legacy("x").as_deref(), Some("secret/x"));
        assert_eq!(legacy("destroy/x").as_deref(), Some("secret/x"));
        assert_eq!(legacy("undelete/team/x").as_deref(), Some("secret/team/x"));
        let ns = KvItem::from_route("team/secret/", "kv-v2", "data/data/x").unwrap().unwrap();
        assert_eq!(ns.legacy_key("team/secret/data/data/x", Some("team")).as_deref(), Some("team/secret/data/x"));
        assert_eq!(ns.key().as_deref(), Some("team/secret/data/x"));
    }

    #[test]
    fn deny_aliases_name_both_data_forms() {
        let aliases = |rel: &str, list: bool| -> Vec<String> {
            v2(rel).unwrap().deny_aliases(list).into_iter().map(|(a, _)| a).collect()
        };
        assert_eq!(aliases("x", false), ["secret/x", "secret/data/x"]);
        assert_eq!(aliases("metadata/prod/x", false), ["secret/prod/x", "secret/data/prod/x"]);
        assert_eq!(aliases("metadata/prod/", true), ["secret/prod/", "secret/data/prod/"]);
        assert_eq!(aliases("metadata/prod", true), ["secret/prod/", "secret/data/prod/"]);
        assert_eq!(aliases("metadata/", true), ["secret/", "secret/data/"]);
        assert_eq!(aliases("metadata", true), ["secret/", "secret/data/"]);
        assert_eq!(aliases("destroy/prod/x", false), ["secret/prod/x", "secret/data/prod/x"]);
        let offsets: Vec<usize> =
            v2("data/prod/x").unwrap().deny_aliases(false).into_iter().map(|(_, at)| at).collect();
        assert_eq!(offsets, [7, 12]);
        assert_eq!(v2("data/prod/x").unwrap().name_at(), 12);
        assert_eq!(v2("prod/x").unwrap().name_at(), 7);
    }

    #[test]
    fn owner_key_follows_the_split_flag() {
        let item = v2("data/data/x");
        assert_eq!(owner_key(item.as_ref(), "secret/data/data/x", None, true).as_deref(), Some("secret/data/x"));
        assert_eq!(owner_key(item.as_ref(), "secret/data/data/x", None, false).as_deref(), Some("secret/x"));
        assert_eq!(owner_key(None, "transit/keys/data/k", None, true).as_deref(), Some("transit/keys/data/k"));
        let root_list = v2("metadata/");
        assert_eq!(owner_key(root_list.as_ref(), "secret/metadata/", None, true).as_deref(), Some("secret"));
    }
}
