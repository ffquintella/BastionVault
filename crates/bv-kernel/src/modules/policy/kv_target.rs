//! The KV secret a request path addresses (T499).
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
}

impl KvItem {
    /// The item behind `rel`, the path below `mount` as requested, or `None`
    /// when the mount is not a KV engine or `rel` names no secret (kv-v2
    /// `config`, an unroutable sub-command, `..`). Independent of the API
    /// version: a version 2 short form `x` is the version 1 `data/x`.
    pub(crate) fn from_route(mount: &str, logical_type: &str, rel: &str) -> Option<Self> {
        let (engine, sub, raw) = match logical_type {
            "kv" => (Engine::V1, None, rel),
            "kv-v2" => {
                let (sub, raw) = classify_v2(rel)?;
                (Engine::V2, Some(sub), raw)
            }
            _ => return None,
        };
        let name = raw.trim_matches('/');
        if name.split('/').any(|s| s == "..") {
            return None;
        }
        if name.is_empty() && sub != Some(KvSub::Metadata) {
            return None;
        }
        Some(Self { engine, mount: mount.to_string(), sub, name: name.to_string() })
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
}

/// The sub-command and the rest of a kv-v2 path, as the router and the
/// engine's routes read it. `None` for `config`, the `metadata` list root
/// without its `/`, and paths no route serves.
fn classify_v2(rel: &str) -> Option<(KvSub, &str)> {
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

/// The KV item a request to `path` addresses, through the router's mount
/// table as `Router::handle_request` resolves it.
pub(crate) fn resolve(router: &Router, path: &str) -> Result<Option<KvItem>, RvError> {
    let path = path.strip_prefix('/').unwrap_or(path);
    let mount = router.matching_mount(path)?;
    let Some(rel) = path.strip_prefix(mount.as_str()).filter(|_| !mount.is_empty()) else {
        return Ok(None);
    };
    let Some(entry) = router.matching_mount_entry(&mount)? else {
        return Ok(None);
    };
    let logical_type = entry.read()?.logical_type.clone();
    Ok(KvItem::from_route(&mount, &logical_type, rel))
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
        KvItem::from_route("secret/", "kv-v2", rel)
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
        for rel in ["config", "metadata", "metadatafoo", "configs/x", "", "data/", "data/a/../b"] {
            assert_eq!(v2(rel).and_then(|i| i.key()), None, "{rel}");
        }
        assert!(v2("metadata/").is_some(), "the mount-root list is an item without a key");
    }

    #[test]
    fn a_kv_v1_path_is_the_name_verbatim() {
        for (rel, key) in [("x", "kv/x"), ("data/x", "kv/data/x"), ("metadata/data/x", "kv/metadata/data/x")] {
            let item = KvItem::from_route("kv/", "kv", rel).unwrap();
            assert_eq!(item.key().as_deref(), Some(key));
        }
        assert_eq!(KvItem::from_route("transit/", "transit", "keys/x"), None);
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
        let ns = KvItem::from_route("team/secret/", "kv-v2", "data/data/x").unwrap();
        assert_eq!(ns.legacy_key("team/secret/data/data/x", Some("team")).as_deref(), Some("team/secret/data/x"));
        assert_eq!(ns.key().as_deref(), Some("team/secret/data/x"));
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
