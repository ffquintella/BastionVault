//! Transfer import routes are authorized as the item they write (T494).
//!
//! `<kv-v2 mount>/v2/transfer/import/<path>` and `<resource mount>/v2/transfer/import/<name>`
//! each write one whole secret or resource. `post_auth` (ACL, owner, share and
//! asset-group lookups), `post_route` (owner stamp) and `sys/capabilities-self`
//! therefore use the path a normal write of that item is authorized on, never
//! the route's own path. Every other path is left alone.

use crate::{errors::RvError, logical::Response, router::Router};

/// The mount-relative prefix both engines serve the import under.
const IMPORT_ROUTE: &str = "v2/transfer/import/";

/// `Router::handle_request` prepends `data/` to a kv-v2 path at API version 2
/// unless it starts with one of these. A secret whose name does is written
/// through `data/<name>` in both API versions.
const KV_V2_SUBCOMMANDS: [&str; 6] = ["data/", "metadata/", "metadata", "destroy/", "undelete/", "config"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    KvSecret,
    Resource,
}

/// The item a transfer import request writes: its kind, the router mount key
/// (namespace prefix included, e.g. `tenant/secret/`) and the requested name
/// exactly as the engine stores it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ImportTarget {
    kind: Kind,
    mount: String,
    name: String,
}

impl ImportTarget {
    /// The import behind `rel`, the mount-relative path as routed, or `None`.
    /// Mirrors the anchored route patterns: kv-v2 `v2/transfer/import/(?P<name>.+)`
    /// and resource `v2/transfer/import/(?P<name>[^/]+)$`. A resource name is
    /// trimmed and ASCII-lowercased as `plan_resource_import` stores it.
    pub(crate) fn from_route(mount: &str, logical_type: &str, api_version: u8, rel: &str) -> Option<Self> {
        let raw = rel.strip_prefix(IMPORT_ROUTE)?;
        let (kind, name) = match logical_type {
            // At version 2 the router reads this shape as the secret `data/<rel>`.
            "kv-v2" if api_version == 2 => return None,
            // `.` in the route regex stops at a newline, so such a path is not routed there.
            "kv-v2" if raw.is_empty() || raw.contains('\n') => return None,
            "kv-v2" => (Kind::KvSecret, raw.to_string()),
            "resource" if raw.is_empty() || raw.contains('/') => return None,
            "resource" => (Kind::Resource, raw.trim().to_ascii_lowercase()),
            _ => return None,
        };
        Some(Self { kind, mount: mount.to_string(), name })
    }

    /// The path `post_auth` authorizes the import on: the one a normal write of
    /// the requested item is authorized on.
    pub(crate) fn acl_path(&self) -> String {
        self.path_of(&self.name)
    }

    /// The real path of the item the import wrote, from the handler's response
    /// (`path` for KV, `name` for a resource): the requested name, or the
    /// `<name>-<n>` that `on_conflict = rename` picks, which the ACL never saw.
    /// That sibling shares the parent a prefix rule authorized, but an exact-name
    /// rule, a deny on the sibling, or a share or group of the requested item
    /// does not cover it. `None` for any other answer: nothing is stamped then.
    pub(crate) fn written_path(&self, resp: Option<&Response>) -> Option<String> {
        let field = match self.kind {
            Kind::KvSecret => "path",
            Kind::Resource => "name",
        };
        let written = resp?.data.as_ref()?.get(field)?.as_str()?;
        let renamed = written
            .strip_prefix(self.name.as_str())
            .and_then(|rest| rest.strip_prefix('-'))
            .is_some_and(|n| !n.is_empty() && !n.starts_with('0') && n.bytes().all(|b| b.is_ascii_digit()));
        (written == self.name || renamed).then(|| self.path_of(written))
    }

    /// The path a normal write of `name` under this mount is authorized on. KV:
    /// `<mount><name>`, the API version 2 form, which the owner and share keys
    /// canonicalize to; `<mount>data/<name>` when the name would read as a
    /// sub-command. Resource: `<mount>resources/<name>`.
    fn path_of(&self, name: &str) -> String {
        match self.kind {
            Kind::KvSecret if KV_V2_SUBCOMMANDS.iter().any(|c| name.starts_with(c)) => {
                format!("{}data/{name}", self.mount)
            }
            Kind::KvSecret => format!("{}{name}", self.mount),
            Kind::Resource => format!("{}resources/{name}", self.mount),
        }
    }
}

/// The import a request to `path` at `api_version` reaches, resolved through
/// the router's mount table as `Router::handle_request` resolves it.
pub(crate) fn resolve(router: &Router, path: &str, api_version: u8) -> Result<Option<ImportTarget>, RvError> {
    let mount = router.matching_mount(path)?;
    let Some(rel) = path.strip_prefix(mount.as_str()).filter(|_| !mount.is_empty()) else {
        return Ok(None);
    };
    let Some(entry) = router.matching_mount_entry(&mount)? else {
        return Ok(None);
    };
    let logical_type = entry.read()?.logical_type.clone();
    Ok(ImportTarget::from_route(&mount, &logical_type, api_version, rel))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn target(mount: &str, logical_type: &str, rel: &str) -> Option<String> {
        ImportTarget::from_route(mount, logical_type, 1, rel).map(|t| t.acl_path())
    }

    #[test]
    fn maps_only_the_two_import_routes_to_their_real_item() {
        assert_eq!(target("secret/", "kv-v2", "v2/transfer/import/team/db").as_deref(), Some("secret/team/db"));
        assert_eq!(target("tenant/secret/", "kv-v2", "v2/transfer/import/x").as_deref(), Some("tenant/secret/x"));
        assert_eq!(
            target("resources/", "resource", "v2/transfer/import/db1").as_deref(),
            Some("resources/resources/db1")
        );
        assert_eq!(
            target("tenant/resources/", "resource", "v2/transfer/import/ DB1 ").as_deref(),
            Some("tenant/resources/resources/db1"),
            "trimmed and lower-cased as the engine stores it"
        );

        // The suffix must be exactly the route: not a substring, not another shape.
        for rel in
            ["data/v2/transfer/import/x", "xv2/transfer/import/x", "v2/transfer/import/", "v2/transfer/importx/y"]
        {
            assert_eq!(target("secret/", "kv-v2", rel), None, "{rel}");
        }
        assert_eq!(target("secret/", "kv-v2", "v2/transfer/import/a\nb"), None, "not routed there");
        assert_eq!(target("resources/", "resource", "v2/transfer/import/a/b"), None, "not routed there");
        assert_eq!(target("resources/", "resource", "resources/db1"), None);
        // Other engines, and KV v1, have no import route.
        assert_eq!(target("kv/", "kv", "v2/transfer/import/x"), None);
        assert_eq!(target("files/", "files", "v2/transfer/import/x"), None);
        // At API version 2 a kv-v2 mount reads the shape as a secret name.
        assert_eq!(ImportTarget::from_route("secret/", "kv-v2", 2, "v2/transfer/import/x"), None);
        let resource = ImportTarget::from_route("resources/", "resource", 2, "v2/transfer/import/db1");
        assert_eq!(resource.map(|t| t.acl_path()).as_deref(), Some("resources/resources/db1"));
    }

    #[test]
    fn a_kv_name_that_reads_as_a_sub_command_is_checked_under_data() {
        for name in ["data/x", "metadata/x", "metadata", "config", "configs/x", "destroy/x", "undelete/x"] {
            let got = target("secret/", "kv-v2", &format!("v2/transfer/import/{name}"));
            assert_eq!(got, Some(format!("secret/data/{name}")), "{name}");
        }
        assert_eq!(target("secret/", "kv-v2", "v2/transfer/import/destroyer/x").as_deref(), Some("secret/destroyer/x"));
    }

    #[test]
    fn the_written_path_is_the_requested_name_or_its_rename() {
        let resp = |field: &str, value: &str| Response::data_response(json!({ field: value }).as_object().cloned());
        let kv = ImportTarget::from_route("secret/", "kv-v2", 1, "v2/transfer/import/team/db").unwrap();
        assert_eq!(kv.written_path(Some(&resp("path", "team/db"))).as_deref(), Some("secret/team/db"));
        assert_eq!(kv.written_path(Some(&resp("path", "team/db-2"))).as_deref(), Some("secret/team/db-2"));
        assert_eq!(kv.written_path(Some(&resp("path", "team/db-1000"))).as_deref(), Some("secret/team/db-1000"));
        for other in ["team/other", "team/db-", "team/db-02", "team/db-x", "team/db-2/x", "team/db2", "db"] {
            assert_eq!(kv.written_path(Some(&resp("path", other))), None, "{other}");
        }
        assert_eq!(kv.written_path(Some(&resp("name", "team/db"))), None, "KV answers with `path`");
        assert_eq!(kv.written_path(None), None);

        let res = ImportTarget::from_route("resources/", "resource", 1, "v2/transfer/import/SRV1").unwrap();
        assert_eq!(res.written_path(Some(&resp("name", "srv1-3"))).as_deref(), Some("resources/resources/srv1-3"));
        assert_eq!(res.written_path(Some(&resp("name", "SRV1"))), None, "the engine answers lower-cased");
    }
}
