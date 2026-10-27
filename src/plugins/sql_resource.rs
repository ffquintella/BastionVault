//! The resource engine's half of `resource_sql_target` and
//! `resource_sql_credential` (features/sql-browser.md §5.4, §6.6, §9.5):
//! the [`SqlResourceSource`] the host installs at assembly. Reads go to the
//! caller's namespace's `resources/` mount view under the server's own
//! authority, after the host has checked the caller's SQL privilege.
//! The effective transport is Rustion's own resolver over its stored tiers,
//! read here because the resource engine may not name another engine.

use std::sync::Arc;

use serde_json::{json, Value};

use super::sql_host::{SqlFuture, SqlReleaseMaterial, SqlResourceSource};
use crate::{
    errors::RvError,
    kernel_api::VaultCtx,
    modules::resource::{
        sql_profile::{reason, SqlRefusal},
        sql_resource::{self as engine, SqlResourceRecord},
    },
    storage::barrier_view::BarrierView,
};

/// The logical type the resource engine registers under, and its mount.
const RESOURCE_LOGICAL_TYPE: &str = "resource";
const RESOURCE_MOUNT: &str = "resources/";

/// The production seam: the resource engine's `sql` protocol.
pub struct ResourceEngineSqlSource;

fn mount_unavailable(detail: impl std::fmt::Display) -> RvError {
    SqlRefusal::new(503, reason::RESOURCE_MOUNT_UNAVAILABLE, format!("the resources/ mount cannot be read: {detail}"))
        .into_rv()
}

/// The namespace's `resources/` mount view, refused unless it is exactly the
/// resource engine's mount and not mid-unmount. `namespace` is canonical
/// (`""` = root), as the host resolved it.
async fn resource_mount_view(core: &dyn VaultCtx, namespace: &str) -> Result<Arc<BarrierView>, RvError> {
    let prefix = if namespace.is_empty() {
        String::new()
    } else {
        let registry = core.namespaces().ok_or_else(|| mount_unavailable("no namespace registry"))?;
        let ns = registry.resolve(namespace).await?.ok_or_else(|| mount_unavailable("unknown namespace"))?;
        registry.ensure_router(&ns.uuid, &ns.path).await?;
        ns.request_prefix()
    };
    let mount = format!("{prefix}{RESOURCE_MOUNT}");
    let probe = format!("{mount}meta");
    let router = core.router();
    if router.matching_mount(&probe)? != mount {
        return Err(mount_unavailable("no resource mount at this path"));
    }
    let entry = router.matching_mount_entry(&probe)?.ok_or_else(|| mount_unavailable("no mount entry"))?;
    {
        let me = entry.read().map_err(|_| mount_unavailable("mount entry lock poisoned"))?;
        if me.tainted || me.logical_type != RESOURCE_LOGICAL_TYPE {
            return Err(mount_unavailable("the mount is not the resource engine, or is being unmounted"));
        }
    }
    router.matching_view(&probe)?.ok_or_else(|| mount_unavailable("no barrier view"))
}

/// The resource's effective Connect transport and the tier that set it,
/// from Rustion's stored policy tiers and its own resolver (§6.6). A lock
/// violation refuses; an unreadable tier refuses (never "direct").
async fn effective_transport(core: &dyn VaultCtx, rec: &SqlResourceRecord) -> Result<(String, String), RvError> {
    use bv_engine_rustion::policy::{resolve, PolicyStore};
    let unavailable = |e: RvError| {
        SqlRefusal::new(
            503,
            "transport_policy_unavailable",
            format!(
                "cannot resolve the resource's Rustion transport policy ({e}); refusing rather than assuming direct"
            ),
        )
        .into_rv()
    };
    let groups = match core.resource_groups() {
        Some(index) => index.groups_for_resource(&rec.name).await.map_err(unavailable)?,
        None => Vec::new(),
    };
    let store = PolicyStore::new(core).await.map_err(unavailable)?;
    let global = store.get_global().await.map_err(unavailable)?;
    let type_policy = store.get_type(&rec.resource_type).await.map_err(unavailable)?;
    let mut group_policies = Vec::new();
    for g in &groups {
        if let Some(p) = store.get_asset_group(g).await.map_err(unavailable)? {
            group_policies.push(p);
        }
    }
    let resource_policy = store.get_resource(&rec.name).await.map_err(unavailable)?;
    let effective = resolve(&global, type_policy.as_ref(), &group_policies, resource_policy.as_ref());
    if let Some(lv) = effective.lock_violation {
        return Err(SqlRefusal::new(
            403,
            "transport_policy",
            format!("rustion policy lock violation (tier {}): {}", lv.locking_tier, lv.detail),
        )
        .into_rv());
    }
    Ok((effective.transport.as_str().to_string(), effective.transport_source.to_string()))
}

async fn load(
    core: &dyn VaultCtx,
    namespace: &str,
    resource: &str,
) -> Result<(Arc<BarrierView>, SqlResourceRecord), RvError> {
    let view = resource_mount_view(core, namespace).await?;
    let rec = engine::load_sql_resource(core, view.as_ref(), !namespace.is_empty(), resource).await?;
    Ok((view, rec))
}

impl SqlResourceSource for ResourceEngineSqlSource {
    fn sql_target<'a>(&'a self, core: &'a dyn VaultCtx, namespace: &'a str, resource: &'a str) -> SqlFuture<'a, Value> {
        Box::pin(async move {
            let (_, rec) = load(core, namespace, resource).await?;
            let mut view = engine::target_view(&rec);
            let (transport, source) = effective_transport(core, &rec).await?;
            view.insert("transport".into(), json!(transport));
            view.insert("transport_source".into(), json!(source));
            Ok(Value::Object(view))
        })
    }

    fn sql_release_material<'a>(
        &'a self,
        core: &'a dyn VaultCtx,
        namespace: &'a str,
        resource: &'a str,
        profile: &'a str,
    ) -> SqlFuture<'a, SqlReleaseMaterial> {
        Box::pin(async move {
            let (view, rec) = load(core, namespace, resource).await?;
            let release = engine::read_release(view.as_ref(), &rec, profile).await?;
            let (transport, transport_source) = effective_transport(core, &rec).await?;
            let engine::SqlRelease { profile, endpoint, secret_id, login } = release;
            Ok(SqlReleaseMaterial {
                protocol: crate::modules::resource::sql_profile::SQL_PROTOCOL.to_string(),
                endpoint,
                transport,
                transport_source,
                secret_id,
                sql_endpoint: login.sql_endpoint,
                username: login.username,
                password: login.password,
                require_mfa: profile.require_mfa,
            })
        })
    }
}
