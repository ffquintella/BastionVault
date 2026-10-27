//! The resource type configuration a request is governed by.
//!
//! Every resource mount keeps its own `config/types`, and a child namespace
//! has its own `resources/` mount. A namespace that has never saved a type
//! configuration inherits the **root namespace's** saved one: Settings, where
//! the types are edited, is a root-namespace page, so without the fallback no
//! resource in a child namespace could ever be opted in to web credential
//! release (`features/web-application-connect.md` §6).
//!
//! The fallback is all-or-nothing. A namespace that has saved *any*
//! configuration is authoritative — no per-type fallback — so a tenant that
//! leaves a type out, or leaves its `web_exposure_max` unset, denies even
//! where the root opts in. Only the root namespace's well-known resource mount
//! is consulted, and only when it is exactly a `resource` mount that is not
//! tainted; anything else is "nothing saved", which denies.

use serde_json::{Map, Value};

use crate::{errors::RvError, kernel_api::VaultCtx, logical::Request, storage::Storage};

/// Storage key of the type configuration inside a resource mount.
pub const TYPE_CONFIG_KEY: &str = "config/types";

/// The root namespace's resource mount: the default mount every namespace
/// gets, and the one the GUI's Settings page writes.
pub const ROOT_RESOURCE_MOUNT: &str = "resources/";

/// Logical type the resource engine registers under.
const RESOURCE_LOGICAL_TYPE: &str = "resource";

/// Where the effective type configuration was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeConfigSource {
    /// The request's own mount (the namespace's, or the root's for a
    /// root-namespace request).
    Mount,
    /// The namespace saved nothing; the root namespace's configuration applies.
    Root,
    /// Nothing saved in either place.
    None,
}

impl TypeConfigSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Mount => "mount",
            Self::Root => "root",
            Self::None => "none",
        }
    }
}

#[derive(Debug)]
pub enum TypeConfigError {
    Storage(RvError),
    /// The stored configuration is not a JSON object.
    Malformed(TypeConfigSource),
}

#[derive(Debug)]
pub struct EffectiveTypeConfig {
    pub source: TypeConfigSource,
    /// `None` exactly when `source` is [`TypeConfigSource::None`].
    pub types: Option<Map<String, Value>>,
}

impl EffectiveTypeConfig {
    /// The entry for `type_id`, if the effective configuration has one.
    pub fn type_def(&self, type_id: &str) -> Option<&Value> {
        self.types.as_ref().and_then(|t| t.get(type_id))
    }
}

fn parse(bytes: &[u8], source: TypeConfigSource) -> Result<Map<String, Value>, TypeConfigError> {
    serde_json::from_slice(bytes).map_err(|_| TypeConfigError::Malformed(source))
}

/// Read the type configuration `req` is governed by: the request mount's own,
/// or — for a child-namespace request whose mount has none — the root's.
#[maybe_async::maybe_async]
pub async fn effective_type_config(core: &dyn VaultCtx, req: &Request) -> Result<EffectiveTypeConfig, TypeConfigError> {
    let storage = req.storage.clone().ok_or(TypeConfigError::Storage(RvError::ErrRequestNotReady))?;
    let in_child_namespace = req.namespace_path.as_deref().is_some_and(|ns| !ns.is_empty());
    effective_type_config_in(core, storage.as_ref(), in_child_namespace).await
}

/// [`effective_type_config`] over a resource mount's own storage view, for a
/// reader that holds the view rather than a request routed to the mount.
#[maybe_async::maybe_async]
pub async fn effective_type_config_in(
    core: &dyn VaultCtx,
    view: &dyn Storage,
    in_child_namespace: bool,
) -> Result<EffectiveTypeConfig, TypeConfigError> {
    if let Some(entry) = view.get(TYPE_CONFIG_KEY).await.map_err(TypeConfigError::Storage)? {
        let types = parse(&entry.value, TypeConfigSource::Mount)?;
        return Ok(EffectiveTypeConfig { source: TypeConfigSource::Mount, types: Some(types) });
    }
    if !in_child_namespace {
        return Ok(EffectiveTypeConfig { source: TypeConfigSource::None, types: None });
    }
    match read_root_type_config(core).await? {
        Some(types) => Ok(EffectiveTypeConfig { source: TypeConfigSource::Root, types: Some(types) }),
        None => Ok(EffectiveTypeConfig { source: TypeConfigSource::None, types: None }),
    }
}

/// The root namespace's saved configuration, read straight from that mount's
/// barrier view. `None` when the mount is absent, is not exactly the resource
/// engine's root mount, is tainted, or has nothing saved.
#[maybe_async::maybe_async]
async fn read_root_type_config(core: &dyn VaultCtx) -> Result<Option<Map<String, Value>>, TypeConfigError> {
    let router = core.router();
    let probe = format!("{ROOT_RESOURCE_MOUNT}{TYPE_CONFIG_KEY}");
    // A child namespace's mounts are keyed `<ns>/…` in the shared router, so
    // the bare key can only match a root-table mount.
    if router.matching_mount(&probe).map_err(TypeConfigError::Storage)? != ROOT_RESOURCE_MOUNT {
        return Ok(None);
    }
    let Some(mount_entry) = router.matching_mount_entry(&probe).map_err(TypeConfigError::Storage)? else {
        return Ok(None);
    };
    {
        let me = mount_entry.read().map_err(|_| TypeConfigError::Storage(RvError::ErrRequestInvalid))?;
        if me.tainted || me.logical_type != RESOURCE_LOGICAL_TYPE {
            return Ok(None);
        }
    }
    let Some(view) = router.matching_view(&probe).map_err(TypeConfigError::Storage)? else {
        return Ok(None);
    };
    match view.get(TYPE_CONFIG_KEY).await.map_err(TypeConfigError::Storage)? {
        Some(entry) => parse(&entry.value, TypeConfigSource::Root).map(Some),
        None => Ok(None),
    }
}
