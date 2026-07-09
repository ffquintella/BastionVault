//! Barrier-encrypted plugin catalog with versioning.
//!
//! Phase 3 introduces multi-version registration: a single plugin
//! `name` can carry several registered `version`s, with one of them
//! marked `active`. Operators stage new versions, smoke-test via the
//! invoke endpoint, then activate when ready. The previously-active
//! version stays registered and can be re-activated for a roll-back.
//!
//! Storage layout (Phase 3):
//! ```text
//! core/plugins/<name>/versions/<version>/manifest   — PluginManifest JSON
//! core/plugins/<name>/versions/<version>/binary     — raw plugin bytes
//! core/plugins/<name>/active                        — single string: active version
//! core/plugins/<name>/config                        — operator-set config (one set per name)
//! core/plugins/<name>/data/...                      — plugin's own storage scope (one set per name)
//! ```
//!
//! Config + the plugin's data slot are **per-name, not per-version**
//! by design: switching to a new version of a plugin shouldn't lose
//! its configured endpoint URL or its accumulated state. If a version
//! genuinely needs to break compatibility on its config schema, the
//! operator re-registers under a different `name`.
//!
//! ## Backward-compatible reads
//!
//! Phase-1/2 plugins were stored at the un-versioned paths
//! `core/plugins/<name>/{manifest,binary}` with no `active` pointer.
//! [`PluginCatalog::get`] / `get_manifest` / `list` transparently fall
//! back to those paths when no `active` pointer is present, so
//! existing registrations keep working without operator action.
//!
//! New `put` calls always write the versioned layout. The first
//! `put` after upgrading from Phase 1/2 will leave the legacy entries
//! in place; they are unreachable through the catalog API once the
//! new versioned entry exists, so the operator can clean them up
//! manually when convenient.

use bv_plugin_surface::{
    ActiveSurfaceBundle, ActiveSurfaceEntry, AppModuleRef, SurfaceGrant, SurfaceManifest,
};
use sha2::{Digest, Sha256};

use crate::{
    errors::RvError,
    storage::{Storage, StorageEntry},
};

use super::manifest::PluginManifest;

pub const PLUGIN_PREFIX: &str = "core/plugins/";

#[derive(Debug, Clone)]
pub struct PluginRecord {
    pub manifest: PluginManifest,
    pub binary: Vec<u8>,
}

#[derive(Default, Clone)]
pub struct PluginCatalog;

impl PluginCatalog {
    pub fn new() -> Self {
        Self
    }

    pub async fn list(&self, storage: &dyn Storage) -> Result<Vec<PluginManifest>, RvError> {
        let names = storage.list(PLUGIN_PREFIX).await?;
        let mut out = Vec::with_capacity(names.len());
        for entry in names {
            // `list` returns either `<name>/` directory entries or
            // bare keys (older code wrote both shapes). Normalise.
            let name = entry.strip_suffix('/').unwrap_or(&entry).to_string();
            if name.is_empty() {
                continue;
            }
            if let Some(manifest) = self.get_manifest(storage, &name).await? {
                out.push(manifest);
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out.dedup_by(|a, b| a.name == b.name);
        Ok(out)
    }

    /// Fetch the active (or only) record for `name`.
    pub async fn get(&self, storage: &dyn Storage, name: &str) -> Result<Option<PluginRecord>, RvError> {
        let manifest = match self.get_manifest(storage, name).await? {
            Some(m) => m,
            None => return Ok(None),
        };
        let bin = match self.read_binary_for(storage, name, &manifest.version).await? {
            Some(b) => b,
            None => return Ok(None),
        };
        Self::verify_integrity(&manifest, &bin)?;
        Ok(Some(PluginRecord { manifest, binary: bin }))
    }

    pub async fn get_manifest(
        &self,
        storage: &dyn Storage,
        name: &str,
    ) -> Result<Option<PluginManifest>, RvError> {
        if let Some(active) = self.read_active(storage, name).await? {
            return self.read_versioned_manifest(storage, name, &active).await;
        }
        // Phase-1/2 fallback: no active pointer; try the un-versioned
        // path the older catalog wrote.
        self.read_legacy_manifest(storage, name).await
    }

    /// Fetch a specific version's record. Used by the GUI's "test this
    /// version before activating" workflow and the activate endpoint.
    pub async fn get_version(
        &self,
        storage: &dyn Storage,
        name: &str,
        version: &str,
    ) -> Result<Option<PluginRecord>, RvError> {
        let manifest = match self.read_versioned_manifest(storage, name, version).await? {
            Some(m) => m,
            None => return Ok(None),
        };
        let bin = match storage.get(&binary_versioned_key(name, version)).await? {
            Some(e) => e.value,
            None => return Ok(None),
        };
        Self::verify_integrity(&manifest, &bin)?;
        Ok(Some(PluginRecord { manifest, binary: bin }))
    }

    /// List every registered version of `name`, sorted ascending.
    pub async fn list_versions(
        &self,
        storage: &dyn Storage,
        name: &str,
    ) -> Result<Vec<PluginManifest>, RvError> {
        let prefix = format!("{}{}/versions/", PLUGIN_PREFIX, name);
        let entries = storage.list(&prefix).await.unwrap_or_default();
        let mut out = Vec::new();
        for entry in entries {
            let version = entry.strip_suffix('/').unwrap_or(&entry).to_string();
            if version.is_empty() {
                continue;
            }
            if let Some(m) = self.read_versioned_manifest(storage, name, &version).await? {
                out.push(m);
            }
        }
        // No `active` pointer + legacy un-versioned record present? Surface it
        // as a single-version list so the GUI doesn't show the plugin as
        // versionless.
        if out.is_empty() {
            if let Some(m) = self.read_legacy_manifest(storage, name).await? {
                out.push(m);
            }
        }
        out.sort_by(|a, b| a.version.cmp(&b.version));
        Ok(out)
    }

    /// Currently-active version string for `name`, if any. Falls back
    /// to the manifest's own `version` field for plugins still on the
    /// legacy un-versioned layout.
    pub async fn get_active_version(
        &self,
        storage: &dyn Storage,
        name: &str,
    ) -> Result<Option<String>, RvError> {
        if let Some(v) = self.read_active(storage, name).await? {
            return Ok(Some(v));
        }
        Ok(self.read_legacy_manifest(storage, name).await?.map(|m| m.version))
    }

    /// Register a new version. Sets `active = manifest.version` if the
    /// plugin is currently un-registered or if no `active` pointer is
    /// present (legacy layout); otherwise leaves the active version
    /// alone so operators can stage without flipping production.
    pub async fn put(
        &self,
        storage: &dyn Storage,
        manifest: &PluginManifest,
        binary: &[u8],
    ) -> Result<(), RvError> {
        manifest.validate().map_err(|_| RvError::ErrRequestInvalid)?;
        Self::verify_integrity(manifest, binary)?;
        // Phase 5.4: host-side ABI version major check. Refuses
        // cross-major manifests (or future-minor manifests against
        // an older host) with a clear error.
        super::manifest::check_abi_compatibility(&manifest.abi_version)
            .map_err(RvError::ErrString)?;
        // Phase 5.5: net allowlist sanity.
        Self::validate_net_allowlist(manifest)?;
        // Phase 5.2: publisher signature verification (or
        // accept_unsigned engine flag).
        super::verifier::verify(storage, manifest, binary).await?;
        // Phase 5.9: refuse capability widening against the currently-
        // active version. Operators who actually want broader caps
        // must DELETE + re-register.
        if let Some(active_version) = self.read_active(storage, &manifest.name).await? {
            if let Some(prev) = self
                .read_versioned_manifest(storage, &manifest.name, &active_version)
                .await?
            {
                Self::check_capability_widening(&prev, manifest)?;
            }
        }
        // Write binary first so a half-failed registration doesn't
        // leave a manifest pointing at nothing.
        storage
            .put(&StorageEntry {
                key: binary_versioned_key(&manifest.name, &manifest.version),
                value: binary.to_vec(),
            })
            .await?;
        let manifest_bytes = serde_json::to_vec(manifest)?;
        storage
            .put(&StorageEntry {
                key: manifest_versioned_key(&manifest.name, &manifest.version),
                value: manifest_bytes,
            })
            .await?;
        // Activate when this is the first registered version (or when
        // we're upgrading from the legacy layout and there's no active
        // pointer yet).
        if self.read_active(storage, &manifest.name).await?.is_none() {
            self.set_active(storage, &manifest.name, &manifest.version).await?;
        }
        // Phase 5.7: clear any quarantine marker — the data prefix
        // preserved by the previous delete is now reachable through
        // the freshly-active version.
        let _ = super::quarantine::clear(storage, &manifest.name).await;
        Ok(())
    }

    /// Phase 5.5 — refuse `allowed_hosts` patterns that defeat the
    /// allowlist. Bare `"*"` is rejected; embedded `*` is allowed only
    /// in the *leading* label (`"*.example.com"` is fine,
    /// `"foo.*.com"` is not). Any host with a `:` is rejected — port
    /// scoping is a separate field that the supervised process runtime
    /// will surface in Phase 5.3.
    fn validate_net_allowlist(manifest: &PluginManifest) -> Result<(), RvError> {
        for h in &manifest.capabilities.allowed_hosts {
            Self::validate_host_pattern(h, "allowed_hosts")?;
        }
        // Extensibility v2: the app-module network request is validated
        // with the identical host rules — one source of truth.
        if let Some(net) = &manifest.capabilities.app.net {
            for h in &net.hosts {
                Self::validate_host_pattern(h, "capabilities.app.net.hosts")?;
            }
        }
        Ok(())
    }

    /// Shared per-host allowlist rule used by both `allowed_hosts` and
    /// `capabilities.app.net.hosts`. Bare `*` is rejected; embedded `*`
    /// is allowed only in the *leading* label (`"*.example.com"` is
    /// fine, `"foo.*.com"` is not); any `:` (a port) is rejected.
    /// `field` names the offending list in the error message.
    fn validate_host_pattern(h: &str, field: &str) -> Result<(), RvError> {
        let trimmed = h.trim();
        if trimmed.is_empty() {
            return Err(RvError::ErrString(format!(
                "{field} entries must not be empty"
            )));
        }
        if trimmed == "*" {
            return Err(RvError::ErrString(format!(
                "wildcard `*` is refused in {field}; require an explicit allowlist"
            )));
        }
        if trimmed.contains(':') {
            return Err(RvError::ErrString(format!(
                "{field} entry `{trimmed}` must not include a port",
            )));
        }
        // `*` is allowed only as the entire first label.
        if trimmed.contains('*') {
            let leading_only = trimmed.starts_with("*.") && !trimmed[2..].contains('*');
            if !leading_only {
                return Err(RvError::ErrString(format!(
                    "{field} entry `{trimmed}` may only use `*` as the leading label (`*.example.com`)",
                )));
            }
        }
        Ok(())
    }

    /// Phase 5.9 — refuse capability widening on re-registration.
    /// "Widening" means: enabling `audit_emit` when the previous
    /// version had it off; declaring a `storage_prefix` when the
    /// previous one had none, or moving to a strictly-broader prefix;
    /// adding any `allowed_keys` or `allowed_hosts` entry that wasn't
    /// in the previous set.
    fn check_capability_widening(
        prev: &PluginManifest,
        new: &PluginManifest,
    ) -> Result<(), RvError> {
        let p = &prev.capabilities;
        let n = &new.capabilities;

        if !p.audit_emit && n.audit_emit {
            return Err(RvError::ErrString(
                "capability widening: audit_emit cannot be enabled on re-register; DELETE + re-register"
                    .into(),
            ));
        }
        match (&p.storage_prefix, &n.storage_prefix) {
            (None, Some(_)) => {
                return Err(RvError::ErrString(
                    "capability widening: storage_prefix cannot be added on re-register; DELETE + re-register"
                        .into(),
                ));
            }
            (Some(old), Some(new_prefix)) if !new_prefix.starts_with(old.as_str()) => {
                return Err(RvError::ErrString(format!(
                    "capability widening: storage_prefix `{new_prefix}` is not a sub-prefix of the existing `{old}`",
                )));
            }
            _ => {}
        }
        let prev_keys: std::collections::BTreeSet<&String> = p.allowed_keys.iter().collect();
        for k in &n.allowed_keys {
            if !prev_keys.contains(k) {
                return Err(RvError::ErrString(format!(
                    "capability widening: allowed_keys gained `{k}`; DELETE + re-register",
                )));
            }
        }
        let prev_hosts: std::collections::BTreeSet<&String> = p.allowed_hosts.iter().collect();
        for h in &n.allowed_hosts {
            if !prev_hosts.contains(h) {
                return Err(RvError::ErrString(format!(
                    "capability widening: allowed_hosts gained `{h}`; DELETE + re-register",
                )));
            }
        }

        // Extensibility v2: every `capabilities.app` field is a
        // capability and participates in the widening guard. Enabling a
        // family, raising the window cap, or gaining an api_path / net
        // host all require DELETE + re-register.
        let pa = &p.app;
        let na = &n.app;
        if !pa.dynamic_menus && na.dynamic_menus {
            return Err(RvError::ErrString(
                "capability widening: app.dynamic_menus cannot be enabled on re-register; DELETE + re-register"
                    .into(),
            ));
        }
        if na.windows.max_open > pa.windows.max_open {
            return Err(RvError::ErrString(format!(
                "capability widening: app.windows.max_open raised from {} to {}; DELETE + re-register",
                pa.windows.max_open, na.windows.max_open,
            )));
        }
        let prev_api: std::collections::BTreeSet<&String> = pa.api_paths.iter().collect();
        for path in &na.api_paths {
            if !prev_api.contains(path) {
                return Err(RvError::ErrString(format!(
                    "capability widening: app.api_paths gained `{path}`; DELETE + re-register",
                )));
            }
        }
        let prev_net: std::collections::BTreeSet<&String> = pa
            .net
            .as_ref()
            .map(|c| c.hosts.iter().collect())
            .unwrap_or_default();
        if let Some(new_net) = &na.net {
            for h in &new_net.hosts {
                if !prev_net.contains(h) {
                    return Err(RvError::ErrString(format!(
                        "capability widening: app.net.hosts gained `{h}`; DELETE + re-register",
                    )));
                }
            }
        }
        Ok(())
    }

    /// Switch the active version. Refuses to point at a version that
    /// isn't registered.
    pub async fn set_active(
        &self,
        storage: &dyn Storage,
        name: &str,
        version: &str,
    ) -> Result<(), RvError> {
        if self.read_versioned_manifest(storage, name, version).await?.is_none() {
            return Err(RvError::ErrRequestInvalid);
        }
        storage
            .put(&StorageEntry {
                key: active_key(name),
                value: version.as_bytes().to_vec(),
            })
            .await
    }

    /// Drop a single version. Refuses to delete the active version
    /// (operator must `set_active` to a different version first).
    /// Per-name shared records (config, data) are preserved.
    pub async fn delete_version(
        &self,
        storage: &dyn Storage,
        name: &str,
        version: &str,
    ) -> Result<(), RvError> {
        if let Some(active) = self.read_active(storage, name).await? {
            if active == version {
                return Err(RvError::ErrRequestInvalid);
            }
        }
        let _ = storage.delete(&binary_versioned_key(name, version)).await;
        let _ = storage.delete(&manifest_versioned_key(name, version)).await;
        let _ = storage.delete(&surface_versioned_key(name, version)).await;
        let asset_prefix = format!("{}{}/versions/{}/assets/", PLUGIN_PREFIX, name, version);
        if let Ok(keys) = storage.list(&asset_prefix).await {
            for k in keys {
                let _ = storage.delete(&format!("{asset_prefix}{k}")).await;
            }
        }
        Ok(())
    }

    /// Drop every version of `name` plus the per-name shared records
    /// (active pointer, config). Mirrors the pre-Phase-3 catalog
    /// `delete` semantics so the existing HTTP + GUI delete path
    /// keeps working.
    ///
    /// Phase 5.7: the per-plugin **data prefix**
    /// (`core/plugins/<name>/data/`) is intentionally preserved — a
    /// quarantine marker is written at `core/plugins/engine/quarantine/<name>`
    /// so a re-register of the same name re-attaches to its data.
    /// Mounts that still reference the deleted plugin surface a
    /// "quarantined" error from `PluginLogicalBackend::handle_request`.
    pub async fn delete(&self, storage: &dyn Storage, name: &str) -> Result<(), RvError> {
        // Capture the last-active version *before* deleting the
        // active pointer, so the quarantine record can carry it.
        let last_active = self.read_active(storage, name).await?.unwrap_or_default();

        // Drop every versioned record.
        let prefix = format!("{}{}/versions/", PLUGIN_PREFIX, name);
        if let Ok(entries) = storage.list(&prefix).await {
            for entry in entries {
                let version = entry.strip_suffix('/').unwrap_or(&entry);
                let _ = storage.delete(&binary_versioned_key(name, version)).await;
                let _ = storage.delete(&manifest_versioned_key(name, version)).await;
                let _ = storage.delete(&surface_versioned_key(name, version)).await;
                let asset_prefix =
                    format!("{}{}/versions/{}/assets/", PLUGIN_PREFIX, name, version);
                if let Ok(asset_keys) = storage.list(&asset_prefix).await {
                    for k in asset_keys {
                        let _ = storage.delete(&format!("{asset_prefix}{k}")).await;
                    }
                }
            }
        }
        // Active pointer + legacy entries.
        let _ = storage.delete(&active_key(name)).await;
        let _ = storage.delete(&legacy_binary_key(name)).await;
        let _ = storage.delete(&legacy_manifest_key(name)).await;
        // Config (per-name; ConfigStore.delete is the canonical path
        // but that's a separate module — replicate the prefix here).
        let _ = storage.delete(&format!("{}{}{}", PLUGIN_PREFIX, name, "/config")).await;
        // Note: we deliberately do NOT touch the data prefix
        // `core/plugins/<name>/data/` — that's the operator's secret
        // material and the whole point of the quarantine model.
        let _ = super::quarantine::quarantine(storage, name, "", &last_active).await;
        // Phase 5.3: tear down any long-lived supervised child so a
        // re-register doesn't inherit a wedged process from the
        // previous version.
        super::process_supervisor::shutdown_for(name).await;
        Ok(())
    }

    /// Recompute sha256 over the raw binary bytes and compare with
    /// the manifest's declared digest. Also asserts size.
    pub fn verify_integrity(manifest: &PluginManifest, binary: &[u8]) -> Result<(), RvError> {
        if (binary.len() as u64) != manifest.size {
            return Err(RvError::ErrRequestInvalid);
        }
        let mut hasher = Sha256::new();
        hasher.update(binary);
        let computed = hasher.finalize();
        let expected = match hex_decode(&manifest.sha256) {
            Some(b) => b,
            None => return Err(RvError::ErrRequestInvalid),
        };
        if computed.as_slice() != expected.as_slice() {
            return Err(RvError::ErrRequestInvalid);
        }
        Ok(())
    }

    // ── Plugin Extensibility v1: surface + client assets ─────────────────

    /// Plugin Extensibility v1 — register or replace the surface JSON
    /// for a (name, version). The caller passes the raw bytes the
    /// operator uploaded; we recompute the SHA-256 and cross-check
    /// against `manifest.surface.sha256` so a tampered surface can't
    /// sneak past the bundle.
    ///
    /// Stored at `core/plugins/<name>/versions/<version>/surface`.
    pub async fn put_surface(
        &self,
        storage: &dyn Storage,
        name: &str,
        version: &str,
        surface_bytes: &[u8],
        expected_sha256: &str,
    ) -> Result<(), RvError> {
        let mut hasher = Sha256::new();
        hasher.update(surface_bytes);
        let computed = hasher.finalize();
        let computed_hex: String = computed.iter().map(|b| format!("{b:02x}")).collect();
        if computed_hex != expected_sha256 {
            return Err(RvError::ErrString(format!(
                "surface sha256 mismatch: manifest declares `{expected_sha256}` but uploaded bytes hash to `{computed_hex}`"
            )));
        }
        // Ensure the bytes are valid surface JSON before persisting.
        // A bad surface should fail registration, not surface 500s on
        // every later read.
        let parsed: SurfaceManifest = serde_json::from_slice(surface_bytes).map_err(|e| {
            RvError::ErrString(format!("surface.json is not a valid SurfaceManifest: {e}"))
        })?;
        // Names of declared client assets, for hook-reference checks.
        // We don't have the manifest here — caller is expected to have
        // validated against `manifest.client_assets` already; pass an
        // empty set so hook references that are present fall back to
        // the asset-store check at GET time.
        let asset_names: std::collections::BTreeSet<&str> =
            std::collections::BTreeSet::new();
        if let Err(e) = parsed.validate(name, &asset_names) {
            return Err(RvError::ErrString(format!("surface.json failed validation: {e}")));
        }
        storage
            .put(&StorageEntry {
                key: surface_versioned_key(name, version),
                value: surface_bytes.to_vec(),
            })
            .await
    }

    /// Read the surface JSON for the active version of `name`.
    /// Returns `None` when the plugin has no surface or no active
    /// version. Recomputes the SHA-256 and refuses to serve a surface
    /// whose bytes don't match `manifest.surface.sha256` — a defensive
    /// bound around storage tampering.
    pub async fn read_active_surface(
        &self,
        storage: &dyn Storage,
        name: &str,
    ) -> Result<Option<(PluginManifest, Vec<u8>)>, RvError> {
        let manifest = match self.get_manifest(storage, name).await? {
            Some(m) => m,
            None => return Ok(None),
        };
        let surface_ref = match &manifest.surface {
            Some(s) => s.clone(),
            None => return Ok(None),
        };
        let key = surface_versioned_key(&manifest.name, &manifest.version);
        let bytes = match storage.get(&key).await? {
            Some(e) => e.value,
            None => return Ok(None),
        };
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let computed: String = hasher.finalize().iter().map(|b| format!("{b:02x}")).collect();
        if computed != surface_ref.sha256 {
            return Err(RvError::ErrString(format!(
                "stored surface for `{name}` v{} hashes to `{computed}` but manifest declares `{}`",
                manifest.version, surface_ref.sha256
            )));
        }
        Ok(Some((manifest, bytes)))
    }

    /// Plugin Extensibility v1 — store one client asset under
    /// `core/plugins/<name>/versions/<version>/assets/<sha256>`.
    /// Content-addressed: the sha256 is the storage key, so re-uploading
    /// the same asset across versions is a no-op rather than a
    /// duplicated copy.
    pub async fn put_asset(
        &self,
        storage: &dyn Storage,
        name: &str,
        version: &str,
        bytes: &[u8],
        expected_sha256: &str,
    ) -> Result<(), RvError> {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let computed: String = hasher.finalize().iter().map(|b| format!("{b:02x}")).collect();
        if computed != expected_sha256 {
            return Err(RvError::ErrString(format!(
                "asset sha256 mismatch: manifest declares `{expected_sha256}` but uploaded bytes hash to `{computed}`"
            )));
        }
        storage
            .put(&StorageEntry {
                key: asset_versioned_key(name, version, expected_sha256),
                value: bytes.to_vec(),
            })
            .await
    }

    /// Read one client asset by its content hash. Used by the
    /// `GET /v1/sys/plugins/<name>/<version>/asset/<sha256>` endpoint.
    /// We re-verify the hash on read so a tampered storage layer
    /// can't substitute one asset for another.
    pub async fn read_asset(
        &self,
        storage: &dyn Storage,
        name: &str,
        version: &str,
        sha256: &str,
    ) -> Result<Option<Vec<u8>>, RvError> {
        let bytes = match storage.get(&asset_versioned_key(name, version, sha256)).await? {
            Some(e) => e.value,
            None => return Ok(None),
        };
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let computed: String = hasher.finalize().iter().map(|b| format!("{b:02x}")).collect();
        if computed != sha256 {
            return Err(RvError::ErrString(format!(
                "stored asset for `{name}` v{version} hashes to `{computed}` but request asked for `{sha256}`"
            )));
        }
        Ok(Some(bytes))
    }

    /// Plugin Extensibility v1 — assemble the aggregated surface
    /// bundle that `GET /v1/sys/plugins/active-surfaces` returns.
    /// Walks every registered plugin, picks up the active version's
    /// surface (if any), and parses it into the typed
    /// [`SurfaceManifest`]. Plugins without a surface are skipped.
    ///
    /// `mount_for_plugin` resolves a plugin name to its mount path —
    /// passed as a closure so callers can wire it to whatever
    /// router/registry knows about mounts. When `None` is returned,
    /// the entry's `mount` is set to the empty string and the GUI
    /// renderer skips bindings that depend on `{mount}` (a future
    /// improvement: drop the entry entirely).
    pub async fn aggregated_active_surfaces<F>(
        &self,
        storage: &dyn Storage,
        mut mount_for_plugin: F,
    ) -> Result<ActiveSurfaceBundle, RvError>
    where
        F: FnMut(&str) -> Option<String>,
    {
        let manifests = self.list(storage).await?;
        let mut entries: Vec<ActiveSurfaceEntry> = Vec::new();
        for m in manifests {
            let surface_ref = match &m.surface {
                Some(s) => s.clone(),
                None => continue,
            };
            let bytes = match storage.get(&surface_versioned_key(&m.name, &m.version)).await? {
                Some(e) => e.value,
                None => continue,
            };
            // Hash check.
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            let computed: String = hasher.finalize().iter().map(|b| format!("{b:02x}")).collect();
            if computed != surface_ref.sha256 {
                // Skip rather than fail the whole bundle — one
                // tampered plugin shouldn't take down everyone's GUI.
                continue;
            }
            let parsed: SurfaceManifest = match serde_json::from_slice(&bytes) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let assets: Vec<(String, String)> = m
                .client_assets
                .iter()
                .map(|a| (a.name.clone(), a.sha256.clone()))
                .collect();
            // Extensibility v2: ship the plugin's *live* network grant
            // in-band. `active_net_hosts` returns the granted hosts only
            // when the grant's pin still matches the active manifest's
            // net request — a stale grant (changed/revoked capability)
            // yields `None`, so the client sees the plugin as ungranted
            // and revocation propagates through the bundle ETag.
            let grant = super::grants::active_net_hosts(storage, &m.name, &m)
                .await?
                .map(|net_hosts| SurfaceGrant { net_hosts });
            // Extensibility v2 (Phase 2): describe the app module (if any)
            // so the Tauri runtime can fetch + gate it from the bundle
            // alone. Pair the `kind == "app-module"` client asset with the
            // manifest's app-capability gates.
            let app = &m.capabilities.app;
            let app_module = m
                .client_assets
                .iter()
                .find(|a| a.kind == "app-module")
                .map(|a| AppModuleRef {
                    asset_name: a.name.clone(),
                    sha256: a.sha256.clone(),
                    dynamic_menus: app.dynamic_menus,
                    windows_max_open: app.windows.max_open,
                    api_paths: app.api_paths.clone(),
                });
            entries.push(ActiveSurfaceEntry {
                plugin: m.name.clone(),
                version: m.version.clone(),
                mount: mount_for_plugin(&m.name).unwrap_or_default(),
                surface: parsed,
                assets,
                grant,
                app_module,
            });
        }
        let etag = ActiveSurfaceBundle::compute_etag(&entries);
        Ok(ActiveSurfaceBundle { etag, entries })
    }

    // ── Internal helpers ──────────────────────────────────────────────────

    async fn read_active(
        &self,
        storage: &dyn Storage,
        name: &str,
    ) -> Result<Option<String>, RvError> {
        let key = active_key(name);
        match storage.get(&key).await? {
            None => Ok(None),
            Some(entry) => match String::from_utf8(entry.value) {
                Ok(s) if !s.is_empty() => Ok(Some(s)),
                _ => Ok(None),
            },
        }
    }

    async fn read_versioned_manifest(
        &self,
        storage: &dyn Storage,
        name: &str,
        version: &str,
    ) -> Result<Option<PluginManifest>, RvError> {
        match storage.get(&manifest_versioned_key(name, version)).await? {
            None => Ok(None),
            Some(entry) => serde_json::from_slice::<PluginManifest>(&entry.value)
                .map(Some)
                .map_err(|_| RvError::ErrRequestInvalid),
        }
    }

    async fn read_legacy_manifest(
        &self,
        storage: &dyn Storage,
        name: &str,
    ) -> Result<Option<PluginManifest>, RvError> {
        match storage.get(&legacy_manifest_key(name)).await? {
            None => Ok(None),
            Some(entry) => serde_json::from_slice::<PluginManifest>(&entry.value)
                .map(Some)
                .map_err(|_| RvError::ErrRequestInvalid),
        }
    }

    async fn read_binary_for(
        &self,
        storage: &dyn Storage,
        name: &str,
        version: &str,
    ) -> Result<Option<Vec<u8>>, RvError> {
        if let Some(entry) = storage.get(&binary_versioned_key(name, version)).await? {
            return Ok(Some(entry.value));
        }
        // Fall back to the legacy un-versioned path so plugins that
        // were registered before Phase 3 keep responding.
        Ok(storage.get(&legacy_binary_key(name)).await?.map(|e| e.value))
    }
}

fn active_key(name: &str) -> String {
    format!("{PLUGIN_PREFIX}{name}/active")
}

fn manifest_versioned_key(name: &str, version: &str) -> String {
    format!("{PLUGIN_PREFIX}{name}/versions/{version}/manifest")
}

fn binary_versioned_key(name: &str, version: &str) -> String {
    format!("{PLUGIN_PREFIX}{name}/versions/{version}/binary")
}

fn legacy_manifest_key(name: &str) -> String {
    format!("{PLUGIN_PREFIX}{name}/manifest")
}

fn legacy_binary_key(name: &str) -> String {
    format!("{PLUGIN_PREFIX}{name}/binary")
}

fn surface_versioned_key(name: &str, version: &str) -> String {
    format!("{PLUGIN_PREFIX}{name}/versions/{version}/surface")
}

fn asset_versioned_key(name: &str, version: &str, sha256: &str) -> String {
    format!("{PLUGIN_PREFIX}{name}/versions/{version}/assets/{sha256}")
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for chunk in s.as_bytes().chunks(2) {
        let hi = ascii_hex(chunk[0])?;
        let lo = ascii_hex(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn ascii_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(10 + b - b'a'),
        b'A'..=b'F' => Some(10 + b - b'A'),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::manifest::{Capabilities, RuntimeKind};

    fn manifest_with(name: &str, version: &str, binary: &[u8]) -> PluginManifest {
        let mut hasher = Sha256::new();
        hasher.update(binary);
        let digest = hasher.finalize();
        let hex = digest.iter().map(|b| format!("{b:02x}")).collect::<String>();
        PluginManifest {
            name: name.to_string(),
            version: version.to_string(),
            plugin_type: "secret-engine".to_string(),
            runtime: RuntimeKind::Wasm,
            abi_version: "1.0".to_string(),
            sha256: hex,
            size: binary.len() as u64,
            capabilities: Capabilities::default(),
            description: String::new(),
            config_schema: vec![],
            signature: String::new(),
            signing_key: String::new(),
            surface: None,
            client_assets: vec![],
        }
    }

    #[test]
    fn verify_integrity_round_trip() {
        let bin = b"some-binary-content".to_vec();
        let m = manifest_with("test", "0.1.0", &bin);
        assert!(PluginCatalog::verify_integrity(&m, &bin).is_ok());
    }

    #[test]
    fn rejects_truncated_binary() {
        let bin = b"some-binary-content".to_vec();
        let m = manifest_with("test", "0.1.0", &bin);
        let truncated = &bin[..bin.len() - 1];
        assert!(PluginCatalog::verify_integrity(&m, truncated).is_err());
    }

    #[test]
    fn rejects_tampered_byte() {
        let bin = b"some-binary-content".to_vec();
        let m = manifest_with("test", "0.1.0", &bin);
        let mut tampered = bin.clone();
        tampered[0] ^= 1;
        assert!(PluginCatalog::verify_integrity(&m, &tampered).is_err());
    }

    /// In-memory `Storage` so we can drive the full versioned API
    /// without standing up a barrier.
    #[derive(Default)]
    struct MemStorage {
        inner: std::sync::Mutex<std::collections::BTreeMap<String, Vec<u8>>>,
    }
    #[async_trait::async_trait]
    impl Storage for MemStorage {
        async fn list(&self, prefix: &str) -> Result<Vec<String>, RvError> {
            let g = self.inner.lock().unwrap();
            let mut out: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
            for k in g.keys() {
                if let Some(rest) = k.strip_prefix(prefix) {
                    if let Some(slash) = rest.find('/') {
                        out.insert(format!("{}/", &rest[..slash]));
                    } else {
                        out.insert(rest.to_string());
                    }
                }
            }
            Ok(out.into_iter().collect())
        }
        async fn get(&self, key: &str) -> Result<Option<StorageEntry>, RvError> {
            let g = self.inner.lock().unwrap();
            Ok(g.get(key)
                .map(|v| StorageEntry { key: key.to_string(), value: v.clone() }))
        }
        async fn put(&self, entry: &StorageEntry) -> Result<(), RvError> {
            self.inner.lock().unwrap().insert(entry.key.clone(), entry.value.clone());
            Ok(())
        }
        async fn delete(&self, key: &str) -> Result<(), RvError> {
            self.inner.lock().unwrap().remove(key);
            Ok(())
        }
    }

    /// Enable the `accept_unsigned` engine flag on `s` so the
    /// existing tests (which pre-date Phase 5.2 publisher signatures)
    /// can keep registering unsigned plugins.
    async fn enable_unsigned(s: &MemStorage) {
        super::super::verifier::write_accept_unsigned(s, true).await.unwrap();
    }

    #[tokio::test]
    async fn put_then_get_uses_versioned_layout_and_activates() {
        let s = MemStorage::default();
        enable_unsigned(&s).await;
        let cat = PluginCatalog::new();
        let bin = b"v1-bytes".to_vec();
        let m = manifest_with("p", "0.1.0", &bin);
        cat.put(&s, &m, &bin).await.unwrap();
        // Active pointer set to the registered version.
        assert_eq!(
            cat.get_active_version(&s, "p").await.unwrap().as_deref(),
            Some("0.1.0"),
        );
        let r = cat.get(&s, "p").await.unwrap().unwrap();
        assert_eq!(r.manifest.version, "0.1.0");
        assert_eq!(r.binary, bin);
    }

    #[tokio::test]
    async fn second_version_does_not_auto_activate() {
        let s = MemStorage::default();
        enable_unsigned(&s).await;
        let cat = PluginCatalog::new();
        let v1 = b"v1".to_vec();
        let v2 = b"v2-different".to_vec();
        cat.put(&s, &manifest_with("p", "0.1.0", &v1), &v1).await.unwrap();
        cat.put(&s, &manifest_with("p", "0.2.0", &v2), &v2).await.unwrap();
        assert_eq!(
            cat.get_active_version(&s, "p").await.unwrap().as_deref(),
            Some("0.1.0"),
        );
        let versions = cat.list_versions(&s, "p").await.unwrap();
        assert_eq!(versions.len(), 2);
        // Activate v2 explicitly.
        cat.set_active(&s, "p", "0.2.0").await.unwrap();
        let r = cat.get(&s, "p").await.unwrap().unwrap();
        assert_eq!(r.manifest.version, "0.2.0");
        assert_eq!(r.binary, v2);
    }

    #[tokio::test]
    async fn cannot_delete_active_version() {
        let s = MemStorage::default();
        enable_unsigned(&s).await;
        let cat = PluginCatalog::new();
        let bin = b"v1".to_vec();
        cat.put(&s, &manifest_with("p", "0.1.0", &bin), &bin).await.unwrap();
        assert!(cat.delete_version(&s, "p", "0.1.0").await.is_err());
    }

    #[tokio::test]
    async fn legacy_layout_still_readable() {
        let s = MemStorage::default();
        // Hand-write the legacy un-versioned layout — no active pointer,
        // no /versions/ subtree.
        let bin = b"legacy".to_vec();
        let m = manifest_with("legacy-plugin", "1.2.3", &bin);
        s.put(&StorageEntry {
            key: legacy_manifest_key("legacy-plugin"),
            value: serde_json::to_vec(&m).unwrap(),
        })
        .await
        .unwrap();
        s.put(&StorageEntry {
            key: legacy_binary_key("legacy-plugin"),
            value: bin.clone(),
        })
        .await
        .unwrap();

        let cat = PluginCatalog::new();
        let got = cat.get(&s, "legacy-plugin").await.unwrap().unwrap();
        assert_eq!(got.manifest.version, "1.2.3");
        assert_eq!(got.binary, bin);
        // get_active_version falls back to the manifest's own version
        // when no /active pointer exists.
        assert_eq!(
            cat.get_active_version(&s, "legacy-plugin").await.unwrap().as_deref(),
            Some("1.2.3"),
        );
        // list_versions surfaces the legacy entry as a single-version list.
        let versions = cat.list_versions(&s, "legacy-plugin").await.unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].version, "1.2.3");
    }

    #[tokio::test]
    async fn delete_clears_versions_and_per_name_records() {
        let s = MemStorage::default();
        enable_unsigned(&s).await;
        let cat = PluginCatalog::new();
        let v1 = b"v1".to_vec();
        let v2 = b"v2-different".to_vec();
        cat.put(&s, &manifest_with("p", "0.1.0", &v1), &v1).await.unwrap();
        cat.put(&s, &manifest_with("p", "0.2.0", &v2), &v2).await.unwrap();
        cat.delete(&s, "p").await.unwrap();
        assert!(cat.get(&s, "p").await.unwrap().is_none());
        assert!(cat.list_versions(&s, "p").await.unwrap().is_empty());
        assert!(cat.get_active_version(&s, "p").await.unwrap().is_none());
    }

    /// Phase 5.7 — `delete` writes a quarantine marker.
    #[tokio::test]
    async fn delete_writes_quarantine_marker() {
        let s = MemStorage::default();
        enable_unsigned(&s).await;
        let cat = PluginCatalog::new();
        let bin = b"quarantine-test".to_vec();
        cat.put(&s, &manifest_with("q", "0.1.0", &bin), &bin).await.unwrap();
        cat.delete(&s, "q").await.unwrap();
        let rec = super::super::quarantine::lookup(&s, "q").await.unwrap();
        let rec = rec.expect("delete should leave a quarantine marker");
        assert_eq!(rec.last_active_version, "0.1.0");
        // Re-registering the same name clears the marker (data prefix
        // remains intact upstream of the catalog — verified by the
        // logical-backend test).
        cat.put(&s, &manifest_with("q", "0.2.0", b"new"), b"new").await.unwrap();
        assert!(super::super::quarantine::lookup(&s, "q").await.unwrap().is_none());
    }

    /// Phase 5.9 — re-registering with a broader `audit_emit` is refused.
    #[tokio::test]
    async fn cap_widening_refused_on_reregister() {
        let s = MemStorage::default();
        enable_unsigned(&s).await;
        let cat = PluginCatalog::new();
        let bin = b"cap-widen".to_vec();
        let mut m = manifest_with("w", "0.1.0", &bin);
        m.capabilities.audit_emit = false;
        cat.put(&s, &m, &bin).await.unwrap();
        // Try to re-register with audit_emit = true.
        let bin2 = b"cap-widen-2".to_vec();
        let mut m2 = manifest_with("w", "0.2.0", &bin2);
        m2.capabilities.audit_emit = true;
        let err = cat.put(&s, &m2, &bin2).await.unwrap_err();
        assert!(format!("{err:?}").contains("capability widening"));
    }

    // ── Extensibility v2: app-capability widening + net grants ──

    fn manifest_with_app_net(name: &str, version: &str, binary: &[u8], hosts: &[&str]) -> PluginManifest {
        use crate::plugins::manifest::{AppCapabilities, NetCapabilities};
        let mut m = manifest_with(name, version, binary);
        m.abi_version = "1.1".to_string();
        m.capabilities.app = AppCapabilities {
            net: Some(NetCapabilities {
                hosts: hosts.iter().map(|h| h.to_string()).collect(),
                https_only: true,
            }),
            ..Default::default()
        };
        m
    }

    #[tokio::test]
    async fn app_dynamic_menus_widening_refused() {
        let s = MemStorage::default();
        enable_unsigned(&s).await;
        let cat = PluginCatalog::new();
        let bin = b"app-dm".to_vec();
        let m = manifest_with("adm", "0.1.0", &bin); // app default (menus off)
        cat.put(&s, &m, &bin).await.unwrap();
        let bin2 = b"app-dm-2".to_vec();
        let mut m2 = manifest_with("adm", "0.2.0", &bin2);
        m2.abi_version = "1.1".to_string();
        m2.capabilities.app.dynamic_menus = true;
        let err = cat.put(&s, &m2, &bin2).await.unwrap_err();
        assert!(format!("{err:?}").contains("app.dynamic_menus"));
    }

    #[tokio::test]
    async fn app_net_host_widening_refused() {
        let s = MemStorage::default();
        enable_unsigned(&s).await;
        let cat = PluginCatalog::new();
        let bin = b"app-net".to_vec();
        let m = manifest_with_app_net("anet", "0.1.0", &bin, &["a.example.com"]);
        cat.put(&s, &m, &bin).await.unwrap();
        // Adding a host on re-register is widening → refused.
        let bin2 = b"app-net-2".to_vec();
        let m2 = manifest_with_app_net("anet", "0.2.0", &bin2, &["a.example.com", "b.example.com"]);
        let err = cat.put(&s, &m2, &bin2).await.unwrap_err();
        assert!(format!("{err:?}").contains("app.net.hosts gained"));
    }

    #[tokio::test]
    async fn app_net_embedded_wildcard_refused_at_registration() {
        let s = MemStorage::default();
        enable_unsigned(&s).await;
        let cat = PluginCatalog::new();
        let bin = b"app-net-wild".to_vec();
        // `foo.*.com` passes the manifest's coarse check (not bare `*`,
        // no port) but must be caught by the catalog's authoritative
        // per-host rule — proving `validate_net_allowlist` covers
        // `capabilities.app.net.hosts`, not just `allowed_hosts`.
        let m = manifest_with_app_net("anw", "0.1.0", &bin, &["foo.*.com"]);
        let err = cat.put(&s, &m, &bin).await.unwrap_err();
        assert!(format!("{err:?}").contains("leading label"));
    }

    /// Roadmap Phase-1 acceptance: register (net requested) → grant →
    /// re-register with a *changed* (narrowed) net set → grant
    /// invalidated because the capability pin no longer matches.
    #[tokio::test]
    async fn net_grant_invalidated_by_changed_capability() {
        let s = MemStorage::default();
        enable_unsigned(&s).await;
        let cat = PluginCatalog::new();

        // v0.1.0 requests two hosts; it becomes the active version.
        let bin = b"wh-v1".to_vec();
        let m1 = manifest_with_app_net("wh", "0.1.0", &bin, &["a.example.com", "b.example.com"]);
        cat.put(&s, &m1, &bin).await.unwrap();

        // Admin grants a narrowed subset.
        super::super::grants::put_net(
            &s,
            "wh",
            &m1,
            vec!["a.example.com".into()],
            "admin-entity",
            "2026-07-09T00:00:00Z".into(),
        )
        .await
        .unwrap();

        // Grant is live against the active manifest.
        let active = cat.get_manifest(&s, "wh").await.unwrap().unwrap();
        assert_eq!(
            super::super::grants::active_net_hosts(&s, "wh", &active).await.unwrap(),
            Some(vec!["a.example.com".to_string()]),
        );

        // Re-register a narrowed v0.2.0 (drops b → not widening) and
        // activate it. The requested net capability changed, so the pin
        // no longer matches and the grant is void.
        let bin2 = b"wh-v2".to_vec();
        let m2 = manifest_with_app_net("wh", "0.2.0", &bin2, &["a.example.com"]);
        cat.put(&s, &m2, &bin2).await.unwrap();
        cat.set_active(&s, "wh", "0.2.0").await.unwrap();
        let active2 = cat.get_manifest(&s, "wh").await.unwrap().unwrap();
        assert_eq!(active2.version, "0.2.0");
        assert_eq!(
            super::super::grants::active_net_hosts(&s, "wh", &active2).await.unwrap(),
            None,
            "a changed net request must void the grant until re-approval",
        );
    }

    /// Phase 5.5 — wildcard hosts are refused at registration.
    #[tokio::test]
    async fn wildcard_host_refused_at_registration() {
        let s = MemStorage::default();
        enable_unsigned(&s).await;
        let cat = PluginCatalog::new();
        let bin = b"net-wild".to_vec();
        let mut m = manifest_with("n", "0.1.0", &bin);
        m.capabilities.allowed_hosts = vec!["*".to_string()];
        let err = cat.put(&s, &m, &bin).await.unwrap_err();
        assert!(format!("{err:?}").contains("wildcard"));
    }

    // ── Plugin Extensibility v1: surface + asset round-trip tests ────

    fn sha256_hex(b: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(b);
        h.finalize().iter().map(|b| format!("{b:02x}")).collect()
    }

    fn build_minimal_surface_json(plugin: &str) -> Vec<u8> {
        let s = serde_json::json!({
            "schema_version": 1,
            "title": plugin,
            "menus": [{
                "id": format!("{plugin}.main"),
                "label": "Main",
                "section": "secrets",
                "route": format!("/plugin/{plugin}/codes"),
            }],
            "pages": [{
                "route": format!("/plugin/{plugin}/codes"),
                "title": "Codes",
                "components": [{
                    "kind": "table",
                    "id": format!("{plugin}.list"),
                    "binding": { "op": "list", "path": "{mount}/codes" },
                    "columns": [{ "field": "name", "label": "Name" }],
                }],
            }],
        });
        serde_json::to_vec(&s).unwrap()
    }

    #[tokio::test]
    async fn put_surface_round_trip() {
        let s = MemStorage::default();
        enable_unsigned(&s).await;
        let cat = PluginCatalog::new();
        let bin = b"v1".to_vec();
        let mut m = manifest_with("p", "0.1.0", &bin);
        let surface_bytes = build_minimal_surface_json("p");
        m.surface = Some(super::super::manifest::SurfaceRef {
            schema_version: 1,
            sha256: sha256_hex(&surface_bytes),
            size: surface_bytes.len() as u64,
        });
        cat.put(&s, &m, &bin).await.unwrap();
        cat.put_surface(&s, "p", "0.1.0", &surface_bytes, &m.surface.as_ref().unwrap().sha256)
            .await
            .unwrap();
        let (got_manifest, got_bytes) = cat.read_active_surface(&s, "p").await.unwrap().unwrap();
        assert_eq!(got_manifest.version, "0.1.0");
        assert_eq!(got_bytes, surface_bytes);
    }

    #[tokio::test]
    async fn put_surface_rejects_hash_mismatch() {
        let s = MemStorage::default();
        let cat = PluginCatalog::new();
        let surface_bytes = build_minimal_surface_json("p");
        let err = cat
            .put_surface(&s, "p", "0.1.0", &surface_bytes, &"0".repeat(64))
            .await
            .unwrap_err();
        assert!(format!("{err:?}").contains("sha256 mismatch"));
    }

    #[tokio::test]
    async fn put_asset_content_addressed_round_trip() {
        let s = MemStorage::default();
        let cat = PluginCatalog::new();
        let asset = b"\x00asm\x01\x00\x00\x00 (mock wasm)".to_vec();
        let h = sha256_hex(&asset);
        cat.put_asset(&s, "p", "0.1.0", &asset, &h).await.unwrap();
        let got = cat.read_asset(&s, "p", "0.1.0", &h).await.unwrap().unwrap();
        assert_eq!(got, asset);
    }

    #[tokio::test]
    async fn read_asset_returns_none_for_unknown_hash() {
        let s = MemStorage::default();
        let cat = PluginCatalog::new();
        let got = cat
            .read_asset(&s, "p", "0.1.0", &"a".repeat(64))
            .await
            .unwrap();
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn aggregated_surfaces_etag_round_trip() {
        let s = MemStorage::default();
        enable_unsigned(&s).await;
        let cat = PluginCatalog::new();
        // Plugin A with a surface
        let bin_a = b"a-bin".to_vec();
        let surface_a = build_minimal_surface_json("a");
        let mut m_a = manifest_with("a", "1.0.0", &bin_a);
        m_a.surface = Some(super::super::manifest::SurfaceRef {
            schema_version: 1,
            sha256: sha256_hex(&surface_a),
            size: surface_a.len() as u64,
        });
        cat.put(&s, &m_a, &bin_a).await.unwrap();
        cat.put_surface(&s, "a", "1.0.0", &surface_a, &m_a.surface.as_ref().unwrap().sha256)
            .await
            .unwrap();
        // Plugin B with no surface
        let bin_b = b"b-bin".to_vec();
        let m_b = manifest_with("b", "1.0.0", &bin_b);
        cat.put(&s, &m_b, &bin_b).await.unwrap();

        let bundle = cat
            .aggregated_active_surfaces(&s, |_| None)
            .await
            .unwrap();
        // Only `a` contributes — `b` has no surface.
        assert_eq!(bundle.entries.len(), 1);
        assert_eq!(bundle.entries[0].plugin, "a");
        assert!(!bundle.etag.is_empty());

        // Re-running with no changes yields the same etag.
        let again = cat
            .aggregated_active_surfaces(&s, |_| None)
            .await
            .unwrap();
        assert_eq!(bundle.etag, again.etag);
    }

    #[tokio::test]
    async fn delete_clears_surface_and_assets() {
        let s = MemStorage::default();
        enable_unsigned(&s).await;
        let cat = PluginCatalog::new();
        let bin = b"v1".to_vec();
        let surface_bytes = build_minimal_surface_json("p");
        let surface_hash = sha256_hex(&surface_bytes);
        let asset = b"asset-bytes".to_vec();
        let asset_hash = sha256_hex(&asset);

        let mut m = manifest_with("p", "0.1.0", &bin);
        m.surface = Some(super::super::manifest::SurfaceRef {
            schema_version: 1,
            sha256: surface_hash.clone(),
            size: surface_bytes.len() as u64,
        });
        m.client_assets.push(super::super::manifest::ClientAssetRef {
            name: "h.wasm".to_string(),
            kind: "form-hook".to_string(),
            sha256: asset_hash.clone(),
            size: asset.len() as u64,
        });
        cat.put(&s, &m, &bin).await.unwrap();
        cat.put_surface(&s, "p", "0.1.0", &surface_bytes, &surface_hash).await.unwrap();
        cat.put_asset(&s, "p", "0.1.0", &asset, &asset_hash).await.unwrap();

        // delete clears both.
        cat.delete(&s, "p").await.unwrap();
        assert!(cat.read_active_surface(&s, "p").await.unwrap().is_none());
        assert!(cat.read_asset(&s, "p", "0.1.0", &asset_hash).await.unwrap().is_none());
    }
}
