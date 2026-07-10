//! Storage layer for the Rustion target registry.
//!
//! Two sub-views under the system area:
//!   - `rustion/targets/<id>`  — `RustionTarget` record.
//!   - `rustion/health/<id>`   — `RustionTargetHealth` record.
//!
//! Split intentionally so a health-update write doesn't churn the
//! target record (whose `updated_at` is a meaningful audit fact) and
//! so a target rotation doesn't reset the health history. Both
//! views serialise via `serde_json` for forward compatibility — CBOR
//! would be tighter but the GUI / CLI already consume JSON-shaped
//! responses and round-tripping through a single codec is one less
//! moving part.

use std::sync::Arc;

use chrono::Utc;
use sha2::{Digest, Sha256};

use crate::{
    bv_error_string,
    core::Core,
    errors::RvError,
    storage::{barrier_view::BarrierView, Storage, StorageEntry},
};

use super::config::{HybridPubKey, RustionTarget, RustionTargetHealth, RustionTargetInput};

const TARGET_SUB_PATH: &str = "rustion/targets/";
const HEALTH_SUB_PATH: &str = "rustion/health/";

pub struct RustionStore {
    targets_view: Arc<BarrierView>,
    health_view: Arc<BarrierView>,
}

#[maybe_async::maybe_async]
impl RustionStore {
    pub async fn new(core: &Core) -> Result<Arc<Self>, RvError> {
        let Some(system_view) = core.state.load().system_view.as_ref().cloned() else {
            return Err(RvError::ErrBarrierSealed);
        };
        let targets_view = Arc::new(system_view.new_sub_view(TARGET_SUB_PATH));
        let health_view = Arc::new(system_view.new_sub_view(HEALTH_SUB_PATH));
        Ok(Arc::new(Self { targets_view, health_view }))
    }

    // ─── Targets ────────────────────────────────────────────────────

    pub async fn list_target_ids(&self) -> Result<Vec<String>, RvError> {
        let mut keys = self.targets_view.get_keys().await?;
        keys.sort();
        Ok(keys)
    }

    /// Resolve every target id into a full `RustionTarget`. Used by
    /// the Phase 9.2 re-attestation sweep + the deenrol-all surface
    /// where the caller wants endpoint addresses, not just ids.
    pub async fn list_targets(&self) -> Result<Vec<RustionTarget>, RvError> {
        let mut out = Vec::new();
        for id in self.list_target_ids().await? {
            if let Some(t) = self.get_target(&id).await? {
                out.push(t);
            }
        }
        Ok(out)
    }

    pub async fn get_target(&self, id: &str) -> Result<Option<RustionTarget>, RvError> {
        let id = sanitize_id(id)?;
        let Some(entry) = self.targets_view.get(&id).await? else {
            return Ok(None);
        };
        let target: RustionTarget = serde_json::from_slice(&entry.value)
            .map_err(|e| bv_error_string!(&format!("decode rustion target {id}: {e}")))?;
        Ok(Some(target))
    }

    pub async fn find_target_by_name(&self, name: &str) -> Result<Option<RustionTarget>, RvError> {
        let needle = name.trim().to_lowercase();
        for id in self.list_target_ids().await? {
            if let Some(t) = self.get_target(&id).await? {
                if t.name.trim().to_lowercase() == needle {
                    return Ok(Some(t));
                }
            }
        }
        Ok(None)
    }

    /// Create a new target. Allocates an id deterministically from the
    /// (lowercased, trimmed) name so accidental double-enrolment via
    /// CLI + GUI lands on the same record instead of fragmenting.
    /// Returns `Err` if a target with the same name already exists.
    pub async fn create_target(&self, input: RustionTargetInput) -> Result<RustionTarget, RvError> {
        let normalized = validate_input(&input)?;
        if self.find_target_by_name(&normalized.name).await?.is_some() {
            return Err(bv_error_string!(&format!("rustion target `{}` already enrolled", normalized.name)));
        }
        let id = id_from_name(&normalized.name);
        let now = Utc::now();
        let target = RustionTarget {
            id: id.clone(),
            name: normalized.name,
            endpoint: normalized.endpoint,
            public_key: normalized.public_key.clone(),
            kem_public_key: normalized.kem_public_key,
            fingerprint: fingerprint(&normalized.public_key),
            description: normalized.description,
            tags: normalized.tags,
            enabled: normalized.enabled,
            default_recording_dir: normalized.default_recording_dir,
            tls_pinned_cert_pem: normalized.tls_pinned_cert_pem,
            created_at: now,
            updated_at: now,
            ssh_listener_host: String::new(),
            ssh_listener_port: 0,
            rdp_listener_host: String::new(),
            rdp_listener_port: 0,
            listeners_synced_at: String::new(),
            ssh_host_key_fingerprint: String::new(),
            rdp_tls_pin_sha256: String::new(),
        };
        self.put_target_record(&target).await?;
        // Seed the health record so a freshly-enrolled target is
        // visible in `targets/health` immediately, with `Unknown`
        // status until the first probe.
        let health = RustionTargetHealth { updated_at: now, ..Default::default() };
        self.put_health_record(&id, &health).await?;
        Ok(target)
    }

    /// Apply a full-record update. Bumps `updated_at`. Pubkey rotation
    /// is allowed in-band but is the only mutation that recomputes the
    /// fingerprint.
    pub async fn update_target(&self, id: &str, input: RustionTargetInput) -> Result<RustionTarget, RvError> {
        let id = sanitize_id(id)?;
        let Some(mut existing) = self.get_target(&id).await? else {
            return Err(bv_error_string!(&format!("rustion target `{id}` not found")));
        };
        let normalized = validate_input(&input)?;
        // Name uniqueness still enforced on rename.
        if normalized.name.to_lowercase() != existing.name.to_lowercase() {
            if let Some(other) = self.find_target_by_name(&normalized.name).await? {
                if other.id != id {
                    return Err(bv_error_string!(&format!("rustion target name `{}` already taken", normalized.name)));
                }
            }
        }
        existing.name = normalized.name;
        existing.endpoint = normalized.endpoint;
        existing.public_key = normalized.public_key.clone();
        existing.kem_public_key = normalized.kem_public_key;
        existing.fingerprint = fingerprint(&normalized.public_key);
        existing.description = normalized.description;
        existing.tags = normalized.tags;
        existing.enabled = normalized.enabled;
        existing.default_recording_dir = normalized.default_recording_dir;
        existing.tls_pinned_cert_pem = normalized.tls_pinned_cert_pem;
        existing.updated_at = Utc::now();
        self.put_target_record(&existing).await?;
        Ok(existing)
    }

    /// Phase 9.3 — apply discovered listener-info to an existing target.
    /// Preserves every other field (including `updated_at`) so listener
    /// pulls don't masquerade as a full re-enrolment in audit logs.
    #[allow(clippy::too_many_arguments)]
    pub async fn set_listener_info(
        &self,
        id: &str,
        ssh_host: &str,
        ssh_port: u16,
        rdp_host: &str,
        rdp_port: u16,
        ssh_host_key_fingerprint: &str,
        rdp_tls_pin_sha256: &str,
    ) -> Result<RustionTarget, RvError> {
        let id = sanitize_id(id)?;
        let Some(mut existing) = self.get_target(&id).await? else {
            return Err(bv_error_string!(&format!("rustion target `{id}` not found")));
        };
        // Log a host-key / TLS-pin rotation so a flip (which the dialler
        // then refuses until re-enrolment) leaves an audit trail rather
        // than silently changing what the operator's client will trust.
        if !existing.ssh_host_key_fingerprint.is_empty()
            && existing.ssh_host_key_fingerprint != ssh_host_key_fingerprint
        {
            log::warn!(
                "rustion: target {id} SSH host-key fingerprint changed on discovery \
                 ({} -> {ssh_host_key_fingerprint}); the dialler will pin the new value",
                existing.ssh_host_key_fingerprint
            );
        }
        if !existing.rdp_tls_pin_sha256.is_empty() && existing.rdp_tls_pin_sha256 != rdp_tls_pin_sha256 {
            log::warn!(
                "rustion: target {id} RDP TLS pin changed on discovery \
                 ({} -> {rdp_tls_pin_sha256}); the dialler will pin the new value",
                existing.rdp_tls_pin_sha256
            );
        }
        existing.ssh_listener_host = ssh_host.to_string();
        existing.ssh_listener_port = ssh_port;
        existing.rdp_listener_host = rdp_host.to_string();
        existing.rdp_listener_port = rdp_port;
        existing.ssh_host_key_fingerprint = ssh_host_key_fingerprint.to_string();
        existing.rdp_tls_pin_sha256 = rdp_tls_pin_sha256.to_string();
        existing.listeners_synced_at = Utc::now().to_rfc3339();
        self.put_target_record(&existing).await?;
        Ok(existing)
    }

    pub async fn delete_target(&self, id: &str) -> Result<(), RvError> {
        let id = sanitize_id(id)?;
        self.targets_view.delete(&id).await?;
        // Best-effort: drop the health record alongside; failures here
        // are logged but never block the registry delete.
        if let Err(e) = self.health_view.delete(&id).await {
            log::warn!("rustion: delete health for target {id} failed (continuing): {e}");
        }
        Ok(())
    }

    async fn put_target_record(&self, target: &RustionTarget) -> Result<(), RvError> {
        let value = serde_json::to_vec(target).map_err(|e| bv_error_string!(&format!("encode rustion target: {e}")))?;
        self.targets_view.put(&StorageEntry { key: target.id.clone(), value }).await
    }

    // ─── Health ─────────────────────────────────────────────────────

    pub async fn get_health(&self, id: &str) -> Result<Option<RustionTargetHealth>, RvError> {
        let id = sanitize_id(id)?;
        let Some(entry) = self.health_view.get(&id).await? else {
            return Ok(None);
        };
        let h: RustionTargetHealth = serde_json::from_slice(&entry.value)
            .map_err(|e| bv_error_string!(&format!("decode rustion health {id}: {e}")))?;
        Ok(Some(h))
    }

    pub async fn put_health(&self, id: &str, health: &RustionTargetHealth) -> Result<(), RvError> {
        let id = sanitize_id(id)?;
        self.put_health_record(&id, health).await
    }

    async fn put_health_record(&self, id: &str, health: &RustionTargetHealth) -> Result<(), RvError> {
        let value = serde_json::to_vec(health).map_err(|e| bv_error_string!(&format!("encode rustion health: {e}")))?;
        self.health_view.put(&StorageEntry { key: id.to_string(), value }).await
    }
}

fn validate_input(input: &RustionTargetInput) -> Result<RustionTargetInput, RvError> {
    let name = input.name.trim().to_string();
    if name.is_empty() {
        return Err(bv_error_string!("rustion target name is required"));
    }
    if name.contains('/') || name.contains("..") {
        return Err(bv_error_string!("rustion target name must not contain `/` or `..`"));
    }
    let endpoint = input.endpoint.trim().to_string();
    if endpoint.is_empty() {
        return Err(bv_error_string!("rustion target endpoint is required"));
    }
    // Reject endpoints without a port — Rustion always listens on an
    // explicit port for the control plane, and the implicit-443 case
    // is a footgun more often than a convenience.
    if !endpoint.contains(':') {
        return Err(bv_error_string!("rustion target endpoint must be `host:port` (no implicit default port)"));
    }
    if input.public_key.ed25519.trim().is_empty() {
        return Err(bv_error_string!("rustion target public_key.ed25519 is required"));
    }
    if input.public_key.mldsa65.trim().is_empty() {
        return Err(bv_error_string!(
            "rustion target public_key.mldsa65 is required (hybrid required; classical-only enrolment refused)"
        ));
    }
    Ok(RustionTargetInput {
        name,
        endpoint,
        public_key: HybridPubKey {
            ed25519: input.public_key.ed25519.trim().to_string(),
            mldsa65: input.public_key.mldsa65.trim().to_string(),
        },
        kem_public_key: input.kem_public_key.trim().to_string(),
        description: input.description.trim().to_string(),
        tags: input.tags.iter().map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect(),
        enabled: input.enabled,
        default_recording_dir: input.default_recording_dir.trim().to_string(),
        tls_pinned_cert_pem: validate_tls_pinned_cert_pem(&input.tls_pinned_cert_pem)?,
    })
}

/// Light-touch validation: an empty value is accepted (= no pin, use
/// system roots). A non-empty value must look like a PEM CERTIFICATE
/// block and decode cleanly via `reqwest::Certificate::from_pem` —
/// catches paste errors at write time rather than at the next probe.
fn validate_tls_pinned_cert_pem(pem: &str) -> Result<String, RvError> {
    let trimmed = pem.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    if !trimmed.contains("-----BEGIN CERTIFICATE-----") || !trimmed.contains("-----END CERTIFICATE-----") {
        return Err(bv_error_string!(
            "rustion target tls_pinned_cert_pem must be PEM-encoded \
             (no BEGIN/END CERTIFICATE markers found)"
        ));
    }
    reqwest::Certificate::from_pem(trimmed.as_bytes())
        .map_err(|e| bv_error_string!(&format!("rustion target tls_pinned_cert_pem failed to parse: {e}")))?;
    Ok(trimmed.to_string())
}

fn id_from_name(name: &str) -> String {
    let mut h = Sha256::new();
    h.update(name.trim().to_lowercase().as_bytes());
    let digest = h.finalize();
    // 16 hex chars (64 bits) is plenty for collision avoidance against
    // an admin's enrolment set and stays short enough to display in
    // URLs / logs.
    let mut id = String::with_capacity(8 + 16);
    id.push_str("rt_");
    for b in &digest[..8] {
        use std::fmt::Write;
        let _ = write!(&mut id, "{b:02x}");
    }
    id
}

fn sanitize_id(id: &str) -> Result<String, RvError> {
    let t = id.trim();
    if t.is_empty() {
        return Err(bv_error_string!("rustion target id is required"));
    }
    if t.contains('/') || t.contains("..") {
        return Err(bv_error_string!("invalid rustion target id"));
    }
    Ok(t.to_string())
}

/// Render the hybrid pubkey fingerprint as `sha256:xx:xx:…` over the
/// concatenation of the two halves' raw bytes (b64-decoded). On a
/// decode failure, the fingerprint is computed over the raw strings
/// — never panic on operator input.
fn fingerprint(pk: &HybridPubKey) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let mut h = Sha256::new();
    match STANDARD.decode(pk.ed25519.as_bytes()) {
        Ok(bytes) => h.update(&bytes),
        Err(_) => h.update(pk.ed25519.as_bytes()),
    }
    match STANDARD.decode(pk.mldsa65.as_bytes()) {
        Ok(bytes) => h.update(&bytes),
        Err(_) => h.update(pk.mldsa65.as_bytes()),
    }
    let digest = h.finalize();
    let mut out = String::from("sha256:");
    for (i, b) in digest.iter().enumerate() {
        if i > 0 {
            out.push(':');
        }
        use std::fmt::Write;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}
