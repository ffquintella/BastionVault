//! Delivery plug-point for the cert-lifecycle module — Phase L7.
//!
//! The renewer hands a [`CertBundle`] to a [`CertDeliveryPlugin`] keyed
//! by [`Target::kind`](super::storage::TargetKind). Two built-in
//! plugins ship with the engine:
//!
//! - [`FileDeliverer`] — atomic-write `cert.pem` / `key.pem` /
//!   `chain.pem` into the target's `address` directory. Was the
//!   monolithic L5 implementation; this phase factors it behind the
//!   trait without behaviour change.
//! - [`HttpPushDeliverer`] — `POST` a JSON envelope to the target's
//!   `address` URL. Useful for cert-manager-style consumers that
//!   prefer to receive renewals over an HTTP webhook rather than
//!   polling a filesystem path.
//!
//! External plugins (loaded via `plugin-ext`) plug into the same
//! [`DelivererRegistry`] at startup time so the renew handler stays
//! agnostic to who's actually doing the I/O. Phase L7 ships the
//! registry + the two built-ins; the plugin-ext bridge is reserved
//! for a follow-up so the L7 surface stays reviewable without
//! pulling the plugin IPC contract into this module.

use std::{collections::HashMap, sync::Arc};

use super::storage::{Target, TargetKind};

/// What the renewer hands the deliverer. The PEM strings are the same
/// material the PKI engine returned — no serialisation pass on top.
#[derive(Debug, Clone)]
pub struct CertBundle {
    pub certificate_pem: String,
    pub private_key_pem: String,
    /// Issuer chain in leaf-issuer → root order, matching the
    /// `ca_chain` array on `pki/issue` / `pki/sign` responses (Phase
    /// L3). Empty when the issuer is a root and the chain has no
    /// extra hops.
    pub chain_pems: Vec<String>,
    pub serial: String,
}

/// Returned by a deliverer on success. The renewer audits + logs
/// these but does not otherwise consume them; tests assert against
/// `destination` to verify the right deliverer ran.
#[derive(Debug, Clone, Default)]
pub struct DeliveryReceipt {
    /// Human-readable destination — for `file` this is the directory
    /// path, for `http-push` the URL.
    pub destination: String,
    /// Free-form note (response status code, file count, etc.).
    pub note: String,
}

/// Plug-point trait. Sync because the built-in deliverers are sync
/// (file I/O, blocking ureq POST). Future async-only deliverers (e.g.
/// kube-rs for `kind = k8s-secret`) should wrap themselves in a
/// `tokio::task::block_in_place` shim here, or the trait can be
/// upgraded to `async-trait` once such a deliverer actually lands.
pub trait CertDeliveryPlugin: Send + Sync {
    /// Stable identifier — must match the [`TargetKind::as_str`] of
    /// the targets this plugin handles. The registry is keyed by this
    /// string.
    fn name(&self) -> &'static str;

    fn deliver(
        &self,
        target: &Target,
        bundle: &CertBundle,
    ) -> Result<DeliveryReceipt, String>;
}

/// Plugin lookup table held by [`CertLifecycleBackendInner`]. Built
/// at module construction with the engine's built-ins; an L7
/// follow-up will extend it from `plugin-ext` discovery at unseal
/// time.
#[derive(Default, Clone)]
pub struct DelivererRegistry {
    by_name: HashMap<String, Arc<dyn CertDeliveryPlugin>>,
}

impl DelivererRegistry {
    pub fn with_builtins() -> Self {
        let mut reg = Self::default();
        reg.register(Arc::new(FileDeliverer));
        reg.register(Arc::new(HttpPushDeliverer));
        reg
    }

    pub fn register(&mut self, plugin: Arc<dyn CertDeliveryPlugin>) {
        self.by_name.insert(plugin.name().to_string(), plugin);
    }

    pub fn get(&self, name: &str) -> Option<Arc<dyn CertDeliveryPlugin>> {
        self.by_name.get(name).cloned()
    }

    /// Names of every registered deliverer; used by the
    /// `cert-lifecycle/sys/deliverers` admin endpoint to surface what
    /// the engine knows how to talk to.
    pub fn names(&self) -> Vec<String> {
        let mut v: Vec<String> = self.by_name.keys().cloned().collect();
        v.sort();
        v
    }
}

/// Atomic-file deliverer for `kind = file`.
///
/// `target.address` is treated as an existing directory. The renewer
/// writes three files via `<file>.tmp` → rename so a partial write
/// does not corrupt the consumer's view.
pub struct FileDeliverer;

impl CertDeliveryPlugin for FileDeliverer {
    fn name(&self) -> &'static str {
        "file"
    }

    fn deliver(
        &self,
        target: &Target,
        bundle: &CertBundle,
    ) -> Result<DeliveryReceipt, String> {
        let dir = std::path::Path::new(&target.address);
        if !dir.is_dir() {
            return Err(format!(
                "address `{}` is not an existing directory",
                target.address
            ));
        }
        atomic_write(dir.join("cert.pem"), bundle.certificate_pem.as_bytes())
            .map_err(|e| format!("write cert.pem: {e}"))?;
        atomic_write(dir.join("key.pem"), bundle.private_key_pem.as_bytes())
            .map_err(|e| format!("write key.pem: {e}"))?;
        let chain_pem = if bundle.chain_pems.is_empty() {
            bundle.certificate_pem.clone()
        } else {
            bundle.chain_pems.join("")
        };
        atomic_write(dir.join("chain.pem"), chain_pem.as_bytes())
            .map_err(|e| format!("write chain.pem: {e}"))?;
        Ok(DeliveryReceipt {
            destination: target.address.clone(),
            note: "wrote cert.pem / key.pem / chain.pem".into(),
        })
    }
}

/// `POST <address>` deliverer for `kind = http-push`.
///
/// Body is a small JSON envelope:
///
/// ```json
/// {
///   "target":      "<target name>",
///   "serial":      "<hex>",
///   "certificate": "<PEM>",
///   "private_key": "<PEM>",
///   "ca_chain":    ["<PEM>", ...]
/// }
/// ```
///
/// The default serialiser uses `ureq` (already a direct dep). 2xx is
/// success; anything else is reported as a delivery failure with the
/// status code surfaced in the error message. `target.address` must
/// be an `http://` or `https://` URL.
pub struct HttpPushDeliverer;

impl CertDeliveryPlugin for HttpPushDeliverer {
    fn name(&self) -> &'static str {
        "http-push"
    }

    fn deliver(
        &self,
        target: &Target,
        bundle: &CertBundle,
    ) -> Result<DeliveryReceipt, String> {
        let url = target.address.trim();
        if !(url.starts_with("http://") || url.starts_with("https://")) {
            return Err(format!(
                "http-push: address must be an http(s) URL, got `{url}`"
            ));
        }
        let body = serde_json::json!({
            "target":      target.name,
            "serial":      bundle.serial,
            "certificate": bundle.certificate_pem,
            "private_key": bundle.private_key_pem,
            "ca_chain":    bundle.chain_pems,
        });
        let resp = ureq::post(url)
            .header("Content-Type", "application/json")
            .send_json(body)
            .map_err(|e| format!("http-push: POST {url} failed: {e}"))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(format!(
                "http-push: POST {url} returned status {}",
                status.as_u16()
            ));
        }
        Ok(DeliveryReceipt {
            destination: url.to_string(),
            note: format!("HTTP {}", status.as_u16()),
        })
    }
}

fn atomic_write(path: std::path::PathBuf, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Map a [`TargetKind`] to its registry key. Kept in this module so
/// the trait + the variants stay in lockstep when L7 follow-ups add
/// new kinds.
pub fn registry_key_for(kind: &TargetKind) -> &'static str {
    match kind {
        TargetKind::File => "file",
        TargetKind::HttpPush => "http-push",
    }
}
