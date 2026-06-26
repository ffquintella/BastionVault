//! Per-principal *default resource account* (Resource Connect).
//!
//! Some resources do not pin a login name on their connection profile;
//! instead they delegate it to *whoever is connecting*. This module records,
//! per credential principal, the OS login name that operator uses on target
//! hosts — one value per OS family (`linux` / `macos` / `windows`).
//!
//! A connection profile opts in by selecting the `default-account` credential
//! source. At connect time the host resolves the *connecting* operator's
//! account for the target's OS and uses it as the SSH cert principal (brokered)
//! or the RDP login user. Profiles that use any other credential source are
//! unaffected.
//!
//! ## Semantics
//!
//! - **No record / empty value ⇒ unconfigured.** A `default-account` profile
//!   fails closed at connect time with a clear error rather than silently
//!   falling back to a profile username. Resources not using the source never
//!   touch this store.
//! - The stored value is a login *name*, never a secret. The credential itself
//!   is still brokered (SSH engine) or prompted at connect (RDP), so a name
//!   here cannot by itself authenticate anywhere — the SSH role's allowed
//!   principals / the target's auth still gate the login.
//!
//! ## Storage layout (barrier-root, alongside the other identity stores)
//!
//! ```text
//! identity/default-account/<b64url(mount)>.<b64url(name)> -> DefaultResourceAccount (JSON)
//! ```
//!
//! The record lives at the raw barrier root (outside every per-tenant prefix)
//! because the connect path must read it regardless of the operator's active
//! namespace, exactly like [`super::super::namespace::ns_assignment`]. Mount and
//! principal name are base64url encoded into a single flat key so an arbitrary
//! name can never break out of its key segment and a `list("")` enumerates every
//! record.

use std::sync::Arc;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::{
    core::Core,
    errors::RvError,
    storage::{barrier_view::BarrierView, Storage, StorageEntry},
};

/// Barrier-root prefix for default resource accounts. Distinct from the
/// namespace assignment prefix (`namespaces/ns-assignment/`) and every
/// per-namespace data prefix (`namespaces/<uuid>/`).
pub const DEFAULT_ACCOUNT_PREFIX: &str = "identity/default-account/";

/// A per-principal set of OS-specific default login names. `mount`/`name`
/// identify the principal (`userpass/` + `alice`, …). Each OS field is empty
/// when the operator has not set an account for that family.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DefaultResourceAccount {
    pub mount: String,
    pub name: String,
    /// Login name used on Linux (and other Unix/BSD) SSH targets.
    #[serde(default)]
    pub linux: String,
    /// Login name used on macOS SSH targets.
    #[serde(default)]
    pub macos: String,
    /// Login name used on Windows RDP targets.
    #[serde(default)]
    pub windows: String,
    /// Optional password for the Windows RDP account. Stored encrypted at rest
    /// behind the barrier (like every other record here); never returned on the
    /// admin read path (only `has_windows_password` is surfaced there) — the
    /// connect host reads it through the caller-scoped `self` path. SSH default
    /// accounts never use it (those logins are brokered). Empty ⇒ the RDP
    /// default-account connect prompts for the password at connect time.
    #[serde(default)]
    pub windows_password: String,
    pub updated_at: String,
}

impl DefaultResourceAccount {
    /// True when nothing is set — equivalent to "no record" (triggers deletion).
    pub fn is_empty(&self) -> bool {
        self.linux.trim().is_empty()
            && self.macos.trim().is_empty()
            && self.windows.trim().is_empty()
            && self.windows_password.is_empty()
    }

    /// Whether a Windows RDP password is stored (without revealing it).
    pub fn has_windows_password(&self) -> bool {
        !self.windows_password.is_empty()
    }

    /// Resolve the account for a structured `os_type` value as used by the
    /// resource metadata / Connect button (`linux`, `macos`, `windows`,
    /// `bsd`, `unix`). BSD/Unix/unknown map to the `linux` account; Windows to
    /// `windows`; macOS to `macos`. Returns an empty string when that family
    /// has no account set.
    pub fn for_os_type(&self, os_type: &str) -> &str {
        match os_type {
            "windows" => &self.windows,
            "macos" => &self.macos,
            // linux, bsd, unix, "", and anything unrecognized fall back to the
            // Linux account — it is the sensible default for any SSH target.
            _ => &self.linux,
        }
    }
}

/// Flat barrier key for `(mount, name)`. Both components are base64url-encoded
/// so neither a `/` in the mount (`userpass/`) nor an arbitrary principal name
/// can escape the key segment. The `.` separator is outside the base64url
/// alphabet, so the split is unambiguous.
fn account_key(mount: &str, name: &str) -> String {
    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(mount.as_bytes()),
        URL_SAFE_NO_PAD.encode(name.as_bytes())
    )
}

pub struct DefaultResourceAccountStore {
    view: Arc<BarrierView>,
}

#[maybe_async::maybe_async]
impl DefaultResourceAccountStore {
    pub fn new(core: &Core) -> Result<Self, RvError> {
        let view = Arc::new(BarrierView::new(core.barrier.clone(), DEFAULT_ACCOUNT_PREFIX));
        Ok(Self { view })
    }

    /// Read the default accounts for a principal. `None` ⇒ unconfigured.
    pub async fn get(
        &self,
        mount: &str,
        name: &str,
    ) -> Result<Option<DefaultResourceAccount>, RvError> {
        match self.view.get(&account_key(mount, name)).await? {
            Some(e) => Ok(Some(serde_json::from_slice(&e.value)?)),
            None => Ok(None),
        }
    }

    /// Set (or clear) a principal's default accounts. Login names are trimmed;
    /// the password is stored verbatim (passwords may legitimately contain
    /// surrounding whitespace). A record with nothing set is deleted (back to
    /// unconfigured) and returns `None`. Otherwise the persisted record is
    /// returned.
    pub async fn set(
        &self,
        mount: &str,
        name: &str,
        linux: &str,
        macos: &str,
        windows: &str,
        windows_password: &str,
    ) -> Result<Option<DefaultResourceAccount>, RvError> {
        if mount.trim().is_empty() || name.trim().is_empty() {
            return Err(crate::bv_error_string!(
                "default resource account requires a non-empty mount and principal name"
            ));
        }

        let record = DefaultResourceAccount {
            mount: mount.to_string(),
            name: name.to_string(),
            linux: linux.trim().to_string(),
            macos: macos.trim().to_string(),
            windows: windows.trim().to_string(),
            windows_password: windows_password.to_string(),
            updated_at: Utc::now().to_rfc3339(),
        };

        if record.is_empty() {
            self.delete(mount, name).await?;
            return Ok(None);
        }

        let value = serde_json::to_vec(&record)?;
        self.view
            .put(&StorageEntry { key: account_key(mount, name), value })
            .await?;
        Ok(Some(record))
    }

    /// Remove a principal's default accounts. Idempotent.
    pub async fn delete(&self, mount: &str, name: &str) -> Result<(), RvError> {
        self.view.delete(&account_key(mount, name)).await
    }

    /// Every record on file (principals without one are absent).
    pub async fn list(&self) -> Result<Vec<DefaultResourceAccount>, RvError> {
        let keys = self.view.list("").await?;
        let mut out = Vec::with_capacity(keys.len());
        for k in keys {
            if let Some(e) = self.view.get(k.trim_end_matches('/')).await? {
                out.push(serde_json::from_slice(&e.value)?);
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::new_unseal_test_bastion_vault;

    #[test]
    fn for_os_type_maps_families() {
        let rec = DefaultResourceAccount {
            linux: "felipe-linux".into(),
            macos: "felipe-mac".into(),
            windows: "FGV\\felipe".into(),
            ..Default::default()
        };
        assert_eq!(rec.for_os_type("linux"), "felipe-linux");
        assert_eq!(rec.for_os_type("bsd"), "felipe-linux");
        assert_eq!(rec.for_os_type("unix"), "felipe-linux");
        assert_eq!(rec.for_os_type(""), "felipe-linux");
        assert_eq!(rec.for_os_type("macos"), "felipe-mac");
        assert_eq!(rec.for_os_type("windows"), "FGV\\felipe");
    }

    #[test]
    fn empty_record_detected() {
        assert!(DefaultResourceAccount::default().is_empty());
        let rec = DefaultResourceAccount { linux: "x".into(), ..Default::default() };
        assert!(!rec.is_empty());
        // Whitespace-only counts as empty.
        let ws = DefaultResourceAccount { macos: "   ".into(), ..Default::default() };
        assert!(ws.is_empty());
        // A stored password alone keeps the record non-empty.
        let pw = DefaultResourceAccount { windows_password: "x".into(), ..Default::default() };
        assert!(!pw.is_empty());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_default_account_store_roundtrip() {
        let (_bvault, core, _root) =
            new_unseal_test_bastion_vault("test_default_account_store").await;
        let store = DefaultResourceAccountStore::new(&core).unwrap();

        // No record ⇒ unconfigured.
        assert!(store.get("userpass/", "alice").await.unwrap().is_none());

        // Set linux + windows (+ a Windows password); macos left empty.
        let rec = store
            .set("userpass/", "alice", "alice-svc", "", "CORP\\alice", "s3cret")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rec.linux, "alice-svc");
        assert_eq!(rec.macos, "");
        assert_eq!(rec.windows, "CORP\\alice");
        assert_eq!(rec.windows_password, "s3cret");
        assert!(rec.has_windows_password());

        // Reads back, including per-OS resolution.
        let got = store.get("userpass/", "alice").await.unwrap().unwrap();
        assert_eq!(got.for_os_type("linux"), "alice-svc");
        assert_eq!(got.for_os_type("windows"), "CORP\\alice");
        assert_eq!(got.for_os_type("macos"), ""); // unset

        // Login names are trimmed on write; the password is stored verbatim.
        let trimmed = store
            .set("userpass/", "bob", "  bob  ", "", "", "  pw ")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(trimmed.linux, "bob");
        assert_eq!(trimmed.windows_password, "  pw "); // not trimmed

        // A record with only a password (no login names) still persists.
        let pw_only = store
            .set("userpass/", "carol", "", "", "", "only-pw")
            .await
            .unwrap()
            .unwrap();
        assert!(pw_only.has_windows_password());

        // Listing surfaces all three records.
        let mut all = store.list().await.unwrap();
        all.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].name, "alice");
        assert_eq!(all[1].name, "bob");
        assert_eq!(all[2].name, "carol");

        // An all-empty set (names blank, password empty) clears the record.
        assert!(store
            .set("userpass/", "alice", "", "  ", "", "")
            .await
            .unwrap()
            .is_none());
        assert!(store.get("userpass/", "alice").await.unwrap().is_none());

        // A blank principal name is rejected.
        assert!(store.set("userpass/", "  ", "x", "", "", "").await.is_err());
    }
}
