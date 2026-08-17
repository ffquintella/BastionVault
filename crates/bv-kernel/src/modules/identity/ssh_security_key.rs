//! Per-principal **SSH security key** enrollment
//! (`features/connect-mfa-and-fido2-ssh.md`).
//!
//! A connection profile with the `fido2` credential source authenticates the
//! SSH session with the *connecting operator's* FIDO2 authenticator, using an
//! OpenSSH `sk-` key. This module records what the connect path needs in
//! order to drive that authenticator:
//!
//!   * the **public key** in `authorized_keys` form — what russh presents to
//!     the target, and what the operator installs on it;
//!   * the **credential id** — the CTAP key handle, needed in the
//!     `getAssertion` allow-list because v1 enrolls non-discoverable
//!     credentials;
//!   * the **application** string (`ssh:` by default) — the CTAP relying-party
//!     id the assertion must be requested under, and the value hashed into
//!     every `sk-` signature.
//!
//! ## Nothing here is a secret
//!
//! The private half of an `sk-` key never leaves the authenticator; it cannot
//! be exported even by its owner. A credential id is a handle, useless without
//! the physical key and the touch it demands. An attacker who dumps this store
//! learns which operators have security keys and what their public keys are —
//! the same thing they would learn from reading `authorized_keys` on any
//! target. Revoking access still means removing the public key from the
//! target, exactly as for any other SSH key; deleting the record here only
//! stops *BastionVault* from offering the key.
//!
//! ## Storage layout (barrier root, alongside the other identity stores)
//!
//! ```text
//! identity/ssh-security-key/<b64url(mount)>.<b64url(name)> -> SshSecurityKey (JSON)
//! ```
//!
//! Barrier root — outside every per-tenant prefix — because the connect path
//! must resolve the operator's key regardless of which namespace they are
//! working in, exactly like [`super::default_account`].

use std::sync::Arc;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::kernel_api::VaultCtx;
use crate::{
    errors::RvError,
    storage::{barrier_view::BarrierView, Storage, StorageEntry},
};

/// Barrier-root prefix for SSH security-key enrollments.
pub const SSH_SECURITY_KEY_PREFIX: &str = "identity/ssh-security-key/";

/// OpenSSH's default `application` for security-key credentials. Anything
/// else must start with `ssh:` per PROTOCOL.u2f, which
/// [`SshSecurityKey::validate`] enforces.
pub const DEFAULT_APPLICATION: &str = "ssh:";

/// The two OpenSSH security-key algorithms. Ed25519 is preferred; ECDSA
/// P-256 exists because a fair number of deployed authenticators do not
/// implement Ed25519.
pub const ALG_SK_ED25519: &str = "sk-ssh-ed25519@openssh.com";
pub const ALG_SK_ECDSA_P256: &str = "sk-ecdsa-sha2-nistp256@openssh.com";

/// One principal's enrolled SSH security key.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SshSecurityKey {
    /// Auth mount of the principal (`userpass/`).
    pub mount: String,
    /// Principal name.
    pub name: String,
    /// `sk-ssh-ed25519@openssh.com` or `sk-ecdsa-sha2-nistp256@openssh.com`.
    pub algorithm: String,
    /// Full `authorized_keys` line: `<algorithm> <base64 blob> [comment]`.
    /// This is what the operator installs on the target and what the connect
    /// path parses into an `ssh_key::PublicKey`.
    pub public_key: String,
    /// CTAP credential id, base64url (no padding). Goes into the
    /// `getAssertion` allow-list.
    pub credential_id: String,
    /// CTAP relying-party id / OpenSSH application string. Hashed into every
    /// signature, so it must match what the key was registered under or the
    /// target's verification fails.
    pub application: String,
    /// Free-text label so an operator with two keys can tell them apart.
    #[serde(default)]
    pub comment: String,
    pub updated_at: String,
}

impl SshSecurityKey {
    /// Reject a record that could not possibly produce a working login.
    ///
    /// Every one of these is a hard error at enrollment rather than a
    /// mystery at 3am: a mismatched algorithm, a public key whose prefix does
    /// not match its declared algorithm, or an application string OpenSSH
    /// will not accept all fail the same way at connect time — with an
    /// unhelpful signature rejection from the target.
    pub fn validate(&self) -> Result<(), String> {
        if self.algorithm != ALG_SK_ED25519 && self.algorithm != ALG_SK_ECDSA_P256 {
            return Err(format!(
                "unsupported SSH security-key algorithm `{}`; expected `{ALG_SK_ED25519}` \
                 or `{ALG_SK_ECDSA_P256}`",
                self.algorithm
            ));
        }
        let key = self.public_key.trim();
        if key.is_empty() {
            return Err("public_key is required".to_string());
        }
        if !key.starts_with(&self.algorithm) {
            return Err(format!(
                "public_key does not start with its declared algorithm `{}`",
                self.algorithm
            ));
        }
        if key.split_whitespace().count() < 2 {
            return Err(
                "public_key must be a full authorized_keys line (`<algorithm> <base64>`)"
                    .to_string(),
            );
        }
        if self.credential_id.trim().is_empty() {
            return Err("credential_id is required (v1 enrols non-discoverable keys)".to_string());
        }
        if URL_SAFE_NO_PAD.decode(self.credential_id.trim()).is_err() {
            return Err("credential_id must be unpadded base64url".to_string());
        }
        // PROTOCOL.u2f: OpenSSH only accepts applications under the `ssh:`
        // scheme. A key registered under anything else would be silently
        // unusable, because the target hashes the application into the
        // signature check.
        if !self.application.starts_with("ssh:") {
            return Err(format!(
                "application must start with `ssh:` (got `{}`)",
                self.application
            ));
        }
        Ok(())
    }

    /// Decoded CTAP credential id.
    pub fn credential_id_bytes(&self) -> Result<Vec<u8>, RvError> {
        URL_SAFE_NO_PAD
            .decode(self.credential_id.trim())
            .map_err(|e| crate::bv_error_string!(&format!("stored credential_id base64: {e}")))
    }
}

/// Flat barrier key for `(mount, name)`. Both halves are base64url-encoded so
/// neither the `/` in `userpass/` nor an arbitrary principal name can escape
/// its key segment; `.` is outside the alphabet, so the split is unambiguous.
fn key_for(mount: &str, name: &str) -> String {
    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(mount.as_bytes()),
        URL_SAFE_NO_PAD.encode(name.as_bytes())
    )
}

pub struct SshSecurityKeyStore {
    view: Arc<BarrierView>,
}

#[maybe_async::maybe_async]
impl SshSecurityKeyStore {
    pub fn new(core: &dyn VaultCtx) -> Result<Self, RvError> {
        Ok(Self {
            view: Arc::new(BarrierView::new(core.barrier().clone(), SSH_SECURITY_KEY_PREFIX)),
        })
    }

    /// Read a principal's enrolled key. `None` ⇒ not enrolled.
    pub async fn get(&self, mount: &str, name: &str) -> Result<Option<SshSecurityKey>, RvError> {
        match self.view.get(&key_for(mount, name)).await? {
            Some(e) => Ok(Some(serde_json::from_slice(&e.value)?)),
            None => Ok(None),
        }
    }

    /// Enroll (or replace) a principal's key. Validated before it is written,
    /// so a malformed record can never reach storage and fail later at
    /// connect time.
    #[allow(clippy::too_many_arguments)]
    pub async fn set(
        &self,
        mount: &str,
        name: &str,
        algorithm: &str,
        public_key: &str,
        credential_id: &str,
        application: &str,
        comment: &str,
    ) -> Result<SshSecurityKey, RvError> {
        if mount.trim().is_empty() || name.trim().is_empty() {
            return Err(crate::bv_error_string!(
                "SSH security-key enrolment requires a non-empty mount and principal name"
            ));
        }
        let application = match application.trim() {
            "" => DEFAULT_APPLICATION.to_string(),
            other => other.to_string(),
        };

        let record = SshSecurityKey {
            mount: mount.to_string(),
            name: name.to_string(),
            algorithm: algorithm.trim().to_string(),
            public_key: public_key.trim().to_string(),
            credential_id: credential_id.trim().to_string(),
            application,
            comment: comment.trim().to_string(),
            updated_at: Utc::now().to_rfc3339(),
        };
        record.validate().map_err(|e| crate::bv_error_string!(&e))?;

        let value = serde_json::to_vec(&record)?;
        self.view.put(&StorageEntry { key: key_for(mount, name), value }).await?;
        Ok(record)
    }

    /// Remove a principal's enrollment. Idempotent.
    ///
    /// This stops BastionVault from offering the key. It does **not** revoke
    /// the operator's access to any target — that means removing the public
    /// key from the target's `authorized_keys`, same as for any SSH key.
    pub async fn delete(&self, mount: &str, name: &str) -> Result<(), RvError> {
        self.view.delete(&key_for(mount, name)).await
    }

    /// Every enrollment on file.
    pub async fn list(&self) -> Result<Vec<SshSecurityKey>, RvError> {
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

    fn ed25519_record() -> SshSecurityKey {
        SshSecurityKey {
            mount: "userpass/".into(),
            name: "alice".into(),
            algorithm: ALG_SK_ED25519.into(),
            public_key: format!("{ALG_SK_ED25519} AAAAGnNr...c3NoOg== alice@laptop"),
            credential_id: URL_SAFE_NO_PAD.encode([7u8; 32]),
            application: DEFAULT_APPLICATION.into(),
            comment: "yubikey 5c".into(),
            updated_at: Utc::now().to_rfc3339(),
        }
    }

    #[test]
    fn validate_accepts_a_well_formed_record() {
        assert!(ed25519_record().validate().is_ok());

        let mut ecdsa = ed25519_record();
        ecdsa.algorithm = ALG_SK_ECDSA_P256.into();
        ecdsa.public_key = format!("{ALG_SK_ECDSA_P256} AAAAInNr...c3NoOg==");
        assert!(ecdsa.validate().is_ok());
    }

    #[test]
    fn validate_rejects_a_non_sk_algorithm() {
        let mut rec = ed25519_record();
        rec.algorithm = "ssh-ed25519".into();
        rec.public_key = "ssh-ed25519 AAAAC3Nz...".into();
        let err = rec.validate().unwrap_err();
        assert!(err.contains("unsupported SSH security-key algorithm"), "{err}");
    }

    #[test]
    fn validate_rejects_an_algorithm_public_key_mismatch() {
        // The single most likely paste error: an ordinary Ed25519 key pasted
        // into a record declaring the sk- algorithm.
        let mut rec = ed25519_record();
        rec.public_key = "ssh-ed25519 AAAAC3Nz... alice@laptop".into();
        let err = rec.validate().unwrap_err();
        assert!(err.contains("does not start with its declared algorithm"), "{err}");
    }

    #[test]
    fn validate_rejects_a_bare_blob_with_no_algorithm_prefix() {
        let mut rec = ed25519_record();
        rec.public_key = ALG_SK_ED25519.to_string();
        let err = rec.validate().unwrap_err();
        assert!(err.contains("full authorized_keys line"), "{err}");
    }

    #[test]
    fn validate_requires_a_decodable_credential_id() {
        let mut rec = ed25519_record();
        rec.credential_id = String::new();
        assert!(rec.validate().unwrap_err().contains("credential_id is required"));

        let mut rec = ed25519_record();
        rec.credential_id = "not base64!!".into();
        assert!(rec.validate().unwrap_err().contains("unpadded base64url"));
    }

    #[test]
    fn validate_requires_the_ssh_application_scheme() {
        let mut rec = ed25519_record();
        rec.application = "https://example.com".into();
        let err = rec.validate().unwrap_err();
        assert!(err.contains("must start with `ssh:`"), "{err}");

        // A scoped application is fine.
        let mut rec = ed25519_record();
        rec.application = "ssh:prod-bastion".into();
        assert!(rec.validate().is_ok());
    }

    #[test]
    fn credential_id_round_trips() {
        let rec = ed25519_record();
        assert_eq!(rec.credential_id_bytes().unwrap(), vec![7u8; 32]);
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn store_roundtrip() {
        let (_bvault, core, _root) = new_unseal_test_bastion_vault("test_ssh_security_key").await;
        let store = SshSecurityKeyStore::new(&core).unwrap();

        assert!(store.get("userpass/", "alice").await.unwrap().is_none());

        let rec = ed25519_record();
        let saved = store
            .set(
                "userpass/",
                "alice",
                &rec.algorithm,
                &rec.public_key,
                &rec.credential_id,
                "",
                "yubikey 5c",
            )
            .await
            .unwrap();
        // An empty application falls back to the OpenSSH default.
        assert_eq!(saved.application, DEFAULT_APPLICATION);

        let got = store.get("userpass/", "alice").await.unwrap().unwrap();
        assert_eq!(got.public_key, rec.public_key);
        assert_eq!(got.comment, "yubikey 5c");

        // A second enrolment replaces the first — one key per principal in v1.
        let replaced = store
            .set(
                "userpass/",
                "alice",
                ALG_SK_ECDSA_P256,
                &format!("{ALG_SK_ECDSA_P256} AAAAInNr..."),
                &URL_SAFE_NO_PAD.encode([9u8; 16]),
                "ssh:prod",
                "",
            )
            .await
            .unwrap();
        assert_eq!(replaced.algorithm, ALG_SK_ECDSA_P256);
        assert_eq!(replaced.application, "ssh:prod");
        assert_eq!(store.list().await.unwrap().len(), 1);

        // A malformed record never lands.
        assert!(store
            .set("userpass/", "bob", "ssh-rsa", "ssh-rsa AAAA", "abcd", "", "")
            .await
            .is_err());
        assert!(store.get("userpass/", "bob").await.unwrap().is_none());

        // A blank principal is rejected.
        assert!(store
            .set("userpass/", "  ", ALG_SK_ED25519, &rec.public_key, &rec.credential_id, "", "")
            .await
            .is_err());

        store.delete("userpass/", "alice").await.unwrap();
        assert!(store.get("userpass/", "alice").await.unwrap().is_none());
        // Idempotent.
        store.delete("userpass/", "alice").await.unwrap();
    }
}
