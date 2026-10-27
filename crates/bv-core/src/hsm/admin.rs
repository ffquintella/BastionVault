//! Device administration for the pool topology (T454 phase 4).
//!
//! Ceremonies run in the leader through an [`HsmAdminSession`], authenticated
//! with `bv-admin`, whose credential an operator supplies per request and
//! BastionVault never stores. Node sessions use a per-node, per-device random
//! [`NodeCredential`]. Spec: `features/hsm-pool-ha.md` § HSM object layout.

use std::{collections::BTreeMap, fmt};

use rand::Rng;
use serde::Serialize;
use zeroize::Zeroizing;

use crate::{
    errors::RvError,
    hsm::{blob::HsmId, AttestedKey, HsmObjectId, HsmObjectIds},
};

/// The YubiHSM 2 factory authentication key. `provision` deletes it, and a
/// device that still holds it is never a pool member.
pub const FACTORY_AUTH_KEY_ID: u16 = 1;
/// The factory key's published default password (YubiHSM 2; the mock mirrors it).
pub const FACTORY_PASSWORD: &str = "password";
/// `bv-admin`: the ceremony key. Auth keys and data objects are separate id
/// namespaces on the device (an object is its id *and* type).
pub const ADMIN_AUTH_KEY_ID: u16 = 2;
/// `bv-node-<node_id>` keys live at `0x100 + slot`.
pub const NODE_AUTH_KEY_BASE: u16 = 0x100;
/// Supported nodes per pool (spec § Session and throughput budget).
pub const MAX_POOL_NODES: usize = 12;
/// A node credential: AES-128 encryption key ‖ AES-128 MAC key, the YubiHSM 2
/// symmetric authentication key format.
pub const NODE_AUTH_KEY_LEN: usize = 32;

/// Capabilities of a wrap key: exactly these, never an export bit.
pub const WRAP_KEY_CAPABILITIES: &[&str] = &["unwrap-data", "wrap-data"];
/// Capabilities that would let key material leave a device.
pub const EXPORT_CAPABILITIES: &[&str] = &["export-wrapped", "exportable-under-wrap"];

/// Which fixed capability set an authentication key carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthKeyRole {
    /// Factory key 1 (everything). Deleted by `provision`.
    Factory,
    /// `bv-admin`: ceremonies only; no `wrap-data` / `unwrap-data`.
    Admin,
    /// `bv-node-<node_id>`: use, never create, delete or export.
    Node,
}

impl AuthKeyRole {
    /// The capability set of the role (spec § HSM object layout).
    pub fn capabilities(&self) -> &'static [&'static str] {
        match self {
            AuthKeyRole::Factory => &["all"],
            AuthKeyRole::Admin => &[
                "delete-asymmetric-key",
                "delete-authentication-key",
                "delete-wrap-key",
                "generate-asymmetric-key",
                "generate-wrap-key",
                "get-object-info",
                "put-authentication-key",
                "sign-attestation-certificate",
                "sign-ecdsa",
            ],
            AuthKeyRole::Node => {
                &["derive-ecdh", "get-object-info", "get-pseudo-random", "sign-eddsa", "unwrap-data", "wrap-data"]
            }
        }
    }
}

/// A node's credential for one device. Debug output never shows the key.
#[derive(Clone)]
pub struct NodeCredential {
    auth_key_id: u16,
    key: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for NodeCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeCredential").field("auth_key_id", &self.auth_key_id).field("key", &"<redacted>").finish()
    }
}

impl NodeCredential {
    /// Fresh random key material for `auth_key_id` (host CSPRNG).
    pub fn generate(auth_key_id: u16) -> Result<Self, RvError> {
        let mut key = Zeroizing::new(vec![0u8; NODE_AUTH_KEY_LEN]);
        rand::rng().fill_bytes(key.as_mut_slice());
        Self::from_parts(auth_key_id, key)
    }

    pub fn from_parts(auth_key_id: u16, key: Zeroizing<Vec<u8>>) -> Result<Self, RvError> {
        node_slot_of(auth_key_id)?;
        if key.len() != NODE_AUTH_KEY_LEN {
            return Err(RvError::ErrHsm(format!("a node credential is {NODE_AUTH_KEY_LEN} bytes, got {}", key.len())));
        }
        Ok(Self { auth_key_id, key })
    }

    pub fn auth_key_id(&self) -> u16 {
        self.auth_key_id
    }

    pub fn key(&self) -> &[u8] {
        &self.key
    }
}

/// The auth key id of node slot `slot` (0-based).
pub fn node_auth_key_id(slot: usize) -> Result<u16, RvError> {
    if slot >= MAX_POOL_NODES {
        return Err(RvError::ErrHsm(format!("node slot {slot} is outside 0..{MAX_POOL_NODES}")));
    }
    Ok(NODE_AUTH_KEY_BASE + slot as u16)
}

/// The slot of a node auth key id; anything outside the node range is refused,
/// so a ceremony can never touch `bv-admin` or the factory key.
pub fn node_slot_of(auth_key_id: u16) -> Result<usize, RvError> {
    let slot = auth_key_id.checked_sub(NODE_AUTH_KEY_BASE).map(usize::from);
    match slot {
        Some(slot) if slot < MAX_POOL_NODES => Ok(slot),
        _ => Err(RvError::ErrHsm(format!(
            "auth key {auth_key_id:#06x} is not a node key (0x{NODE_AUTH_KEY_BASE:04x}..0x{:04x})",
            NODE_AUTH_KEY_BASE as usize + MAX_POOL_NODES - 1
        ))),
    }
}

/// Admin credentials for one ceremony request, by member name. Zeroized on
/// drop and never printed; they live for the request that carries them.
#[derive(Default)]
pub struct AdminCredentials(BTreeMap<String, Zeroizing<String>>);

impl fmt::Debug for AdminCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.0.keys()).finish()
    }
}

impl AdminCredentials {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add the credential for `member`. An empty credential is refused.
    pub fn insert(&mut self, member: &str, credential: Zeroizing<String>) -> Result<(), RvError> {
        if credential.is_empty() {
            return Err(RvError::ErrHsm(format!("the admin credential for HSM pool member {member:?} is empty")));
        }
        self.0.insert(member.to_string(), credential);
        Ok(())
    }

    /// From a request's `admin_credentials` object (`{"<member>": "<credential>"}`).
    /// Absent or null is empty; anything else that is not strings is refused,
    /// and no error ever repeats a value.
    pub fn from_json(value: Option<&serde_json::Value>) -> Result<Self, RvError> {
        let mut out = Self::new();
        let map = match value {
            None | Some(serde_json::Value::Null) => return Ok(out),
            Some(serde_json::Value::Object(map)) => map,
            Some(_) => return Err(RvError::ErrHsm("`admin_credentials` must map member names to strings".into())),
        };
        for (member, credential) in map {
            let credential = credential
                .as_str()
                .ok_or_else(|| RvError::ErrHsm(format!("the admin credential for {member:?} must be a string")))?;
            out.insert(member, Zeroizing::new(credential.to_string()))?;
        }
        Ok(out)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn has(&self, member: &str) -> bool {
        self.0.contains_key(member)
    }

    /// The credential for `member`, or an error naming the member.
    pub fn for_member(&self, member: &str) -> Result<&str, RvError> {
        self.0
            .get(member)
            .map(|c| c.as_str())
            .ok_or_else(|| RvError::ErrHsm(format!("no admin credential was supplied for HSM pool member {member:?}")))
    }
}

/// Kind of a device object; with the id, what names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObjectKind {
    WrapKey,
    AsymmetricKey,
    AuthenticationKey,
}

/// `get-object-info`, reduced to what layout verification needs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ObjectInfo {
    pub id: u16,
    pub kind: ObjectKind,
    pub label: String,
    pub capabilities: Vec<String>,
    pub delegated: Vec<String>,
}

/// A session authenticated with `bv-admin`. Every method is a device command;
/// none returns key material.
#[maybe_async::maybe_async]
pub trait HsmAdminSession: Send + Sync {
    /// The device this session reaches (from its serial).
    fn hsm_id(&self) -> Result<HsmId, RvError>;

    async fn object_info(&self, kind: ObjectKind, id: u16) -> Result<Option<ObjectInfo>, RvError>;

    /// Ids of every authentication key on the device.
    async fn auth_key_ids(&self) -> Result<Vec<u16>, RvError>;

    /// `put-authentication-key` with the node capability set, domain 1, no
    /// delegated capabilities. Refuses an id outside the node range or in use.
    async fn put_node_auth_key(&self, label: &str, credential: &NodeCredential) -> Result<(), RvError>;

    /// Delete a node authentication key. `Ok(false)` when it was not there.
    async fn delete_node_auth_key(&self, auth_key_id: u16) -> Result<bool, RvError>;

    /// Public key of an asymmetric object (`bv-identity`, `bv-authz`).
    async fn public_key(&self, key: HsmObjectId) -> Result<Vec<u8>, RvError>;

    /// ECDSA signature by `bv-identity` over `domain_separated(ctx, msg)`.
    async fn identity_sign(&self, key: HsmObjectId, ctx: &str, msg: &[u8]) -> Result<Vec<u8>, RvError>;

    /// Verify an attestation produced by this backend type.
    async fn verify_attestation(&self, attestation: &[u8]) -> Result<AttestedKey, RvError>;

    /// Release the session slot.
    async fn close(&self) -> Result<(), RvError>;
}

/// What a pool member must look like (spec § attestation step 5): no factory
/// key, a `bv-admin` key, wrap keys with exactly `wrap-data` / `unwrap-data`
/// and nothing delegated, and no export capability on the attested keys.
#[maybe_async::maybe_async]
pub async fn verify_layout(session: &dyn HsmAdminSession, objects: &HsmObjectIds) -> Result<(), RvError> {
    let hsm_id = session.hsm_id()?;
    let refuse = |why: String| {
        log::error!(target: "security", "HSM {hsm_id} fails layout verification: {why}");
        RvError::ErrHsmAttestationInvalid(format!("HSM {hsm_id}: {why}"))
    };
    let auth_keys = session.auth_key_ids().await?;
    if auth_keys.contains(&FACTORY_AUTH_KEY_ID) {
        return Err(refuse("the factory authentication key 1 is still present".into()));
    }
    if !auth_keys.contains(&ADMIN_AUTH_KEY_ID) {
        return Err(refuse("no bv-admin authentication key".into()));
    }
    for (label, id) in [("bv-wrap-barrier", objects.wrap_barrier), ("bv-wrap-pqc", objects.wrap_pqc)] {
        let info =
            session.object_info(ObjectKind::WrapKey, id).await?.ok_or_else(|| refuse(format!("{label} missing")))?;
        let mut caps = info.capabilities.clone();
        caps.sort();
        if caps != WRAP_KEY_CAPABILITIES {
            return Err(refuse(format!(
                "{label} has capabilities {caps:?}, expected exactly {WRAP_KEY_CAPABILITIES:?}"
            )));
        }
        if !info.delegated.is_empty() {
            return Err(refuse(format!("{label} delegates {:?}", info.delegated)));
        }
    }
    for (label, id) in [("bv-identity", objects.identity), ("bv-authz", objects.authz)] {
        let info = session
            .object_info(ObjectKind::AsymmetricKey, id)
            .await?
            .ok_or_else(|| refuse(format!("{label} missing")))?;
        let export =
            info.capabilities.iter().chain(&info.delegated).find(|c| EXPORT_CAPABILITIES.contains(&c.as_str()));
        if let Some(bit) = export {
            return Err(refuse(format!("{label} carries {bit}")));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_key_ids_stay_in_the_node_range() {
        assert_eq!(node_auth_key_id(0).unwrap(), 0x100);
        assert_eq!(node_auth_key_id(MAX_POOL_NODES - 1).unwrap(), 0x10b);
        assert!(node_auth_key_id(MAX_POOL_NODES).is_err(), "a 13th slot does not exist");
        for id in [FACTORY_AUTH_KEY_ID, ADMIN_AUTH_KEY_ID, 0xff, 0x10c, u16::MAX] {
            assert!(node_slot_of(id).is_err(), "{id:#x} is not a node key");
        }
        assert_eq!(node_slot_of(0x105).unwrap(), 5);
    }

    #[test]
    fn credentials_are_random_sized_and_never_printed() {
        let a = NodeCredential::generate(0x100).unwrap();
        let b = NodeCredential::generate(0x100).unwrap();
        assert_eq!(a.key().len(), NODE_AUTH_KEY_LEN);
        assert_ne!(a.key(), b.key());
        let shown = format!("{a:?}");
        assert!(shown.contains("redacted") && !shown.contains(&format!("{:?}", a.key())), "{shown}");
        assert!(NodeCredential::from_parts(0x100, Zeroizing::new(vec![0; 16])).is_err());
        assert!(NodeCredential::from_parts(ADMIN_AUTH_KEY_ID, Zeroizing::new(vec![0; 32])).is_err());

        let mut admin = AdminCredentials::new();
        admin.insert("hsm-a", Zeroizing::new("s3cret-admin".into())).unwrap();
        assert!(!format!("{admin:?}").contains("s3cret"), "admin credentials are never printed");
        assert!(admin.insert("hsm-b", Zeroizing::new(String::new())).is_err());
        assert!(admin.for_member("hsm-b").unwrap_err().to_string().contains("hsm-b"));
    }

    #[test]
    fn roles_never_mix_admin_and_use() {
        let admin = AuthKeyRole::Admin.capabilities();
        let node = AuthKeyRole::Node.capabilities();
        assert!(!admin.contains(&"wrap-data") && !admin.contains(&"unwrap-data"), "bv-admin never wraps");
        for cap in ["put-authentication-key", "delete-authentication-key", "generate-wrap-key"] {
            assert!(!node.contains(&cap), "a node key cannot {cap}");
        }
        assert!(EXPORT_CAPABILITIES.iter().all(|c| !node.contains(c) && !admin.contains(c)));
    }
}
