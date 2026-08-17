//! Versioned, domain-separating context strings (spec § Context Strings).
//!
//! Every KDF `info`, signature domain, and blob AAD is built from one of these
//! constructors. A blob wrapped under one context can never be unwrapped or
//! accepted under another; a version bump (`v1` → `v2`) is a new context.

/// Common versioned prefix for all HSM context strings.
pub const HSM_CTX_PREFIX: &str = "bastionvault/hsm/v1";

/// `bastionvault/hsm/v1/barrier-kek/<cluster-uuid>`
pub fn barrier_kek(cluster_uuid: &str) -> String {
    format!("{HSM_CTX_PREFIX}/barrier-kek/{cluster_uuid}")
}

/// `bastionvault/hsm/v1/pqc-seed/ml-kem-768/<cluster-uuid>/<key-epoch>`
pub fn pqc_kem_seed(cluster_uuid: &str, epoch: u64) -> String {
    format!("{HSM_CTX_PREFIX}/pqc-seed/ml-kem-768/{cluster_uuid}/{epoch}")
}

/// `bastionvault/hsm/v1/pqc-seed/ml-dsa-65/<cluster-uuid>/<key-epoch>`
pub fn pqc_sig_seed(cluster_uuid: &str, epoch: u64) -> String {
    format!("{HSM_CTX_PREFIX}/pqc-seed/ml-dsa-65/{cluster_uuid}/{epoch}")
}

/// `bastionvault/hsm/v1/unwrap-authz/<node-id>/<purpose>`
pub fn unwrap_authz(node_id: &str, purpose: &str) -> String {
    format!("{HSM_CTX_PREFIX}/unwrap-authz/{node_id}/{purpose}")
}

/// `bastionvault/hsm/v1/replication-channel/<cluster-uuid>/<epoch>`
pub fn replication_channel(cluster_uuid: &str, epoch: u64) -> String {
    format!("{HSM_CTX_PREFIX}/replication-channel/{cluster_uuid}/{epoch}")
}

/// `bastionvault/hsm/v1/migration-transcript/<cluster-uuid>/<epoch>`
pub fn migration_transcript(cluster_uuid: &str, epoch: u64) -> String {
    format!("{HSM_CTX_PREFIX}/migration-transcript/{cluster_uuid}/{epoch}")
}
