//! Pillar 3: lifecycle-driven revocation. One view of what is revoked
//! (identities that are not active; certificates marked revoked or owned by
//! an identity that is not active), from which both the KRL and the signed
//! deny feed are built under one version.

pub mod feed;
pub mod krl;
pub mod store;
#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet, HashMap};

use chrono::{DateTime, Utc};

use crate::{
    errors::RvError,
    posix::{model::IdentityState, store::PosixStore},
    provider::ssh::store::{format_serial, SshStore},
};

use feed::{content_digest, DeniedIdentity, DenyFeed, FEED_FORMAT, FEED_FORMAT_VERSION};
use store::FeedStore;

/// What is revoked right now.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RevocationView {
    /// Identities that are not active, sorted by entity id.
    pub identities: Vec<DeniedIdentity>,
    /// Revoked, unexpired certificate serials per signing CA (OpenSSH line).
    pub certificates: BTreeMap<String, BTreeSet<u64>>,
}

#[maybe_async::maybe_async]
impl RevocationView {
    /// A certificate is revoked when it was marked so, or when its owner is
    /// not active (or has no record at all). Expired certificates are left
    /// out: sshd refuses them already.
    pub async fn build(posix: &PosixStore, ssh: &SshStore, now_secs: u64) -> Result<Self, RvError> {
        let mut states = HashMap::new();
        let mut identities = Vec::new();
        for rec in posix.list_identities().await? {
            states.insert(rec.entity_id.clone(), rec.state);
            if rec.state != IdentityState::Active {
                identities.push(DeniedIdentity {
                    entity_id: rec.entity_id,
                    login: rec.login,
                    uid: rec.uid,
                    state: rec.state.as_str().to_string(),
                    since: rec.state_changed_at.map(|t| t.timestamp()),
                });
            }
        }
        let mut certificates: BTreeMap<String, BTreeSet<u64>> = BTreeMap::new();
        for cert in ssh.list_certs().await? {
            if cert.valid_before <= now_secs {
                continue;
            }
            let owner_active = states.get(&cert.entity_id) == Some(&IdentityState::Active);
            if cert.revoked_at.is_some() || !owner_active {
                certificates.entry(cert.ca_public_key.clone()).or_default().insert(cert.serial_u64()?);
            }
        }
        Ok(Self { identities, certificates })
    }
}

impl RevocationView {
    /// Every revoked serial, hex, sorted and unique.
    pub fn serials(&self) -> Vec<String> {
        let all: BTreeSet<u64> = self.certificates.values().flatten().copied().collect();
        all.into_iter().map(format_serial).collect()
    }

    pub fn digest(&self) -> Result<String, RvError> {
        content_digest(&self.identities, &self.serials())
    }

    pub fn into_feed(self, feed_version: u64, generated_at: i64) -> DenyFeed {
        let revoked_serials = self.serials();
        DenyFeed {
            format: FEED_FORMAT.to_string(),
            format_version: FEED_FORMAT_VERSION,
            feed_version,
            generated_at,
            identities: self.identities,
            revoked_serials,
        }
    }
}

/// Build the view and fix its version, both under the feed lock, so two
/// concurrent refreshes cannot publish an older view under a newer version.
#[maybe_async::maybe_async]
pub async fn refresh(
    posix: &PosixStore,
    ssh: &SshStore,
    feed: &FeedStore,
    now: DateTime<Utc>,
) -> Result<(RevocationView, u64), RvError> {
    let mut lock = feed.lock().await?;
    let now_secs = u64::try_from(now.timestamp()).unwrap_or(0);
    let view = RevocationView::build(posix, ssh, now_secs).await?;
    let version = feed.advance_locked(&mut lock, &view.digest()?, now).await?;
    Ok((view, version))
}
