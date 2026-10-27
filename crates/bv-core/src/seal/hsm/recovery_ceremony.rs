//! The recovery ceremony (T454 phase 5, `v2/sys/hsm/recover`): shares in,
//! the KEK and every custody set opened from their recovery copies, wrapped
//! on new devices, the old members retired and the epoch bumped. Accepted
//! only on a sealed node while every member is unreachable or retired.
//! Spec: `features/hsm-pool-ha.md` § Recovery: Shamir ceremony.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use serde_json::{json, Value};
use zeroize::Zeroizing;

use super::{
    pool_admin::{close_all, Sessions},
    record::{HsmMember, HsmSealRecord, MemberState, Topology},
    targets_of, HsmSealProvider, PoolDevices, HSM_SEAL_RECORD_PATH,
};
use crate::{
    errors::RvError,
    hsm::{
        admin::{node_auth_key_id, AdminCredentials, NodeCredential},
        blob::{Context, HsmId, Purpose},
        ceremony::{
            list_enrollments, verify_member, write_enrollment, AttestationBundle, NodeEnrollment, ENROLLMENT_CONTEXT,
        },
        custody_store::{is_key_id, CustodyRecord, PqcKeypair, CUSTODY_STORE_PREFIX, HSM_CUSTODY_LOCK},
        node_creds::{read_delivery, seal_credential, write_delivery, CredentialDelivery},
        pool::{HsmPool, PoolEventKind},
        recovery::{custody_recovery_aad, kek_recovery_aad, RecoveryKey, ShareSet},
        repair::HSM_REPAIR_LOCK,
        validate_member_name, MemberTarget, MAX_POOL_MEMBERS,
    },
    storage::{barrier::SecurityBarrier, Storage, StorageEntry},
};

/// One new device the ceremony moves the pool onto.
pub struct RecoveryMember {
    pub bundle: AttestationBundle,
    /// `https://` gateway (yubihsm2); empty for a mock or a local connector.
    pub gateway: String,
}

/// One request to `v2/sys/hsm/recover`. A share is added to the running
/// ceremony; `members` (with their admin credentials) run it once enough
/// shares are in; `reset` discards the shares submitted so far.
#[derive(Default)]
pub struct RecoverySubmission {
    pub share: Option<Zeroizing<Vec<u8>>>,
    pub members: BTreeMap<String, RecoveryMember>,
    pub admin: AdminCredentials,
    pub reset: bool,
}

/// What enrolling the nodes on the new members produced, before commit.
struct Enrolled {
    own: Vec<(HsmId, NodeCredential)>,
    deliveries: BTreeMap<String, CredentialDelivery>,
    enrollments: Vec<NodeEnrollment>,
    created: Vec<(HsmId, u16)>,
}

/// Custody sets the ceremony looked at.
#[derive(Default)]
struct CustodyOutcome {
    recovered: usize,
    already: usize,
    unrecovered: Vec<String>,
    invalid: Vec<String>,
}

impl HsmSealProvider {
    /// Shares a running ceremony holds (status reports the count only).
    pub(super) fn recovery_progress(&self) -> usize {
        self.recovery_shares.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    /// Drop the submitted shares; each one is zeroized as it goes.
    fn take_recovery_shares(&self) -> ShareSet {
        std::mem::take(&mut *self.recovery_shares.lock().unwrap_or_else(|p| p.into_inner()))
    }

    /// The spec's gate: a pool record with a recovery key, and every member
    /// that is not retired unreachable from this node. Only a transport
    /// failure counts as unreachable; any other answer refuses, because a
    /// device that answers is repaired or replaced, never recovered around.
    #[maybe_async::maybe_async]
    async fn recovery_gate(&self, devices: &PoolDevices) -> Result<HsmSealRecord, RvError> {
        let stored = self
            .load_record()
            .await?
            .ok_or_else(|| RvError::ErrHsm("there is no HSM seal record; recovery needs an initialized pool".into()))?;
        let record = stored.record;
        if record.topology != Topology::Pool {
            return Err(RvError::ErrHsm("HSM recovery exists only for the pool topology".into()));
        }
        if record.recovery_pub.is_none() {
            return Err(RvError::ErrHsm(
                "this pool was initialized with recovery = \"none\": there is no recovery key, so losing both \
                 devices cannot be recovered"
                    .into(),
            ));
        }
        let store = devices.cache.credentials.as_ref();
        let mut answering = Vec::new();
        for (target, _) in targets_of(record.members.iter().filter(|(_, m)| m.state != MemberState::Retired)) {
            let credential = match store {
                Some(store) => store.credential_for(&target.hsm_id)?,
                None => None,
            };
            let reached = match devices.cache.opener.open_client(&target, credential) {
                Ok(client) => client.probe().await.map(|_| ()),
                Err(e) => Err(e),
            };
            match reached {
                Err(RvError::ErrHsmTransport(_)) => {}
                Ok(()) => answering.push(format!("{} answers", target.name)),
                Err(e) => answering.push(format!("{}: {e}", target.name)),
            }
        }
        if !answering.is_empty() {
            log::error!(target: "security", "HSM recovery refused: not every pool member is unreachable ({answering:?})");
            return Err(RvError::ErrHsm(format!(
                "recovery is accepted only while every pool member is unreachable or retired; {}. Repair, or replace \
                 a member with `member add`, instead",
                answering.join("; ")
            )));
        }
        Ok(record)
    }

    /// `POST v2/sys/hsm/recover`. `barrier` is this node's (sealed) barrier:
    /// the ceremony opens it with the recovered KEK only to reach the custody
    /// sets, and seals it again before returning, whatever the outcome.
    #[maybe_async::maybe_async]
    pub async fn recover_submit(
        &self,
        submission: RecoverySubmission,
        barrier: Arc<dyn SecurityBarrier>,
        actor: &str,
    ) -> Result<Value, RvError> {
        let RecoverySubmission { share, members, admin, reset } = submission;
        let devices = self.pool_devices()?;
        if reset {
            drop(self.take_recovery_shares());
            log::warn!(target: "security", "HSM recovery ceremony: the submitted shares were discarded (reset)");
            if share.is_none() && members.is_empty() {
                return Ok(json!({ "progress": 0, "reset": true, "complete": false }));
            }
        }
        if !barrier.sealed()? {
            return Err(RvError::ErrHsm(
                "this node is unsealed; the recovery ceremony runs only on a sealed node".into(),
            ));
        }
        let record = self.recovery_gate(devices).await?;
        let recovery = record.recovery_pub.clone().ok_or_else(|| RvError::ErrHsm("no recovery key".into()))?;
        let threshold = usize::from(recovery.threshold);
        let progress = {
            let mut shares = self.recovery_shares.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(share) = share {
                if shares.len() >= threshold {
                    return Err(RvError::ErrHsm(format!(
                        "{threshold} shares are already in; submit the new members, or reset the ceremony"
                    )));
                }
                shares.add(share)?;
            }
            shares.len()
        };
        let mut out = json!({
            "progress": progress,
            "threshold": recovery.threshold,
            "recovery_fingerprint": recovery.fingerprint,
            "ready": progress >= threshold,
            "complete": false,
        });
        if members.is_empty() {
            return Ok(out);
        }
        if progress < threshold {
            return Err(RvError::ErrHsm(format!(
                "{progress} of {threshold} recovery shares submitted; submit the rest before the new members"
            )));
        }
        // A mistyped member list is refused before it costs the shares.
        let min_copies = self.config.pool.as_ref().map(|p| p.min_wrap_copies).unwrap_or(1);
        self.new_member_targets(&record, &members, min_copies)?;
        // Every attempt consumes the shares: a failure means resubmitting.
        let shares = self.take_recovery_shares();
        let key = shares.combine(recovery.threshold, &recovery.fingerprint)?;
        let indexes = shares.indexes();
        drop(shares);
        let report = self.recovery_ceremony(devices, &key, &indexes, members, &admin, barrier, actor).await;
        drop(key);
        let report = report?;
        if let (Some(obj), Some(extra)) = (out.as_object_mut(), report.as_object()) {
            obj.extend(extra.clone());
            obj.insert("progress".into(), json!(0));
            obj.insert("ready".into(), json!(false));
            obj.insert("complete".into(), json!(true));
        }
        Ok(out)
    }

    /// The new devices as targets: 1–2 of them (at least `min_wrap_copies`),
    /// valid unique names, this backend, none already in the record.
    fn new_member_targets(
        &self,
        record: &HsmSealRecord,
        members: &BTreeMap<String, RecoveryMember>,
        min_wrap_copies: usize,
    ) -> Result<Vec<MemberTarget>, RvError> {
        let min_copies = min_wrap_copies.max(1);
        if members.len() < min_copies || members.len() > MAX_POOL_MEMBERS {
            return Err(RvError::ErrHsm(format!(
                "recover onto {min_copies} to {MAX_POOL_MEMBERS} new devices (min_wrap_copies = {min_copies}); {} given",
                members.len()
            )));
        }
        let mut targets: Vec<MemberTarget> = Vec::new();
        for (name, m) in members {
            validate_member_name(name)?;
            let hsm_id = m.bundle.hsm_id()?;
            if hsm_id.backend_type() != self.config.backend_type {
                return Err(RvError::ErrHsm(format!("{hsm_id} is not a {} device", self.config.backend_type)));
            }
            if self.config.backend_type == "yubihsm2" && !m.gateway.trim().starts_with("https://") {
                return Err(RvError::ErrHsm(format!("yubihsm2 member {name} needs an https:// (mTLS) gateway URL")));
            }
            if record.members.values().any(|r| r.name == *name) || record.members.contains_key(&hsm_id) {
                return Err(RvError::ErrHsm(format!(
                    "{name} ({hsm_id}) is already in the seal record; use new devices"
                )));
            }
            if targets.iter().any(|t| t.hsm_id == hsm_id) {
                return Err(RvError::ErrHsm(format!("{hsm_id} is named twice")));
            }
            targets.push(MemberTarget { name: name.clone(), hsm_id, gateway: m.gateway.trim().to_string() });
        }
        Ok(targets)
    }

    #[maybe_async::maybe_async]
    #[allow(clippy::too_many_arguments)] // one caller; every argument is a distinct ceremony input
    async fn recovery_ceremony(
        &self,
        devices: &PoolDevices,
        key: &RecoveryKey,
        indexes: &[u8],
        members: BTreeMap<String, RecoveryMember>,
        admin: &AdminCredentials,
        barrier: Arc<dyn SecurityBarrier>,
        actor: &str,
    ) -> Result<Value, RvError> {
        let pool_cfg = self.config.pool.as_ref().ok_or_else(|| RvError::ErrHsm("not a pool provider".into()))?;
        if devices.cache.credentials.is_none() {
            return Err(RvError::ErrHsmConfigInvalid(
                "the recovery ceremony enrolls this node on the new members and needs `credential_dir`".into(),
            ));
        }
        let physical = self.physical.as_ref();
        let _repair_lock = physical.lock(HSM_REPAIR_LOCK).await?;
        let anchor = physical
            .get(HSM_SEAL_RECORD_PATH)
            .await?
            .ok_or_else(|| RvError::ErrHsm("the HSM seal record disappeared".into()))?
            .value;
        let record = HsmSealRecord::decode(&anchor)?.record;
        if record.recovery_pub.as_ref().map(|r| r.fingerprint.as_str()) != Some(key.fingerprint().as_str()) {
            return Err(RvError::ErrHsm("the seal record's recovery key changed during the ceremony".into()));
        }

        let targets = self.new_member_targets(&record, &members, pool_cfg.min_wrap_copies)?;

        let kek_set = record.kek.clone().ok_or_else(|| RvError::ErrHsm("pool seal record has no KEK set".into()))?;
        let envelope = kek_set.recovery.as_ref().ok_or_else(|| {
            RvError::ErrHsm("the barrier KEK has no recovery copy; this pool cannot be recovered".into())
        })?;
        let kek = key.open(envelope, &kek_recovery_aad(&record.cluster_uuid, kek_set.epoch)).inspect_err(|e| {
            self.event(PoolEventKind::CryptoFailure, "", "", &format!("recovery: barrier KEK recovery copy: {e}"));
        })?;

        let enrollments: Vec<NodeEnrollment> =
            list_enrollments(physical).await?.into_iter().filter(|e| !e.is_revoked()).collect();
        if !enrollments.iter().any(|e| e.node_id == self.config.node_id) {
            return Err(RvError::ErrHsm(format!(
                "node {} is not enrolled in the pool; run the ceremony on an enrolled node",
                self.config.node_id
            )));
        }
        let sessions = self.open_admin_sessions(targets, admin).await?;
        let result = self
            .recover_on(&sessions, devices, key, &kek, &record, &anchor, &members, enrollments, barrier, actor)
            .await;
        close_all(sessions).await;
        let (mut report, new_names, retired, custody) = result?;
        let detail = format!(
            "shares={indexes:?} new_members={new_names:?} retired={retired:?} custody_recovered={} \
             custody_unrecovered={} by={actor}",
            custody.recovered,
            custody.unrecovered.len()
        );
        self.event(PoolEventKind::RecoveryCeremony, "", "", &detail);
        if let Some(obj) = report.as_object_mut() {
            obj.insert("share_indexes".into(), json!(indexes));
        }
        Ok(report)
    }

    /// Steps 1–8 with the admin sessions open. Device keys it created are
    /// deleted again if anything fails before the record is committed.
    #[maybe_async::maybe_async]
    #[allow(clippy::too_many_arguments)] // the ceremony's state, threaded through once
    async fn recover_on(
        &self,
        sessions: &Sessions,
        devices: &PoolDevices,
        key: &RecoveryKey,
        kek: &Zeroizing<Vec<u8>>,
        record: &HsmSealRecord,
        anchor: &[u8],
        members: &BTreeMap<String, RecoveryMember>,
        enrollments: Vec<NodeEnrollment>,
        barrier: Arc<dyn SecurityBarrier>,
        actor: &str,
    ) -> Result<(Value, Vec<String>, Vec<String>, CustodyOutcome), RvError> {
        let objects = self.config.objects;
        // 1. Attest each device; give it this epoch's wrap keys (and a
        //    rotation target's), as `member add` does for a replacement.
        let mut new_members = BTreeMap::new();
        for (target, session) in sessions {
            let bundle = &members[&target.name].bundle;
            let verified = verify_member(session.as_ref(), bundle, &objects).await?;
            let mut epoch_keys = vec![record.wrap_key_ids(record.epoch, &objects)?];
            if let Some(next) = record.rotating_to {
                epoch_keys.push(record.wrap_key_ids(next, &objects)?);
            }
            Self::ensure_wrap_keys(session.as_ref(), &epoch_keys).await?;
            new_members.insert(
                target.hsm_id.clone(),
                HsmMember {
                    name: target.name.clone(),
                    gateway: target.gateway.clone(),
                    serial: bundle.serial.clone(),
                    identity_pub: verified.identity_pub,
                    seed_ecdh_pub: verified.seed_ecdh_pub,
                    authz_pub: verified.authz_pub,
                    authz_alg: crate::hsm::blob::AuthzAlg::Ed25519,
                    attestation_fps: verified.attestation_fps,
                    state: MemberState::Active,
                    pending_revocations: Vec::new(),
                },
            );
        }
        // 2. Every enrolled node gets a key on every new device.
        let mut enrolled = Enrolled { own: Vec::new(), deliveries: BTreeMap::new(), enrollments, created: Vec::new() };
        let mut prepared = self.enroll_on_new_members(sessions, &mut enrolled).await;
        if prepared.is_ok() {
            // 3. The barrier, opened with the recovered KEK for the custody
            //    sets and the epoch bump only; this also proves the KEK.
            prepared = barrier.unseal(kek).await;
        }
        let outcome = match prepared {
            Ok(()) => {
                let committed = self
                    .wrap_and_commit(devices, sessions, key, kek, record, anchor, new_members, &enrolled, &barrier)
                    .await;
                let rotation = match &committed {
                    Ok((committed_record, ..)) => {
                        Some(self.bump_epoch(sessions, devices, &barrier, committed_record, actor).await)
                    }
                    Err(_) => None,
                };
                committed.map(|c| (c, rotation))
            }
            Err(e) => Err(e),
        };
        if !barrier.sealed().unwrap_or(false) {
            if let Err(e) = barrier.seal() {
                log::error!(target: "security", "HSM recovery: resealing the barrier failed: {e}");
            }
        }
        let ((committed, new_names, retired, custody), rotation) = match outcome {
            Ok(done) => done,
            Err(e) => {
                for (target, session) in sessions {
                    for (_, id) in enrolled.created.iter().filter(|(h, _)| *h == target.hsm_id) {
                        if let Err(undo) = session.delete_node_auth_key(*id).await {
                            log::error!(target: "security", "recovery rollback of key {id:#06x} on {} failed: {undo}", target.name);
                        }
                    }
                }
                log::error!(target: "security", "HSM recovery ceremony failed and was rolled back: {e}");
                return Err(e);
            }
        };
        let (epoch, rotation_error) = match rotation {
            Some(Ok(value)) => (value["epoch"].as_u64().unwrap_or(committed.epoch), None),
            Some(Err(e)) => (committed.epoch, Some(e.to_string())),
            None => (committed.epoch, None),
        };
        let report = json!({
            "new_members": new_names,
            "retired_members": retired,
            "epoch": epoch,
            "epoch_rotated": rotation_error.is_none(),
            "rotation_error": rotation_error,
            "custody_recovered": custody.recovered,
            "custody_already_on_new_members": custody.already,
            "custody_unrecovered": custody.unrecovered,
            "invalid_custody_entries": custody.invalid,
            "nodes_enrolled": enrolled.enrollments.iter().map(|e| e.node_id.clone()).collect::<Vec<_>>(),
            "operator_steps": [
                "reset or destroy the lost devices if they are ever found: their keys still open old copies",
                "remove the lost devices' gateways from every node's config and point the `member` blocks at the new ones",
                "every other enrolled node picks up its new credentials on its next membership refresh and unseals",
            ],
        });
        Ok((report, new_names, retired, custody))
    }

    /// Create every live node's key on every new member: this node's
    /// credentials are kept for local install (never storage), the others
    /// are sealed to their transport keys for delivery.
    #[maybe_async::maybe_async]
    async fn enroll_on_new_members(&self, sessions: &Sessions, enrolled: &mut Enrolled) -> Result<(), RvError> {
        let physical = self.physical.as_ref();
        for (target, session) in sessions {
            for e in enrolled.enrollments.iter_mut() {
                let auth_key_id = node_auth_key_id(e.slot()?)?;
                let credential = NodeCredential::generate(auth_key_id)?;
                session.put_node_auth_key(&format!("bv-node-{}", e.node_id), &credential).await?;
                enrolled.created.push((target.hsm_id.clone(), auth_key_id));
                if e.node_id == self.config.node_id {
                    enrolled.own.push((target.hsm_id.clone(), credential));
                } else {
                    if !enrolled.deliveries.contains_key(&e.node_id) {
                        let existing =
                            read_delivery(physical, &e.node_id).await?.filter(|d| d.transport_fp == e.transport_fp);
                        let delivery = existing.unwrap_or_else(|| CredentialDelivery::new(&e.node_id, &e.transport_fp));
                        enrolled.deliveries.insert(e.node_id.clone(), delivery);
                    }
                    let sealed = seal_credential(&e.node_id, &target.hsm_id, &e.transport_pub, &credential)?;
                    if let Some(delivery) = enrolled.deliveries.get_mut(&e.node_id) {
                        delivery.credentials.insert(target.hsm_id.clone(), sealed);
                    }
                }
                e.auth_keys.insert(target.hsm_id.clone(), auth_key_id);
                let sig = session
                    .identity_sign(self.config.objects.identity, ENROLLMENT_CONTEXT, &e.tbs(&target.hsm_id)?)
                    .await?;
                e.signatures.insert(target.hsm_id.clone(), hex::encode(sig));
            }
        }
        Ok(())
    }

    /// Steps 3–7: install this node's credentials, wrap and verify the KEK on
    /// every new member, recover the custody sets through the barrier, then
    /// commit the record (old members retired) against the bytes the
    /// ceremony started from.
    #[maybe_async::maybe_async]
    #[allow(clippy::too_many_arguments)] // the ceremony's state, threaded through once
    async fn wrap_and_commit(
        &self,
        devices: &PoolDevices,
        sessions: &Sessions,
        key: &RecoveryKey,
        kek: &Zeroizing<Vec<u8>>,
        record: &HsmSealRecord,
        anchor: &[u8],
        new_members: BTreeMap<HsmId, HsmMember>,
        enrolled: &Enrolled,
        barrier: &Arc<dyn SecurityBarrier>,
    ) -> Result<(HsmSealRecord, Vec<String>, Vec<String>, CustodyOutcome), RvError> {
        let physical = self.physical.as_ref();
        let objects = self.config.objects;
        let pool_cfg = self.config.pool.as_ref().ok_or_else(|| RvError::ErrHsm("not a pool provider".into()))?;
        let store = devices.cache.credentials.as_ref().ok_or_else(|| RvError::ErrHsm("no credential_dir".into()))?;
        store.install_direct(&enrolled.own)?;
        let new_ids: Vec<HsmId> = sessions.iter().map(|(t, _)| t.hsm_id.clone()).collect();
        devices.cache.forget_clients(&new_ids);
        let specs = devices.cache.specs_for(pool_cfg, sessions.iter().map(|(t, _)| (t.clone(), Vec::new())).collect());
        let pool = HsmPool::new(&self.config.node_id, specs, 1, devices.clock.clone(), devices.events.clone())?;

        // The KEK on every new member, each copy proven by an authorized
        // unwrap through that member before anything is committed.
        let kek_set = record.kek.clone().ok_or_else(|| RvError::ErrHsm("pool seal record has no KEK set".into()))?;
        let ctx = self.barrier_context(&record.cluster_uuid, kek_set.epoch);
        let barrier_key = record.wrap_key_ids(kek_set.epoch, &objects)?.barrier;
        let mut new_kek = kek_set.clone();
        for id in &new_ids {
            let copy = pool.wrap_on(id, barrier_key, &ctx, kek).await?;
            let member = pool.member(id).ok_or_else(|| RvError::ErrHsm(format!("{id} is not in this pool")))?;
            let pinned = &new_members[id];
            let counter = self.next_counter().await?;
            let back =
                self.rewrap_unwrap(member, pinned, &copy, &ctx, Purpose::BarrierKek, counter, barrier_key).await?;
            if back.as_slice() != kek.as_slice() {
                return Err(RvError::ErrHsm(format!("the new KEK copy on {id} does not unwrap to the KEK")));
            }
            new_kek.insert_copy(copy)?;
        }

        let storage: Arc<dyn Storage> = barrier.clone();
        let custody = self.recover_custody(&pool, key, record, &new_ids, &storage).await?;

        let mut committed = record.clone();
        committed.kek = Some(new_kek);
        let mut retired = Vec::new();
        for m in committed.members.values_mut().filter(|m| m.state != MemberState::Retired) {
            m.state = MemberState::Retired;
            if !m.pending_revocations.is_empty() {
                log::warn!(
                    target: "security",
                    "HSM recovery: member {} is retired with revocations still pending for {:?}; reset or destroy the \
                     device",
                    m.name,
                    m.pending_revocations
                );
                m.pending_revocations.clear();
            }
            retired.push(m.name.clone());
        }
        let new_names: Vec<String> = new_members.values().map(|m| m.name.clone()).collect();
        committed.members.extend(new_members);
        for delivery in enrolled.deliveries.values() {
            write_delivery(physical, delivery).await?;
        }
        for e in &enrolled.enrollments {
            write_enrollment(physical, e).await?;
        }
        {
            let _custody_lock = physical.lock(HSM_CUSTODY_LOCK).await?;
            let current = physical.get(HSM_SEAL_RECORD_PATH).await?.map(|e| e.value);
            if current.as_deref() != Some(anchor) {
                return Err(RvError::ErrHsm(
                    "the seal record changed during the recovery ceremony; nothing was committed".into(),
                ));
            }
            self.store_record(&committed).await?;
        }
        if let Err(e) = devices.pool_for_record(&self.config, &committed) {
            log::warn!(target: "security", "rebuilding this node's HSM pool after recovery failed: {e}");
        }
        for (id, m) in committed.members.iter().filter(|(_, m)| m.state == MemberState::Active) {
            self.event(PoolEventKind::MemberAdded, &m.name, id.as_str(), "state=active (recovery ceremony)");
        }
        Ok((committed, new_names, retired, custody))
    }

    /// Every custody set without a copy on each new member is opened from
    /// its recovery copy, checked against its public key, and wrapped on the
    /// new members at its own epoch. A set that cannot be recovered is
    /// reported and raised, never skipped silently; it does not stop the
    /// others.
    #[maybe_async::maybe_async]
    async fn recover_custody(
        &self,
        pool: &HsmPool,
        key: &RecoveryKey,
        record: &HsmSealRecord,
        new_ids: &[HsmId],
        storage: &Arc<dyn Storage>,
    ) -> Result<CustodyOutcome, RvError> {
        let mut out = CustodyOutcome::default();
        for key_id in storage.list(CUSTODY_STORE_PREFIX).await? {
            let skey = format!("{CUSTODY_STORE_PREFIX}{key_id}");
            let Some(entry) = storage.get(&skey).await? else { continue };
            let custody = match (is_key_id(&key_id), CustodyRecord::decode(&key_id, &entry.value)) {
                (true, Ok(r)) => r,
                _ => {
                    out.invalid.push(key_id);
                    continue;
                }
            };
            if new_ids.iter().all(|id| custody.set.copy_for(id).is_some()) {
                out.already += 1;
                continue;
            }
            let kind = custody.kind()?;
            let epoch = custody.set.epoch;
            let unrecoverable = |why: String| {
                self.event(PoolEventKind::CryptoFailure, "", "", &format!("recovery: custody key {key_id}: {why}"));
                format!("{key_id}: {why}")
            };
            let Some(envelope) = &custody.set.recovery else {
                out.unrecovered.push(format!("{key_id}: no recovery copy"));
                continue;
            };
            let seed = match key.open(envelope, &custody_recovery_aad(&record.cluster_uuid, kind, epoch, &key_id)) {
                Ok(seed) => seed,
                Err(e) => {
                    out.unrecovered.push(unrecoverable(e.to_string()));
                    continue;
                }
            };
            if PqcKeypair::from_seed(kind, &seed)?.public_key() != custody.public_key.as_slice() {
                out.unrecovered
                    .push(unrecoverable("the recovered seed does not derive the recorded public key".into()));
                continue;
            }
            let ctx = Context::new(
                kind.seed_context(&record.cluster_uuid, epoch),
                kind.purpose(),
                epoch,
                &self.config.node_id,
            );
            let wrap_key = record.wrap_key_ids(epoch, &self.config.objects)?.pqc;
            let mut set = custody.set.clone();
            for id in new_ids.iter().filter(|id| custody.set.copy_for(id).is_none()) {
                set.insert_copy(pool.wrap_on(id, wrap_key, &ctx, &seed).await?)?;
            }
            drop(seed);
            let _custody_lock = storage.lock(HSM_CUSTODY_LOCK).await?;
            if storage.get(&skey).await?.is_none_or(|c| c.value != entry.value) {
                return Err(RvError::ErrHsm(format!("custody key {key_id} changed during the recovery ceremony")));
            }
            let updated = CustodyRecord { set, ..custody };
            storage.put(&StorageEntry { key: skey, value: updated.encode()? }).await?;
            out.recovered += 1;
        }
        if !out.unrecovered.is_empty() {
            log::error!(target: "security", "HSM recovery: custody sets not recovered: {:?}", out.unrecovered);
        }
        Ok(out)
    }

    /// Step 8, the epoch bump: the rotation ceremony on the new members,
    /// which also drops every retired copy and re-seals each recovery copy
    /// at the new epoch. Recovery is complete without it; a failure is
    /// reported and `rotate-epoch` finishes it later.
    #[maybe_async::maybe_async]
    async fn bump_epoch(
        &self,
        sessions: &Sessions,
        devices: &PoolDevices,
        barrier: &Arc<dyn SecurityBarrier>,
        record: &HsmSealRecord,
        actor: &str,
    ) -> Result<Value, RvError> {
        let storage: Arc<dyn Storage> = barrier.clone();
        let target = record.rotating_to.unwrap_or(record.epoch + 1);
        let active: BTreeSet<&HsmId> = record.active_members().map(|(id, _)| id).collect();
        if sessions.iter().any(|(t, _)| !active.contains(&t.hsm_id)) {
            return Err(RvError::ErrHsm("the new members are not the active ones".into()));
        }
        self.rotate_on(sessions, devices, &storage, record.clone(), record.epoch, target, actor).await.inspect_err(
            |e| log::error!(target: "security", "HSM recovery: the epoch bump failed (run rotate-epoch): {e}"),
        )
    }
}
