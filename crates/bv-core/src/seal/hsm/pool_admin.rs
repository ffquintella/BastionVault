//! Pool ceremonies and repair on the seal provider (T454 phase 4).
//!
//! Node enroll and revoke, member add and retire, and the repair job. Each
//! ceremony takes the admin credentials it needs for that request only, holds
//! `hsm-custody` for its whole read-modify-write, and closes every admin
//! session it opened. Spec: `features/hsm-pool-ha.md` § Node enrollment and
//! revocation, § Pool membership, § Degraded operation and repair.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use bv_metrics::hsm_metrics::{hsm_metrics, UnderReplicatedScope};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use super::{
    record::{HsmMember, HsmSealRecord, MemberState, Topology, WrapKeyIds},
    targets_of, Devices, HsmSealProvider, PoolDevices,
};
use crate::{
    errors::RvError,
    hsm::{
        admin::{
            node_auth_key_id, AdminCredentials, HsmAdminSession, NodeCredential, ObjectKind, MAX_POOL_NODES,
            WRAP_KEY_CAPABILITIES,
        },
        authz::{self, UnwrapRequest},
        authz_fingerprint_of,
        blob::{AuthzAlg, BvHsmBlob, Context, HsmId, Purpose},
        blobset::{unix_now_secs, BvHsmBlobSet},
        ceremony::{
            list_enrollments, read_enrollment, verify_member, write_bootstrap, write_enrollment, write_promotion,
            AttestationBundle, BootstrapRecord, NodeEnrollment, PromotionTranscript, Revocation, ENROLLMENT_CONTEXT,
            PROMOTION_CONTEXT,
        },
        custody_store::{is_key_id, CustodyRecord, CUSTODY_STORE_PREFIX, HSM_CUSTODY_LOCK},
        node_creds::{
            self, discard_node_entries, list_pending, read_delivery, read_pending, seal_credential, write_delivery,
            CredentialDelivery,
        },
        pool::{HsmPool, PoolEvent, PoolEventKind, PoolMember, MAX_LIVE_MEMBERS},
        repair::{drop_retired, plan, Pacer, RepairReport, SetPlan, HSM_REPAIR_LOCK, REPAIR_INTERVAL},
        validate_member_name, validate_node_id, verify_identity_signature, HsmObjectId, MemberTarget,
    },
    storage::{Storage, StorageEntry},
};

type Sessions = Vec<(MemberTarget, Box<dyn HsmAdminSession>)>;

#[maybe_async::maybe_async]
async fn close_all(sessions: Sessions) {
    for (target, session) in sessions {
        if let Err(e) = session.close().await {
            log::warn!(target: "security", "closing the admin session on {} failed: {e}", target.name);
        }
    }
}

fn live(member: &HsmMember) -> bool {
    matches!(member.state, MemberState::Active | MemberState::Joining)
}

fn member_named<'r>(record: &'r HsmSealRecord, name: &str) -> Result<(&'r HsmId, &'r HsmMember), RvError> {
    record
        .members
        .iter()
        .find(|(_, m)| m.name == name)
        .ok_or_else(|| RvError::ErrHsm(format!("{name:?} is not an HSM pool member")))
}

impl HsmSealProvider {
    /// Raise a pool event: the security log, and the audit log once attached.
    fn event(&self, kind: PoolEventKind, member: &str, hsm_id: &str, detail: &str) {
        if let Devices::Pool(devices) = &self.devices {
            let event =
                PoolEvent { kind, member: member.to_string(), hsm_id: hsm_id.to_string(), detail: detail.to_string() };
            devices.events.emit(&event);
        }
    }

    fn pool_devices(&self) -> Result<&PoolDevices, RvError> {
        match &self.devices {
            Devices::Pool(devices) => Ok(devices),
            Devices::PerNode(_) => Err(RvError::ErrHsm(
                "HSM pool ceremonies need topology = \"pool\"; this node runs the per-node topology".into(),
            )),
        }
    }

    /// The pool seal record; ceremonies need an initialized pool.
    #[maybe_async::maybe_async]
    async fn pool_record(&self) -> Result<HsmSealRecord, RvError> {
        let stored = self.load_record().await?.ok_or_else(|| {
            RvError::ErrHsm("the HSM pool is not initialized (no seal record); run `operator init` first".into())
        })?;
        if stored.record.topology != Topology::Pool {
            return Err(RvError::ErrHsm("the HSM seal record is per-node, not a pool".into()));
        }
        Ok(stored.record)
    }

    /// Open a `bv-admin` session on each target, or none: every credential is
    /// checked first, and a session to the wrong device is refused.
    #[maybe_async::maybe_async]
    async fn open_admin_sessions(
        &self,
        targets: Vec<MemberTarget>,
        admin: &AdminCredentials,
    ) -> Result<Sessions, RvError> {
        let devices = self.pool_devices()?;
        for target in &targets {
            admin.for_member(&target.name)?;
        }
        let mut sessions: Sessions = Vec::new();
        for target in targets {
            let opened = devices.cache.opener.open_admin(&target, admin.for_member(&target.name)?);
            let checked = opened.and_then(|session| match session.hsm_id() {
                Ok(id) if id == target.hsm_id => Ok(session),
                Ok(id) => {
                    Err(RvError::ErrHsm(format!("member {} reached device {id}, not {}", target.name, target.hsm_id)))
                }
                Err(e) => Err(e),
            });
            match checked {
                Ok(session) => sessions.push((target, session)),
                Err(e) => {
                    close_all(sessions).await;
                    log::error!(target: "security", "admin session on HSM pool member {} refused: {e}", target.name);
                    return Err(e);
                }
            }
        }
        Ok(sessions)
    }

    /// Delete, through `sessions`, every pending revocation on those members.
    /// Returns "node on member" for each one applied; the record is updated.
    #[maybe_async::maybe_async]
    async fn apply_pending_revocations(
        &self,
        sessions: &Sessions,
        record: &mut HsmSealRecord,
        enrollments: &[NodeEnrollment],
    ) -> Result<Vec<String>, RvError> {
        let mut applied = Vec::new();
        for (target, session) in sessions {
            let Some(member) = record.members.get_mut(&target.hsm_id) else { continue };
            let mut still_pending = Vec::new();
            for node in std::mem::take(&mut member.pending_revocations) {
                let key_id =
                    enrollments.iter().find(|e| e.node_id == node).and_then(|e| e.auth_keys.get(&target.hsm_id));
                let Some(key_id) = key_id else {
                    log::error!(target: "security", "pending revocation of {node} on {}: no enrollment names its key", target.name);
                    still_pending.push(node);
                    continue;
                };
                match session.delete_node_auth_key(*key_id).await {
                    Ok(_) => {
                        let detail = format!("node={node} (pending revocation applied)");
                        self.event(PoolEventKind::NodeRevoked, &target.name, target.hsm_id.as_str(), &detail);
                        applied.push(format!("{node} on {}", target.name));
                    }
                    Err(e) => {
                        log::error!(target: "security", "pending revocation of {node} on {} failed: {e}", target.name);
                        still_pending.push(node);
                    }
                }
            }
            member.pending_revocations = still_pending;
        }
        Ok(applied)
    }

    /// `GET v2/sys/hsm/members`: the record's members and this node's view.
    #[maybe_async::maybe_async]
    pub async fn hsm_members(&self) -> Result<Value, RvError> {
        let devices = self.pool_devices()?;
        let record = self.pool_record().await?;
        let pool = devices.pool_for_record(&self.config, &record)?;
        let view = pool.member_status();
        let members: Vec<Value> = record
            .members
            .iter()
            .map(|(id, m)| {
                let seen = view.iter().find(|v| v.hsm_id == id.as_str());
                json!({
                    "name": m.name,
                    "hsm_id": id,
                    "serial": m.serial,
                    "gateway": m.gateway,
                    "state": m.state,
                    "authz_alg": m.authz_alg,
                    "attestation_fps": m.attestation_fps,
                    "pending_revocations": m.pending_revocations,
                    "holds_kek_copy": record.kek.as_ref().is_some_and(|k| k.copy_for(id).is_some()),
                    "up": seen.map(|v| v.up),
                    "last_error": seen.and_then(|v| v.last_error.clone()),
                })
            })
            .collect();
        Ok(json!({ "members": members, "max_live_members": MAX_LIVE_MEMBERS }))
    }

    /// `GET v2/sys/hsm/nodes`: enrolled and pending nodes.
    #[maybe_async::maybe_async]
    pub async fn hsm_nodes(&self) -> Result<Value, RvError> {
        self.pool_devices()?;
        let record = self.pool_record().await?;
        let physical = self.physical.as_ref();
        let enrollments = list_enrollments(physical).await?;
        let mut enrolled = Vec::new();
        for e in &enrollments {
            let signatures: BTreeMap<String, bool> = e
                .auth_keys
                .keys()
                .map(|id| {
                    let ok = record.members.get(id).is_some_and(|m| e.verify(id, &m.identity_pub).is_ok());
                    (id.to_string(), ok)
                })
                .collect();
            let auth_keys: BTreeMap<String, String> =
                e.auth_keys.iter().map(|(id, k)| (id.to_string(), format!("{k:#06x}"))).collect();
            enrolled.push(json!({
                "node_id": e.node_id,
                "auth_keys": auth_keys,
                "transport_fp": e.transport_fp,
                "enrolled_at": e.enrolled_at,
                "enrolled_by": e.enrolled_by,
                "revoked": e.revoked,
                "signatures_valid": signatures,
                "credentials_waiting": read_delivery(physical, &e.node_id).await?.is_some(),
            }));
        }
        let mut pending = Vec::new();
        for node in list_pending(physical).await? {
            if enrollments.iter().any(|e| e.node_id == node && !e.is_revoked()) {
                continue;
            }
            if let Some(p) = read_pending(physical, &node).await? {
                pending
                    .push(json!({ "node_id": p.node_id, "transport_fp": p.transport_fp, "created_at": p.created_at }));
            }
        }
        let active = enrollments.iter().filter(|e| !e.is_revoked()).count();
        Ok(json!({ "enrolled": enrolled, "pending": pending, "enrolled_count": active, "max_nodes": MAX_POOL_NODES }))
    }

    /// `node add` (spec § Node enrollment): create `bv-node-<node_id>` on
    /// every live member, seal each credential to the node's transport key
    /// (whose fingerprint the operator confirmed), and sign the enrollment.
    #[maybe_async::maybe_async]
    pub async fn enroll_node(
        &self,
        node_id: &str,
        transport_fp: &str,
        admin: &AdminCredentials,
        actor: &str,
    ) -> Result<Value, RvError> {
        validate_node_id(node_id)?;
        if transport_fp.trim().is_empty() {
            return Err(RvError::ErrHsm(
                "node add needs the transport key fingerprint the node logged, confirmed out of band".into(),
            ));
        }
        self.pool_devices()?;
        let physical = self.physical.as_ref();
        let _custody_lock = physical.lock(HSM_CUSTODY_LOCK).await?;
        let mut record = self.pool_record().await?;
        let pending = read_pending(physical, node_id).await?.ok_or_else(|| {
            RvError::ErrHsm(format!(
                "node {node_id} has published no transport key; start it with topology = \"pool\" and `credential_dir`"
            ))
        })?;
        if pending.transport_fp != transport_fp.trim() {
            log::error!(target: "security", "enrollment of {node_id} refused: the confirmed fingerprint does not match");
            return Err(RvError::ErrHsm(format!(
                "the fingerprint given does not match node {node_id}'s transport key ({}); enrollment refused",
                pending.transport_fp
            )));
        }
        let enrollments = list_enrollments(physical).await?;
        if enrollments.iter().any(|e| e.node_id == node_id && !e.is_revoked()) {
            return Err(RvError::ErrHsm(format!("node {node_id} is already enrolled; revoke it first")));
        }
        let enrolled = enrollments.iter().filter(|e| !e.is_revoked()).count();
        if enrolled >= MAX_POOL_NODES {
            log::error!(target: "security", "enrollment of {node_id} refused: the pool has {enrolled} nodes");
            return Err(RvError::ErrHsm(format!(
                "the HSM pool already has {enrolled} enrolled nodes, the supported maximum of {MAX_POOL_NODES} (16 \
                 device sessions); revoke a node first"
            )));
        }
        let targets: Vec<MemberTarget> =
            targets_of(record.members.iter().filter(|(_, m)| live(m))).into_iter().map(|(t, _)| t).collect();
        let sessions = self.open_admin_sessions(targets, admin).await?;
        let result = self.enroll_on(&sessions, &mut record, &enrollments, &pending, actor).await;
        close_all(sessions).await;
        result
    }

    #[maybe_async::maybe_async]
    async fn enroll_on(
        &self,
        sessions: &Sessions,
        record: &mut HsmSealRecord,
        enrollments: &[NodeEnrollment],
        pending: &node_creds::PendingNode,
        actor: &str,
    ) -> Result<Value, RvError> {
        let physical = self.physical.as_ref();
        let node_id = pending.node_id.as_str();
        let revocations_applied = self.apply_pending_revocations(sessions, record, enrollments).await?;
        let pending_nodes: BTreeSet<String> =
            record.members.values().flat_map(|m| m.pending_revocations.iter().cloned()).collect();
        let auth_key_id = node_auth_key_id(self.free_slot(sessions, &pending_nodes, enrollments).await?)?;
        let mut enrollment = NodeEnrollment::new(
            node_id,
            pending.transport_pub.clone(),
            pending.transport_fp.clone(),
            unix_now_secs()?,
            actor,
        );
        let mut delivery = CredentialDelivery::new(node_id, &pending.transport_fp);
        let mut created: Vec<usize> = Vec::new();
        let outcome: Result<(), RvError> = async {
            for (i, (target, session)) in sessions.iter().enumerate() {
                let credential = NodeCredential::generate(auth_key_id)?;
                session.put_node_auth_key(&format!("bv-node-{node_id}"), &credential).await?;
                created.push(i);
                let sealed = seal_credential(node_id, &target.hsm_id, &pending.transport_pub, &credential)?;
                delivery.credentials.insert(target.hsm_id.clone(), sealed);
                enrollment.auth_keys.insert(target.hsm_id.clone(), auth_key_id);
                let tbs = enrollment.tbs(&target.hsm_id)?;
                let sig = session.identity_sign(self.config.objects.identity, ENROLLMENT_CONTEXT, &tbs).await?;
                enrollment.signatures.insert(target.hsm_id.clone(), hex::encode(sig));
            }
            write_delivery(physical, &delivery).await?;
            write_enrollment(physical, &enrollment).await?;
            node_creds::delete_pending(physical, node_id).await?;
            self.store_record(record).await
        }
        .await;
        if let Err(e) = outcome {
            for i in created {
                let (target, session) = &sessions[i];
                if let Err(undo) = session.delete_node_auth_key(auth_key_id).await {
                    log::error!(target: "security", "rolling back bv-node-{node_id} on {} failed: {undo}", target.name);
                }
            }
            log::error!(target: "security", "enrollment of {node_id} failed and was rolled back: {e}");
            return Err(e);
        }
        let members: Vec<&str> = sessions.iter().map(|(t, _)| t.name.as_str()).collect();
        for (target, _) in sessions {
            let detail = format!("node={node_id} auth_key={auth_key_id:#06x} by={actor}");
            self.event(PoolEventKind::NodeEnrolled, &target.name, target.hsm_id.as_str(), &detail);
        }
        Ok(json!({
            "node_id": node_id,
            "auth_key_id": format!("{auth_key_id:#06x}"),
            "members": members,
            "transport_fp": pending.transport_fp,
            "revocations_applied": revocations_applied,
            "next": "the node installs its credentials on its next unseal or membership refresh (30 s)",
        }))
    }

    /// Init's bootstrap enrollment (spec § Bootstrap at init, steps 1–3 and
    /// 7): before any seal record exists, create this node's key on every
    /// configured member with the admin credentials, store the credentials
    /// locally (never in storage), and write the enrollment record.
    #[maybe_async::maybe_async]
    pub async fn bootstrap_enroll(
        &self,
        admin: &AdminCredentials,
        bundles: &BTreeMap<String, AttestationBundle>,
        actor: &str,
    ) -> Result<Value, RvError> {
        let devices = self.pool_devices()?;
        let pool_cfg = self.config.pool.as_ref().ok_or_else(|| RvError::ErrHsm("not a pool provider".into()))?;
        let store = devices.cache.credentials.as_ref().ok_or_else(|| {
            RvError::ErrHsmConfigInvalid("bootstrap enrollment needs `credential_dir` in the pool `hsm` block".into())
        })?;
        let node_id = self.config.node_id.as_str();
        let physical = self.physical.as_ref();
        let _custody_lock = physical.lock(HSM_CUSTODY_LOCK).await?;
        // Allowed over a per-node record only when this node is set up to
        // migrate it (`migrate_from`); otherwise the pool is initialized.
        if let Some(stored) = self.load_record().await? {
            if stored.record.topology != Topology::PerNode || self.migration_source.is_none() {
                return Err(RvError::ErrHsm(
                    "the HSM pool is already initialized; enroll further nodes with `node add`".into(),
                ));
            }
        }
        if read_enrollment(physical, node_id).await?.is_some_and(|e| !e.is_revoked()) {
            return Err(RvError::ErrHsm(format!("node {node_id} is already enrolled for bootstrap")));
        }
        let enrollments = list_enrollments(physical).await?;
        let pending = store.ensure_transport_key()?;
        let targets = pool_cfg
            .members
            .iter()
            .map(|m| {
                let hsm_id = m.hsm_id(&self.config.backend_type)?;
                Ok(MemberTarget { name: m.name.clone(), hsm_id, gateway: m.gateway.clone() })
            })
            .collect::<Result<Vec<_>, RvError>>()?;
        let sessions = self.open_admin_sessions(targets, admin).await?;
        let result: Result<Value, RvError> = async {
            // Spec § Bootstrap, step 1: attest both devices before anything changes.
            let mut attested = BootstrapRecord::new(node_id);
            for (target, session) in &sessions {
                let bundle = bundles.get(&target.name).ok_or_else(|| {
                    RvError::ErrHsmAttestationInvalid(format!("no attestation bundle for member {}", target.name))
                })?;
                let verified = verify_member(session.as_ref(), bundle, &self.config.objects).await?;
                attested.insert(&target.name, &verified);
            }
            let auth_key_id = node_auth_key_id(self.free_slot(&sessions, &BTreeSet::new(), &enrollments).await?)?;
            let mut enrollment =
                NodeEnrollment::new(node_id, pending.transport_pub.clone(), pending.transport_fp.clone(), unix_now_secs()?, actor);
            let mut made = Vec::new();
            let outcome: Result<(), RvError> = async {
                for (target, session) in &sessions {
                    let credential = NodeCredential::generate(auth_key_id)?;
                    session.put_node_auth_key(&format!("bv-node-{node_id}"), &credential).await?;
                    made.push((target.hsm_id.clone(), credential));
                    enrollment.auth_keys.insert(target.hsm_id.clone(), auth_key_id);
                    let tbs = enrollment.tbs(&target.hsm_id)?;
                    let sig = session.identity_sign(self.config.objects.identity, ENROLLMENT_CONTEXT, &tbs).await?;
                    enrollment.signatures.insert(target.hsm_id.clone(), hex::encode(sig));
                }
                store.install_direct(&made)?;
                write_bootstrap(physical, &attested).await?;
                write_enrollment(physical, &enrollment).await
            }
            .await;
            if let Err(e) = outcome {
                for (target, session) in sessions.iter().filter(|(t, _)| made.iter().any(|(id, _)| *id == t.hsm_id)) {
                    if let Err(undo) = session.delete_node_auth_key(auth_key_id).await {
                        log::error!(target: "security", "rolling back bv-node-{node_id} on {} failed: {undo}", target.name);
                    }
                }
                return Err(e);
            }
            let ids: Vec<HsmId> = made.iter().map(|(id, _)| id.clone()).collect();
            devices.cache.forget_clients(&ids);
            devices.rebuild_bootstrap(&self.config)?;
            for (target, _) in &sessions {
                let detail = format!("node={node_id} auth_key={auth_key_id:#06x} (init bootstrap) by={actor}");
                self.event(PoolEventKind::NodeEnrolled, &target.name, target.hsm_id.as_str(), &detail);
            }
            Ok(json!({ "node_id": node_id, "auth_key_id": format!("{auth_key_id:#06x}"), "members": ids }))
        }
        .await;
        close_all(sessions).await;
        result
    }

    /// Make sure every id in `ids` is a wrap key on the session's device with
    /// exactly `wrap-data` / `unwrap-data`: generate the missing ones, refuse
    /// one that exists with any other capability.
    #[maybe_async::maybe_async]
    async fn ensure_wrap_keys(session: &dyn HsmAdminSession, ids: &[WrapKeyIds]) -> Result<(), RvError> {
        for set in ids {
            for (id, name) in [(set.barrier, "bv-wrap-barrier"), (set.pqc, "bv-wrap-pqc")] {
                match session.object_info(ObjectKind::WrapKey, id).await? {
                    None => session.generate_wrap_key(id, name).await?,
                    Some(info) => {
                        let mut caps = info.capabilities.clone();
                        caps.sort();
                        if caps != WRAP_KEY_CAPABILITIES || !info.delegated.is_empty() {
                            return Err(RvError::ErrHsmAttestationInvalid(format!(
                                "wrap key {id} on {} has capabilities {caps:?}",
                                session.hsm_id()?
                            )));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// The lowest pair of wrap-key ids from 0x20 that no epoch, no configured
    /// object and no device among `sessions` uses.
    #[maybe_async::maybe_async]
    async fn allocate_wrap_ids(&self, sessions: &Sessions, record: &HsmSealRecord) -> Result<WrapKeyIds, RvError> {
        let o = &self.config.objects;
        let mut taken: BTreeSet<HsmObjectId> = [o.wrap_barrier, o.wrap_pqc, o.identity, o.authz, o.seed_ecdh].into();
        taken.extend(record.wrap_keys.values().flat_map(|k| [k.barrier, k.pqc]));
        let mut free = Vec::new();
        for id in 0x20u16..0x400 {
            if taken.contains(&id) {
                continue;
            }
            let mut used = false;
            for (_, session) in sessions {
                used |= session.object_info(ObjectKind::WrapKey, id).await?.is_some();
            }
            if !used {
                free.push(id);
                if free.len() == 2 {
                    return Ok(WrapKeyIds { barrier: free[0], pqc: free[1] });
                }
            }
        }
        Err(RvError::ErrHsm("no free wrap-key ids below 0x400".into()))
    }

    /// `rotate-epoch` (spec § HSM key epoch rotation): new wrap keys on every
    /// active member, every set re-wrapped to epoch + 1, then the old keys
    /// deleted. Crash-safe: the target epoch and its keys are recorded first
    /// (`rotating_to`), so a rerun resumes with them and skips moved sets.
    #[maybe_async::maybe_async]
    pub async fn rotate_epoch(
        &self,
        admin: &AdminCredentials,
        barrier: Option<Arc<dyn Storage>>,
        actor: &str,
    ) -> Result<Value, RvError> {
        let devices = self.pool_devices()?;
        let barrier = barrier
            .ok_or_else(|| RvError::ErrHsm("rotate-epoch needs the unsealed barrier to re-wrap custody sets".into()))?;
        let physical = self.physical.as_ref();
        let _repair_lock = physical.lock(HSM_REPAIR_LOCK).await?;
        if let Some(store) = &devices.cache.credentials {
            let installed = node_creds::pick_up(physical, store).await?;
            devices.cache.forget_clients(&installed);
        }
        let record = self.pool_record().await?;
        if record.members.values().any(|m| m.state == MemberState::Joining) {
            return Err(RvError::ErrHsm("a member is joining; promote or retire it before rotating the epoch".into()));
        }
        if record.members.values().any(|m| !m.pending_revocations.is_empty()) {
            return Err(RvError::ErrHsm("apply the pending revocations before rotating the epoch".into()));
        }
        if record.kek.as_ref().is_none_or(|k| k.recovery.is_some()) {
            return Err(RvError::ErrHsm("recovery copies are re-sealed by phase 5; rotation refuses them".into()));
        }
        let old_epoch = record.epoch;
        let target = record.rotating_to.unwrap_or(old_epoch + 1);
        let targets: Vec<MemberTarget> = targets_of(record.active_members()).into_iter().map(|(t, _)| t).collect();
        let sessions = self.open_admin_sessions(targets, admin).await?;
        let result = self.rotate_on(&sessions, devices, &barrier, record, old_epoch, target, actor).await;
        close_all(sessions).await;
        result
    }

    #[maybe_async::maybe_async]
    async fn rotate_on(
        &self,
        sessions: &Sessions,
        devices: &PoolDevices,
        barrier: &Arc<dyn Storage>,
        mut record: HsmSealRecord,
        old_epoch: u64,
        target: u64,
        actor: &str,
    ) -> Result<Value, RvError> {
        let physical = self.physical.as_ref();
        let defaults = self.config.objects;
        let old_ids = record.wrap_key_ids(old_epoch, &defaults)?;
        let new_ids = match record.wrap_keys.get(&target) {
            Some(ids) if record.rotating_to == Some(target) => *ids,
            _ => self.allocate_wrap_ids(sessions, &record).await?,
        };
        for (_, session) in sessions {
            Self::ensure_wrap_keys(session.as_ref(), &[new_ids]).await?;
        }
        if record.rotating_to != Some(target) {
            let _custody_lock = physical.lock(HSM_CUSTODY_LOCK).await?;
            record = self.pool_record().await?;
            record.wrap_keys.entry(old_epoch).or_insert(old_ids);
            record.wrap_keys.insert(target, new_ids);
            record.rotating_to = Some(target);
            self.store_record(&record).await?;
        }

        let pool_cfg = self.config.pool.as_ref().ok_or_else(|| RvError::ErrHsm("not a pool provider".into()))?;
        let specs = devices.cache.specs_for(pool_cfg, targets_of(record.active_members()));
        let pool = HsmPool::new(&self.config.node_id, specs, 1, devices.clock.clone(), devices.events.clone())?;
        let pacer = Pacer::new(pool_cfg.repair_rate);
        let mut moved = 0usize;
        for key_id in barrier.list(CUSTODY_STORE_PREFIX).await? {
            let key = format!("{CUSTODY_STORE_PREFIX}{key_id}");
            let Some(entry) = barrier.get(&key).await? else { continue };
            let custody = CustodyRecord::decode(&key_id, &entry.value)?;
            if custody.set.epoch == target {
                continue;
            }
            if custody.set.epoch != old_epoch {
                return Err(RvError::ErrHsm(format!(
                    "custody key {key_id} is at epoch {}, neither {old_epoch} nor {target}; rotation stopped",
                    custody.set.epoch
                )));
            }
            if custody.set.recovery.is_some() {
                return Err(RvError::ErrHsm(format!("custody key {key_id} has a recovery copy (phase 5)")));
            }
            let kind = custody.kind()?;
            let ctx_at = |e: u64| {
                Context::new(kind.seed_context(&record.cluster_uuid, e), kind.purpose(), e, &self.config.node_id)
            };
            let set = self
                .rewrapped(&pool, &record, &custody.set, &ctx_at(old_epoch), old_ids.pqc, &ctx_at(target), new_ids.pqc)
                .await?;
            let _custody_lock = barrier.lock(HSM_CUSTODY_LOCK).await?;
            if barrier.get(&key).await?.is_none_or(|c| c.value != entry.value) {
                return Err(RvError::ErrHsm(format!("custody key {key_id} changed during rotation; run it again")));
            }
            let updated = CustodyRecord { set, ..custody };
            barrier.put(&StorageEntry { key, value: updated.encode()? }).await?;
            moved += 1;
            pacer.pause().await;
        }

        let kek = record.kek.clone().ok_or_else(|| RvError::ErrHsm("pool seal record has no KEK set".into()))?;
        let ctx_old = self.barrier_context(&record.cluster_uuid, old_epoch);
        let ctx_new = self.barrier_context(&record.cluster_uuid, target);
        let new_kek =
            self.rewrapped(&pool, &record, &kek, &ctx_old, old_ids.barrier, &ctx_new, new_ids.barrier).await?;
        {
            let _custody_lock = physical.lock(HSM_CUSTODY_LOCK).await?;
            let mut current = self.pool_record().await?;
            if current.kek.as_ref() != Some(&kek) || current.rotating_to != Some(target) {
                return Err(RvError::ErrHsm("the seal record changed during rotation; run it again".into()));
            }
            current.kek = Some(new_kek);
            current.epoch = target;
            current.rotating_to = None;
            self.store_record(&current).await?;
            record = current;
        }

        // No set references the old epoch any more: delete its keys.
        let mut not_deleted = Vec::new();
        for (target_member, session) in sessions {
            for id in [old_ids.barrier, old_ids.pqc] {
                if let Err(e) = session.delete_wrap_key(id).await {
                    not_deleted.push(format!("{} on {}: {e}", id, target_member.name));
                }
            }
        }
        if not_deleted.is_empty() {
            let _custody_lock = physical.lock(HSM_CUSTODY_LOCK).await?;
            let mut current = self.pool_record().await?;
            current.wrap_keys.remove(&old_epoch);
            self.store_record(&current).await?;
        }
        for (t, _) in sessions {
            let detail = format!("epoch {old_epoch} -> {target}; custody sets moved={moved} by={actor}");
            self.event(PoolEventKind::EpochRotated, &t.name, t.hsm_id.as_str(), &detail);
        }
        Ok(json!({
            "epoch": record.epoch,
            "previous_epoch": old_epoch,
            "wrap_keys": { "barrier": new_ids.barrier, "pqc": new_ids.pqc },
            "custody_sets_moved": moved,
            "old_keys_not_deleted": not_deleted,
        }))
    }

    /// `set` unwrapped once (a `rewrap` authorization) and wrapped on every
    /// member of `pool` under `new_key` at `new_ctx`: a full set or an error.
    #[maybe_async::maybe_async]
    async fn rewrapped(
        &self,
        pool: &HsmPool,
        record: &HsmSealRecord,
        set: &BvHsmBlobSet,
        old_ctx: &Context,
        old_key: HsmObjectId,
        new_ctx: &Context,
        new_key: HsmObjectId,
    ) -> Result<BvHsmBlobSet, RvError> {
        let plaintext = self.rewrap_source(pool, record, set, old_ctx, old_key).await?;
        let outcome = pool.wrap_on_every_member(new_key, new_ctx, &plaintext).await?;
        drop(plaintext);
        let mut copies = outcome.copies.into_values();
        let first = copies.next().ok_or_else(|| RvError::ErrHsm("re-wrap produced no copy".into()))?;
        let mut new_set = BvHsmBlobSet::new(set.purpose, new_ctx.epoch, first, &self.config.node_id, unix_now_secs()?)?;
        for copy in copies {
            new_set.insert_copy(copy)?;
        }
        Ok(new_set)
    }

    /// `migrate-to-pool` (spec § Per-node → pool): the KEK through this
    /// node's per-node device (`migrate_from`, a signed unwrap), dual-wrapped
    /// on the attested pool members, written as a pool record that keeps the
    /// cluster id and epoch and drops the legacy blobs. One-way.
    #[maybe_async::maybe_async]
    pub async fn migrate_to_pool(&self, actor: &str) -> Result<Value, RvError> {
        let devices = self.pool_devices()?;
        let source = self.migration_source.as_ref().ok_or_else(|| {
            RvError::ErrHsmConfigInvalid("migrate-to-pool needs a `migrate_from` block in the pool `hsm` block".into())
        })?;
        let physical = self.physical.as_ref();
        let raw = physical
            .get(super::HSM_SEAL_RECORD_PATH)
            .await?
            .ok_or_else(|| RvError::ErrHsm("there is no seal record to migrate".into()))?
            .value;
        let stored = HsmSealRecord::decode(&raw)?;
        if stored.record.topology != Topology::PerNode {
            return Err(RvError::ErrHsm("the seal record is already a pool record".into()));
        }
        let kek = self.recover_per_node(source, &stored.record).await?;
        let (cluster_uuid, epoch) = (stored.record.cluster_uuid.clone(), stored.record.epoch);
        self.write_pool_record(devices, &kek, &cluster_uuid, epoch, Some(&raw)).await?;
        drop(kek);
        let legacy = stored.record.legacy_node_blobs.len() + usize::from(stored.record.kek.is_some());
        log::warn!(
            target: "security",
            "hsm.migrated_to_pool: cluster={cluster_uuid} epoch={epoch} per-node copies dropped={legacy} by={actor}; \
             this vault can no longer be unsealed per node"
        );
        Ok(json!({
            "cluster_uuid": cluster_uuid,
            "epoch": epoch,
            "topology": "pool",
            "per_node_copies_dropped": legacy,
            "note": "one-way: a pool record cannot be unsealed by a per-node configuration or an older build",
        }))
    }

    /// The lowest node slot no record holds and no live device uses.
    #[maybe_async::maybe_async]
    async fn free_slot(
        &self,
        sessions: &Sessions,
        pending: &BTreeSet<String>,
        enrollments: &[NodeEnrollment],
    ) -> Result<usize, RvError> {
        let mut used = BTreeSet::new();
        for e in enrollments {
            if !e.is_revoked() || pending.contains(&e.node_id) {
                used.insert(e.slot()?);
            }
        }
        let mut on_devices = BTreeSet::new();
        for (_, session) in sessions {
            on_devices.extend(session.auth_key_ids().await?);
        }
        (0..MAX_POOL_NODES)
            .find(|slot| !used.contains(slot) && node_auth_key_id(*slot).is_ok_and(|id| !on_devices.contains(&id)))
            .ok_or_else(|| RvError::ErrHsm(format!("no free node slot among {MAX_POOL_NODES}; revoke a node first")))
    }

    /// `node revoke` (spec § revoke): delete the node's key on every member
    /// reachable with an admin credential; any other member records a pending
    /// revocation and is treated as down by every node until it is applied.
    #[maybe_async::maybe_async]
    pub async fn revoke_node(&self, node_id: &str, admin: &AdminCredentials, actor: &str) -> Result<Value, RvError> {
        validate_node_id(node_id)?;
        let devices = self.pool_devices()?;
        let physical = self.physical.as_ref();
        let _custody_lock = physical.lock(HSM_CUSTODY_LOCK).await?;
        let mut record = self.pool_record().await?;
        let mut enrollment = read_enrollment(physical, node_id)
            .await?
            .ok_or_else(|| RvError::ErrHsm(format!("node {node_id} is not enrolled in the HSM pool")))?;
        // Undelivered credentials must never be installed after this point.
        discard_node_entries(physical, node_id).await?;

        let mut revoked_on = Vec::new();
        let mut pending = Vec::new();
        for (hsm_id, key_id) in &enrollment.auth_keys {
            let Some(member) = record.members.get(hsm_id) else { continue };
            if member.state == MemberState::Retired {
                continue;
            }
            let target =
                MemberTarget { name: member.name.clone(), hsm_id: hsm_id.clone(), gateway: member.gateway.clone() };
            let deleted = match admin.for_member(&member.name) {
                Err(e) => Err(e),
                Ok(password) => match devices.cache.opener.open_admin(&target, password) {
                    Err(e) => Err(e),
                    Ok(session) => {
                        let outcome = session.delete_node_auth_key(*key_id).await;
                        if let Err(e) = session.close().await {
                            log::warn!(target: "security", "closing the admin session on {} failed: {e}", member.name);
                        }
                        outcome
                    }
                },
            };
            match deleted {
                Ok(_) => revoked_on.push((hsm_id.clone(), member.name.clone())),
                Err(e) => pending.push((hsm_id.clone(), member.name.clone(), e.to_string())),
            }
        }
        for (hsm_id, _) in &revoked_on {
            if let Some(m) = record.members.get_mut(hsm_id) {
                m.pending_revocations.retain(|n| n != node_id);
            }
        }
        for (hsm_id, name, why) in &pending {
            log::error!(target: "security", "revocation of {node_id} on {name} is pending: {why}");
            if let Some(m) = record.members.get_mut(hsm_id) {
                if !m.pending_revocations.iter().any(|n| n == node_id) {
                    m.pending_revocations.push(node_id.to_string());
                }
            }
        }
        if enrollment.revoked.is_none() {
            enrollment.revoked = Some(Revocation { revoked_at: unix_now_secs()?, revoked_by: actor.to_string() });
        }
        write_enrollment(physical, &enrollment).await?;
        self.store_record(&record).await?;
        // This node stops using a member with a pending revocation at once.
        if let Err(e) = devices.pool_for_record(&self.config, &record) {
            log::warn!(target: "security", "rebuilding this node's HSM pool after the revocation failed: {e}");
        }
        for (hsm_id, name) in &revoked_on {
            self.event(PoolEventKind::NodeRevoked, name, hsm_id.as_str(), &format!("node={node_id} by={actor}"));
        }
        for (hsm_id, name, why) in &pending {
            let detail = format!("node={node_id} by={actor}: {why}");
            self.event(PoolEventKind::RevocationPending, name, hsm_id.as_str(), &detail);
        }
        Ok(json!({
            "node_id": node_id,
            "revoked_on": revoked_on.iter().map(|(_, n)| n).collect::<Vec<_>>(),
            "revocation_pending": pending.iter().map(|(_, n, why)| json!({ "member": n, "reason": why })).collect::<Vec<_>>(),
            "operator_steps": [
                format!("remove {node_id} from `allowed_clients` on every HSM gateway and reload it (SIGHUP)"),
                "update a down member's gateway before its host comes back".to_string(),
            ],
            "residual_risk": if pending.is_empty() { Value::Null } else { json!(
                "until each pending revocation is applied, a member that comes back still accepts this node's key on \
                 its device; every BastionVault node treats it as down, but only device-side deletion (node revoke or \
                 repair with that member's admin credential) closes it"
            ) },
        }))
    }

    /// `member add` (spec § Replace a failed device): attest the device,
    /// enroll every enrolled node on it, and add it as `joining`. Repair then
    /// fills its copies; an admin-credentialed repair promotes it.
    #[maybe_async::maybe_async]
    pub async fn add_member(
        &self,
        name: &str,
        bundle: &AttestationBundle,
        gateway: &str,
        admin: &AdminCredentials,
        actor: &str,
    ) -> Result<Value, RvError> {
        validate_member_name(name)?;
        let gateway = gateway.trim();
        if self.config.backend_type == "yubihsm2" && !gateway.starts_with("https://") {
            return Err(RvError::ErrHsm("a yubihsm2 member needs an https:// (mTLS) gateway URL".into()));
        }
        self.pool_devices()?;
        let hsm_id = bundle.hsm_id()?;
        if hsm_id.backend_type() != self.config.backend_type {
            return Err(RvError::ErrHsm(format!("{hsm_id} is not a {} device", self.config.backend_type)));
        }
        let physical = self.physical.as_ref();
        let _custody_lock = physical.lock(HSM_CUSTODY_LOCK).await?;
        let mut record = self.pool_record().await?;
        if record.members.values().any(|m| m.name == name) {
            return Err(RvError::ErrHsm(format!("the HSM pool already has a member named {name:?}")));
        }
        if let Some(existing) = record.members.get(&hsm_id) {
            return Err(RvError::ErrHsm(format!(
                "{hsm_id} is already member {:?} ({:?})",
                existing.name, existing.state
            )));
        }
        let live_members = record.members.values().filter(|m| m.state != MemberState::Retired).count();
        if live_members >= MAX_LIVE_MEMBERS {
            return Err(RvError::ErrHsm(format!(
                "the pool has {live_members} members that are not retired, the most it holds; retire the device \
                 being replaced first"
            )));
        }
        let target = MemberTarget { name: name.to_string(), hsm_id: hsm_id.clone(), gateway: gateway.to_string() };
        let sessions = self.open_admin_sessions(vec![target], admin).await?;
        let result = self.add_member_on(&sessions, &mut record, bundle, actor).await;
        close_all(sessions).await;
        result
    }

    #[maybe_async::maybe_async]
    async fn add_member_on(
        &self,
        sessions: &Sessions,
        record: &mut HsmSealRecord,
        bundle: &AttestationBundle,
        actor: &str,
    ) -> Result<Value, RvError> {
        let physical = self.physical.as_ref();
        let (target, session) = &sessions[0];
        let verified = verify_member(session.as_ref(), bundle, &self.config.objects).await?;
        // A device provisioned after a rotation holds only the default ids.
        let mut epoch_keys = vec![record.wrap_key_ids(record.epoch, &self.config.objects)?];
        if let Some(target_epoch) = record.rotating_to {
            epoch_keys.push(record.wrap_key_ids(target_epoch, &self.config.objects)?);
        }
        Self::ensure_wrap_keys(session.as_ref(), &epoch_keys).await?;
        let mut enrollments = list_enrollments(physical).await?;
        let mut created: Vec<u16> = Vec::new();
        let mut deliveries: Vec<CredentialDelivery> = Vec::new();
        let outcome: Result<(), RvError> = async {
            for e in enrollments.iter_mut().filter(|e| !e.is_revoked()) {
                let auth_key_id = node_auth_key_id(e.slot()?)?;
                let credential = NodeCredential::generate(auth_key_id)?;
                session.put_node_auth_key(&format!("bv-node-{}", e.node_id), &credential).await?;
                created.push(auth_key_id);
                let mut delivery = read_delivery(physical, &e.node_id)
                    .await?
                    .filter(|d| d.transport_fp == e.transport_fp)
                    .unwrap_or_else(|| CredentialDelivery::new(&e.node_id, &e.transport_fp));
                let sealed = seal_credential(&e.node_id, &target.hsm_id, &e.transport_pub, &credential)?;
                delivery.credentials.insert(target.hsm_id.clone(), sealed);
                deliveries.push(delivery);
                e.auth_keys.insert(target.hsm_id.clone(), auth_key_id);
                let sig = session
                    .identity_sign(self.config.objects.identity, ENROLLMENT_CONTEXT, &e.tbs(&target.hsm_id)?)
                    .await?;
                e.signatures.insert(target.hsm_id.clone(), hex::encode(sig));
            }
            record.members.insert(
                target.hsm_id.clone(),
                HsmMember {
                    name: target.name.clone(),
                    gateway: target.gateway.clone(),
                    serial: bundle.serial.clone(),
                    seed_ecdh_pub: verified.seed_ecdh_pub.clone(),
                    identity_pub: verified.identity_pub.clone(),
                    authz_pub: verified.authz_pub.clone(),
                    // Both backends sign authorizations with Ed25519 (phase 7
                    // settles `ecdsa-p256` for FIPS-mode devices).
                    authz_alg: AuthzAlg::Ed25519,
                    attestation_fps: verified.attestation_fps.clone(),
                    state: MemberState::Joining,
                    pending_revocations: Vec::new(),
                },
            );
            self.store_record(record).await?;
            for delivery in &deliveries {
                write_delivery(physical, delivery).await?;
            }
            for e in enrollments.iter().filter(|e| !e.is_revoked()) {
                write_enrollment(physical, e).await?;
            }
            Ok(())
        }
        .await;
        if let Err(e) = outcome {
            for id in created {
                if let Err(undo) = session.delete_node_auth_key(id).await {
                    log::error!(target: "security", "rolling back auth key {id:#06x} on {} failed: {undo}", target.name);
                }
            }
            log::error!(target: "security", "adding HSM pool member {} failed and was rolled back: {e}", target.name);
            return Err(e);
        }
        let nodes: Vec<&str> = enrollments.iter().filter(|e| !e.is_revoked()).map(|e| e.node_id.as_str()).collect();
        let detail = format!("state=joining nodes_enrolled={nodes:?} by={actor}");
        self.event(PoolEventKind::MemberAdded, &target.name, target.hsm_id.as_str(), &detail);
        Ok(json!({
            "name": target.name,
            "hsm_id": target.hsm_id,
            "state": "joining",
            "nodes_enrolled": nodes,
            "attestation_fps": verified.attestation_fps,
            "next": "repair fills this member's copies; a repair run with admin credentials for it and an active \
                     member promotes it to active",
        }))
    }

    /// `member retire`: refused if it would leave fewer active members than
    /// `min_wrap_copies` (at least one), or strand a set without another copy.
    #[maybe_async::maybe_async]
    pub async fn retire_member(
        &self,
        name: &str,
        barrier: Option<&dyn Storage>,
        actor: &str,
    ) -> Result<Value, RvError> {
        self.pool_devices()?;
        let min_copies = self.config.pool.as_ref().map(|p| p.min_wrap_copies).unwrap_or(1).max(1);
        let physical = self.physical.as_ref();
        let _custody_lock = physical.lock(HSM_CUSTODY_LOCK).await?;
        let mut record = self.pool_record().await?;
        let (hsm_id, member) = member_named(&record, name)?;
        let hsm_id = hsm_id.clone();
        if member.state == MemberState::Retired {
            return Err(RvError::ErrHsm(format!("member {name:?} is already retired")));
        }
        if member.state == MemberState::Active {
            let others: BTreeSet<HsmId> =
                record.active_members().map(|(id, _)| id.clone()).filter(|id| *id != hsm_id).collect();
            if others.len() < min_copies {
                return Err(RvError::ErrHsm(format!(
                    "retiring {name} would leave {} active member(s); min_wrap_copies = {min_copies} needs at least \
                     {min_copies}",
                    others.len()
                )));
            }
            let stranded = |set: &BvHsmBlobSet| !set.copies.keys().any(|id| others.contains(id));
            let mut stranded_sets = Vec::new();
            if record.kek.as_ref().is_some_and(stranded) {
                stranded_sets.push("the barrier KEK".to_string());
            }
            let barrier = barrier.ok_or_else(|| {
                RvError::ErrHsm(
                    "retiring an active member needs the unsealed barrier to check every custody set".into(),
                )
            })?;
            for key_id in barrier.list(CUSTODY_STORE_PREFIX).await? {
                if let Some(entry) = barrier.get(&format!("{CUSTODY_STORE_PREFIX}{key_id}")).await? {
                    if CustodyRecord::decode(&key_id, &entry.value).is_ok_and(|r| stranded(&r.set)) {
                        stranded_sets.push(format!("custody key {key_id}"));
                    }
                }
            }
            if !stranded_sets.is_empty() {
                return Err(RvError::ErrHsm(format!(
                    "retiring {name} would leave {} with no copy on another active member; run repair first",
                    stranded_sets.join(", ")
                )));
            }
        }
        if let Some(m) = record.members.get_mut(&hsm_id) {
            m.state = MemberState::Retired;
        }
        self.store_record(&record).await?;
        self.event(PoolEventKind::MemberRetired, name, hsm_id.as_str(), &format!("by={actor}"));
        Ok(json!({
            "name": name,
            "hsm_id": hsm_id,
            "state": "retired",
            "next": "repair removes its copies from every set; reset or destroy the device",
        }))
    }

    /// `GET v2/sys/hsm/repair`.
    pub fn repair_status(&self) -> Value {
        let last = self.repair_state.lock().unwrap_or_else(|p| p.into_inner()).clone();
        json!({
            "repair_rate": self.config.pool.as_ref().map(|p| p.repair_rate),
            "interval_secs": REPAIR_INTERVAL.as_secs(),
            "last_run": last,
        })
    }

    /// The repair job (spec § Degraded operation and repair). `barrier` is
    /// the unsealed barrier (custody sets); `admin` lets the run also apply
    /// pending revocations and promote joining members that hold every set.
    #[maybe_async::maybe_async]
    pub async fn repair(
        &self,
        barrier: Option<Arc<dyn Storage>>,
        admin: Option<&AdminCredentials>,
    ) -> Result<RepairReport, RvError> {
        let devices = self.pool_devices()?;
        let rate = self.config.pool.as_ref().map(|p| p.repair_rate).unwrap_or(1);
        let pacer = Pacer::new(rate);
        let physical = self.physical.as_ref();
        let _repair_lock = physical.lock(HSM_REPAIR_LOCK).await?;
        let mut report =
            RepairReport { started_at: unix_now_secs()?, custody_scanned: barrier.is_some(), ..Default::default() };
        // The leader's own credential for a member added since its last refresh.
        if let Some(store) = &devices.cache.credentials {
            let installed = node_creds::pick_up(physical, store).await?;
            devices.cache.forget_clients(&installed);
        }

        if let Some(admin) = admin {
            let _custody_lock = physical.lock(HSM_CUSTODY_LOCK).await?;
            let mut record = self.pool_record().await?;
            let targets: Vec<MemberTarget> = targets_of(
                record.members.iter().filter(|(_, m)| !m.pending_revocations.is_empty() && admin.has(&m.name)),
            )
            .into_iter()
            .map(|(t, _)| t)
            .collect();
            if !targets.is_empty() {
                let enrollments = list_enrollments(physical).await?;
                let sessions = self.open_admin_sessions(targets, admin).await?;
                let applied = self.apply_pending_revocations(&sessions, &mut record, &enrollments).await;
                close_all(sessions).await;
                report.revocations_applied = applied?;
                self.store_record(&record).await?;
            }
        }

        let record = self.pool_record().await?;
        let targets: BTreeSet<HsmId> =
            record.members.iter().filter(|(_, m)| live(m)).map(|(id, _)| id.clone()).collect();
        let retired: BTreeSet<HsmId> =
            record.members.iter().filter(|(_, m)| m.state == MemberState::Retired).map(|(id, _)| id.clone()).collect();
        let pool_cfg = self.config.pool.as_ref().ok_or_else(|| RvError::ErrHsm("not a pool provider".into()))?;
        let specs = devices.cache.specs_for(pool_cfg, targets_of(record.members.iter().filter(|(_, m)| live(m))));
        let pool = HsmPool::new(&self.config.node_id, specs, 1, devices.clock.clone(), devices.events.clone())?;
        report.revocations_pending = record
            .members
            .values()
            .flat_map(|m| m.pending_revocations.iter().map(move |n| format!("{n} on {}", m.name)))
            .collect();

        let mut holds: BTreeMap<HsmId, usize> = BTreeMap::new();
        let mut sets_total = 0usize;
        if let Some(kek) = record.kek.clone() {
            sets_total += 1;
            report.sets_scanned += 1;
            let ctx = self.barrier_context(&record.cluster_uuid, record.epoch);
            let set_plan = plan(&kek, &targets, &retired);
            let mut final_set = kek.clone();
            if !set_plan.is_empty() {
                let key = record.wrap_key_ids(kek.epoch, &self.config.objects)?.barrier;
                match self.rewrap_set(&pool, &record, &kek, &set_plan, &ctx, key).await {
                    Ok((new_set, added, removed, failures)) => {
                        report.failures.extend(failures.into_iter().map(|f| format!("barrier KEK: {f}")));
                        if added + removed > 0 {
                            let _custody_lock = physical.lock(HSM_CUSTODY_LOCK).await?;
                            let mut current = self.pool_record().await?;
                            if current.kek.as_ref() == Some(&kek) {
                                current.kek = Some(new_set.clone());
                                self.store_record(&current).await?;
                                report.copies_added += added;
                                report.copies_removed += removed;
                                final_set = new_set;
                            } else {
                                report.failures.push("barrier KEK: changed during repair; retried next run".into());
                            }
                        }
                    }
                    Err(e) => report.failures.push(format!("barrier KEK: {e}")),
                }
                pacer.pause().await;
            }
            for id in final_set.copies.keys() {
                *holds.entry(id.clone()).or_default() += 1;
            }
            let kek_under = !plan(&final_set, &targets, &retired).add.is_empty();
            report.under_replicated += usize::from(kek_under);
            hsm_metrics().set_under_replicated(UnderReplicatedScope::SealRecord, usize::from(kek_under));
        }

        if let Some(barrier) = &barrier {
            let mut custody_under = 0usize;
            for key_id in barrier.list(CUSTODY_STORE_PREFIX).await? {
                let key = format!("{CUSTODY_STORE_PREFIX}{key_id}");
                let Some(entry) = barrier.get(&key).await? else { continue };
                let custody = match (is_key_id(&key_id), CustodyRecord::decode(&key_id, &entry.value)) {
                    (true, Ok(r)) => r,
                    (_, Err(e)) => {
                        log::error!(target: "security", "repair: {e}");
                        report.invalid_custody_entries.push(key_id);
                        continue;
                    }
                    (false, Ok(_)) => {
                        report.invalid_custody_entries.push(key_id);
                        continue;
                    }
                };
                sets_total += 1;
                report.sets_scanned += 1;
                let set = custody.set.clone();
                let set_plan = plan(&set, &targets, &retired);
                let mut final_set = set.clone();
                if !set_plan.is_empty() {
                    let kind = custody.kind()?;
                    let ctx = Context::new(
                        kind.seed_context(&record.cluster_uuid, set.epoch),
                        kind.purpose(),
                        set.epoch,
                        &self.config.node_id,
                    );
                    let wrap_key = record.wrap_key_ids(set.epoch, &self.config.objects)?.pqc;
                    match self.rewrap_set(&pool, &record, &set, &set_plan, &ctx, wrap_key).await {
                        Ok((new_set, added, removed, failures)) => {
                            report.failures.extend(failures.into_iter().map(|f| format!("custody key {key_id}: {f}")));
                            if added + removed > 0 {
                                let _custody_lock = barrier.lock(HSM_CUSTODY_LOCK).await?;
                                let current = barrier.get(&key).await?;
                                if current.is_some_and(|c| c.value == entry.value) {
                                    let updated = CustodyRecord { set: new_set.clone(), ..custody.clone() };
                                    barrier.put(&StorageEntry { key: key.clone(), value: updated.encode()? }).await?;
                                    report.copies_added += added;
                                    report.copies_removed += removed;
                                    final_set = new_set;
                                } else {
                                    report.failures.push(format!("custody key {key_id}: changed during repair"));
                                }
                            }
                        }
                        Err(e) => report.failures.push(format!("custody key {key_id}: {e}")),
                    }
                    pacer.pause().await;
                }
                for id in final_set.copies.keys() {
                    *holds.entry(id.clone()).or_default() += 1;
                }
                if !plan(&final_set, &targets, &retired).add.is_empty() {
                    report.under_replicated += 1;
                    custody_under += 1;
                }
            }
            hsm_metrics().set_under_replicated(UnderReplicatedScope::Custody, custody_under);
        }

        // Promotion: a joining member that holds every set, with every set seen.
        let complete = report.custody_scanned && report.invalid_custody_entries.is_empty();
        for (id, member) in record.members.iter().filter(|(_, m)| m.state == MemberState::Joining) {
            if !(complete && holds.get(id).copied().unwrap_or(0) == sets_total) {
                continue;
            }
            match admin {
                Some(admin) => match self.promote(id, sets_total, admin).await {
                    Ok(()) => report.promoted.push(member.name.clone()),
                    Err(e) => {
                        report.failures.push(format!("promoting {}: {e}", member.name));
                        report.ready_to_promote.push(member.name.clone());
                    }
                },
                None => report.ready_to_promote.push(member.name.clone()),
            }
        }

        report.finished_at = unix_now_secs()?;
        log::info!(
            target: "security",
            "hsm repair: scanned={} added={} removed={} under_replicated={} failures={} promoted={:?}",
            report.sets_scanned,
            report.copies_added,
            report.copies_removed,
            report.under_replicated,
            report.failures.len(),
            report.promoted
        );
        *self.repair_state.lock().unwrap_or_else(|p| p.into_inner()) = Some(report.clone());
        Ok(report)
    }

    /// Unwrap `set` once through a member that holds it (a `Rewrap`
    /// authorization checked against the pinned key), wrap it on each member
    /// `plan.add` names, and drop retired copies. The plaintext is zeroized.
    #[maybe_async::maybe_async]
    async fn rewrap_set(
        &self,
        pool: &HsmPool,
        record: &HsmSealRecord,
        set: &BvHsmBlobSet,
        set_plan: &SetPlan,
        ctx: &Context,
        wrap_key: HsmObjectId,
    ) -> Result<(BvHsmBlobSet, usize, usize, Vec<String>), RvError> {
        let mut new_set = set.clone();
        let mut failures = Vec::new();
        let mut added = 0;
        let reachable: Vec<&HsmId> = set_plan.add.iter().filter(|id| pool.member(id).is_some()).collect();
        if !reachable.is_empty() {
            let plaintext = self.rewrap_source(pool, record, set, ctx, wrap_key).await?;
            for target in reachable {
                match pool.wrap_on(target, wrap_key, ctx, &plaintext).await {
                    Ok(blob) => {
                        new_set.insert_copy(blob)?;
                        added += 1;
                        let detail = format!("{} copy added", set.purpose.as_token());
                        self.event(PoolEventKind::SetRepaired, "", target.as_str(), &detail);
                    }
                    Err(e) => failures.push(format!("{target}: {e}")),
                }
            }
        }
        let removed = drop_retired(&mut new_set, &set_plan.remove);
        Ok((new_set, added, removed, failures))
    }

    #[maybe_async::maybe_async]
    async fn rewrap_source(
        &self,
        pool: &HsmPool,
        record: &HsmSealRecord,
        set: &BvHsmBlobSet,
        ctx: &Context,
        wrap_key: HsmObjectId,
    ) -> Result<Zeroizing<Vec<u8>>, RvError> {
        let mut attempt = pool.read(|id| set.copy_for(id).is_some());
        while let Some(member) = attempt.next_member() {
            let (Some(copy), Some(pinned)) = (set.copy_for(member.hsm_id()), record.members.get(member.hsm_id()))
            else {
                continue;
            };
            let counter = self.next_counter().await?;
            match self.rewrap_unwrap(member, pinned, copy, ctx, set.purpose, counter, wrap_key).await {
                Ok(plaintext) => {
                    attempt.succeeded(member);
                    return Ok(plaintext);
                }
                Err(e) => attempt.failed(member, "repair unwrap", e)?,
            }
        }
        Err(attempt.into_error("HSM repair: no member released the set"))
    }

    #[maybe_async::maybe_async]
    async fn rewrap_unwrap(
        &self,
        member: &PoolMember,
        pinned: &HsmMember,
        copy: &BvHsmBlob,
        ctx: &Context,
        purpose: Purpose,
        counter: u64,
        wrap_key: HsmObjectId,
    ) -> Result<Zeroizing<Vec<u8>>, RvError> {
        let backend = member.backend()?;
        let blob_bytes = copy.to_bytes()?;
        let node_id = &self.config.node_id;
        let request =
            UnwrapRequest::new(ctx.context.clone(), &blob_bytes, node_id, ctx.epoch, counter, purpose).rewrap();
        let authorization =
            authz::sign_authorization(backend.as_ref(), self.config.objects.authz, request.clone()).await?;
        let pinned_fp = authz_fingerprint_of(&pinned.authz_pub);
        if authorization.authz_fp != pinned_fp || copy.aad.authz_fp() != pinned_fp {
            log::error!(target: "security", "hsm repair: {}'s authorization key is not the pinned one", member.name());
            return Err(RvError::ErrHsmAuthzInvalid);
        }
        authz::verify_authorization(&authorization, &pinned.authz_pub, &request)?;
        log::info!(
            target: "security",
            "hsm repair re-wrap authorized (member={}, hsm_id={}): {}",
            member.name(),
            member.hsm_id(),
            authz::audit_record(&authorization)
        );
        backend.unwrap_data(wrap_key, ctx, &blob_bytes).await
    }

    /// Joining → active, with a transcript signed by the member's identity
    /// and by an active member's identity (spec § Replace, step 5).
    #[maybe_async::maybe_async]
    async fn promote(&self, hsm_id: &HsmId, sets_checked: usize, admin: &AdminCredentials) -> Result<(), RvError> {
        let physical = self.physical.as_ref();
        let _custody_lock = physical.lock(HSM_CUSTODY_LOCK).await?;
        let mut record = self.pool_record().await?;
        let joining = record
            .members
            .get(hsm_id)
            .filter(|m| m.state == MemberState::Joining)
            .ok_or_else(|| RvError::ErrHsm(format!("{hsm_id} is no longer joining")))?;
        let witness = record
            .active_members()
            .find(|(_, m)| admin.has(&m.name) && m.pending_revocations.is_empty())
            .map(|(id, m)| MemberTarget { name: m.name.clone(), hsm_id: id.clone(), gateway: m.gateway.clone() })
            .ok_or_else(|| RvError::ErrHsm("promotion needs the admin credential of an active member".into()))?;
        let joining_target =
            MemberTarget { name: joining.name.clone(), hsm_id: hsm_id.clone(), gateway: joining.gateway.clone() };
        let mut transcript =
            PromotionTranscript::new(&record.cluster_uuid, record.epoch, hsm_id, sets_checked, unix_now_secs()?);
        let sessions = self.open_admin_sessions(vec![joining_target, witness], admin).await?;
        let mut signed: Result<(), RvError> = Ok(());
        for (target, session) in &sessions {
            let identity_pub = &record.members[&target.hsm_id].identity_pub;
            let tbs = transcript.tbs();
            let outcome = match session.identity_sign(self.config.objects.identity, PROMOTION_CONTEXT, &tbs).await {
                Ok(sig) => verify_identity_signature(identity_pub, PROMOTION_CONTEXT, &tbs, &sig).map(|_| sig),
                Err(e) => Err(e),
            };
            match outcome {
                Ok(sig) => {
                    transcript.signatures.insert(target.hsm_id.clone(), hex::encode(sig));
                }
                Err(e) => {
                    signed = Err(e);
                    break;
                }
            }
        }
        close_all(sessions).await;
        signed?;
        write_promotion(physical, &transcript).await?;
        if let Some(m) = record.members.get_mut(hsm_id) {
            m.state = MemberState::Active;
        }
        self.store_record(&record).await?;
        let name = record.members.get(hsm_id).map(|m| m.name.clone()).unwrap_or_default();
        self.event(
            PoolEventKind::MemberPromoted,
            &name,
            hsm_id.as_str(),
            &format!("sets={sets_checked} joining -> active"),
        );
        Ok(())
    }
}

#[cfg(all(test, feature = "hsm_mock", not(feature = "sync_handler")))]
mod tests {
    use std::{collections::HashMap, sync::Mutex, time::Duration};

    use rand::Rng;

    use super::*;
    use crate::{
        core::SealConfig,
        hsm::{
            admin::FACTORY_PASSWORD,
            clock::ManualClock,
            custody_store::{CustodyScope, CustodyStore},
            derive::PqcKeyKind,
            mock::{MockHsmBackend, MockHsmDevice},
            node_creds::NodeCredentialStore,
            HsmBackend, HsmObjectIds, MemberOpener, RecoveryMode, ResolvedHsmConfig, ResolvedPoolConfig,
            ResolvedPoolMember,
        },
        seal::SealProvider,
        storage::{
            barrier::SecurityBarrier, barrier_aes_gcm::AESGCMBarrier, test_support::new_test_backend,
            Backend as PhysicalBackend,
        },
    };

    const KEK: [u8; 32] = [42u8; 32];

    #[derive(Default)]
    struct Recorder(Mutex<Vec<PoolEvent>>);

    impl crate::hsm::pool::PoolEventSink for Recorder {
        fn emit(&self, event: &PoolEvent) {
            self.0.lock().unwrap().push(event.clone());
        }
    }

    impl Recorder {
        fn count(&self, kind: PoolEventKind) -> usize {
            self.0.lock().unwrap().iter().filter(|e| e.kind == kind).count()
        }
    }

    type Registry = Arc<Mutex<BTreeMap<HsmId, Arc<MockHsmDevice>>>>;

    /// Reaches in-process devices by id, as a gateway would reach hosts.
    struct TestOpener {
        node: String,
        registry: Registry,
    }

    impl TestOpener {
        fn device(&self, target: &MemberTarget) -> Result<Arc<MockHsmDevice>, RvError> {
            let registry = self.registry.lock().unwrap();
            registry
                .get(&target.hsm_id)
                .cloned()
                .ok_or_else(|| RvError::ErrHsmTransport(format!("no route to {}", target.hsm_id)))
        }
    }

    impl MemberOpener for TestOpener {
        fn open_client(
            &self,
            target: &MemberTarget,
            credential: Option<NodeCredential>,
        ) -> Result<Arc<dyn HsmBackend>, RvError> {
            let (device, objects) = (self.device(target)?, HsmObjectIds::default());
            Ok(Arc::new(match credential {
                Some(c) => MockHsmBackend::connect_with_credential(device, &self.node, objects, c)?,
                None => MockHsmBackend::connect(device, &self.node, objects)?,
            }))
        }

        fn open_admin(&self, target: &MemberTarget, password: &str) -> Result<Box<dyn HsmAdminSession>, RvError> {
            Ok(Box::new(self.device(target)?.admin_session(password, HsmObjectIds::default())?))
        }
    }

    fn rand_tag() -> String {
        let mut b = [0u8; 5];
        rand::rng().fill_bytes(&mut b);
        hex::encode(b)
    }

    fn temp_file_backend() -> Arc<dyn PhysicalBackend> {
        let dir = std::env::temp_dir().join(format!("bv-pool-admin-{}", rand_tag()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut conf: HashMap<String, serde_json::Value> = HashMap::new();
        conf.insert("path".to_string(), serde_json::Value::String(dir.to_string_lossy().to_string()));
        crate::storage::new_backend("file", &conf).unwrap()
    }

    fn seal_config() -> SealConfig {
        SealConfig { secret_shares: 1, secret_threshold: 1 }
    }

    async fn provisioned(
        serial: &str,
        admin: &str,
        clock: &Arc<ManualClock>,
    ) -> (Arc<MockHsmDevice>, AttestationBundle) {
        let device = MockHsmDevice::open_factory("", serial, clock.clone()).unwrap();
        let bundle = device.provision(FACTORY_PASSWORD, admin, &HsmObjectIds::default(), false).await.unwrap();
        (device, bundle)
    }

    fn id_of(device: &MockHsmDevice) -> HsmId {
        HsmId::from_parts("mock", &device.serial()).unwrap()
    }

    /// Two provisioned mock devices, shared storage, and per-node providers.
    struct Pool {
        tag: String,
        clock: Arc<ManualClock>,
        registry: Registry,
        physical: Arc<dyn PhysicalBackend>,
        a: Arc<MockHsmDevice>,
        b: Arc<MockHsmDevice>,
        bundles: BTreeMap<String, AttestationBundle>,
        dirs: Mutex<HashMap<String, String>>,
        hooks: Arc<crate::seal::hsm::hooks::ProviderHooks>,
        seen: Arc<Recorder>,
        min_wrap_copies: usize,
    }

    impl Pool {
        async fn new(min_wrap_copies: usize) -> Self {
            let tag = rand_tag();
            let clock = ManualClock::new();
            let seen = Arc::new(Recorder::default());
            let (a, bundle_a) = provisioned(&format!("A{tag}"), "admin-a", &clock).await;
            let (b, bundle_b) = provisioned(&format!("B{tag}"), "admin-b", &clock).await;
            let registry: Registry =
                Arc::new(Mutex::new(BTreeMap::from([(id_of(&a), a.clone()), (id_of(&b), b.clone())])));
            Self {
                tag: tag.clone(),
                clock,
                registry,
                physical: temp_file_backend(),
                a,
                b,
                bundles: BTreeMap::from([(format!("a-{tag}"), bundle_a), (format!("b-{tag}"), bundle_b)]),
                dirs: Mutex::new(HashMap::new()),
                hooks: {
                    let hooks = crate::seal::hsm::hooks::ProviderHooks::new();
                    hooks.add_sink(seen.clone());
                    hooks
                },
                seen,
                min_wrap_copies,
            }
        }

        fn name(&self, m: &str) -> String {
            format!("{m}-{}", self.tag)
        }

        fn admin(&self, members: &[(&str, &str)]) -> AdminCredentials {
            let mut admin = AdminCredentials::new();
            for (m, password) in members {
                admin.insert(&self.name(m), Zeroizing::new(password.to_string())).unwrap();
            }
            admin
        }

        fn both(&self) -> AdminCredentials {
            self.admin(&[("a", "admin-a"), ("b", "admin-b")])
        }

        fn dir(&self, node: &str) -> String {
            let mut dirs = self.dirs.lock().unwrap();
            dirs.entry(node.to_string())
                .or_insert_with(|| {
                    std::env::temp_dir()
                        .join(format!("bv-pool-creds-{}-{node}", rand_tag()))
                        .to_string_lossy()
                        .to_string()
                })
                .clone()
        }

        fn config(&self, node: &str) -> ResolvedHsmConfig {
            let member = |m: &str, device: &MockHsmDevice| ResolvedPoolMember {
                name: self.name(m),
                gateway: String::new(),
                connector: String::new(),
                serial: device.serial(),
                state_path: format!("/unused/{m}.json"),
                prefer: m == "a",
            };
            ResolvedHsmConfig {
                backend_type: "mock".into(),
                connector: String::new(),
                objects: HsmObjectIds::default(),
                password: Zeroizing::new(String::new()),
                domains: vec![1],
                pqc_key_cache_ttl: Duration::from_secs(60),
                recovery: RecoveryMode::None,
                state_path: String::new(),
                node_id: node.into(),
                pool: Some(ResolvedPoolConfig {
                    min_wrap_copies: self.min_wrap_copies,
                    repair_rate: 100,
                    credential_dir: self.dir(node),
                    link: None,
                    migrate_from: None,
                    members: vec![member("a", &self.a), member("b", &self.b)],
                }),
                recovery_explicit: true,
            }
        }

        fn provider(&self, node: &str) -> HsmSealProvider {
            let opener = Arc::new(TestOpener { node: node.into(), registry: self.registry.clone() });
            let store = NodeCredentialStore::new(&self.dir(node), node).unwrap();
            HsmSealProvider::new_pool_with(
                opener,
                Some(store),
                self.physical.clone(),
                self.config(node),
                self.clock.clone(),
                self.hooks.clone(),
            )
            .unwrap()
        }

        async fn init(&self) -> HsmSealProvider {
            let p = self.provider("n1");
            p.bootstrap_enroll(&self.both(), &self.bundles, "root").await.unwrap();
            p.check_init(&seal_config()).await.unwrap();
            p.init_kek(&KEK, &seal_config()).await.unwrap();
            p
        }

        async fn fingerprint(&self, node: &str) -> String {
            read_pending(self.physical.as_ref(), node).await.unwrap().unwrap().transport_fp
        }

        /// Start `node` (it publishes its transport key) and enroll it.
        async fn join(&self, node: &str, leader: &HsmSealProvider) -> HsmSealProvider {
            let p = self.provider(node);
            p.refresh_membership().await.unwrap();
            leader.enroll_node(node, &self.fingerprint(node).await, &self.both(), "root").await.unwrap();
            p
        }

        async fn barrier(&self) -> Arc<dyn Storage> {
            let barrier = AESGCMBarrier::new(new_test_backend(&format!("pool_admin_{}", self.tag)));
            let key = barrier.generate_key().unwrap();
            barrier.init(&key).await.unwrap();
            barrier.unseal(&key).await.unwrap();
            Arc::new(barrier)
        }

        async fn custody(&self, provider: &HsmSealProvider, barrier: Arc<dyn Storage>) -> CustodyStore {
            let record = provider.pool_record().await.unwrap();
            let pool = provider.pool().unwrap();
            let binding_pub = record.members.values().next().unwrap().identity_pub.clone();
            let scope = CustodyScope {
                cluster_uuid: record.cluster_uuid.clone(),
                epoch: record.epoch,
                ecdh_key: HsmObjectIds::default().seed_ecdh,
                binding_pub,
                pqc_wrap_keys: record.wrap_keys.iter().map(|(e, k)| (*e, k.pqc)).collect(),
            };
            CustodyStore::with_pool(barrier, pool, provider.config.clone(), scope)
        }

        fn node_keys(&self, device: &Arc<MockHsmDevice>, password: &str) -> Vec<u16> {
            let session = device.admin_session(password, HsmObjectIds::default()).unwrap();
            futures_lite_block(session.auth_key_ids())
        }
    }

    /// The mock's admin commands are synchronous underneath; poll once.
    fn futures_lite_block<F: std::future::Future<Output = Result<Vec<u16>, RvError>>>(f: F) -> Vec<u16> {
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        let mut f = std::pin::pin!(f);
        match f.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(ids) => ids.unwrap().into_iter().filter(|id| *id >= 0x100).collect(),
            std::task::Poll::Pending => panic!("mock admin command did not complete synchronously"),
        }
    }

    #[tokio::test]
    async fn provisioning_takes_a_factory_device_and_nothing_else() {
        let clock = ManualClock::new();
        let device = MockHsmDevice::open_factory("", "PROV", clock.clone()).unwrap();
        let objects = HsmObjectIds::default();
        assert!(MockHsmBackend::connect(device.clone(), "n", objects).is_err(), "no unauthenticated session");
        assert!(device.provision("wrong", "admin", &objects, false).await.is_err(), "the factory password is checked");
        let bundle = device.provision(FACTORY_PASSWORD, "admin", &objects, false).await.unwrap();
        assert_eq!(bundle.hsm_id().unwrap(), id_of(&device));
        let err = device.provision(FACTORY_PASSWORD, "admin", &objects, false).await.unwrap_err();
        assert!(err.to_string().contains("not in factory state"), "{err}");
        device.provision("", "admin", &objects, true).await.unwrap();
        assert!(device.provision("", "not-the-admin", &objects, true).await.is_err());
        assert!(device.admin_session("not-the-admin", objects).is_err());
        assert!(MockHsmBackend::connect(device.clone(), "n", objects).is_err(), "provisioned: credentials only");
        let session = device.admin_session("admin", objects).unwrap();
        let keys = session.auth_key_ids().await.unwrap();
        assert!(!keys.contains(&1) && keys.contains(&2), "factory key gone, bv-admin present: {keys:?}");
    }

    #[tokio::test]
    async fn bootstrap_init_then_enrolled_nodes_unseal() {
        let p = Pool::new(1).await;
        let n1 = p.init().await;
        assert_eq!(n1.recover_kek().await.unwrap().as_slice(), &KEK);

        let n2 = p.provider("n2");
        n2.refresh_membership().await.unwrap();
        assert!(n2.recover_kek().await.is_err(), "not enrolled: no credential, no session");
        let fp = p.fingerprint("n2").await;
        let wrong = n1.enroll_node("n2", &"0".repeat(64), &p.both(), "root").await.unwrap_err();
        assert!(wrong.to_string().contains("does not match"), "{wrong}");
        let partial = n1.enroll_node("n2", &fp, &p.admin(&[("a", "admin-a")]), "root").await.unwrap_err();
        assert!(partial.to_string().contains(&p.name("b")), "every live member needs its credential: {partial}");
        let out = n1.enroll_node("n2", &fp, &p.both(), "root").await.unwrap();
        assert_eq!(out["auth_key_id"], "0x0101", "slot 0 is the init node's");
        assert!(n1.enroll_node("n2", &fp, &p.both(), "root").await.is_err(), "enrolled once");
        assert!(n1.enroll_node("n9", &fp, &p.both(), "root").await.is_err(), "no transport key published");

        let nodes = n1.hsm_nodes().await.unwrap();
        assert_eq!(nodes["enrolled_count"], 2);
        for node in nodes["enrolled"].as_array().unwrap() {
            assert!(node["signatures_valid"].as_object().unwrap().values().all(|v| v == true), "{node}");
        }
        assert_eq!(n2.recover_kek().await.unwrap().as_slice(), &KEK);
        assert!(read_delivery(p.physical.as_ref(), "n2").await.unwrap().is_none(), "picked up and removed");
        let raw = serde_json::to_string(&n1.hsm_nodes().await.unwrap()).unwrap();
        assert!(!raw.contains("admin-a") && !raw.contains("admin-b"), "no credential in any listing");
    }

    #[tokio::test]
    async fn a_revoked_node_is_cut_off_and_a_pending_revocation_keeps_the_member_down() {
        let p = Pool::new(1).await;
        let n1 = p.init().await;
        let n2 = p.join("n2", &n1).await;
        let n3 = p.join("n3", &n1).await;
        n2.recover_kek().await.unwrap();
        n3.recover_kek().await.unwrap();

        let out = n1.revoke_node("n2", &p.both(), "root").await.unwrap();
        assert_eq!(out["revoked_on"].as_array().unwrap().len(), 2);
        let err = n2.recover_kek().await.unwrap_err();
        assert!(err.to_string().contains("authentication"), "device-enforced: {err}");

        p.b.set_offline(true);
        let out = n1.revoke_node("n3", &p.both(), "root").await.unwrap();
        assert_eq!(out["revocation_pending"][0]["member"], p.name("b"), "{out}");
        assert_eq!(p.seen.count(PoolEventKind::RevocationPending), 1);
        assert!(p.seen.count(PoolEventKind::NodeRevoked) >= 3, "n2 on both, n3 on A");
        assert!(out["residual_risk"].is_string());
        assert!(n3.recover_kek().await.is_err(), "deleted on A, B is down for everyone");
        p.b.set_offline(false);
        let n3_key = 0x102;
        assert!(p.node_keys(&p.b, "admin-b").contains(&n3_key), "the device still holds it");
        p.a.set_offline(true);
        let err = n1.recover_kek().await.unwrap_err();
        assert!(err.to_string().contains("revocation pending"), "B is not used until applied: {err}");

        let report = n1.repair(None, Some(&p.admin(&[("b", "admin-b")]))).await.unwrap();
        assert_eq!(report.revocations_applied, vec![format!("n3 on {}", p.name("b"))]);
        assert!(!p.node_keys(&p.b, "admin-b").contains(&n3_key));
        assert_eq!(n1.recover_kek().await.unwrap().as_slice(), &KEK, "B serves again");
    }

    #[tokio::test]
    async fn the_thirteenth_node_is_refused() {
        let p = Pool::new(1).await;
        let n1 = p.init().await;
        for i in 2..=MAX_POOL_NODES {
            p.join(&format!("n{i}"), &n1).await;
        }
        let late = p.provider("n13");
        late.refresh_membership().await.unwrap();
        let err = n1.enroll_node("n13", &p.fingerprint("n13").await, &p.both(), "root").await.unwrap_err();
        assert!(err.to_string().contains("supported maximum of 12"), "{err}");
        n1.revoke_node("n12", &p.both(), "root").await.unwrap();
        n1.enroll_node("n13", &p.fingerprint("n13").await, &p.both(), "root").await.unwrap();
    }

    #[tokio::test]
    async fn repair_fills_the_copies_a_returning_member_missed() {
        let p = Pool::new(1).await;
        let n1 = p.init().await;
        let barrier = p.barrier().await;
        p.a.set_offline(true);
        n1.recover_kek().await.unwrap();
        let store = p.custody(&n1, barrier.clone()).await;
        store.create(PqcKeyKind::MlKem768).await.unwrap();
        store.create(PqcKeyKind::MlDsa65).await.unwrap();
        assert_eq!(store.replication_report().await.unwrap().under_replicated.len(), 2);

        p.a.set_offline(false);
        let report = n1.repair(Some(barrier.clone()), None).await.unwrap();
        assert_eq!((report.sets_scanned, report.copies_added, report.under_replicated), (3, 2, 0), "{report:?}");
        assert!(report.failures.is_empty(), "{report:?}");
        assert!(store.replication_report().await.unwrap().under_replicated.is_empty());
        assert_eq!(n1.repair_status()["last_run"]["copies_added"], 2);
        let again = n1.repair(Some(barrier), None).await.unwrap();
        assert_eq!(again.copies_added, 0, "converged");
    }

    #[tokio::test]
    async fn a_failed_device_is_replaced_without_downtime() {
        let p = Pool::new(1).await;
        let n1 = p.init().await;
        let n2 = p.join("n2", &n1).await;
        let barrier = p.barrier().await;
        n2.recover_kek().await.unwrap();
        p.custody(&n1, barrier.clone()).await.create(PqcKeyKind::MlKem768).await.unwrap();

        p.b.set_offline(true);
        let (b2, bundle) = provisioned(&format!("C{}", p.tag), "admin-b2", &p.clock).await;
        p.registry.lock().unwrap().insert(id_of(&b2), b2.clone());
        let out = n1.add_member(&p.name("b2"), &bundle, "", &p.admin(&[("b2", "admin-b2")]), "root").await.unwrap();
        assert_eq!(out["state"], "joining");
        assert_eq!(out["nodes_enrolled"].as_array().unwrap().len(), 2);

        let report = n1.repair(Some(barrier.clone()), None).await.unwrap();
        assert_eq!(report.copies_added, 2, "{report:?}");
        assert_eq!(report.ready_to_promote, vec![p.name("b2")]);
        let report =
            n1.repair(Some(barrier.clone()), Some(&p.admin(&[("a", "admin-a"), ("b2", "admin-b2")]))).await.unwrap();
        assert_eq!(report.promoted, vec![p.name("b2")], "{report:?}");

        n1.retire_member(&p.name("b"), Some(barrier.as_ref()), "root").await.unwrap();
        let report = n1.repair(Some(barrier.clone()), None).await.unwrap();
        assert_eq!(report.copies_removed, 2, "{report:?}");
        let record = n1.pool_record().await.unwrap();
        assert!(!record.kek.as_ref().unwrap().copies.contains_key(&id_of(&p.b)));

        p.a.set_offline(true);
        n2.refresh_membership().await.unwrap();
        assert_eq!(n2.recover_kek().await.unwrap().as_slice(), &KEK, "n2 unseals through the replacement");
        for kind in [
            PoolEventKind::NodeEnrolled,
            PoolEventKind::MemberAdded,
            PoolEventKind::SetRepaired,
            PoolEventKind::MemberPromoted,
            PoolEventKind::MemberRetired,
        ] {
            assert!(p.seen.count(kind) > 0, "{} raised", kind.name());
        }
    }

    #[tokio::test]
    async fn member_add_refuses_another_devices_bundle_and_an_exportable_layout() {
        let p = Pool::new(1).await;
        let n1 = p.init().await;
        let (c, _) = provisioned(&format!("C{}", p.tag), "admin-c", &p.clock).await;
        p.registry.lock().unwrap().insert(id_of(&c), c.clone());
        let (_, foreign) = provisioned(&format!("D{}", p.tag), "admin-d", &p.clock).await;
        let mut misdirected = foreign.clone();
        misdirected.serial = c.serial();
        let err =
            n1.add_member(&p.name("c"), &misdirected, "", &p.admin(&[("c", "admin-c")]), "root").await.unwrap_err();
        assert!(matches!(err, RvError::ErrHsmAttestationInvalid(_)), "{err}");

        let (e, bundle) = provisioned(&format!("E{}", p.tag), "admin-e", &p.clock).await;
        p.registry.lock().unwrap().insert(id_of(&e), e.clone());
        e.add_capability(HsmObjectIds::default().wrap_barrier, "exportable-under-wrap");
        let err = n1.add_member(&p.name("e"), &bundle, "", &p.admin(&[("e", "admin-e")]), "root").await.unwrap_err();
        assert!(err.to_string().contains("bv-wrap-barrier"), "{err}");
        assert!(p.node_keys(&e, "admin-e").is_empty(), "no node key was created");
        assert_eq!(n1.pool_record().await.unwrap().members.len(), 2, "nothing was added");
    }

    #[tokio::test]
    async fn retire_never_strands_a_set_or_drops_below_min_wrap_copies() {
        let p = Pool::new(2).await;
        let n1 = p.init().await;
        let barrier = p.barrier().await;
        let err = n1.retire_member(&p.name("a"), Some(barrier.as_ref()), "root").await.unwrap_err();
        assert!(err.to_string().contains("min_wrap_copies"), "{err}");

        let p = Pool::new(1).await;
        let n1 = p.init().await;
        let barrier = p.barrier().await;
        p.b.set_offline(true);
        n1.recover_kek().await.unwrap();
        p.custody(&n1, barrier.clone()).await.create(PqcKeyKind::MlKem768).await.unwrap();
        p.b.set_offline(false);
        let err = n1.retire_member(&p.name("a"), Some(barrier.as_ref()), "root").await.unwrap_err();
        assert!(err.to_string().contains("no copy on another active member"), "{err}");
        assert!(n1.retire_member(&p.name("a"), None, "root").await.is_err(), "custody sets must be checked");
        n1.retire_member(&p.name("b"), Some(barrier.as_ref()), "root").await.unwrap();
        let err = n1.retire_member(&p.name("a"), Some(barrier.as_ref()), "root").await.unwrap_err();
        assert!(err.to_string().contains("0 active member"), "{err}");
    }

    #[tokio::test]
    async fn ceremonies_refuse_the_per_node_topology_and_a_pool_without_a_record() {
        let p = Pool::new(1).await;
        let n1 = p.provider("n1");
        let err = n1.enroll_node("n2", "fp", &p.both(), "root").await.unwrap_err();
        assert!(err.to_string().contains("not initialized"), "{err}");
        n1.bootstrap_enroll(&p.both(), &p.bundles, "root").await.unwrap();
        assert!(n1.bootstrap_enroll(&p.both(), &p.bundles, "root").await.is_err(), "once");
        n1.init_kek(&KEK, &seal_config()).await.unwrap();
        assert!(n1.bootstrap_enroll(&p.both(), &p.bundles, "root").await.is_err(), "not after init");
    }

    #[tokio::test]
    async fn init_pins_the_bootstrap_attestation_and_nodes_never_reach_bv_identity() {
        let p = Pool::new(1).await;
        let mut partial = p.bundles.clone();
        partial.remove(&p.name("b"));
        let err = p.provider("n1").bootstrap_enroll(&p.both(), &partial, "root").await.unwrap_err();
        assert!(err.to_string().contains("no attestation bundle"), "{err}");

        let n1 = p.init().await;
        let record = n1.pool_record().await.unwrap();
        for m in record.members.values() {
            assert_eq!(m.attestation_fps.len(), 3, "identity, authz and seed-ecdh attested");
            assert_ne!(m.seed_ecdh_pub, m.identity_pub, "bv-seed-ecdh is its own key");
        }
        let bootstrap = crate::hsm::ceremony::read_bootstrap(p.physical.as_ref()).await.unwrap();
        assert!(bootstrap.is_none(), "consumed by init");

        let pool = n1.pool().unwrap();
        let node = pool.members()[0].backend().unwrap();
        let objects = HsmObjectIds::default();
        let peer = record.members.values().next().unwrap().identity_pub.clone();
        assert!(node.sign(objects.identity, "c", b"m").await.is_err(), "bv-identity is domain 2");
        assert!(node.derive_ecdh(objects.identity, &peer).await.is_err());
        assert!(node.derive_ecdh(objects.seed_ecdh, &peer).await.is_ok());
    }

    #[tokio::test]
    async fn init_refuses_a_member_whose_keys_differ_from_its_attestation() {
        let p = Pool::new(1).await;
        let n1 = p.provider("n1");
        n1.bootstrap_enroll(&p.both(), &p.bundles, "root").await.unwrap();
        let mut rec = crate::hsm::ceremony::read_bootstrap(p.physical.as_ref()).await.unwrap().unwrap();
        rec.members.values_mut().next().unwrap().authz_pub = vec![9; 32];
        crate::hsm::ceremony::write_bootstrap(p.physical.as_ref(), &rec).await.unwrap();
        let err = n1.init_kek(&KEK, &seal_config()).await.unwrap_err();
        assert!(matches!(err, RvError::ErrHsmAttestationInvalid(_)), "{err}");
        assert!(n1.load_record().await.unwrap().is_none(), "nothing initialized");
    }

    fn admin_session(device: &Arc<MockHsmDevice>, password: &str) -> crate::hsm::mock::MockAdminSession {
        device.admin_session(password, HsmObjectIds::default()).unwrap()
    }

    #[tokio::test]
    async fn rotate_epoch_rewraps_every_set_and_deletes_the_old_keys() {
        let p = Pool::new(1).await;
        let n1 = p.init().await;
        let n2 = p.join("n2", &n1).await;
        n2.recover_kek().await.unwrap();
        let barrier = p.barrier().await;
        let (handle, public) = p.custody(&n1, barrier.clone()).await.create(PqcKeyKind::MlKem768).await.unwrap();
        let defaults = HsmObjectIds::default();
        let before = n1.pool_record().await.unwrap();
        assert_eq!(before.wrap_keys.get(&0), Some(&WrapKeyIds::of(&defaults)), "a new pool record names its keys");

        let out = n1.rotate_epoch(&p.both(), Some(barrier.clone()), "root").await.unwrap();
        assert_eq!((out["epoch"].as_u64(), out["custody_sets_moved"].as_u64()), (Some(1), Some(1)), "{out}");
        assert!(out["old_keys_not_deleted"].as_array().unwrap().is_empty(), "{out}");
        let after = n1.pool_record().await.unwrap();
        assert_eq!((after.epoch, after.rotating_to, after.kek.as_ref().unwrap().epoch), (1, None, 1));
        assert_eq!(after.wrap_keys.keys().copied().collect::<Vec<_>>(), vec![1], "epoch 0 forgotten");
        assert_eq!(after.kek.as_ref().unwrap().copies.len(), 2, "fully replicated");

        assert_eq!(n2.recover_kek().await.unwrap().as_slice(), &KEK, "nodes unseal at the new epoch");
        let store = p.custody(&n1, barrier.clone()).await;
        assert_eq!(store.with_private(&handle, |k| k.public_key().to_vec()).await.unwrap(), public);
        for (device, password) in [(&p.a, "admin-a"), (&p.b, "admin-b")] {
            let session = admin_session(device, password);
            for id in [defaults.wrap_barrier, defaults.wrap_pqc] {
                assert!(session.object_info(ObjectKind::WrapKey, id).await.unwrap().is_none(), "old key {id} deleted");
            }
        }
        assert_eq!(p.seen.count(PoolEventKind::EpochRotated), 2);
    }

    #[tokio::test]
    async fn an_interrupted_rotation_resumes_with_the_keys_it_recorded() {
        let p = Pool::new(1).await;
        let n1 = p.init().await;
        let barrier = p.barrier().await;
        let next = WrapKeyIds { barrier: 0x40, pqc: 0x41 };
        for (device, password) in [(&p.a, "admin-a"), (&p.b, "admin-b")] {
            let session = admin_session(device, password);
            session.generate_wrap_key(next.barrier, "bv-wrap-barrier").await.unwrap();
            session.generate_wrap_key(next.pqc, "bv-wrap-pqc").await.unwrap();
        }
        let mut record = n1.pool_record().await.unwrap();
        record.wrap_keys.insert(1, next);
        record.rotating_to = Some(1);
        n1.store_record(&record).await.unwrap();
        assert_eq!(n1.recover_kek().await.unwrap().as_slice(), &KEK, "still epoch 0 until the KEK moves");

        let out = n1.rotate_epoch(&p.both(), Some(barrier), "root").await.unwrap();
        assert_eq!(out["wrap_keys"]["barrier"].as_u64(), Some(0x40), "{out}");
        let after = n1.pool_record().await.unwrap();
        assert_eq!((after.epoch, after.rotating_to), (1, None));
        assert_eq!(n1.recover_kek().await.unwrap().as_slice(), &KEK);
    }

    #[tokio::test]
    async fn rotation_refuses_what_it_cannot_finish() {
        let p = Pool::new(1).await;
        let n1 = p.init().await;
        let barrier = p.barrier().await;
        assert!(n1.rotate_epoch(&p.both(), None, "root").await.unwrap_err().to_string().contains("barrier"));
        let err = n1.rotate_epoch(&p.admin(&[("a", "admin-a")]), Some(barrier.clone()), "root").await.unwrap_err();
        assert!(err.to_string().contains(&p.name("b")), "{err}");
        p.b.set_offline(true);
        assert!(n1.rotate_epoch(&p.both(), Some(barrier), "root").await.is_err(), "every member must take part");
        let record = n1.pool_record().await.unwrap();
        assert_eq!((record.epoch, record.rotating_to), (0, None), "nothing changed");
    }

    const FIXTURE_STATE: &[u8] = include_bytes!("../testdata/hsm-seal-v1/mock-hsm-state.json");
    const FIXTURE_RECORD: &[u8] = include_bytes!("../testdata/hsm-seal-v1/core-hsm-seal.json");
    const FIXTURE_COUNTER: &[u8] = include_bytes!("../testdata/hsm-seal-v1/core-hsm-authz-counter");

    #[tokio::test]
    async fn migrate_to_pool_moves_a_v1_per_node_record_onto_the_pool() {
        use crate::storage::BackendEntry;
        let p = Pool::new(1).await;
        let node = "fixture-node";
        let state = std::env::temp_dir().join(format!("bv-migrate-{}.json", rand_tag()));
        std::fs::write(&state, FIXTURE_STATE).unwrap();
        let mut per_node = p.config(node);
        per_node.pool = None;
        per_node.state_path = state.to_string_lossy().to_string();
        let source: Arc<dyn HsmBackend> = Arc::new(MockHsmBackend::open(&per_node).await.unwrap());
        let put = |key: &str, value: &[u8]| BackendEntry { key: key.into(), value: value.to_vec() };
        p.physical.put(&put("core/hsm-seal", FIXTURE_RECORD)).await.unwrap();
        p.physical.put(&put("core/hsm-authz-counter", FIXTURE_COUNTER)).await.unwrap();

        let without_source = p.provider(node);
        assert!(without_source.migrate_to_pool("root").await.unwrap_err().to_string().contains("migrate_from"));
        assert!(without_source.bootstrap_enroll(&p.both(), &p.bundles, "root").await.is_err(), "not over a record");
        let n = p.provider(node).with_migration_source(source);
        assert!(n.recover_kek().await.is_err(), "a pool node never unseals a per-node record");
        n.bootstrap_enroll(&p.both(), &p.bundles, "root").await.unwrap();
        let out = n.migrate_to_pool("root").await.unwrap();
        assert_eq!(out["per_node_copies_dropped"], 1, "{out}");

        let v1: serde_json::Value = serde_json::from_slice(FIXTURE_RECORD).unwrap();
        let record = n.pool_record().await.unwrap();
        assert_eq!(record.topology, Topology::Pool);
        assert_eq!(record.cluster_uuid, v1["cluster_uuid"].as_str().unwrap(), "the cluster keeps its identity");
        assert_eq!(record.epoch, v1["epoch"].as_u64().unwrap());
        assert!(record.legacy_node_blobs.is_empty() && record.wrap_keys.contains_key(&record.epoch));
        assert!(record.members.values().all(|m| m.attestation_fps.len() == 3), "attested at bootstrap");
        let kek: Vec<u8> = (0u8..32).collect();
        assert_eq!(n.recover_kek().await.unwrap().as_slice(), kek.as_slice(), "the fixture's KEK, through the pool");
        assert!(n.migrate_to_pool("root").await.is_err(), "one-way, once");
        let _ = std::fs::remove_file(&state);
    }
}
