//! The device-log drain on the seal provider (T454 phase 6).
//!
//! While unsealed, under `hsm-device-audit`, each live member's log is read
//! with `bv-auditor`, verified against its cursor, raised as `hsm.device_log`
//! and `hsm.device_log_gap`, and acknowledged. An admin-credentialed repair
//! run installs the `bv-auditor` credentials. Spec: § Audit.

use std::collections::BTreeMap;

use bv_metrics::hsm_metrics::hsm_metrics;
use serde::Serialize;
use serde_json::{json, Value};

use super::{
    pool_admin::Sessions,
    record::{HsmSealRecord, MemberState},
    HsmSealProvider, PoolDevices,
};
use crate::{
    errors::RvError,
    hsm::{
        admin::HsmAdminSession,
        blob::HsmId,
        blobset::unix_now_secs,
        ceremony::{list_enrollments, NodeEnrollment},
        device_audit::{
            actor_of, describe, read_auditor, read_cursor, verify_log, write_auditor, write_cursor, AuditCursor,
            AuditorCredential, DeviceAuditMode, HsmAuditSession, AUDITOR_AUTH_KEY_ID, DEVICE_AUDIT_INTERVAL,
            HSM_DEVICE_AUDIT_LOCK,
        },
        pool::PoolEventKind,
        MemberTarget,
    },
    storage::Storage,
};

/// One member's drain as this node last saw it (status). No secrets.
#[derive(Debug, Clone, Default, Serialize)]
pub struct DrainMemberStatus {
    pub name: String,
    pub hsm_id: String,
    /// Whether the barrier holds a `bv-auditor` credential for the member;
    /// `None` until this node has run a drain.
    pub enrolled: Option<bool>,
    pub last_index: Option<u16>,
    pub last_drain_at: Option<u64>,
    pub drained_by: Option<String>,
    /// Entries this node drained since it started.
    pub entries_drained: u64,
    /// Gaps this node found since it started.
    pub gaps: u64,
    pub last_error: Option<String>,
}

/// One drain run, over every live member.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DrainReport {
    pub members: usize,
    pub drained: usize,
    /// Drained by another node less than an interval ago.
    pub skipped: usize,
    /// Members with no `bv-auditor` credential yet.
    pub without_auditor: usize,
    pub entries: usize,
    pub gaps: usize,
    pub failures: Vec<String>,
}

enum MemberOutcome {
    NoCredential,
    Skipped(AuditCursor),
    Drained { entries: usize, gaps: usize, cursor: Option<AuditCursor> },
}

pub(super) type DrainState = BTreeMap<HsmId, DrainMemberStatus>;

impl HsmSealProvider {
    /// `device_audit` of a pool; a per-node provider never drains.
    pub fn device_audit_mode(&self) -> DeviceAuditMode {
        self.config.pool.as_ref().map(|p| p.device_audit).unwrap_or(DeviceAuditMode::Off)
    }

    /// One drain over every member that is not retired. Per-member failures
    /// are reported and the others still drain; `Err` only when the pool
    /// record, the lock or the enrollment list cannot be read.
    #[maybe_async::maybe_async]
    pub async fn drain_device_logs(&self, barrier: &dyn Storage) -> Result<DrainReport, RvError> {
        let devices = self.pool_devices()?;
        let mut report = DrainReport::default();
        if self.device_audit_mode() == DeviceAuditMode::Off {
            return Ok(report);
        }
        let physical = self.physical.as_ref();
        let _audit_lock = physical.lock(HSM_DEVICE_AUDIT_LOCK).await?;
        let record = self.pool_record().await?;
        let enrollments = list_enrollments(physical).await?;
        for (hsm_id, member) in record.members.iter().filter(|(_, m)| m.state != MemberState::Retired) {
            report.members += 1;
            let target =
                MemberTarget { name: member.name.clone(), hsm_id: hsm_id.clone(), gateway: member.gateway.clone() };
            let outcome = self.drain_member(devices, &target, barrier, &enrollments).await;
            self.note_drain(&target, outcome, &mut report);
        }
        Ok(report)
    }

    #[maybe_async::maybe_async]
    async fn drain_member(
        &self,
        devices: &PoolDevices,
        target: &MemberTarget,
        barrier: &dyn Storage,
        enrollments: &[NodeEnrollment],
    ) -> Result<MemberOutcome, RvError> {
        let Some(credential) = read_auditor(barrier, &target.hsm_id).await? else {
            return Ok(MemberOutcome::NoCredential);
        };
        let cursor = read_cursor(self.physical.as_ref(), &target.hsm_id).await?;
        let now = unix_now_secs()?;
        if let Some(c) = cursor.as_ref().filter(|c| c.fresh_from_another_node(&self.config.node_id, now)) {
            return Ok(MemberOutcome::Skipped(c.clone()));
        }
        let session = devices.cache.opener.open_auditor(target, &credential)?;
        let drained = self.drain_session(devices, session.as_ref(), target, cursor, enrollments).await;
        if let Err(e) = session.close().await {
            log::debug!(target: "security", "closing the bv-auditor session on {} failed: {e}", target.name);
        }
        drained
    }

    /// Read, verify, raise, store the cursor, acknowledge. The cursor is
    /// written before `set-log-index`: a failure in between re-reads entries
    /// (duplicate events), never loses one.
    #[maybe_async::maybe_async]
    async fn drain_session(
        &self,
        devices: &PoolDevices,
        session: &dyn HsmAuditSession,
        target: &MemberTarget,
        cursor: Option<AuditCursor>,
        enrollments: &[NodeEnrollment],
    ) -> Result<MemberOutcome, RvError> {
        let reached = session.hsm_id()?;
        if reached != target.hsm_id {
            return Err(RvError::ErrHsm(format!(
                "member {} reached device {reached}, not {}; its log is not drained",
                target.name, target.hsm_id
            )));
        }
        let started = devices.clock.now();
        let read = session.get_log_entries().await;
        let took = devices.clock.now().saturating_sub(started);
        hsm_metrics().observe_command(&target.name, "get_log_entries", took.as_secs_f64());
        let log = read?;

        let (verified, last) = verify_log(cursor.as_ref(), &log)?;
        for gap in &verified.gaps {
            hsm_metrics().record_device_log_gap(&target.name);
            self.event(PoolEventKind::DeviceLogGap, &target.name, target.hsm_id.as_str(), gap);
        }
        // The drain's own reads are verified with the rest but not raised.
        for entry in verified.new_entries.iter().filter(|e| e.session_key != AUDITOR_AUTH_KEY_ID) {
            let actor = actor_of(entry.session_key, &target.hsm_id, enrollments);
            self.event(PoolEventKind::DeviceLog, &target.name, target.hsm_id.as_str(), &describe(entry, &actor));
        }
        let gaps = verified.gaps.len();
        let entries = verified.new_entries.len();
        let Some(last) = last else {
            return Ok(MemberOutcome::Drained { entries, gaps, cursor: None });
        };
        let next = AuditCursor::new(&target.hsm_id, last, &log, unix_now_secs()?, &self.config.node_id);
        write_cursor(self.physical.as_ref(), &next).await?;
        if !log.entries.is_empty() {
            session.set_log_index(last.0).await?;
        }
        Ok(MemberOutcome::Drained { entries, gaps, cursor: Some(next) })
    }

    /// Record a member's outcome for status. A missing credential and a
    /// failure are logged when they first appear, not on every tick.
    fn note_drain(&self, target: &MemberTarget, outcome: Result<MemberOutcome, RvError>, report: &mut DrainReport) {
        let mut states = self.device_audit_state.lock().unwrap_or_else(|p| p.into_inner());
        let st = states.entry(target.hsm_id.clone()).or_default();
        st.name = target.name.clone();
        st.hsm_id = target.hsm_id.to_string();
        let from_cursor = |st: &mut DrainMemberStatus, c: &AuditCursor| {
            st.last_index = Some(c.last_index);
            st.last_drain_at = Some(c.drained_at);
            st.drained_by = Some(c.drained_by.clone());
        };
        match outcome {
            Ok(MemberOutcome::NoCredential) => {
                if st.enrolled != Some(false) {
                    log::warn!(
                        target: "security",
                        "HSM pool member {} ({}) has no bv-auditor credential, so its device log is not drained; \
                         run `bvault operator hsm repair` with that member's admin credential",
                        target.name,
                        target.hsm_id
                    );
                }
                st.enrolled = Some(false);
                st.last_error = None;
                report.without_auditor += 1;
            }
            Ok(MemberOutcome::Skipped(cursor)) => {
                st.enrolled = Some(true);
                st.last_error = None;
                from_cursor(st, &cursor);
                report.skipped += 1;
            }
            Ok(MemberOutcome::Drained { entries, gaps, cursor }) => {
                st.enrolled = Some(true);
                st.last_error = None;
                st.entries_drained += entries as u64;
                st.gaps += gaps as u64;
                if let Some(cursor) = &cursor {
                    from_cursor(st, cursor);
                }
                report.drained += 1;
                report.entries += entries;
                report.gaps += gaps;
            }
            Err(e) => {
                let msg = e.to_string();
                if st.last_error.as_deref() != Some(msg.as_str()) {
                    log::warn!(target: "security", "device-log drain of HSM pool member {} failed: {msg}", target.name);
                }
                report.failures.push(format!("{}: {msg}", target.name));
                st.last_error = Some(msg);
            }
        }
    }

    /// The `device_audit` block of `v2/sys/hsm/status`: one row per member
    /// that is not retired, from this node's last drain.
    pub(super) fn device_audit_status(&self, record: Option<&HsmSealRecord>) -> Value {
        let states = self.device_audit_state.lock().unwrap_or_else(|p| p.into_inner());
        let members: Vec<Value> = record
            .map(|r| {
                r.members
                    .iter()
                    .filter(|(_, m)| m.state != MemberState::Retired)
                    .map(|(id, m)| {
                        let st = states.get(id).cloned().unwrap_or_else(|| DrainMemberStatus {
                            name: m.name.clone(),
                            hsm_id: id.to_string(),
                            ..Default::default()
                        });
                        serde_json::to_value(st).unwrap_or(Value::Null)
                    })
                    .collect()
            })
            .unwrap_or_default();
        json!({
            "mode": self.device_audit_mode().as_str(),
            "interval_secs": DEVICE_AUDIT_INTERVAL.as_secs(),
            "members": members,
        })
    }

    /// Give each member in `sessions` a working `bv-auditor` and set its
    /// forced-audit option to match `device_audit`. Returns the members that
    /// got a new credential and one failure line per member that did not.
    #[maybe_async::maybe_async]
    pub(super) async fn ensure_auditors(
        &self,
        sessions: &Sessions,
        barrier: &dyn Storage,
    ) -> (Vec<String>, Vec<String>) {
        let mut installed = Vec::new();
        let mut failures = Vec::new();
        let Ok(devices) = self.pool_devices() else { return (installed, failures) };
        let forced = self.device_audit_mode() == DeviceAuditMode::Forced;
        for (target, session) in sessions {
            match self.ensure_auditor(devices, target, session.as_ref(), barrier).await {
                Ok(true) => installed.push(target.name.clone()),
                Ok(false) => {}
                Err(e) => {
                    failures.push(format!("bv-auditor on {}: {e}", target.name));
                    continue;
                }
            }
            if let Err(e) = session.set_forced_audit(forced).await {
                failures.push(format!("forced audit {} on {}: {e}", if forced { "on" } else { "off" }, target.name));
            }
        }
        (installed, failures)
    }

    /// Keep a stored credential that still authenticates; otherwise replace
    /// key 8 on the device first and store the new credential second, so a
    /// failure in between leaves no stored credential and the next run retries.
    #[maybe_async::maybe_async]
    async fn ensure_auditor(
        &self,
        devices: &PoolDevices,
        target: &MemberTarget,
        session: &dyn HsmAdminSession,
        barrier: &dyn Storage,
    ) -> Result<bool, RvError> {
        if session.auth_key_ids().await?.contains(&AUDITOR_AUTH_KEY_ID) {
            if let Some(credential) = read_auditor(barrier, &target.hsm_id).await? {
                if let Ok(audit) = devices.cache.opener.open_auditor(target, &credential) {
                    if let Err(e) = audit.close().await {
                        log::debug!(target: "security", "closing the bv-auditor session on {} failed: {e}", target.name);
                    }
                    return Ok(false);
                }
            }
        }
        let credential = AuditorCredential::generate();
        session.put_auditor_auth_key(&credential).await?;
        write_auditor(barrier, &target.hsm_id, &credential).await?;
        log::info!(target: "security", "bv-auditor installed on HSM pool member {} ({})", target.name, target.hsm_id);
        Ok(true)
    }
}
