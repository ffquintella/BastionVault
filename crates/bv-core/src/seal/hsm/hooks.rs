//! Where HSM pool events go, and the background repair tick (T454 phase 4).
//!
//! Every event is written to the `security` log. Once the provider is
//! attached to a `Core` whose audit broker is up, it also becomes an audit
//! entry at `sys/hsm/events/<event>/<member>`. A `member up` event wakes the
//! repair tick, which otherwise runs every [`REPAIR_INTERVAL`]. The device-log
//! drain (phase 6) ticks every 5 s (`device_audit::DEVICE_AUDIT_INTERVAL`).

use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, OnceLock, Weak,
    },
    time::Duration,
};

use super::HsmSealProvider;
use crate::{
    audit::AuditEntry,
    core::Core,
    hsm::{
        pool::{LogEventSink, PoolEvent, PoolEventKind, PoolEventSink},
        repair::REPAIR_INTERVAL,
    },
    logical::{Operation, Request},
};

/// How often the tick checks for a `member up` wake-up.
pub const REPAIR_POLL: Duration = Duration::from_secs(10);

/// The provider's event sink: the security log always, the audit broker when
/// one is attached and up, and any extra sink (tests, embedders).
#[derive(Default)]
pub struct ProviderHooks {
    log: LogEventSink,
    core: OnceLock<Weak<Core>>,
    member_came_up: AtomicBool,
    extra: Mutex<Vec<Arc<dyn PoolEventSink>>>,
}

impl ProviderHooks {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Also deliver every event to `sink`.
    pub fn add_sink(&self, sink: Arc<dyn PoolEventSink>) {
        self.extra.lock().unwrap_or_else(|p| p.into_inner()).push(sink);
    }

    fn core(&self) -> Option<Arc<Core>> {
        self.core.get().and_then(Weak::upgrade)
    }

    /// True once since the last call when a member came back up.
    pub fn take_member_up(&self) -> bool {
        self.member_came_up.swap(false, Ordering::SeqCst)
    }

    /// The audit entry for `event`: names in the path (readable), details
    /// in the body (HMAC-redacted like any request body). No key material.
    pub fn audit_request(event: &PoolEvent) -> Request {
        let member = if event.member.is_empty() { "-" } else { event.member.as_str() };
        let mut req = Request::default();
        req.path = format!("sys/hsm/events/{}/{member}", event.kind.name());
        req.operation = Operation::Write;
        let mut body = serde_json::Map::new();
        body.insert("hsm_id".into(), serde_json::Value::String(event.hsm_id.clone()));
        body.insert("detail".into(), serde_json::Value::String(event.detail.clone()));
        req.body = Some(body);
        req
    }

    fn deliver_to_audit(&self, event: &PoolEvent) {
        let Some(core) = self.core() else { return };
        let Some(broker) = core.audit_broker.load_full() else { return };
        if !broker.has_devices() {
            return;
        }
        let mut entry = AuditEntry::from_response(&Self::audit_request(event), &None, None, broker.hmac_key(), false);
        #[cfg(not(feature = "sync_handler"))]
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => {
                let name = event.kind.name();
                runtime.spawn(async move {
                    if let Err(e) = broker.log(&mut entry).await {
                        log::error!(target: "security", "audit entry for {name} not written: {e}");
                    }
                });
            }
            Err(_) => {
                log::error!(target: "security", "no async runtime: {} not written to the audit log", event.kind.name())
            }
        }
        #[cfg(feature = "sync_handler")]
        if let Err(e) = broker.log(&mut entry) {
            log::error!(target: "security", "audit entry for {} not written: {e}", event.kind.name());
        }
    }
}

impl PoolEventSink for ProviderHooks {
    fn emit(&self, event: &PoolEvent) {
        self.log.emit(event);
        if event.kind == PoolEventKind::MemberUp {
            self.member_came_up.store(true, Ordering::SeqCst);
        }
        self.deliver_to_audit(event);
        for sink in self.extra.lock().unwrap_or_else(|p| p.into_inner()).iter() {
            sink.emit(event);
        }
    }
}

impl HsmSealProvider {
    /// Wire the provider to its `Core`: audit delivery of pool events and,
    /// for a pool, the repair tick over the unsealed barrier. Once.
    pub fn attach(self: &Arc<Self>, core: &Arc<Core>) {
        let Some(hooks) = &self.hooks else { return };
        if hooks.core.set(Arc::downgrade(core)).is_err() {
            return;
        }
        #[cfg(not(feature = "sync_handler"))]
        {
            self.start_repair_tick();
            self.start_device_audit_tick();
        }
    }

    /// Drain the device logs every `DEVICE_AUDIT_INTERVAL` while unsealed
    /// (pool, `device_audit` not `off`). Every node runs it; the
    /// `hsm-device-audit` lock and the cursor's `drained_by` keep the cluster
    /// to about one drain per member per interval.
    #[cfg(not(feature = "sync_handler"))]
    fn start_device_audit_tick(self: &Arc<Self>) {
        use crate::hsm::device_audit::{DeviceAuditMode, DEVICE_AUDIT_INTERVAL};
        if self.pool().is_none() || self.device_audit_mode() == DeviceAuditMode::Off {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            log::error!(target: "security", "no async runtime: the HSM device-log drain is not running");
            return;
        };
        let provider = Arc::downgrade(self);
        runtime.spawn(async move {
            loop {
                tokio::time::sleep(DEVICE_AUDIT_INTERVAL).await;
                let Some(p) = provider.upgrade() else { return };
                p.device_audit_tick().await;
            }
        });
    }

    /// One drain: skipped while sealed (the credentials are behind the
    /// barrier). Per-member failures are logged by the drain when they change.
    #[maybe_async::maybe_async]
    pub async fn device_audit_tick(&self) {
        let Some(core) = self.hooks.as_ref().and_then(|h| h.core()) else { return };
        if core.sealed() {
            return;
        }
        let barrier: Arc<dyn crate::storage::Storage> = core.barrier.clone();
        if let Err(e) = self.drain_device_logs(barrier.as_ref()).await {
            log::warn!(target: "security", "hsm device-log drain failed: {e}");
        }
    }

    /// Run the repair job every [`REPAIR_INTERVAL`], or within
    /// [`REPAIR_POLL`] of a member coming back up, while the vault is
    /// unsealed. Every node runs it; the `hsm-repair` lock serializes them.
    #[cfg(not(feature = "sync_handler"))]
    fn start_repair_tick(self: &Arc<Self>) {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            log::error!(target: "security", "no async runtime: the HSM pool repair tick is not running");
            return;
        };
        let provider = Arc::downgrade(self);
        runtime.spawn(async move {
            loop {
                let mut waited = Duration::ZERO;
                loop {
                    tokio::time::sleep(REPAIR_POLL).await;
                    waited += REPAIR_POLL;
                    let Some(p) = provider.upgrade() else { return };
                    let woken = p.hooks.as_ref().is_some_and(|h| h.take_member_up());
                    if woken || waited >= REPAIR_INTERVAL {
                        break;
                    }
                }
                let Some(p) = provider.upgrade() else { return };
                p.repair_tick().await;
            }
        });
    }

    /// One tick: skipped while sealed (the custody sets are behind the barrier).
    #[maybe_async::maybe_async]
    pub async fn repair_tick(&self) {
        let Some(core) = self.hooks.as_ref().and_then(|h| h.core()) else { return };
        if core.sealed() {
            return;
        }
        let barrier: Arc<dyn crate::storage::Storage> = core.barrier.clone();
        match self.repair(Some(barrier), None).await {
            Ok(r) if r.copies_added + r.copies_removed > 0 || !r.failures.is_empty() => log::info!(
                target: "security",
                "hsm repair tick: added={} removed={} under_replicated={} failures={:?}",
                r.copies_added,
                r.copies_removed,
                r.under_replicated,
                r.failures
            ),
            Ok(_) => {}
            Err(e) => log::warn!(target: "security", "hsm repair tick failed: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Count(Mutex<Vec<PoolEventKind>>);

    impl PoolEventSink for Count {
        fn emit(&self, event: &PoolEvent) {
            self.0.lock().unwrap().push(event.kind);
        }
    }

    fn event(kind: PoolEventKind) -> PoolEvent {
        PoolEvent { kind, member: "hsm-a".into(), hsm_id: "mock:A".into(), detail: "node=vault-2".into() }
    }

    #[test]
    fn events_reach_every_sink_and_member_up_wakes_repair_once() {
        let hooks = ProviderHooks::new();
        let count = Arc::new(Count::default());
        hooks.add_sink(count.clone());
        hooks.emit(&event(PoolEventKind::NodeEnrolled));
        assert!(!hooks.take_member_up());
        hooks.emit(&event(PoolEventKind::MemberUp));
        assert!(hooks.take_member_up());
        assert!(!hooks.take_member_up(), "consumed");
        assert_eq!(*count.0.lock().unwrap(), vec![PoolEventKind::NodeEnrolled, PoolEventKind::MemberUp]);
    }

    #[test]
    fn audit_entries_name_the_event_in_the_path_and_carry_no_key_material() {
        let req = ProviderHooks::audit_request(&event(PoolEventKind::NodeRevoked));
        assert_eq!(req.path, "sys/hsm/events/hsm.node_revoked/hsm-a");
        let body = req.body.unwrap();
        assert_eq!(body.keys().cloned().collect::<Vec<_>>(), vec!["detail".to_string(), "hsm_id".to_string()]);
        let anonymous = PoolEvent { member: String::new(), ..event(PoolEventKind::SetRepaired) };
        assert_eq!(ProviderHooks::audit_request(&anonymous).path, "sys/hsm/events/hsm.set_repaired/-");
    }
}
