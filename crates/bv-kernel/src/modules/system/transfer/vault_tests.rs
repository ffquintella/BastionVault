//! `run_transfer` against a whole vault through a `VaultCtx` interposer, for
//! what the route cannot show: a source that changes between the copy and the
//! move's delete. Request-only (no `get_module` lookups), so it is sound in
//! this crate's test binary. The route's own tests are in the facade
//! (`src/engine_tests/namespace_transfer.rs`).

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Weak,
    },
};

use serde_json::{json, Value};

use super::{run_transfer, TransferOp, TransferRequest};
use crate::{
    audit::AuditBroker,
    core::Core,
    errors::RvError,
    kernel_api::{
        dos::DosGuard,
        mount::{MountsMonitor, MountsRouter},
        router::Router,
        stats::DashboardStats,
        KernelServices, LogicalBackendNewFunc, MountEntryHMACLevel, VaultCtx,
    },
    logical::{
        handler::{AuthHandler, Handler},
        Operation, Request, Response,
    },
    storage::{barrier::SecurityBarrier, barrier_view::BarrierView, cache::CacheConfig, Backend as PhysicalBackend},
    test_utils::new_unseal_test_bastion_vault,
};

#[maybe_async::maybe_async]
async fn send(core: &Arc<Core>, root: &str, op: Operation, path: &str, ns: &str, body: Value) -> Option<Value> {
    let mut req = Request::new(path);
    req.operation = op;
    req.client_token = root.to_string();
    req.body = body.as_object().cloned();
    if !ns.is_empty() {
        req.headers = Some(HashMap::from([("x-bastionvault-namespace".to_string(), ns.to_string())]));
    }
    core.handle_request(&mut req).await.unwrap().and_then(|r| r.data).map(Value::Object)
}

/// Regression: a source changed after the import is not deleted by a move;
/// the copy is kept and the 409 says what was written, never a value.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn source_changed_during_copy_aborts_move() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("ns_transfer_source_changed").await;
    for ns in ["src", "dst"] {
        send(&core, &root, Operation::Write, &format!("sys/namespaces/{ns}"), "", json!({})).await;
    }
    let meta = json!({ "type": "server", "hostname": "h.example" });
    send(&core, &root, Operation::Write, "resources/resources/srv1", "src", meta).await;
    send(&core, &root, Operation::Write, "resources/secrets/srv1/login", "src", json!({ "value": "pw-1" })).await;

    let ctx = Interposer { inner: core.clone(), root: root.clone(), fired: AtomicBool::new(false) };
    let mut caller = Request::new("sys/namespace-transfer/move");
    caller.client_token = root.clone();
    let request: TransferRequest = serde_json::from_value(json!({
        "kind": "resource",
        "source": { "namespace": "src", "mount": "resources", "path": "srv1" },
        "destination": { "namespace": "dst", "mount": "resources", "path": "srv1" },
    }))
    .unwrap();

    match run_transfer(&ctx, &caller, TransferOp::Move, request).await {
        Err(RvError::ErrResponseStatus(409, m)) => {
            assert!(m.contains("changed") && m.contains("dst/resources/srv1"), "says what was written: {m}");
            assert!(!m.contains("pw-"), "{m}");
        }
        other => panic!("expected 409, got {other:?}"),
    }
    assert!(ctx.fired.load(Ordering::SeqCst), "the source was changed after the import");
    let read = |path: &'static str, ns: &'static str| send(&core, &root, Operation::Read, path, ns, json!({}));
    assert!(read("resources/resources/srv1", "src").await.is_some(), "the source is not deleted");
    let login = read("resources/secrets/srv1/login", "src").await.unwrap();
    assert_eq!(login["value"], json!("pw-3"), "and keeps the change");
    assert!(read("resources/resources/srv1", "dst").await.is_some(), "the copy is kept");
}

/// The vault with one change slipped in: right after the destination import
/// succeeds, a new version of the source's `login` secret is written, as a
/// concurrent writer would. Everything else is the real `Core`.
struct Interposer {
    inner: Arc<Core>,
    root: String,
    fired: AtomicBool,
}

#[maybe_async::maybe_async]
impl VaultCtx for Interposer {
    async fn handle_request(&self, req: &mut Request) -> Result<Option<Response>, RvError> {
        let is_import = req.operation == Operation::Write && req.path.contains("v2/transfer/import/");
        let result = VaultCtx::handle_request(self.inner.as_ref(), req).await;
        if is_import && result.is_ok() && !self.fired.swap(true, Ordering::SeqCst) {
            let mut change = Request::new("resources/secrets/srv1/login");
            change.operation = Operation::Write;
            change.client_token = self.root.clone();
            change.body = json!({ "value": "pw-3" }).as_object().cloned();
            change.headers = Some(HashMap::from([("x-bastionvault-namespace".to_string(), "src".to_string())]));
            VaultCtx::handle_request(self.inner.as_ref(), &mut change).await.unwrap();
        }
        result
    }
    fn barrier(&self) -> Arc<dyn SecurityBarrier> {
        VaultCtx::barrier(self.inner.as_ref())
    }
    fn system_view(&self) -> Option<Arc<BarrierView>> {
        VaultCtx::system_view(self.inner.as_ref())
    }
    fn hmac_key(&self) -> Vec<u8> {
        VaultCtx::hmac_key(self.inner.as_ref())
    }
    fn sealed(&self) -> bool {
        VaultCtx::sealed(self.inner.as_ref())
    }
    async fn inited(&self) -> Result<bool, RvError> {
        VaultCtx::inited(self.inner.as_ref()).await
    }
    fn router(&self) -> Arc<Router> {
        VaultCtx::router(self.inner.as_ref())
    }
    fn mounts_router(&self) -> Arc<MountsRouter> {
        VaultCtx::mounts_router(self.inner.as_ref())
    }
    fn root_storage_prefix(&self) -> Arc<String> {
        VaultCtx::root_storage_prefix(self.inner.as_ref())
    }
    fn add_logical_backend(&self, logical_type: &str, backend: Arc<LogicalBackendNewFunc>) -> Result<(), RvError> {
        VaultCtx::add_logical_backend(self.inner.as_ref(), logical_type, backend)
    }
    fn delete_logical_backend(&self, logical_type: &str) -> Result<(), RvError> {
        VaultCtx::delete_logical_backend(self.inner.as_ref(), logical_type)
    }
    fn add_handler(&self, handler: Arc<dyn Handler>) -> Result<(), RvError> {
        VaultCtx::add_handler(self.inner.as_ref(), handler)
    }
    fn delete_handler(&self, handler: Arc<dyn Handler>) -> Result<(), RvError> {
        VaultCtx::delete_handler(self.inner.as_ref(), handler)
    }
    fn add_auth_handler(&self, handler: Arc<dyn AuthHandler>) -> Result<(), RvError> {
        VaultCtx::add_auth_handler(self.inner.as_ref(), handler)
    }
    fn delete_auth_handler(&self, handler: Arc<dyn AuthHandler>) -> Result<(), RvError> {
        VaultCtx::delete_auth_handler(self.inner.as_ref(), handler)
    }
    fn mount_entry_hmac_level(&self) -> MountEntryHMACLevel {
        VaultCtx::mount_entry_hmac_level(self.inner.as_ref())
    }
    fn mounts_monitor(&self) -> Option<Arc<MountsMonitor>> {
        VaultCtx::mounts_monitor(self.inner.as_ref())
    }
    fn kernel(&self) -> &KernelServices {
        VaultCtx::kernel(self.inner.as_ref())
    }
    fn stats(&self) -> Arc<DashboardStats> {
        VaultCtx::stats(self.inner.as_ref())
    }
    fn audit_broker(&self) -> Option<Arc<AuditBroker>> {
        VaultCtx::audit_broker(self.inner.as_ref())
    }
    fn dos_guard(&self) -> Arc<DosGuard> {
        VaultCtx::dos_guard(self.inner.as_ref())
    }
    fn approle_require_machine(&self) -> Arc<AtomicBool> {
        VaultCtx::approle_require_machine(self.inner.as_ref())
    }
    async fn set_approle_require_machine(&self, required: bool) -> Result<(), RvError> {
        VaultCtx::set_approle_require_machine(self.inner.as_ref(), required).await
    }
    fn cache_config(&self) -> &CacheConfig {
        VaultCtx::cache_config(self.inner.as_ref())
    }
    fn auth_handlers(&self) -> Arc<Vec<Arc<dyn AuthHandler>>> {
        VaultCtx::auth_handlers(self.inner.as_ref())
    }
    fn root_logical_prefix(&self) -> String {
        VaultCtx::root_logical_prefix(self.inner.as_ref())
    }
    fn weak_ctx(&self) -> Weak<dyn VaultCtx> {
        VaultCtx::weak_ctx(self.inner.as_ref())
    }
    fn physical(&self) -> Arc<dyn PhysicalBackend> {
        VaultCtx::physical(self.inner.as_ref())
    }
    fn require_machine_identity(&self) -> Arc<AtomicBool> {
        VaultCtx::require_machine_identity(self.inner.as_ref())
    }
    async fn set_require_machine_identity(&self, required: bool) -> Result<(), RvError> {
        VaultCtx::set_require_machine_identity(self.inner.as_ref(), required).await
    }
}
