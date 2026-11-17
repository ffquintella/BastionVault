//! `run_transfer` against a whole vault through a `VaultCtx` interposer, for
//! what the route cannot show: a source that changes during a move, and
//! faults injected into one kind of sub-request. Request-only (stores are
//! built on storage, no `get_module`), so it is sound in this test binary.
//! The route's own tests are in the facade (`src/engine_tests/`).

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Weak,
    },
};

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use serde_json::{json, Value};

use super::{run_transfer, IdentityStores, TransferOp, TransferRequest};
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
    modules::identity::{EntityStore, GroupStore, ShareStore, ShareTargetKind},
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

    let ctx = Interposer::new(&core, &root, Fault::ChangeSourceAfterImport);
    let (caller, request) = srv1_to_dst(&root);

    // No identity stores: the source has no share, so the planner never runs.
    match run_transfer(&ctx, &caller, TransferOp::Move, request, None).await {
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

/// The caller and request of a transfer of `src/resources/srv1` to `dst`.
fn srv1_to_dst(root: &str) -> (Request, TransferRequest) {
    let mut caller = Request::new("sys/namespace-transfer/move");
    caller.client_token = root.to_string();
    let request = serde_json::from_value(json!({
        "kind": "resource",
        "source": { "namespace": "src", "mount": "resources", "path": "srv1" },
        "destination": { "namespace": "dst", "mount": "resources", "path": "srv1" },
    }))
    .unwrap();
    (caller, request)
}

/// `src` and `dst`, `src/srv1` with one secret, and user group `qa` (src only)
/// and `ops`, `ops2` (both namespaces), each granted a share on `srv1`.
#[maybe_async::maybe_async]
async fn seed(core: &Arc<Core>, root: &str) -> IdentityStores {
    let (core, root) = (core.clone(), root.to_string());
    for ns in ["src", "dst"] {
        send(&core, &root, Operation::Write, &format!("sys/namespaces/{ns}"), "", json!({})).await;
    }
    let meta = json!({ "type": "server", "hostname": "h.example" });
    send(&core, &root, Operation::Write, "resources/resources/srv1", "src", meta).await;
    send(&core, &root, Operation::Write, "resources/secrets/srv1/login", "src", json!({ "value": "pw-1" })).await;
    let groups = [("qa", &["src"][..]), ("ops", &["src", "dst"][..]), ("ops2", &["src", "dst"][..])];
    for (group, namespaces) in groups {
        for ns in namespaces {
            send(&core, &root, Operation::Write, &format!("identity/group/user/{group}"), ns, json!({})).await;
        }
        let path = format!("identity/sharing/by-target/resource/{}/{group}", URL_SAFE_NO_PAD.encode("srv1"));
        let share = json!({ "grantee_kind": "group_user", "capabilities": ["read"] });
        send(&core, &root, Operation::Write, &path, "src", share).await;
    }
    let entities = EntityStore::new(core.as_ref()).await.unwrap();
    let groups = GroupStore::new(core.as_ref()).await.unwrap();
    IdentityStores { entities, groups }
}

/// Regression (4b review): a fault while checking attached files after a
/// completed move is a warning, and the share warnings already gathered
/// reach the caller; the fault's own text does not.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_files_fault_after_a_completed_move_is_a_warning_and_keeps_the_share_warnings() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("ns_transfer_files_fault").await;
    let stores = seed(&core, &root).await;
    let file = json!({ "name": "id.pem", "resource": "srv1", "content_base64": STANDARD.encode("x") });
    send(&core, &root, Operation::Write, "files/files", "src", file).await;
    let ctx = Interposer::new(&core, &root, Fault::FileReads);
    let (caller, request) = srv1_to_dst(&root);

    let out = run_transfer(&ctx, &caller, TransferOp::Move, request, Some(&stores)).await.expect("the move completes");
    assert!(ctx.fired.load(Ordering::SeqCst), "a file record read was refused");
    let find = |code: &str, subject: &str| out.warnings.iter().find(|w| w.code == code && w.subject == subject);
    let files = find("files-not-transferred", "srv1").expect("the fault is a warning");
    assert!(files.message.contains("status 500") && !files.message.contains("injected"), "{}", files.message);
    assert!(find("group-not-in-destination", "qa").is_some(), "the share warnings stand: {:?}", out.warnings);
    assert_eq!(out.transferred.shares, 2, "ops and ops2 were carried");
    let read = |path: &'static str, ns: &'static str| send(&core, &root, Operation::Read, path, ns, json!({}));
    assert!(read("resources/resources/srv1", "src").await.is_none(), "the move deleted the source");
    assert!(read("resources/resources/srv1", "dst").await.is_some());
}

/// Regression (4b review): a server fault on one share write says how many
/// were written before it, and which one failed; the copy stays.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_share_write_fault_says_how_many_shares_were_written() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("ns_transfer_share_fault").await;
    let stores = seed(&core, &root).await;
    let ctx = Interposer::new(&core, &root, Fault::SecondShareWrite);
    let (caller, request) = srv1_to_dst(&root);

    match run_transfer(&ctx, &caller, TransferOp::Move, request, Some(&stores)).await {
        Err(RvError::ErrResponseStatus(503, m)) => {
            assert!(m.contains("1 of 2 planned shares were written before share 2 failed"), "{m}");
            assert!(m.contains("dst/resources/srv1 was written") && m.contains("the source is untouched"), "{m}");
        }
        other => panic!("expected 503, got {other:?}"),
    }
    let shares = ShareStore::new(core.as_ref()).await.unwrap();
    assert_eq!(shares.list_shares_for_target(ShareTargetKind::Resource, "dst/srv1").await.unwrap().len(), 1);
    let source = send(&core, &root, Operation::Read, "resources/resources/srv1", "src", json!({})).await;
    assert!(source.is_some(), "the move stopped before deleting the source");
}

/// Regression (final review): when re-pointing the attached files after a
/// same-namespace move fails, a server fault is reported by its status only,
/// while a refusal keeps the route's own reason.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_repoint_fault_names_only_its_status_and_a_refusal_keeps_its_reason() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("ns_transfer_repoint_fault").await;
    send(&core, &root, Operation::Write, "sys/namespaces/src", "", json!({})).await;
    for (status, from, to) in [(500, "srv1", "srv2"), (409, "srv3", "srv4")] {
        let meta = json!({ "type": "server", "hostname": "h.example" });
        send(&core, &root, Operation::Write, &format!("resources/resources/{from}"), "src", meta).await;
        let file = json!({ "name": format!("{from}.pem"), "resource": from, "content_base64": STANDARD.encode("x") });
        send(&core, &root, Operation::Write, "files/files", "src", file).await;
        let ctx = Interposer::new(&core, &root, Fault::Repoint(status));
        let mut caller = Request::new("sys/namespace-transfer/move");
        caller.client_token = root.clone();
        let request: TransferRequest = serde_json::from_value(json!({
            "kind": "resource",
            "source": { "namespace": "src", "mount": "resources", "path": from },
            "destination": { "namespace": "src", "mount": "resources", "path": to },
        }))
        .unwrap();

        let out = run_transfer(&ctx, &caller, TransferOp::Move, request, None).await.expect("the move completes");
        assert!(ctx.fired.load(Ordering::SeqCst), "{status}: the re-point was refused");
        let files = out.warnings.iter().find(|w| w.code == "files-not-transferred").expect("a files warning");
        assert!(files.message.contains(&format!("status {status}")), "{}", files.message);
        assert_eq!(files.message.contains("injected"), status < 500, "{status}: {}", files.message);
    }
}

/// The fault an [`Interposer`] injects.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    /// Right after the import, a new version of the source's `login` secret.
    ChangeSourceAfterImport,
    /// Every read of a file record fails as a storage fault would.
    FileReads,
    /// The second share write fails as a storage fault would.
    SecondShareWrite,
    /// Re-pointing the attached files answers this status.
    Repoint(u16),
}

/// The real `Core` with one [`Fault`] slipped in.
struct Interposer {
    inner: Arc<Core>,
    root: String,
    fault: Fault,
    fired: AtomicBool,
    share_writes: AtomicUsize,
}

impl Interposer {
    fn new(core: &Arc<Core>, root: &str, fault: Fault) -> Self {
        let (inner, root) = (core.clone(), root.to_string());
        Self { inner, root, fault, fired: AtomicBool::new(false), share_writes: AtomicUsize::new(0) }
    }

    fn injected(&self) -> Result<Option<Response>, RvError> {
        self.fired.store(true, Ordering::SeqCst);
        let status = match self.fault {
            Fault::FileReads => 500,
            Fault::Repoint(status) => status,
            _ => 503,
        };
        Err(RvError::ErrResponseStatus(status, "injected fault".to_string()))
    }
}

#[maybe_async::maybe_async]
impl VaultCtx for Interposer {
    async fn handle_request(&self, req: &mut Request) -> Result<Option<Response>, RvError> {
        let file_read = req.operation == Operation::Read && req.path.starts_with("files/files/");
        let share_write = req.operation == Operation::Write && req.path.starts_with("identity/sharing/by-target/");
        let repoint = req.operation == Operation::Write && req.path == "files/files/repoint-resource";
        match self.fault {
            Fault::FileReads if file_read => return self.injected(),
            Fault::Repoint(_) if repoint => return self.injected(),
            Fault::SecondShareWrite if share_write && self.share_writes.fetch_add(1, Ordering::SeqCst) == 1 => {
                return self.injected();
            }
            _ => {}
        }
        let is_import = req.operation == Operation::Write && req.path.contains("v2/transfer/import/");
        let result = VaultCtx::handle_request(self.inner.as_ref(), req).await;
        let change = self.fault == Fault::ChangeSourceAfterImport && is_import && result.is_ok();
        if change && !self.fired.swap(true, Ordering::SeqCst) {
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
