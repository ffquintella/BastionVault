//! A backup restore brings back a resource deleted after the backup was taken.

use std::sync::Arc;

use serde_json::{json, Value};

use crate::{
    core::Core,
    errors::RvError,
    logical::{Operation, Request, Response},
    test_utils::new_unseal_test_bastion_vault,
};

async fn send(
    core: &Arc<Core>,
    token: &str,
    op: Operation,
    path: &str,
    body: Value,
) -> Result<Option<Response>, RvError> {
    let mut req = Request::new(path);
    req.operation = op;
    req.client_token = token.to_string();
    req.body = body.as_object().cloned();
    core.handle_request(&mut req).await
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn restore_brings_back_a_deleted_resource() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("backup_restore_resource").await;
    let meta = json!({ "type": "server", "hostname": "srv1.example" });
    send(&core, &root, Operation::Write, "resources/resources/srv1", meta).await.unwrap();

    let hmac_key = core.barrier.derive_hmac_key().unwrap();
    let mut backup = Vec::new();
    crate::backup::create::create_backup(core.physical.as_ref(), &hmac_key, &mut backup, false).await.unwrap();

    send(&core, &root, Operation::Delete, "resources/resources/srv1", json!({})).await.unwrap();
    let gone = send(&core, &root, Operation::Read, "resources/resources/srv1", json!({})).await;
    assert!(matches!(gone, Ok(None)) || gone.is_err(), "deleted: {gone:?}");

    let mut reader = std::io::Cursor::new(backup);
    crate::backup::restore::restore_backup_live(&core, &mut reader).await.unwrap();

    let back = send(&core, &root, Operation::Read, "resources/resources/srv1", json!({})).await;
    assert!(matches!(back, Ok(Some(_))), "restored resource must be readable: {back:?}");
    let listed = send(&core, &root, Operation::List, "resources/resources/", json!({})).await;
    let keys = format!("{listed:?}");
    assert!(keys.contains("srv1"), "restored resource must be listed: {keys}");
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn bvx_restore_brings_back_a_deleted_resource() {
    use crate::exchange::{
        export_all_namespaces, import_all_namespaces as import_document, ConflictPolicy, ExporterInfo, ScopeKind,
        ScopeSpec,
    };

    let (_bvault, core, root) = new_unseal_test_bastion_vault("bvx_restore_resource").await;
    let meta = json!({ "type": "server", "hostname": "srv1.example" });
    send(&core, &root, Operation::Write, "resources/resources/srv1", meta).await.unwrap();

    send(&core, &root, Operation::Write, "resources/secrets/srv1/login", json!({ "password": "pw-1" })).await.unwrap();
    send(&core, &root, Operation::Write, "resources/secrets/srv1/login", json!({ "password": "pw-2" })).await.unwrap();

    send(&core, &root, Operation::Write, "resource-group/groups/club", json!({ "members": "srv1" })).await.unwrap();

    let scope = ScopeSpec { kind: ScopeKind::Full, include: vec![] };
    let doc = export_all_namespaces(&core, ExporterInfo::default(), scope).await.unwrap();
    assert_eq!(doc.items.resources.len(), 1, "export carries the resource: {:?}", doc.items.resources);

    send(&core, &root, Operation::Delete, "resources/resources/srv1", json!({})).await.unwrap();

    let result = import_document(&core, &doc, ConflictPolicy::Skip, false).await.unwrap();
    eprintln!("import result: {result:?}");

    let back = send(&core, &root, Operation::Read, "resources/resources/srv1", json!({})).await;
    assert!(matches!(back, Ok(Some(_))), "restored resource must be readable: {back:?}");
    let sec = send(&core, &root, Operation::Read, "resources/secrets/srv1/login", json!({})).await;
    assert!(matches!(sec, Ok(Some(_))), "restored secret must be readable: {sec:?}");
    let listed = send(&core, &root, Operation::List, "resources/resources/", json!({})).await;
    assert!(format!("{listed:?}").contains("srv1"), "restored resource must be listed: {listed:?}");
    let g = send(&core, &root, Operation::Read, "resource-group/groups/club", json!({})).await;
    assert!(format!("{g:?}").contains("srv1"), "group membership must be restored: {g:?}");
    let by = send(&core, &root, Operation::Read, "resource-group/by-resource/srv1", json!({})).await;
    assert!(format!("{by:?}").contains("club"), "by-resource lookup must find the group: {by:?}");
}

async fn send_ns(
    core: &Arc<Core>,
    token: &str,
    op: Operation,
    path: &str,
    ns: &str,
    body: Value,
) -> Result<Option<Response>, RvError> {
    let mut req = Request::new(path);
    req.operation = op;
    req.client_token = token.to_string();
    req.body = body.as_object().cloned();
    req.headers = Some(std::collections::HashMap::from([("x-bastionvault-namespace".to_string(), ns.to_string())]));
    core.handle_request(&mut req).await
}

/// The same restore for a resource living inside a namespace.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn bvx_restore_brings_back_a_deleted_resource_in_a_namespace() {
    use crate::exchange::{
        export_all_namespaces, import_all_namespaces, ConflictPolicy, ExporterInfo, ScopeKind, ScopeSpec,
    };

    let (_bvault, core, root) = new_unseal_test_bastion_vault("bvx_restore_resource_ns").await;
    send(&core, &root, Operation::Write, "sys/namespaces/a", json!({})).await.unwrap();
    let meta = json!({ "type": "server", "hostname": "srv1.example" });
    send_ns(&core, &root, Operation::Write, "resources/resources/srv1", "a", meta).await.unwrap();
    send_ns(&core, &root, Operation::Write, "resources/secrets/srv1/login", "a", json!({ "password": "pw" }))
        .await
        .unwrap();
    send_ns(&core, &root, Operation::Write, "resource-group/groups/club", "a", json!({ "members": "srv1" }))
        .await
        .unwrap();

    let scope = ScopeSpec { kind: ScopeKind::Full, include: vec![] };
    let doc = export_all_namespaces(&core, ExporterInfo::default(), scope).await.unwrap();
    let bundled: usize = doc.items.namespaces.iter().map(|b| b.items.resources.len()).sum();
    assert_eq!(bundled, 1, "the namespace bundle carries the resource");

    send_ns(&core, &root, Operation::Delete, "resources/resources/srv1", "a", json!({})).await.unwrap();

    let result = import_all_namespaces(&core, &doc, ConflictPolicy::Skip, false).await.unwrap();
    eprintln!("ns import warnings: {:?}", result.warnings);

    let back = send_ns(&core, &root, Operation::Read, "resources/resources/srv1", "a", json!({})).await;
    assert!(matches!(back, Ok(Some(_))), "restored resource must be readable: {back:?}");
    let sec = send_ns(&core, &root, Operation::Read, "resources/secrets/srv1/login", "a", json!({})).await;
    assert!(matches!(sec, Ok(Some(_))), "restored secret must be readable: {sec:?}");
    let g = send_ns(&core, &root, Operation::Read, "resource-group/groups/club", "a", json!({})).await;
    assert!(format!("{g:?}").contains("srv1"), "group membership must be restored: {g:?}");
    let by = send_ns(&core, &root, Operation::Read, "resource-group/by-resource/srv1", "a", json!({})).await;
    assert!(format!("{by:?}").contains("club"), "by-resource lookup must find the group: {by:?}");
}

/// The daily backup: `run_once` writes the file, a restore reads it back.
async fn daily_roundtrip(
    kind: crate::exchange::ScopeKind,
    in_ns: bool,
    include: Vec<crate::exchange::ScopeSelector>,
) -> (String, String) {
    use crate::{
        exchange::{import_all_namespaces, ConflictPolicy, ExchangeDocument, ScopeSpec},
        scheduled_exports::{runner::run_once, schedule::ExportFormat, DestinationKind, Schedule},
    };

    let (_bvault, core, root) = new_unseal_test_bastion_vault(if in_ns { "daily_ns" } else { "daily_root" }).await;
    let ns = if in_ns { "a" } else { "" };
    if in_ns {
        send(&core, &root, Operation::Write, "sys/namespaces/a", json!({})).await.unwrap();
    }
    let meta = json!({ "type": "server", "hostname": "srv1.example" });
    send_ns(&core, &root, Operation::Write, "resources/resources/srv1", ns, meta).await.unwrap();

    let dir = std::env::temp_dir().join(format!("bv-daily-{}-{}", in_ns, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sched = Schedule {
        id: "daily1".into(),
        name: "daily".into(),
        cron: "0 0 3 * * *".into(),
        format: ExportFormat::Json,
        scope: ScopeSpec { kind, include },
        destination: DestinationKind::LocalPath { path: dir.to_string_lossy().into() },
        password_ref: None,
        allow_plaintext: true,
        comment: None,
        created_at: "t".into(),
        updated_at: "t".into(),
        enabled: true,
    };
    run_once(&core, &sched).await.unwrap();
    let file = std::fs::read_dir(&dir).unwrap().filter_map(|e| e.ok()).next().expect("a backup file").path();
    let doc: ExchangeDocument = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
    let carried = format!("top={} bundles={}", doc.items.resources.len(), doc.items.namespaces.len());

    send_ns(&core, &root, Operation::Delete, "resources/resources/srv1", ns, json!({})).await.unwrap();
    import_all_namespaces(&core, &doc, ConflictPolicy::Skip, false).await.unwrap();
    let back = send_ns(&core, &root, Operation::Read, "resources/resources/srv1", ns, json!({})).await;
    let _ = std::fs::remove_dir_all(&dir);
    (carried, format!("{:?}", back.map(|r| r.is_some())))
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn daily_backup_restores_a_deleted_resource_root_and_namespace() {
    use crate::exchange::{
        ScopeKind::{AllNamespaces, Full, Selective},
        ScopeSelector,
    };
    let pick = || vec![ScopeSelector::Resource { id: "srv1".into() }];
    let cases = [
        (Full, false, vec![]),
        (Full, true, vec![]),
        (AllNamespaces, false, vec![]),
        (AllNamespaces, true, vec![]),
        (Selective, false, pick()),
        (Selective, true, pick()),
    ];
    for (kind, ns, include) in cases {
        let (carried, back) = daily_roundtrip(kind, ns, include).await;
        assert_eq!(back, "Ok(true)", "daily backup of kind {kind:?} (resource in namespace: {ns}) carried [{carried}]");
    }
}
