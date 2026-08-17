//! Integration tests for the files engine, which lives in
//! `crates/bv-engine-files`.
//!
//! They stayed in the root crate because they stand up a whole vault through
//! `crate::test_utils`, and a crate below the root cannot depend on the root.
//! The engine's own unit tests -- the ones that only need `super::*` -- stayed
//! with the engine.
//!
//! See roadmaps/workspace-decomposition.md § Phase 3.

mod integration_tests {
    //! End-to-end tests driving `/files/…` through `core.handle_request`.
    //! Exercise the real logical-backend pipeline (auth → routing →
    //! handler → storage) and the public response shape — not just
    //! individual helpers in isolation.

    use bv_kernel_api::VaultCtx;

    use serde_json::json;

    use crate::test_utils::{new_unseal_test_bastion_vault, test_write_api};

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_file_resource_create_read_roundtrip() {
        let (_bv, core, root_token) =
            new_unseal_test_bastion_vault("test_file_resource_create_read_roundtrip").await;

        let content = b"-----BEGIN CERTIFICATE-----\nMIIDtest\n-----END CERTIFICATE-----\n";
        let b64 = base64::engine::general_purpose::STANDARD.encode(content);

        let body = json!({
            "name": "gateway-tls.pem",
            "mime_type": "application/x-pem-file",
            "tags": "tls,production",
            "notes": "test cert",
            "content_base64": b64,
        })
        .as_object()
        .cloned();
        let resp = test_write_api(&core, &root_token, "files/files", true, body)
            .await
            .expect("create must succeed")
            .expect("create returns data envelope");
        let data = resp.data.expect("data present");
        let id = data
            .get("id")
            .and_then(|v| v.as_str())
            .expect("id returned")
            .to_string();
        assert!(!id.is_empty());
        assert_eq!(data.get("size_bytes").and_then(|v| v.as_u64()), Some(content.len() as u64));
        let sha_returned = data.get("sha256").and_then(|v| v.as_str()).unwrap_or("");
        assert_eq!(sha_returned.len(), 64);

        // Read metadata back.
        let mut req = crate::logical::Request::new(format!("files/files/{id}"));
        req.operation = crate::logical::Operation::Read;
        req.client_token = root_token.clone();
        let meta_resp = core.handle_request(&mut req).await.unwrap().unwrap();
        let meta = meta_resp.data.expect("meta data");
        assert_eq!(meta.get("name").and_then(|v| v.as_str()), Some("gateway-tls.pem"));
        assert_eq!(
            meta.get("mime_type").and_then(|v| v.as_str()),
            Some("application/x-pem-file")
        );
        assert_eq!(
            meta.get("sha256").and_then(|v| v.as_str()),
            Some(sha_returned),
            "metadata sha256 must equal the one returned at create"
        );

        // Read content back; verify round-trip.
        let mut req = crate::logical::Request::new(format!("files/files/{id}/content"));
        req.operation = crate::logical::Operation::Read;
        req.client_token = root_token.clone();
        let content_resp = core.handle_request(&mut req).await.unwrap().unwrap();
        let cdata = content_resp.data.expect("content data");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(
                cdata
                    .get("content_base64")
                    .and_then(|v| v.as_str())
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(decoded, content, "round-tripped bytes must match");
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_file_repoint_resource_moves_only_matching_files() {
        let (_bv, core, root_token) =
            new_unseal_test_bastion_vault("test_file_repoint_resource_moves_only_matching_files")
                .await;

        // Create two files on `old01` and one on an unrelated resource.
        let mk = |name: &str, resource: &str, content: &[u8]| {
            json!({
                "name": name,
                "resource": resource,
                "content_base64": base64::engine::general_purpose::STANDARD.encode(content),
            })
            .as_object()
            .cloned()
        };
        let content = b"secret-bytes";
        let a = test_write_api(&core, &root_token, "files/files", true, mk("a.pem", "old01", content))
            .await
            .unwrap()
            .unwrap();
        let a_id = a.data.unwrap()["id"].as_str().unwrap().to_string();
        let _ = test_write_api(&core, &root_token, "files/files", true, mk("b.pem", "old01", b"b"))
            .await;
        let c = test_write_api(&core, &root_token, "files/files", true, mk("c.pem", "other", b"c"))
            .await
            .unwrap()
            .unwrap();
        let c_id = c.data.unwrap()["id"].as_str().unwrap().to_string();

        // Re-point old01 -> new01.
        let resp = test_write_api(
            &core,
            &root_token,
            "files/files/repoint-resource",
            true,
            json!({ "old_resource": "old01", "new_resource": "new01" })
                .as_object()
                .cloned(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(resp.data.unwrap()["moved"], json!(2));

        // Matching files now report the new resource...
        let read_meta = |id: &str| {
            let mut req = crate::logical::Request::new(format!("files/files/{id}"));
            req.operation = crate::logical::Operation::Read;
            req.client_token = root_token.clone();
            req
        };
        let mut req = read_meta(&a_id);
        let meta = core.handle_request(&mut req).await.unwrap().unwrap().data.unwrap();
        assert_eq!(meta.get("resource").and_then(|v| v.as_str()), Some("new01"));

        // ...the unrelated file is untouched...
        let mut req = read_meta(&c_id);
        let meta = core.handle_request(&mut req).await.unwrap().unwrap().data.unwrap();
        assert_eq!(meta.get("resource").and_then(|v| v.as_str()), Some("other"));

        // ...and the blob content of a moved file is intact.
        let mut req = crate::logical::Request::new(format!("files/files/{a_id}/content"));
        req.operation = crate::logical::Operation::Read;
        req.client_token = root_token.clone();
        let cdata = core.handle_request(&mut req).await.unwrap().unwrap().data.unwrap();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(cdata.get("content_base64").and_then(|v| v.as_str()).unwrap())
            .unwrap();
        assert_eq!(decoded, content, "blob must survive a resource re-point");
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_file_resource_oversized_rejected_before_store() {
        let (_bv, core, root_token) =
            new_unseal_test_bastion_vault("test_file_resource_oversized_rejected").await;

        // One byte over the cap. base64 encoding inflates ~4/3; this
        // is still a valid but oversized payload.
        let oversized = vec![0u8; crate::modules::files::MAX_FILE_BYTES + 1];
        let b64 = base64::engine::general_purpose::STANDARD.encode(&oversized);
        let body = json!({ "name": "huge.bin", "content_base64": b64 })
            .as_object()
            .cloned();

        // test_write_api with `is_ok = false` asserts the call errors.
        let _ = test_write_api(&core, &root_token, "files/files", false, body).await;
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_file_resource_update_replaces_content() {
        let (_bv, core, root_token) =
            new_unseal_test_bastion_vault("test_file_resource_update_replaces_content").await;

        let v1 = b"version-1".to_vec();
        let v2 = b"VERSION-2-DIFFERENT".to_vec();
        let engine = base64::engine::general_purpose::STANDARD;

        let body = json!({
            "name": "cfg.txt",
            "content_base64": engine.encode(&v1),
        })
        .as_object()
        .cloned();
        let resp = test_write_api(&core, &root_token, "files/files", true, body)
            .await
            .unwrap()
            .unwrap();
        let id = resp
            .data
            .unwrap()
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        // PUT new content.
        let put_body = json!({ "content_base64": engine.encode(&v2) }).as_object().cloned();
        let put = test_write_api(&core, &root_token, &format!("files/files/{id}"), true, put_body)
            .await
            .unwrap()
            .unwrap();
        let put_data = put.data.unwrap();
        let new_sha = put_data.get("sha256").and_then(|v| v.as_str()).unwrap();
        assert_ne!(new_sha, crate::modules::files::sha256_hex(&v1), "sha must change on content replace");
        assert_eq!(new_sha, crate::modules::files::sha256_hex(&v2));

        // Read content back → must be v2.
        let mut req = crate::logical::Request::new(format!("files/files/{id}/content"));
        req.operation = crate::logical::Operation::Read;
        req.client_token = root_token.clone();
        let content_resp = core.handle_request(&mut req).await.unwrap().unwrap();
        let decoded = engine
            .decode(
                content_resp
                    .data
                    .unwrap()
                    .get("content_base64")
                    .and_then(|v| v.as_str())
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(decoded, v2);

        // History must have two entries (create + update with
        // "content" in changed_fields).
        let mut hist_req = crate::logical::Request::new(format!("files/files/{id}/history"));
        hist_req.operation = crate::logical::Operation::Read;
        hist_req.client_token = root_token.clone();
        let hist_resp = core.handle_request(&mut hist_req).await.unwrap().unwrap();
        let entries = hist_resp
            .data
            .unwrap()
            .get("entries")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        assert!(entries.len() >= 2, "create + update must produce ≥2 history entries");
        let update_entry = entries
            .iter()
            .find(|e| e.get("op").and_then(|v| v.as_str()) == Some("update"))
            .expect("an update entry exists");
        let changed = update_entry
            .get("changed_fields")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        assert!(
            changed.iter().any(|v| v.as_str() == Some("content")),
            "content change must be recorded in changed_fields, got: {changed:?}"
        );
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_file_resource_delete_then_read_is_gone() {
        let (_bv, core, root_token) =
            new_unseal_test_bastion_vault("test_file_resource_delete_gone").await;
        let engine = base64::engine::general_purpose::STANDARD;

        let body = json!({
            "name": "temp.txt",
            "content_base64": engine.encode(b"bye"),
        })
        .as_object()
        .cloned();
        let resp = test_write_api(&core, &root_token, "files/files", true, body)
            .await
            .unwrap()
            .unwrap();
        let id = resp
            .data
            .unwrap()
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        // DELETE
        let mut del = crate::logical::Request::new(format!("files/files/{id}"));
        del.operation = crate::logical::Operation::Delete;
        del.client_token = root_token.clone();
        let _ = core.handle_request(&mut del).await.unwrap();

        // Subsequent metadata read must return None (which the HTTP
        // layer renders as 404).
        let mut req = crate::logical::Request::new(format!("files/files/{id}"));
        req.operation = crate::logical::Operation::Read;
        req.client_token = root_token.clone();
        let after = core.handle_request(&mut req).await.unwrap();
        assert!(after.is_none(), "deleted file must not be readable");
    }

    use base64::Engine;

    // ── Phase 2: ownership / sharing / backfill ──────────────────

    use crate::modules::identity::IdentityModule;

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_file_create_stamps_root_owner() {
        // Phase 2: a root-token write stamps `root` as the file's
        // owner. Mirrors `test_root_token_resource_write_captures_owner`.
        let (_bv, core, root_token) =
            new_unseal_test_bastion_vault("test_file_create_stamps_root_owner").await;
        let engine = base64::engine::general_purpose::STANDARD;

        let body = json!({
            "name": "ssh.key",
            "content_base64": engine.encode(b"PRIVATE KEY PAYLOAD"),
        })
        .as_object()
        .cloned();
        let resp = crate::test_utils::test_write_api(&core, &root_token, "files/files", true, body)
            .await
            .unwrap()
            .unwrap();
        let id = resp
            .data
            .unwrap()
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        let identity = core
            .module_manager()
            .get_module::<IdentityModule>("identity")
            .expect("identity module");
        let owner_store = identity.owner_store().expect("owner store");
        let rec = owner_store
            .get_file_owner(&id)
            .await
            .unwrap()
            .expect("owner record must exist after root-token file write");
        assert_eq!(rec.entity_id, "root");
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_file_delete_forgets_owner_and_cascades_shares() {
        let (_bv, core, root_token) =
            new_unseal_test_bastion_vault("test_file_delete_forgets_owner").await;
        let engine = base64::engine::general_purpose::STANDARD;

        // Create a file.
        let body = json!({
            "name": "temp.key",
            "content_base64": engine.encode(b"to-be-deleted"),
        })
        .as_object()
        .cloned();
        let resp = crate::test_utils::test_write_api(&core, &root_token, "files/files", true, body)
            .await
            .unwrap()
            .unwrap();
        let id = resp
            .data
            .unwrap()
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        let identity = core
            .module_manager()
            .get_module::<IdentityModule>("identity")
            .expect("identity module");
        let owner_store = identity.owner_store().expect("owner store");
        assert!(owner_store.get_file_owner(&id).await.unwrap().is_some());

        // Seed a share against this file so we can verify cascade.
        let share_store = identity.share_store().expect("share store");
        let share = crate::modules::identity::share_store::SecretShare {
            target_kind: "file".to_string(),
            target_path: id.clone(),
            grantee_kind: String::new(),
            grantee_entity_id: "some-user-entity".to_string(),
            granted_by_entity_id: "root".to_string(),
            capabilities: vec!["read".into()],
            granted_at: chrono::Utc::now().to_rfc3339(),
            expires_at: String::new(),
        };
        share_store.set_share(share).await.expect("seed share");

        // Delete the file via the logical API.
        let mut del = crate::logical::Request::new(format!("files/files/{id}"));
        del.operation = crate::logical::Operation::Delete;
        del.client_token = root_token.clone();
        core.handle_request(&mut del).await.unwrap();

        // Owner record gone.
        assert!(
            owner_store.get_file_owner(&id).await.unwrap().is_none(),
            "delete must forget owner"
        );

        // Share cascade-revoked.
        let remaining = share_store
            .list_shares_for_target(
                crate::modules::identity::share_store::ShareTargetKind::File,
                &id,
            )
            .await
            .unwrap();
        assert!(
            remaining.is_empty(),
            "share_store must drop shares targeting the deleted file, got: {remaining:?}"
        );
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_backfill_stamps_unowned_files() {
        let (_bv, core, root_token) =
            new_unseal_test_bastion_vault("test_backfill_files").await;

        let body = json!({
            "entity_id": "root",
            "file_ids": [
                "018f3b2a-abcd-1234-5678-000000000001",
                "018f3b2a-abcd-1234-5678-000000000002",
                "has/slash/invalid",
            ],
            "dry_run": false,
        })
        .as_object()
        .cloned();
        let resp = crate::test_utils::test_write_api(&core, &root_token, "sys/owner/backfill", true, body)
            .await
            .unwrap()
            .unwrap();
        let data = resp.data.unwrap();
        let files = data.get("files").expect("files summary present");
        assert_eq!(files.get("stamped").and_then(|v| v.as_u64()), Some(2));
        let invalid: Vec<String> = files
            .get("invalid")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();
        assert_eq!(invalid, vec!["has/slash/invalid".to_string()]);

        // The stamped records should now exist.
        let identity = core
            .module_manager()
            .get_module::<IdentityModule>("identity")
            .expect("identity module");
        let owner_store = identity.owner_store().expect("owner store");
        for id in [
            "018f3b2a-abcd-1234-5678-000000000001",
            "018f3b2a-abcd-1234-5678-000000000002",
        ] {
            let rec = owner_store.get_file_owner(id).await.unwrap();
            assert!(rec.is_some(), "{id} must be stamped");
            assert_eq!(rec.unwrap().entity_id, "root");
        }
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_file_owner_transfer_admin_endpoint() {
        let (_bv, core, root_token) =
            new_unseal_test_bastion_vault("test_file_owner_transfer").await;
        let engine = base64::engine::general_purpose::STANDARD;

        let body = json!({
            "name": "cfg.yml",
            "content_base64": engine.encode(b"original"),
        })
        .as_object()
        .cloned();
        let resp = crate::test_utils::test_write_api(&core, &root_token, "files/files", true, body)
            .await
            .unwrap()
            .unwrap();
        let id = resp
            .data
            .unwrap()
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        let identity = core
            .module_manager()
            .get_module::<IdentityModule>("identity")
            .expect("identity module");
        let owner_store = identity.owner_store().expect("owner store");

        // Pre: root is the owner.
        assert_eq!(
            owner_store.get_file_owner(&id).await.unwrap().unwrap().entity_id,
            "root"
        );

        // Transfer to a different entity id.
        let xfer = json!({
            "id": id,
            "new_owner_entity_id": "ent-alice",
        })
        .as_object()
        .cloned();
        let _ = crate::test_utils::test_write_api(
            &core,
            &root_token,
            "sys/file-owner/transfer",
            true,
            xfer,
        )
        .await
        .unwrap();

        // Post: new owner recorded.
        assert_eq!(
            owner_store.get_file_owner(&id).await.unwrap().unwrap().entity_id,
            "ent-alice",
            "transfer must overwrite owner unconditionally"
        );
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_sync_target_local_fs_push_writes_file() {
        use std::fs;

        let (_bv, core, root_token) =
            new_unseal_test_bastion_vault("test_sync_local_fs_push").await;
        let engine = base64::engine::general_purpose::STANDARD;

        // 1. Create a file.
        let content = b"PRIVATE KEY CONTENT";
        let body = json!({
            "name": "jump.key",
            "content_base64": engine.encode(content),
        })
        .as_object()
        .cloned();
        let resp = crate::test_utils::test_write_api(&core, &root_token, "files/files", true, body)
            .await
            .unwrap()
            .unwrap();
        let id = resp
            .data
            .unwrap()
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        // 2. Configure a local-fs sync target.
        let tmp = std::env::temp_dir().join(format!("bvault-sync-{id}/key.pem"));
        // Ensure clean slate (prior test run leftovers).
        let _ = fs::remove_file(&tmp);
        let cfg = json!({
            "kind": "local-fs",
            "target_path": tmp.to_string_lossy(),
            "mode": "0600",
        })
        .as_object()
        .cloned();
        let _ = crate::test_utils::test_write_api(
            &core,
            &root_token,
            &format!("files/files/{id}/sync/primary"),
            true,
            cfg,
        )
        .await
        .unwrap();

        // 3. Push.
        let _ = crate::test_utils::test_write_api(
            &core,
            &root_token,
            &format!("files/files/{id}/sync/primary/push"),
            true,
            None,
        )
        .await
        .unwrap();

        // 4. Target file must exist with the right bytes.
        let got = fs::read(&tmp).expect("sync push must produce the target file");
        assert_eq!(got, content, "target bytes must match file content");

        // 5. Sync state must show last_success_at + matching hash.
        let mut list_req = crate::logical::Request::new(format!("files/files/{id}/sync"));
        list_req.operation = crate::logical::Operation::Read;
        list_req.client_token = root_token.clone();
        let list_resp = core.handle_request(&mut list_req).await.unwrap().unwrap();
        let targets = list_resp
            .data
            .unwrap()
            .get("targets")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        assert_eq!(targets.len(), 1);
        let state = targets[0].get("state").expect("state node present");
        let last_ok = state.get("last_success_at").and_then(|v| v.as_str()).unwrap_or("");
        assert!(
            !last_ok.is_empty(),
            "last_success_at must be populated: {state:?}"
        );
        assert_eq!(
            state.get("last_success_sha256").and_then(|v| v.as_str()),
            Some(crate::modules::files::sha256_hex(content).as_str())
        );

        let _ = fs::remove_file(&tmp);
    }

    /// `sync_on_write = true` causes the file-content write to push
    /// the bytes to the target inline, without a separate `push`
    /// call. The response carries a `sync_on_write` array with one
    /// entry per target attempted.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_sync_on_write_inline_push() {
        use std::fs;
        let (_bv, core, root_token) =
            new_unseal_test_bastion_vault("test_sync_on_write_inline").await;
        let engine = base64::engine::general_purpose::STANDARD;

        // Create the file.
        let v1 = b"v1-content";
        let body = json!({
            "name": "config.yaml",
            "content_base64": engine.encode(v1),
        })
        .as_object()
        .cloned();
        let resp = crate::test_utils::test_write_api(&core, &root_token, "files/files", true, body)
            .await
            .unwrap()
            .unwrap();
        let id = resp
            .data
            .unwrap()
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        // Configure a local-fs sync target with sync_on_write = true.
        let tmp = std::env::temp_dir().join(format!("bvault-sow-{id}/config.yaml"));
        let _ = fs::remove_file(&tmp);
        let cfg = json!({
            "kind": "local-fs",
            "target_path": tmp.to_string_lossy(),
            "sync_on_write": true,
        })
        .as_object()
        .cloned();
        let _ = crate::test_utils::test_write_api(
            &core,
            &root_token,
            &format!("files/files/{id}/sync/primary"),
            true,
            cfg,
        )
        .await
        .unwrap();

        // Update the file content. The write handler should fire
        // an inline push to the target.
        let v2 = b"v2-content-with-sync-on-write";
        let body = json!({
            "name": "config.yaml",
            "content_base64": engine.encode(v2),
        })
        .as_object()
        .cloned();
        let resp = crate::test_utils::test_write_api(
            &core,
            &root_token,
            &format!("files/files/{id}"),
            true,
            body,
        )
        .await
        .unwrap()
        .unwrap();
        let data = resp.data.unwrap();
        let pushes = data
            .get("sync_on_write")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        assert_eq!(pushes.len(), 1, "exactly one target should have fired");
        assert_eq!(pushes[0].get("name").and_then(|v| v.as_str()), Some("primary"));
        assert_eq!(pushes[0].get("ok").and_then(|v| v.as_bool()), Some(true));

        // Target file must carry the v2 bytes — proves the inline
        // push ran as part of the write handler.
        let got = fs::read(&tmp).expect("sync_on_write must produce the target file");
        assert_eq!(got, v2);

        let _ = fs::remove_file(&tmp);
    }

    /// The manual `POST /v1/<mount>/sync-tick` endpoint runs the
    /// scheduler sweep on demand. Targets without
    /// `auto_sync_interval_seconds` are skipped; targets with it set
    /// are pushed (and their `last_attempt_source = "scheduler"`).
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_manual_sync_tick_endpoint() {
        use std::fs;
        let (_bv, core, root_token) =
            new_unseal_test_bastion_vault("test_manual_sync_tick").await;
        let engine = base64::engine::general_purpose::STANDARD;

        let body = json!({
            "name": "deploy.cfg",
            "content_base64": engine.encode(b"deploy-bytes"),
        })
        .as_object()
        .cloned();
        let resp = crate::test_utils::test_write_api(&core, &root_token, "files/files", true, body)
            .await
            .unwrap()
            .unwrap();
        let id = resp
            .data
            .unwrap()
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        let tmp = std::env::temp_dir().join(format!("bvault-tick-{id}/deploy.cfg"));
        let _ = fs::remove_file(&tmp);

        // Configure two targets: one with auto_sync, one without.
        let cfg_auto = json!({
            "kind": "local-fs",
            "target_path": tmp.to_string_lossy(),
            "auto_sync_interval_seconds": 60u64,
        })
        .as_object()
        .cloned();
        let _ = crate::test_utils::test_write_api(
            &core,
            &root_token,
            &format!("files/files/{id}/sync/auto"),
            true,
            cfg_auto,
        )
        .await
        .unwrap();
        let tmp2 = std::env::temp_dir().join(format!("bvault-tick-{id}/manual.cfg"));
        let cfg_manual = json!({
            "kind": "local-fs",
            "target_path": tmp2.to_string_lossy(),
            // auto_sync_interval_seconds omitted = 0 = scheduler skips
        })
        .as_object()
        .cloned();
        let _ = crate::test_utils::test_write_api(
            &core,
            &root_token,
            &format!("files/files/{id}/sync/manual"),
            true,
            cfg_manual,
        )
        .await
        .unwrap();

        // Trigger the tick.
        let resp = crate::test_utils::test_write_api(
            &core,
            &root_token,
            "files/sync-tick",
            true,
            None,
        )
        .await
        .unwrap()
        .unwrap();
        let data = resp.data.unwrap();
        let attempted = data.get("attempted").and_then(|v| v.as_u64()).unwrap_or(0);
        let succeeded = data.get("succeeded").and_then(|v| v.as_u64()).unwrap_or(0);
        let skipped = data.get("skipped").and_then(|v| v.as_u64()).unwrap_or(0);
        assert_eq!(attempted, 1, "exactly the auto target should have been attempted");
        assert_eq!(succeeded, 1, "the local-fs auto push should succeed");
        assert!(skipped >= 1, "the manual target should be skipped");

        // The auto target should have produced the file. The manual
        // target should not have been touched.
        let got = fs::read(&tmp).expect("auto target must be written by the tick");
        assert_eq!(got, b"deploy-bytes");
        assert!(!tmp2.exists(), "manual-only target must not be written by the tick");

        let _ = fs::remove_file(&tmp);
    }

    // Exercises both the SMB and SSH URL validators alongside the
    // generic credential checks. The URL parsers live in
    // feature-gated submodules (`files_smb` / `files_ssh_sync`) so
    // a build without those features accepts malformed URLs at save
    // time and the test fails on the assertion that follows. Gate
    // the whole test on those features so the default `cargo test
    // --lib` (no extra features) doesn't see it.
    #[cfg(all(feature = "files_smb", feature = "files_ssh_sync"))]
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_sync_target_unsupported_kind_rejected_at_save() {
        let (_bv, core, root_token) =
            new_unseal_test_bastion_vault("test_sync_unsupported_kind").await;
        let engine = base64::engine::general_purpose::STANDARD;

        let body = json!({
            "name": "cfg",
            "content_base64": engine.encode(b"x"),
        })
        .as_object()
        .cloned();
        let resp = crate::test_utils::test_write_api(&core, &root_token, "files/files", true, body)
            .await
            .unwrap()
            .unwrap();
        let id = resp
            .data
            .unwrap()
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        let cfg = json!({
            "kind": "sftp",
            "target_path": "/etc/ssl/thing.pem",
        })
        .as_object()
        .cloned();
        let _ = crate::test_utils::test_write_api(
            &core,
            &root_token,
            &format!("files/files/{id}/sync/primary"),
            false, // expect error
            cfg,
        )
        .await;

        // smb without credentials: rejected at save time so the
        // operator gets an immediate error rather than discovering
        // the misconfig at first push.
        let cfg = json!({
            "kind": "smb",
            "target_path": "smb://server/share/file.txt",
        })
        .as_object()
        .cloned();
        let _ = crate::test_utils::test_write_api(
            &core,
            &root_token,
            &format!("files/files/{id}/sync/primary"),
            false, // expect error
            cfg,
        )
        .await;

        // smb with malformed URL: also rejected at save time.
        let cfg = json!({
            "kind": "smb",
            "target_path": "not-a-smb-url",
            "smb_username": "user",
            "smb_password": "pw",
        })
        .as_object()
        .cloned();
        let _ = crate::test_utils::test_write_api(
            &core,
            &root_token,
            &format!("files/files/{id}/sync/primary"),
            false, // expect error
            cfg,
        )
        .await;

        // sftp without credentials: rejected at save time.
        let cfg = json!({
            "kind": "sftp",
            "target_path": "sftp://server/srv/x.txt",
            "ssh_username": "alice",
        })
        .as_object()
        .cloned();
        let _ = crate::test_utils::test_write_api(
            &core,
            &root_token,
            &format!("files/files/{id}/sync/primary"),
            false, // expect error: at least one of ssh_password / ssh_private_key required
            cfg,
        )
        .await;

        // scp with malformed URL: rejected at save time.
        let cfg = json!({
            "kind": "scp",
            "target_path": "scp://no-path-here",
            "ssh_username": "alice",
            "ssh_password": "pw",
        })
        .as_object()
        .cloned();
        let _ = crate::test_utils::test_write_api(
            &core,
            &root_token,
            &format!("files/files/{id}/sync/primary"),
            false, // expect error
            cfg,
        )
        .await;
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_file_versioning_snapshots_on_update() {
        let (_bv, core, root_token) =
            new_unseal_test_bastion_vault("test_file_versioning_snapshots").await;
        let engine = base64::engine::general_purpose::STANDARD;

        let v1 = b"content-v1".to_vec();
        let v2 = b"content-v2-different".to_vec();
        let v3 = b"content-v3-different-again".to_vec();

        // Create with v1.
        let resp = crate::test_utils::test_write_api(
            &core,
            &root_token,
            "files/files",
            true,
            json!({ "name": "versioned.txt", "content_base64": engine.encode(&v1) })
                .as_object()
                .cloned(),
        )
        .await
        .unwrap()
        .unwrap();
        let id = resp
            .data
            .unwrap()
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        // No versions yet — only one content write so far.
        let mut req = crate::logical::Request::new(format!("files/files/{id}/versions"));
        req.operation = crate::logical::Operation::Read;
        req.client_token = root_token.clone();
        let r = core.handle_request(&mut req).await.unwrap().unwrap();
        let entries: Vec<serde_json::Value> = r
            .data
            .unwrap()
            .get("versions")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        assert!(entries.is_empty(), "no versions before first update");

        // First update: snapshots v1 as version 1, current = 2.
        let _ = crate::test_utils::test_write_api(
            &core,
            &root_token,
            &format!("files/files/{id}"),
            true,
            json!({ "content_base64": engine.encode(&v2) })
                .as_object()
                .cloned(),
        )
        .await
        .unwrap();

        // Second update: snapshots v2 as version 2, current = 3.
        let _ = crate::test_utils::test_write_api(
            &core,
            &root_token,
            &format!("files/files/{id}"),
            true,
            json!({ "content_base64": engine.encode(&v3) })
                .as_object()
                .cloned(),
        )
        .await
        .unwrap();

        // List versions: 2 entries.
        let mut req = crate::logical::Request::new(format!("files/files/{id}/versions"));
        req.operation = crate::logical::Operation::Read;
        req.client_token = root_token.clone();
        let r = core.handle_request(&mut req).await.unwrap().unwrap();
        let data = r.data.unwrap();
        let current_version = data.get("current_version").and_then(|v| v.as_u64()).unwrap();
        let versions: Vec<serde_json::Value> = data
            .get("versions")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        assert_eq!(current_version, 3);
        assert_eq!(versions.len(), 2);
        let v1_hash = crate::modules::files::sha256_hex(&v1);
        let v2_hash = crate::modules::files::sha256_hex(&v2);
        assert_eq!(versions[0].get("version").and_then(|v| v.as_u64()), Some(1));
        assert_eq!(versions[0].get("sha256").and_then(|v| v.as_str()), Some(v1_hash.as_str()));
        assert_eq!(versions[1].get("version").and_then(|v| v.as_u64()), Some(2));
        assert_eq!(versions[1].get("sha256").and_then(|v| v.as_str()), Some(v2_hash.as_str()));

        // Read historical content of v1.
        let mut req = crate::logical::Request::new(format!("files/files/{id}/versions/1/content"));
        req.operation = crate::logical::Operation::Read;
        req.client_token = root_token.clone();
        let r = core.handle_request(&mut req).await.unwrap().unwrap();
        let b64 = r
            .data
            .unwrap()
            .get("content_base64")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();
        let decoded = engine.decode(&b64).unwrap();
        assert_eq!(decoded, v1);

        // Restore v1 as current. Expected: current_version bumps; v3
        // becomes another snapshot; content read returns v1.
        let mut req = crate::logical::Request::new(format!("files/files/{id}/versions/1/restore"));
        req.operation = crate::logical::Operation::Write;
        req.client_token = root_token.clone();
        let r = core.handle_request(&mut req).await.unwrap().unwrap();
        let rdata = r.data.unwrap();
        assert_eq!(rdata.get("restored_version").and_then(|v| v.as_u64()), Some(1));

        let mut req = crate::logical::Request::new(format!("files/files/{id}/content"));
        req.operation = crate::logical::Operation::Read;
        req.client_token = root_token.clone();
        let r = core.handle_request(&mut req).await.unwrap().unwrap();
        let b64 = r
            .data
            .unwrap()
            .get("content_base64")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();
        let decoded = engine.decode(&b64).unwrap();
        assert_eq!(decoded, v1, "restore must make v1 the live content");
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_file_versioning_retention_prunes_oldest() {
        let (_bv, core, root_token) =
            new_unseal_test_bastion_vault("test_file_versioning_retention").await;
        let engine = base64::engine::general_purpose::STANDARD;

        // Create.
        let resp = crate::test_utils::test_write_api(
            &core,
            &root_token,
            "files/files",
            true,
            json!({ "name": "churn.txt", "content_base64": engine.encode(b"v1") })
                .as_object()
                .cloned(),
        )
        .await
        .unwrap()
        .unwrap();
        let id = resp
            .data
            .unwrap()
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        // Seven updates → should retain only the last DEFAULT_VERSION_RETENTION (5).
        for i in 2..=8 {
            let _ = crate::test_utils::test_write_api(
                &core,
                &root_token,
                &format!("files/files/{id}"),
                true,
                json!({ "content_base64": engine.encode(format!("v{i}").as_bytes()) })
                    .as_object()
                    .cloned(),
            )
            .await
            .unwrap();
        }

        let mut req = crate::logical::Request::new(format!("files/files/{id}/versions"));
        req.operation = crate::logical::Operation::Read;
        req.client_token = root_token.clone();
        let r = core.handle_request(&mut req).await.unwrap().unwrap();
        let data = r.data.unwrap();
        let versions: Vec<serde_json::Value> = data
            .get("versions")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        assert_eq!(
            versions.len(),
            crate::modules::files::DEFAULT_VERSION_RETENTION,
            "retention must prune oldest beyond cap"
        );
        // Oldest retained version number = total_writes (8) - retention (5) = 3.
        // versions[0] is version 4 (after pruning 1, 2, 3).
        // Total content writes = 1 create + 7 updates = 8 ⇒ current_version = 8, first retained = 4.
        let first = versions[0].get("version").and_then(|v| v.as_u64()).unwrap();
        let last = versions
            .last()
            .unwrap()
            .get("version")
            .and_then(|v| v.as_u64())
            .unwrap();
        assert_eq!(first, 3, "after 8 writes with retention=5, oldest retained is v3");
        assert_eq!(last, 7);
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_file_delete_sweeps_versions() {
        use crate::logical::{Operation, Request as Lreq};
        let (_bv, core, root_token) =
            new_unseal_test_bastion_vault("test_file_delete_sweeps_versions").await;
        let engine = base64::engine::general_purpose::STANDARD;

        let resp = crate::test_utils::test_write_api(
            &core,
            &root_token,
            "files/files",
            true,
            json!({ "name": "x", "content_base64": engine.encode(b"a") })
                .as_object()
                .cloned(),
        )
        .await
        .unwrap()
        .unwrap();
        let id = resp
            .data
            .unwrap()
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();
        // One update → one snapshot exists.
        let _ = crate::test_utils::test_write_api(
            &core,
            &root_token,
            &format!("files/files/{id}"),
            true,
            json!({ "content_base64": engine.encode(b"b") })
                .as_object()
                .cloned(),
        )
        .await
        .unwrap();

        // Delete file.
        let mut del = Lreq::new(format!("files/files/{id}"));
        del.operation = Operation::Delete;
        del.client_token = root_token.clone();
        core.handle_request(&mut del).await.unwrap();

        // Version list must be empty (vmeta swept).
        let mut req = Lreq::new(format!("files/files/{id}/versions"));
        req.operation = Operation::Read;
        req.client_token = root_token.clone();
        let r = core.handle_request(&mut req).await.unwrap().unwrap();
        let data = r.data.unwrap();
        assert_eq!(data.get("current_version").and_then(|v| v.as_u64()), Some(0));
        assert!(data
            .get("versions")
            .and_then(|v| v.as_array())
            .unwrap()
            .is_empty());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_identity_owner_file_read_endpoint() {
        let (_bv, core, root_token) =
            new_unseal_test_bastion_vault("test_identity_owner_file_read").await;
        let engine = base64::engine::general_purpose::STANDARD;

        let body = json!({
            "name": "api.key",
            "content_base64": engine.encode(b"stuff"),
        })
        .as_object()
        .cloned();
        let resp = crate::test_utils::test_write_api(&core, &root_token, "files/files", true, body)
            .await
            .unwrap()
            .unwrap();
        let id = resp
            .data
            .unwrap()
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        // `identity/owner/file/<id>` returns { target_kind, target, owner }.
        let resp =
            crate::test_utils::test_read_api(&core, &root_token, &format!("identity/owner/file/{id}"), true)
                .await
                .unwrap()
                .unwrap();
        let data = resp.data.expect("owner envelope");
        assert_eq!(data.get("target_kind").and_then(|v| v.as_str()), Some("file"));
        assert_eq!(data.get("target").and_then(|v| v.as_str()), Some(id.as_str()));
        assert_eq!(data.get("owned").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(data.get("entity_id").and_then(|v| v.as_str()), Some("root"));
    }
}
