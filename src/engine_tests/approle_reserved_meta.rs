//! An AppRole secret-id's `metadata` cannot forge the login token's identity
//! (T103, S107).
//!
//! The token's metadata starts as a copy of the secret-id's, and `entity_id`
//! is what a credential provider scopes a person's data by. A secret-id
//! carrying `entity_id` / `username` (or any other backend-owned key) is
//! therefore refused when it is created, and a secret-id already stored with
//! them — written before that check existed — has them dropped at login.
//!
//! In its own file, rather than `approle.rs`, so it does not depend on that
//! file's helpers.

mod approle_reserved_meta_tests {
    use serde_json::{json, Map, Value};

    use crate::kernel_api::VaultCtx;
    use crate::logical::{Operation, Request};
    use crate::storage::{Storage, StorageEntry};
    use crate::test_utils::{new_unseal_test_bastion_vault, test_mount_auth_api, test_read_api, test_write_api};

    const MARKER: &str = "pre-fix-marker-7f3a";

    fn obj(v: Value) -> Option<Map<String, Value>> {
        v.as_object().cloned()
    }

    async fn write(core: &dyn VaultCtx, token: &str, path: &str, body: Value) -> Result<Map<String, Value>, String> {
        let mut req = Request::new(path);
        req.operation = Operation::Write;
        req.client_token = token.to_string();
        req.body = obj(body);
        match core.handle_request(&mut req).await {
            Ok(r) => Ok(r.and_then(|r| r.data).unwrap_or_default()),
            Err(e) => Err(e.to_string()),
        }
    }

    /// Every barrier key under `prefix`, recursively.
    async fn keys_under(storage: &dyn Storage, prefix: &str) -> Vec<String> {
        let mut stack = vec![prefix.to_string()];
        let mut out = Vec::new();
        while let Some(p) = stack.pop() {
            for n in storage.list(&p).await.unwrap() {
                match n.strip_suffix('/') {
                    Some(d) => stack.push(format!("{p}{d}/")),
                    None => out.push(format!("{p}{n}")),
                }
            }
        }
        out
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn secret_id_metadata_cannot_forge_the_token_identity() {
        let (_vault, core, root) = new_unseal_test_bastion_vault("approle_reserved_meta").await;
        core.approle_require_machine().store(false, std::sync::atomic::Ordering::Relaxed);
        test_mount_auth_api(core.as_ref(), &root, "approle", "approle").await;
        test_write_api(
            core.as_ref(),
            &root,
            "auth/approle/role/app1",
            true,
            obj(json!({ "policies": "default", "secret_id_num_uses": 10, "secret_id_ttl": 300,
                        "token_ttl": 400, "token_max_ttl": 500 })),
        )
        .await
        .unwrap();
        let role_id = test_read_api(core.as_ref(), &root, "auth/approle/role/app1/role-id", true)
            .await
            .unwrap()
            .unwrap()
            .data
            .unwrap()["role_id"]
            .as_str()
            .unwrap()
            .to_string();

        // (1) Creation refuses the keys, on both secret-id routes, naming
        // them and not their values.
        let forged = r#"{"entity_id":"victim","username":"alice"}"#;
        for (path, body) in [
            ("auth/approle/role/app1/secret-id", json!({ "metadata": forged })),
            (
                "auth/approle/role/app1/custom-secret-id",
                json!({ "secret_id": "custom-secret-id-0001", "metadata": forged }),
            ),
        ] {
            let e = write(core.as_ref(), &root, path, body).await.expect_err("reserved keys must be refused");
            assert!(e.contains("entity_id") && e.contains("username"), "{path}: {e}");
            assert!(!e.contains("victim") && !e.contains("alice"), "{path}: values are never echoed: {e}");
        }

        // (2) A secret-id stored before the check existed: create a benign
        // one, then rewrite its stored metadata the way old data could hold it.
        let secret_id = write(
            core.as_ref(),
            &root,
            "auth/approle/role/app1/secret-id",
            json!({ "metadata": format!(r#"{{"marker":"{MARKER}"}}"#) }),
        )
        .await
        .unwrap()["secret_id"]
            .as_str()
            .unwrap()
            .to_string();
        let storage = core.barrier.as_storage();
        let mut rewritten = 0;
        for key in keys_under(storage, "").await {
            // Barrier-internal keys (the keyring) are not readable through
            // the barrier; they are not secret-ids either.
            let Ok(Some(entry)) = storage.get(&key).await else { continue };
            if !String::from_utf8_lossy(&entry.value).contains(MARKER) {
                continue;
            }
            let mut v: Value = serde_json::from_slice(&entry.value).unwrap();
            v["metadata"]["entity_id"] = json!("victim");
            v["metadata"]["username"] = json!("alice");
            v["metadata"]["spiffe_id"] = json!("spiffe://forged/machine");
            storage.put(&StorageEntry { key, value: serde_json::to_vec(&v).unwrap() }).await.unwrap();
            rewritten += 1;
        }
        assert_eq!(rewritten, 1, "exactly one stored secret-id carries the marker");

        let mut req = Request::new("auth/approle/login");
        req.operation = Operation::Write;
        req.body = obj(json!({ "role_id": role_id, "secret_id": secret_id }));
        let auth = match core.handle_request(&mut req).await {
            Ok(Some(r)) => r.auth.expect("login returns auth"),
            Ok(None) => panic!("login returned nothing"),
            Err(e) => panic!("login failed: {e}"),
        };
        let meta = &auth.metadata;
        assert_ne!(meta.get("entity_id").map(String::as_str), Some("victim"), "entity_id must not be forged");
        assert_eq!(meta.get("username"), None, "an AppRole token carries no username");
        assert_eq!(meta.get("spiffe_id"), None, "machine identity must not be forged");
        assert_eq!(meta.get("role_name").map(String::as_str), Some("app1"));
        assert_eq!(meta.get("marker").map(String::as_str), Some(MARKER), "ordinary metadata is kept");

        // What a credential provider would be told about this caller.
        let mut probe = Request::default();
        probe.auth = Some(auth.clone());
        let caller = crate::kernel_api::provider::CallerIdentity::from_request(&probe);
        assert_ne!(caller.entity_id, "victim");
        assert_eq!(caller.principal_name, "app1");
    }
}
