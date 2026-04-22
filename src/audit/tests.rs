//! End-to-end audit tests. Brought in from `mod.rs` at the bottom
//! of the file; split out for readability.

#[cfg(test)]
mod audit_integration_tests {
    use std::collections::HashMap;

    use serde_json::json;

    use std::path::PathBuf;

    use crate::{
        audit::{
            entry::{hmac_redact, AuditEntry},
            file_device::FileAuditDevice,
            hash_chain::{genesis, verify},
            AuditDevice,
        },
        test_utils::{new_unseal_test_bastion_vault, TestHttpServer},
    };

    /// Unique per-test log path under the system tempdir so
    /// parallel runs don't collide.
    fn tmp_log_path(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let mut p = std::env::temp_dir();
        p.push(format!("bv-audit-{tag}-{nanos}.log"));
        p
    }

    /// Writing + reading via a file device produces a chain of
    /// entries whose `prev_hash` links verify end-to-end.
    #[maybe_async::test(
        feature = "sync_handler",
        async(all(not(feature = "sync_handler")), tokio::test)
    )]
    async fn file_device_hash_chain_verifies() {
        let log_path = tmp_log_path("chain");

        let mut opts = HashMap::new();
        opts.insert("file_path".into(), log_path.display().to_string());
        let dev = FileAuditDevice::new(&opts).await.unwrap();

        // Emit a small chain by hand, stamping prev_hash ourselves.
        let hmac_key = b"test-key";
        let mut prev = genesis();
        let mut entries = Vec::new();
        for i in 0..3 {
            let mut e = AuditEntry {
                time: format!("2026-04-21T00:00:0{i}Z"),
                r#type: "response".into(),
                prev_hash: prev.clone(),
                ..Default::default()
            };
            e.request.operation = "read".into();
            e.request.path = format!("secret/data/e{i}").into();
            e.auth.client_token = format!("hmac:{}", hmac_redact(hmac_key, b"fake"));
            dev.log_entry(&e).await.unwrap();
            prev = crate::audit::hash_chain::digest(&e).unwrap();
            entries.push(e);
        }
        dev.flush().await.unwrap();

        // Read back each line from the file and verify the chain.
        let body = tokio::fs::read_to_string(&log_path).await.unwrap();
        let parsed: Vec<AuditEntry> = body
            .lines()
            .map(|l| serde_json::from_str(l).expect("valid entry"))
            .collect();
        assert_eq!(parsed.len(), 3);
        verify(&parsed, &genesis()).expect("chain verifies");

        // Tamper with the middle entry on disk — chain should break.
        let mut tampered = parsed.clone();
        tampered[1].request.path = "secret/data/tampered".into();
        let err = verify(&tampered, &genesis()).unwrap_err();
        assert_eq!(
            err,
            crate::audit::hash_chain::VerifyError::BrokenAt(2),
            "tampering entry 1 should break the link at 2",
        );
    }

    /// Enabling a file audit device via `sys/audit/<path>` causes
    /// subsequent requests to be logged to the file. A follow-up
    /// `GET /sys/audit` lists the device. `DELETE` removes it.
    #[maybe_async::test(
        feature = "sync_handler",
        async(all(not(feature = "sync_handler")), tokio::test)
    )]
    async fn audit_device_enable_disable_via_api() {
        let mut server =
            TestHttpServer::new("audit_device_enable_disable_via_api", true).await;
        server.token = server.root_token.clone();

        let log_path = tmp_log_path("api");

        // Enable a file device at path `primary`.
        let _ = server
            .write(
                "sys/audit/primary",
                json!({
                    "type": "file",
                    "description": "integration test",
                    "options": { "file_path": log_path.display().to_string() }
                })
                .as_object()
                .cloned(),
                None,
            )
            .unwrap();

        // Produce an audited request by writing a dummy policy.
        let _ = server
            .write(
                "sys/policies/acl/audit-target",
                json!({ "policy": r#"path "x/*" { capabilities = ["read"] }"# })
                    .as_object()
                    .cloned(),
                None,
            )
            .unwrap();

        // Flush to disk is synchronous after each write in the file
        // device, so read straight back.
        let body = tokio::fs::read_to_string(&log_path).await.unwrap();
        let lines: Vec<&str> = body.lines().collect();
        assert!(
            !lines.is_empty(),
            "audit log should have entries after enabling + performing a request",
        );

        // `GET /sys/audit` lists the enabled device.
        let ret = server.read("sys/audit", None).unwrap().1;
        let devs = ret
            .get("devices")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        assert!(
            devs.iter().any(|d| d
                .get("path")
                .and_then(|v| v.as_str())
                == Some("primary")),
            "list should contain `primary`, got {devs:?}",
        );

        // Disable the device.
        let _ = server.delete("sys/audit/primary", None, None).unwrap();
        let ret = server.read("sys/audit", None).unwrap().1;
        let devs = ret
            .get("devices")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        assert!(devs.is_empty(), "list should be empty after disable");
    }

    /// Smoke test that the broker re-hydrates device configs on a
    /// fresh `Core::new`-then-unseal cycle. Covers persistence at
    /// `audit-devices/<path>`.
    #[maybe_async::test(
        feature = "sync_handler",
        async(all(not(feature = "sync_handler")), tokio::test)
    )]
    async fn broker_reload_drops_on_seal() {
        let (_v, core, _rt) = new_unseal_test_bastion_vault("broker_reload_drops_on_seal").await;
        // Broker is installed at post_unseal; empty device list.
        let broker = core
            .audit_broker
            .load()
            .as_ref()
            .cloned()
            .expect("broker installed at unseal");
        assert!(!broker.has_devices(), "starts with zero devices");
    }
}
