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

    /// Per-namespace routing + superuser mirror + per-namespace chains.
    ///
    /// Three devices: a plain root device, a tenant-a device, and a root
    /// device with `mirror = true`. A root event and two tenant-a events are
    /// logged. The plain root device sees only the root event; the tenant
    /// device sees only the tenant events; the mirror device sees all three.
    /// Each device file is an independently-verifiable hash chain.
    #[maybe_async::test(
        feature = "sync_handler",
        async(all(not(feature = "sync_handler")), tokio::test)
    )]
    async fn per_namespace_routing_and_mirror() {
        let (_v, core, _rt) = new_unseal_test_bastion_vault("audit_per_ns").await;
        let broker = core
            .audit_broker
            .load()
            .as_ref()
            .cloned()
            .expect("broker installed at unseal");

        let root_path = tmp_log_path("ns-root");
        let a_path = tmp_log_path("ns-a");
        let mirror_path = tmp_log_path("ns-mirror");

        let dev_cfg = |path: &str, file: &PathBuf, namespace: &str, mirror: bool| {
            let mut options = HashMap::new();
            options.insert("file_path".to_string(), file.display().to_string());
            crate::audit::AuditDeviceConfig {
                path: path.to_string(),
                device_type: "file".to_string(),
                description: String::new(),
                options,
                namespace: namespace.to_string(),
                mirror,
            }
        };

        broker.enable_device(dev_cfg("root-dev", &root_path, "", false)).await.unwrap();
        broker.enable_device(dev_cfg("a-dev", &a_path, "tenant-a", false)).await.unwrap();
        broker.enable_device(dev_cfg("mirror-dev", &mirror_path, "", true)).await.unwrap();

        let mk = |ns: &str, i: usize| {
            let mut e = AuditEntry {
                time: format!("2026-06-17T00:00:0{i}Z"),
                r#type: "response".into(),
                ..Default::default()
            };
            e.namespace = ns.to_string();
            e.request.operation = "update".into();
            e.request.path = format!("{ns}/p{i}").into();
            e
        };

        let mut e_root = mk("", 0);
        broker.log(&mut e_root).await.unwrap();
        let mut e_a1 = mk("tenant-a", 1);
        broker.log(&mut e_a1).await.unwrap();
        let mut e_a2 = mk("tenant-a", 2);
        broker.log(&mut e_a2).await.unwrap();

        async fn read_entries(p: &PathBuf) -> Vec<AuditEntry> {
            let body = tokio::fs::read_to_string(p).await.unwrap_or_default();
            body.lines().map(|l| serde_json::from_str(l).expect("valid entry")).collect()
        }
        fn paths(entries: &[AuditEntry]) -> Vec<String> {
            entries.iter().map(|e| e.request.path.to_string()).collect()
        }

        let root_entries = read_entries(&root_path).await;
        let a_entries = read_entries(&a_path).await;
        let mirror_entries = read_entries(&mirror_path).await;

        // Plain root device: only the root event.
        assert_eq!(paths(&root_entries), vec!["/p0".to_string()]);
        // Tenant device: only the two tenant events, none from root.
        assert_eq!(
            paths(&a_entries),
            vec!["tenant-a/p1".to_string(), "tenant-a/p2".to_string()]
        );
        // Mirror device: root event + both tenant events, tenant attribution kept.
        assert_eq!(
            paths(&mirror_entries),
            vec!["/p0".to_string(), "tenant-a/p1".to_string(), "tenant-a/p2".to_string()]
        );
        assert_eq!(mirror_entries[1].namespace, "tenant-a");

        // Each file is an independently-verifiable chain from genesis.
        verify(&root_entries, &genesis()).expect("root chain verifies");
        verify(&a_entries, &genesis()).expect("tenant-a chain verifies");
        verify(&mirror_entries, &genesis()).expect("mirror chain verifies");
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
