//! Tests for the notifications engine, which lives in
//! `crates/bv-engine-notifications`.
//!
//! They stayed in the root crate for the reason Phase 1 established: they
//! stand up a whole vault through `crate::test_utils`, and a crate below the
//! root cannot depend on the root. They drive the engine entirely through its
//! mounted HTTP surface, so nothing here needs a private item.
//!
//! See roadmaps/workspace-decomposition.md § Phase 3.

mod notifications_tests {
    use crate::kernel_api::VaultCtx;
    use serde_json::{json, Map};

    use crate::test_utils::{
        new_unseal_test_bastion_vault, test_mount_auth_api, test_read_api, test_write_api,
    };

    fn obj(v: serde_json::Value) -> Option<Map<String, serde_json::Value>> {
        v.as_object().cloned()
    }

    /// End-to-end: send a notification to a user, read it from that
    /// user's inbox, mark it read, and confirm the admin + channel views.
    #[maybe_async::test(
        feature = "sync_handler",
        async(all(not(feature = "sync_handler")), tokio::test)
    )]
    async fn notification_send_and_inbox_roundtrip() {
        let (_bvault, core, root) =
            new_unseal_test_bastion_vault("notif_roundtrip").await;

        // A userpass user (pre-provisions the identity entity + alias).
        test_mount_auth_api(&core, &root, "userpass", "pass").await;
        test_write_api(
            &core,
            &root,
            "auth/pass/users/alice",
            true,
            obj(json!({ "password": "123qwe!@#", "ttl": 0 })),
        )
        .await
        .unwrap();

        // Log in as alice → token carrying her entity_id.
        let login = test_write_api(
            &core,
            "",
            "auth/pass/login/alice",
            true,
            obj(json!({ "password": "123qwe!@#" })),
        )
        .await
        .unwrap()
        .unwrap();
        let alice_token = login.auth.unwrap().client_token;

        // Root broadcasts to alice by login name.
        let sent = test_write_api(
            &core,
            &root,
            "notifications/send",
            true,
            obj(json!({
                "title": "Maintenance",
                "body": "tonight at 22:00",
                "severity": "warning",
                "target": { "kind": "username", "name": "alice" },
                "channels": []
            })),
        )
        .await
        .unwrap()
        .unwrap();
        let sent_data = sent.data.unwrap();
        assert_eq!(
            sent_data.get("recipient_count").and_then(|v| v.as_u64()),
            Some(1)
        );
        let notif_id = sent_data
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        // Alice sees one unread notification.
        let inbox = test_read_api(&core, &alice_token, "notifications/inbox", true)
            .await
            .unwrap()
            .unwrap();
        let items = inbox
            .data
            .unwrap()
            .get("notifications")
            .unwrap()
            .as_array()
            .unwrap()
            .clone();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].get("read").and_then(|v| v.as_bool()), Some(false));

        let unread = test_read_api(
            &core,
            &alice_token,
            "notifications/inbox/unread-count",
            true,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            unread.data.unwrap().get("unread").and_then(|v| v.as_u64()),
            Some(1)
        );

        // Mark read → unread drops to zero.
        test_write_api(
            &core,
            &alice_token,
            &format!("notifications/inbox/{notif_id}/read"),
            true,
            Some(Map::new()),
        )
        .await
        .unwrap();
        let unread2 = test_read_api(
            &core,
            &alice_token,
            "notifications/inbox/unread-count",
            true,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            unread2.data.unwrap().get("unread").and_then(|v| v.as_u64()),
            Some(0)
        );

        // The built-in in-app channel is always present.
        let channels = test_read_api(&core, &root, "notifications/channels", true)
            .await
            .unwrap()
            .unwrap();
        let chans = channels
            .data
            .unwrap()
            .get("channels")
            .unwrap()
            .as_array()
            .unwrap()
            .clone();
        assert!(chans
            .iter()
            .any(|c| c.get("id").and_then(|v| v.as_str()) == Some("in-app")));

        // Admin "sent" view lists the broadcast.
        let sent_list = test_read_api(&core, &root, "notifications/sent", true)
            .await
            .unwrap()
            .unwrap();
        let sent_arr = sent_list
            .data
            .unwrap()
            .get("notifications")
            .unwrap()
            .as_array()
            .unwrap()
            .clone();
        assert_eq!(sent_arr.len(), 1);
    }

    /// Targeting `all_users` reaches a provisioned user; dismiss removes
    /// the inbox entry.
    #[maybe_async::test(
        feature = "sync_handler",
        async(all(not(feature = "sync_handler")), tokio::test)
    )]
    async fn notification_all_users_and_dismiss() {
        let (_bvault, core, root) =
            new_unseal_test_bastion_vault("notif_all_users").await;
        test_mount_auth_api(&core, &root, "userpass", "pass").await;
        test_write_api(
            &core,
            &root,
            "auth/pass/users/bob",
            true,
            obj(json!({ "password": "123qwe!@#", "ttl": 0 })),
        )
        .await
        .unwrap();
        let login = test_write_api(
            &core,
            "",
            "auth/pass/login/bob",
            true,
            obj(json!({ "password": "123qwe!@#" })),
        )
        .await
        .unwrap()
        .unwrap();
        let bob_token = login.auth.unwrap().client_token;

        let sent = test_write_api(
            &core,
            &root,
            "notifications/send",
            true,
            obj(json!({
                "title": "Everyone",
                "body": "hello all",
                "severity": "info",
                "target": { "kind": "all_users" },
                "channels": []
            })),
        )
        .await
        .unwrap()
        .unwrap();
        let id = sent
            .data
            .unwrap()
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        // Bob dismisses it (DELETE) → inbox empties.
        dismiss(&core, &bob_token, &id).await.unwrap();

        let inbox = test_read_api(&core, &bob_token, "notifications/inbox", true)
            .await
            .unwrap()
            .unwrap();
        let items = inbox
            .data
            .unwrap()
            .get("notifications")
            .unwrap()
            .as_array()
            .unwrap()
            .clone();
        assert_eq!(items.len(), 0);
    }

    /// Helper: issue a DELETE against the inbox dismiss route (the
    /// generic test helpers only cover read/write/list).
    async fn dismiss(
        core: &dyn VaultCtx,
        token: &str,
        id: &str,
    ) -> Result<Option<crate::logical::Response>, crate::errors::RvError> {
        let mut req = crate::logical::Request::new(format!("notifications/inbox/{id}"));
        req.operation = crate::logical::Operation::Delete;
        req.client_token = token.to_string();
        core.handle_request(&mut req).await
    }
}
