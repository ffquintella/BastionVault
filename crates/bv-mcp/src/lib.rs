//! BastionVault's MCP (Model Context Protocol) dispatcher. See
//! features/mcp-access.md for the design this crate implements (Phase 1 —
//! `bv-mcp` core: JSON-RPC types, the read-only tool catalogue, the
//! `tools/call` gates and result shaping). Deliberately depends on neither
//! the vault stack nor the official Rust MCP SDK — see that spec's §
//! Dependencies.

pub mod catalogue;
pub mod dispatcher;
pub mod error;
pub mod jsonrpc;
pub mod pairing;
pub mod request_state;
pub mod sanitize;

pub use bv_logical::{McpBinding, McpBindingKind};
pub use dispatcher::{DispatchContext, PrincipalInfo};
pub use error::McpError;
pub use jsonrpc::{CallToolResult, ContentBlock, ResultType};

#[cfg(test)]
mod dispatch_tests {
    use std::collections::HashMap;

    use async_trait::async_trait;
    use bv_client::{Backend, ClientError, JsonResponse, Operation};
    use serde_json::{json, Map, Value};

    use super::*;
    use crate::request_state::SingleUseGuard;

    /// A `Backend` test double that records every call it receives and
    /// answers with a fixed response per path, so gate-order and
    /// path-argument construction can be asserted without any real vault
    /// stack.
    #[derive(Default)]
    struct FakeBackend {
        responses: HashMap<String, Map<String, Value>>,
    }

    impl FakeBackend {
        fn with(mut self, path: &str, data: Value) -> Self {
            self.responses.insert(path.to_string(), data.as_object().unwrap().clone());
            self
        }
    }

    #[async_trait]
    impl Backend for FakeBackend {
        async fn handle(
            &self,
            _operation: Operation,
            path: &str,
            _body: Option<Map<String, Value>>,
            _token: &str,
        ) -> Result<Option<JsonResponse>, ClientError> {
            Ok(self.responses.get(path).map(|d| JsonResponse { data: Some(d.clone()), ..Default::default() }))
        }
    }

    fn binding(tool_allowlist: &[&str], path_scope: &[&str]) -> McpBinding {
        McpBinding {
            kind: McpBindingKind::App("test-app".into()),
            catalogue_hash: catalogue::catalogue_hash(),
            tool_allowlist: tool_allowlist.iter().map(|s| s.to_string()).collect(),
            path_scope: path_scope.iter().map(|s| s.to_string()).collect(),
            reveal_allowed: false,
            destructive_allowed: false,
            client_name: "test-client".into(),
            client_version: "1.0".into(),
            waived_until: None,
        }
    }

    fn principal() -> PrincipalInfo {
        PrincipalInfo {
            accessor: "acc-test".into(),
            display_name: "test principal".into(),
            policies: vec!["ai-reader".into()],
        }
    }

    fn ctx<'a>(
        binding: &'a McpBinding,
        backend: &'a FakeBackend,
        principal: &'a PrincipalInfo,
        guard: &'a SingleUseGuard,
    ) -> DispatchContext<'a> {
        DispatchContext {
            binding,
            backend,
            token: "test-token",
            principal,
            confirm_reveal: false,
            confirm_destructive: false,
            request_state_key: b"test-key",
            single_use_guard: guard,
        }
    }

    #[tokio::test]
    async fn tool_not_in_allowlist_is_refused() {
        let b = binding(&[], &["secret/*"]);
        let backend = FakeBackend::default();
        let p = principal();
        let guard = SingleUseGuard::new();
        let err = dispatcher::call("bv_kv_read_metadata", Map::new(), None, &ctx(&b, &backend, &p, &guard))
            .await
            .unwrap_err();
        assert_eq!(err.code(), "mcp_tool_not_allowed");
    }

    #[tokio::test]
    async fn allowed_tool_within_scope_succeeds() {
        let b = binding(&["bv_kv_read_metadata"], &["secret/metadata/*"]);
        let backend = FakeBackend::default().with("secret/metadata/foo", json!({ "current_version": 3 }));
        let p = principal();
        let guard = SingleUseGuard::new();
        let mut args = Map::new();
        args.insert("mount".into(), json!("secret"));
        args.insert("path".into(), json!("foo"));
        let result = dispatcher::call("bv_kv_read_metadata", args, None, &ctx(&b, &backend, &p, &guard)).await.unwrap();
        assert!(!result.is_error);
        assert_eq!(result.structured_content.unwrap()["current_version"], json!(3));
    }

    #[tokio::test]
    async fn path_outside_scope_is_refused() {
        let b = binding(&["bv_kv_read_metadata"], &["kv/metadata/*"]);
        let backend = FakeBackend::default();
        let p = principal();
        let guard = SingleUseGuard::new();
        let mut args = Map::new();
        args.insert("mount".into(), json!("secret"));
        args.insert("path".into(), json!("foo"));
        let err =
            dispatcher::call("bv_kv_read_metadata", args, None, &ctx(&b, &backend, &p, &guard)).await.unwrap_err();
        assert_eq!(err.code(), "mcp_path_out_of_scope");
    }

    #[tokio::test]
    async fn reveal_false_returns_redacted_sentinel() {
        let b = binding(&["bv_kv_read"], &["secret/data/*"]);
        let backend = FakeBackend::default().with("secret/data/foo", json!({ "data": { "k": "v" } }));
        let p = principal();
        let guard = SingleUseGuard::new();
        let mut args = Map::new();
        args.insert("mount".into(), json!("secret"));
        args.insert("path".into(), json!("foo"));
        let result = dispatcher::call("bv_kv_read", args, None, &ctx(&b, &backend, &p, &guard)).await.unwrap();
        assert_eq!(result.structured_content.unwrap()["data"], json!("<redacted>"));
    }

    #[tokio::test]
    async fn reveal_true_without_reveal_allowed_is_denied() {
        let b = binding(&["bv_kv_read"], &["secret/data/*"]);
        let backend = FakeBackend::default().with("secret/data/foo", json!({ "data": { "k": "v" } }));
        let p = principal();
        let guard = SingleUseGuard::new();
        let mut args = Map::new();
        args.insert("mount".into(), json!("secret"));
        args.insert("path".into(), json!("foo"));
        args.insert("reveal".into(), json!(true));
        let err = dispatcher::call("bv_kv_read", args, None, &ctx(&b, &backend, &p, &guard)).await.unwrap_err();
        assert_eq!(err.code(), "mcp_reveal_denied");
    }

    #[tokio::test]
    async fn reveal_true_with_reveal_allowed_returns_value() {
        let mut b = binding(&["bv_kv_read"], &["secret/data/*"]);
        b.reveal_allowed = true;
        let backend = FakeBackend::default().with("secret/data/foo", json!({ "data": { "k": "v" } }));
        let p = principal();
        let guard = SingleUseGuard::new();
        let mut args = Map::new();
        args.insert("mount".into(), json!("secret"));
        args.insert("path".into(), json!("foo"));
        args.insert("reveal".into(), json!(true));
        let result = dispatcher::call("bv_kv_read", args, None, &ctx(&b, &backend, &p, &guard)).await.unwrap();
        assert_eq!(result.structured_content.unwrap()["data"], json!({ "k": "v" }));
    }

    #[tokio::test]
    async fn reveal_with_confirmation_requires_state_then_succeeds() {
        let mut b = binding(&["bv_kv_read"], &["secret/data/*"]);
        b.reveal_allowed = true;
        let backend = FakeBackend::default().with("secret/data/foo", json!({ "data": { "k": "v" } }));
        let p = principal();
        let guard = SingleUseGuard::new();
        let mut args = Map::new();
        args.insert("mount".into(), json!("secret"));
        args.insert("path".into(), json!("foo"));
        args.insert("reveal".into(), json!(true));

        let mut dc = ctx(&b, &backend, &p, &guard);
        dc.confirm_reveal = true;

        let first = dispatcher::call("bv_kv_read", args.clone(), None, &dc).await.unwrap();
        assert_eq!(first.result_type, ResultType::InputRequired);
        let state = first.request_state.expect("input_required must carry a requestState");

        let second = dispatcher::call("bv_kv_read", args, Some(&state), &dc).await.unwrap();
        assert_eq!(second.structured_content.unwrap()["data"], json!({ "k": "v" }));
    }

    #[tokio::test]
    async fn confirmation_state_is_single_use() {
        let mut b = binding(&["bv_kv_read"], &["secret/data/*"]);
        b.reveal_allowed = true;
        let backend = FakeBackend::default().with("secret/data/foo", json!({ "data": { "k": "v" } }));
        let p = principal();
        let guard = SingleUseGuard::new();
        let mut args = Map::new();
        args.insert("mount".into(), json!("secret"));
        args.insert("path".into(), json!("foo"));
        args.insert("reveal".into(), json!(true));

        let mut dc = ctx(&b, &backend, &p, &guard);
        dc.confirm_reveal = true;

        let first = dispatcher::call("bv_kv_read", args.clone(), None, &dc).await.unwrap();
        let state = first.request_state.unwrap();
        dispatcher::call("bv_kv_read", args.clone(), Some(&state), &dc).await.unwrap();
        let replay = dispatcher::call("bv_kv_read", args, Some(&state), &dc).await;
        assert!(replay.is_err(), "a second use of the same requestState must be refused");
    }

    #[tokio::test]
    async fn whoami_answers_without_any_backend_call() {
        let b = binding(&["bv_whoami"], &[]);
        // No responses registered — a real dispatch would return `None`
        // and this test would fail if bv_whoami actually routed anywhere.
        let backend = FakeBackend::default();
        let p = principal();
        let guard = SingleUseGuard::new();
        let result = dispatcher::call("bv_whoami", Map::new(), None, &ctx(&b, &backend, &p, &guard)).await.unwrap();
        assert_eq!(result.structured_content.unwrap()["accessor"], json!("acc-test"));
    }

    #[tokio::test]
    async fn dotdot_in_path_argument_is_rejected() {
        let b = binding(&["bv_kv_read_metadata"], &["secret/metadata/*"]);
        let backend = FakeBackend::default();
        let p = principal();
        let guard = SingleUseGuard::new();
        let mut args = Map::new();
        args.insert("mount".into(), json!("secret"));
        args.insert("path".into(), json!("../../etc/passwd"));
        let err =
            dispatcher::call("bv_kv_read_metadata", args, None, &ctx(&b, &backend, &p, &guard)).await.unwrap_err();
        assert_eq!(err.code(), "mcp_invalid_argument");
    }

    #[tokio::test]
    async fn sys_prefix_in_path_argument_is_out_of_scope() {
        let b = binding(&["bv_resource_describe"], &["resource/*"]);
        let backend = FakeBackend::default();
        let p = principal();
        let guard = SingleUseGuard::new();
        let mut args = Map::new();
        args.insert("path".into(), json!("sys/seal-status"));
        let err =
            dispatcher::call("bv_resource_describe", args, None, &ctx(&b, &backend, &p, &guard)).await.unwrap_err();
        assert_eq!(err.code(), "mcp_path_out_of_scope");
    }

    #[tokio::test]
    async fn ansi_in_response_value_is_stripped() {
        let b = binding(&["bv_resource_describe"], &["resource/*"]);
        let backend = FakeBackend::default().with("resource/foo", json!({ "note": "\u{1b}[31mred\u{1b}[0m" }));
        let p = principal();
        let guard = SingleUseGuard::new();
        let mut args = Map::new();
        args.insert("path".into(), json!("foo"));
        let result =
            dispatcher::call("bv_resource_describe", args, None, &ctx(&b, &backend, &p, &guard)).await.unwrap();
        assert_eq!(result.structured_content.unwrap()["note"], json!("red"));
    }

    #[test]
    fn destructive_gate_pure_function_allows_and_denies() {
        let mut b = binding(&[], &[]);
        assert!(crate::dispatcher::check_destructive_gate(true, &b).is_err());
        b.destructive_allowed = true;
        assert!(crate::dispatcher::check_destructive_gate(true, &b).is_ok());
    }

    #[tokio::test]
    async fn destructive_tool_denied_by_default() {
        let b = binding(&["bv_kv_write"], &["secret/data/*"]);
        let backend = FakeBackend::default();
        let p = principal();
        let guard = SingleUseGuard::new();
        let mut args = Map::new();
        args.insert("mount".into(), json!("secret"));
        args.insert("path".into(), json!("foo"));
        args.insert("data".into(), json!({ "k": "v" }));
        let err = dispatcher::call("bv_kv_write", args, None, &ctx(&b, &backend, &p, &guard)).await.unwrap_err();
        assert_eq!(err.code(), "mcp_destructive_denied");
    }

    #[tokio::test]
    async fn destructive_tool_allowed_after_grant_dispatches() {
        let mut b = binding(&["bv_kv_write"], &["secret/data/*"]);
        b.destructive_allowed = true;
        let backend = FakeBackend::default().with("secret/data/foo", json!({ "ok": true }));
        let p = principal();
        let guard = SingleUseGuard::new();
        let mut args = Map::new();
        args.insert("mount".into(), json!("secret"));
        args.insert("path".into(), json!("foo"));
        args.insert("data".into(), json!({ "k": "v" }));
        let result = dispatcher::call("bv_kv_write", args, None, &ctx(&b, &backend, &p, &guard)).await.unwrap();
        assert!(!result.is_error);
    }

    #[tokio::test]
    async fn destructive_with_confirmation_requires_state_then_succeeds_and_is_single_use() {
        let mut b = binding(&["bv_kv_delete"], &["secret/data/*"]);
        b.destructive_allowed = true;
        let backend = FakeBackend::default().with("secret/data/foo", json!({ "ok": true }));
        let p = principal();
        let guard = SingleUseGuard::new();
        let mut args = Map::new();
        args.insert("mount".into(), json!("secret"));
        args.insert("path".into(), json!("foo"));

        let mut dc = ctx(&b, &backend, &p, &guard);
        dc.confirm_destructive = true;

        let first = dispatcher::call("bv_kv_delete", args.clone(), None, &dc).await.unwrap();
        assert_eq!(first.result_type, ResultType::InputRequired);
        let state = first.request_state.expect("input_required must carry a requestState");

        let second = dispatcher::call("bv_kv_delete", args.clone(), Some(&state), &dc).await.unwrap();
        assert!(!second.is_error);

        let replay = dispatcher::call("bv_kv_delete", args, Some(&state), &dc).await;
        assert!(replay.is_err(), "a second use of the same requestState must be refused");
    }

    #[tokio::test]
    async fn pki_issue_requires_both_destructive_and_reveal_allowed() {
        let backend = FakeBackend::default().with(
            "pki/issue/web-server",
            json!({ "certificate": "-----BEGIN CERTIFICATE-----", "private_key": "-----BEGIN PRIVATE KEY-----" }),
        );
        let p = principal();
        let mut args = Map::new();
        args.insert("role".into(), json!("web-server"));
        args.insert("common_name".into(), json!("example.com"));
        args.insert("reveal".into(), json!(true));

        // destructive_allowed alone is not enough — reveal is also gated.
        let mut b = binding(&["bv_pki_issue"], &["pki/issue/*"]);
        b.destructive_allowed = true;
        let guard = SingleUseGuard::new();
        let err =
            dispatcher::call("bv_pki_issue", args.clone(), None, &ctx(&b, &backend, &p, &guard)).await.unwrap_err();
        assert_eq!(err.code(), "mcp_reveal_denied");

        // Both granted: succeeds and the private key is not redacted.
        b.reveal_allowed = true;
        let guard = SingleUseGuard::new();
        let result = dispatcher::call("bv_pki_issue", args, None, &ctx(&b, &backend, &p, &guard)).await.unwrap();
        assert_eq!(result.structured_content.unwrap()["private_key"], json!("-----BEGIN PRIVATE KEY-----"));
    }

    #[tokio::test]
    async fn pki_issue_without_reveal_requested_redacts_private_key() {
        let backend = FakeBackend::default().with(
            "pki/issue/web-server",
            json!({ "certificate": "-----BEGIN CERTIFICATE-----", "private_key": "-----BEGIN PRIVATE KEY-----" }),
        );
        let p = principal();
        let mut b = binding(&["bv_pki_issue"], &["pki/issue/*"]);
        b.destructive_allowed = true;
        b.reveal_allowed = true;
        let guard = SingleUseGuard::new();
        let mut args = Map::new();
        args.insert("role".into(), json!("web-server"));
        args.insert("common_name".into(), json!("example.com"));
        let result = dispatcher::call("bv_pki_issue", args, None, &ctx(&b, &backend, &p, &guard)).await.unwrap();
        assert_eq!(result.structured_content.unwrap()["private_key"], json!("<redacted>"));
    }
}
