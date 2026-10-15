//! BastionVault's MCP (Model Context Protocol) dispatcher. See
//! features/mcp-access.md for the design this crate implements (Phase 1 —
//! `bv-mcp` core: JSON-RPC types, the read-only tool catalogue, the
//! `tools/call` gates and result shaping), plus the local server's
//! gatekeeper ([`local`]) and pairing store ([`pairing`]) that `bvault mcp`
//! and the desktop app share. Deliberately depends on neither the vault
//! stack nor the official Rust MCP SDK — see that spec's § Dependencies.

pub mod catalogue;
pub mod dispatcher;
pub mod error;
pub mod jsonrpc;
pub mod local;
pub mod pairing;
pub mod request_state;
pub mod sanitize;
pub mod untrusted;

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
        calls: std::sync::Mutex<Vec<(Operation, String, Option<Map<String, Value>>)>>,
    }

    impl FakeBackend {
        fn with(mut self, path: &str, data: Value) -> Self {
            self.responses.insert(path.to_string(), data.as_object().unwrap().clone());
            self
        }

        /// The one call this backend received, as (operation, path, body).
        fn only_call(&self) -> (Operation, String, Option<Map<String, Value>>) {
            let calls = self.calls.lock().unwrap();
            assert_eq!(calls.len(), 1, "expected exactly one backend call, got {calls:?}");
            calls[0].clone()
        }
    }

    #[async_trait]
    impl Backend for FakeBackend {
        async fn handle(
            &self,
            operation: Operation,
            path: &str,
            body: Option<Map<String, Value>>,
            _token: &str,
        ) -> Result<Option<JsonResponse>, ClientError> {
            self.calls.lock().unwrap().push((operation, path.to_string(), body));
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
            connect_allowed: false,
            confirm_connect: false,
            operator: None,
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
        let b = binding(&["bv_resource_describe"], &["resources/*"]);
        let backend = FakeBackend::default();
        let p = principal();
        let guard = SingleUseGuard::new();
        let mut args = Map::new();
        args.insert("name".into(), json!("sys/seal-status"));
        let err =
            dispatcher::call("bv_resource_describe", args, None, &ctx(&b, &backend, &p, &guard)).await.unwrap_err();
        assert_eq!(err.code(), "mcp_path_out_of_scope");
    }

    #[tokio::test]
    async fn ansi_in_response_value_is_stripped() {
        let b = binding(&["bv_resource_describe"], &["resources/*"]);
        let backend =
            FakeBackend::default().with("resources/resources/foo", json!({ "note": "\u{1b}[31mred\u{1b}[0m" }));
        let p = principal();
        let guard = SingleUseGuard::new();
        let mut args = Map::new();
        args.insert("name".into(), json!("foo"));
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

    fn kv_list_args(path: Option<&str>) -> Map<String, Value> {
        let mut args = Map::new();
        args.insert("mount".into(), json!("secret"));
        if let Some(path) = path {
            args.insert("path".into(), json!(path));
        }
        args
    }

    /// Regression: KV v2 lists only `metadata/<prefix>/`. Without the
    /// trailing slash the request hit the single-key route, which has no
    /// list operation, and every `bv_kv_list` failed with "operation not
    /// supported".
    #[tokio::test]
    async fn kv_list_lists_the_directory_with_a_trailing_slash() {
        let b = binding(&["bv_kv_list"], &["secret/*"]);
        let p = principal();
        let guard = SingleUseGuard::new();
        for path in ["ai", "ai/", "/ai/"] {
            let backend = FakeBackend::default().with("secret/metadata/ai/", json!({ "keys": ["x"] }));
            let result = dispatcher::call("bv_kv_list", kv_list_args(Some(path)), None, &ctx(&b, &backend, &p, &guard))
                .await
                .unwrap();
            assert_eq!(result.structured_content.unwrap()["keys"], json!(["x"]), "path {path:?}");
            let (op, routed, _) = backend.only_call();
            assert_eq!((op, routed.as_str()), (Operation::List, "secret/metadata/ai/"), "path {path:?}");
        }
    }

    /// Regression: an empty `path` was refused, so a mount's top level
    /// could not be listed at all. Absent, empty and `/` all list it now.
    #[tokio::test]
    async fn kv_list_without_a_path_lists_the_mount_top_level() {
        let b = binding(&["bv_kv_list"], &["secret/*"]);
        let p = principal();
        let guard = SingleUseGuard::new();
        for path in [None, Some(""), Some("/")] {
            let backend = FakeBackend::default().with("secret/metadata/", json!({ "keys": ["ai/"] }));
            let result =
                dispatcher::call("bv_kv_list", kv_list_args(path), None, &ctx(&b, &backend, &p, &guard)).await.unwrap();
            assert_eq!(result.structured_content.unwrap()["keys"], json!(["ai/"]), "path {path:?}");
            assert_eq!(backend.only_call().1, "secret/metadata/", "path {path:?}");
        }
    }

    #[tokio::test]
    async fn kv_list_keeps_the_path_gates() {
        let p = principal();
        let guard = SingleUseGuard::new();
        let backend = FakeBackend::default();
        let b = binding(&["bv_kv_list"], &["secret/metadata/ai/*"]);
        let err =
            dispatcher::call("bv_kv_list", kv_list_args(None), None, &ctx(&b, &backend, &p, &guard)).await.unwrap_err();
        assert_eq!(err.code(), "mcp_path_out_of_scope", "the top level is outside a sub-directory grant");
        let err =
            dispatcher::call("bv_kv_list", kv_list_args(Some("ai/../../x")), None, &ctx(&b, &backend, &p, &guard))
                .await
                .unwrap_err();
        assert_eq!(err.code(), "mcp_invalid_argument");
        let mut args = kv_list_args(None);
        args.insert("path".into(), json!(7));
        let err = dispatcher::call("bv_kv_list", args, None, &ctx(&b, &backend, &p, &guard)).await.unwrap_err();
        assert_eq!(err.code(), "mcp_invalid_argument");
        assert!(backend.calls.lock().unwrap().is_empty(), "no refused call reaches the vault");
    }

    /// Regression: `bv_capabilities` sent a read with a `path` string, but
    /// `sys/capabilities-self` is a write taking a `paths` array, so every
    /// call was refused whatever the policy said.
    #[tokio::test]
    async fn capabilities_writes_a_paths_array_to_capabilities_self() {
        let b = binding(&["bv_capabilities"], &["secret/*"]);
        let backend = FakeBackend::default()
            .with("sys/capabilities-self", json!({ "capabilities": { "secret/data/ai/x": ["read"] } }));
        let p = principal();
        let guard = SingleUseGuard::new();
        let mut args = Map::new();
        args.insert("path".into(), json!("secret/data/ai/x"));
        let result = dispatcher::call("bv_capabilities", args, None, &ctx(&b, &backend, &p, &guard)).await.unwrap();
        assert_eq!(result.structured_content.unwrap()["capabilities"]["secret/data/ai/x"], json!(["read"]));
        let (op, routed, body) = backend.only_call();
        assert_eq!((op, routed.as_str()), (Operation::Write, "sys/capabilities-self"));
        assert_eq!(Value::Object(body.unwrap()), json!({ "paths": ["secret/data/ai/x"] }));
    }

    /// The scope covers the path asked about, not the `sys/` endpoint:
    /// a probe outside the grant is refused, and a grant naming
    /// `sys/capabilities-self` does not open every path.
    #[tokio::test]
    async fn capabilities_is_scoped_by_the_path_asked_about() {
        let p = principal();
        let guard = SingleUseGuard::new();
        let backend = FakeBackend::default();
        let mut args = Map::new();
        args.insert("path".into(), json!("kv/data/other"));
        for scope in [&["secret/*"][..], &["sys/capabilities-self"][..]] {
            let b = binding(&["bv_capabilities"], scope);
            let err = dispatcher::call("bv_capabilities", args.clone(), None, &ctx(&b, &backend, &p, &guard))
                .await
                .unwrap_err();
            assert_eq!(err.code(), "mcp_path_out_of_scope", "scope {scope:?}");
        }
        args.insert("path".into(), json!("sys/policy/root"));
        let b = binding(&["bv_capabilities"], &["*"]);
        let err = dispatcher::call("bv_capabilities", args, None, &ctx(&b, &backend, &p, &guard)).await.unwrap_err();
        assert_eq!(err.code(), "mcp_path_out_of_scope", "sys/ stays unreachable from a tool argument");
        assert!(backend.calls.lock().unwrap().is_empty());
    }

    /// Regression: the resource tools routed to `resource/<path>`, a mount
    /// that does not exist, so neither ever answered. The engine is mounted
    /// at `resources/` and keeps its records under `resources/resources/`.
    #[tokio::test]
    async fn resource_tools_route_to_the_resource_engine() {
        let b = binding(&["bv_resource_list", "bv_resource_describe"], &["resources/*"]);
        let p = principal();
        let guard = SingleUseGuard::new();

        let backend = FakeBackend::default().with("resources/resources/", json!({ "keys": ["db1"] }));
        let result =
            dispatcher::call("bv_resource_list", Map::new(), None, &ctx(&b, &backend, &p, &guard)).await.unwrap();
        assert_eq!(result.structured_content.unwrap()["keys"], json!(["db1"]));
        assert_eq!(backend.only_call().0, Operation::List);

        let backend = FakeBackend::default().with("resources/resources/db1", json!({ "hostname": "db1.example" }));
        let mut args = Map::new();
        args.insert("name".into(), json!("db1"));
        let result =
            dispatcher::call("bv_resource_describe", args, None, &ctx(&b, &backend, &p, &guard)).await.unwrap();
        assert_eq!(result.structured_content.unwrap()["hostname"], json!("db1.example"));
        assert_eq!(backend.only_call().0, Operation::Read);
    }

    /// A test-only open-world entry. The catalogue carries no session tool
    /// until `bv_resource_ssh_exec` ships, but the gate must already hold.
    fn test_session_tool() -> catalogue::ToolMeta {
        catalogue::ToolMeta {
            name: "bv_test_session_tool",
            description: "test-only",
            read_only: false,
            destructive: true,
            idempotent: false,
            is_reveal: false,
            open_world: true,
            input_schema: || json!({ "type": "object" }),
            output_schema: || json!({ "type": "object" }),
        }
    }

    fn session_binding(kind: McpBindingKind, connect_allowed: bool, confirm_connect: bool) -> McpBinding {
        let mut b = binding(&["bv_test_session_tool"], &["resources/secrets/*"]);
        b.kind = kind;
        b.connect_allowed = connect_allowed;
        b.confirm_connect = confirm_connect;
        b
    }

    async fn dispatch_session_tool(b: &McpBinding) -> (McpError, usize) {
        let backend = FakeBackend::default();
        let p = principal();
        let guard = SingleUseGuard::new();
        let mut args = Map::new();
        args.insert("resource".into(), json!("web-01"));
        args.insert("profile".into(), json!("agent"));
        args.insert("command".into(), json!("uptime"));
        let err =
            dispatcher::dispatch(&test_session_tool(), args, None, &ctx(b, &backend, &p, &guard)).await.unwrap_err();
        let calls = backend.calls.lock().unwrap().len();
        (err, calls)
    }

    #[tokio::test]
    async fn open_world_tool_needs_connect_allowed() {
        let b = session_binding(McpBindingKind::Pairing("p".into()), false, false);
        let (err, calls) = dispatch_session_tool(&b).await;
        assert_eq!((err.code(), calls), ("mcp_connect_not_allowed", 0));
    }

    /// `connect_allowed` without `confirm_connect` is a binding no exchange
    /// mints: refused, not trusted.
    #[tokio::test]
    async fn open_world_tool_needs_confirm_connect_too() {
        let b = session_binding(McpBindingKind::Pairing("p".into()), true, false);
        let (err, calls) = dispatch_session_tool(&b).await;
        assert_eq!((err.code(), calls), ("mcp_connect_not_allowed", 0));
    }

    /// Network-mode apps never open sessions, whatever the binding claims.
    #[tokio::test]
    async fn open_world_tool_refuses_an_app_binding_permanently() {
        let b = session_binding(McpBindingKind::App("ci".into()), true, true);
        let (err, calls) = dispatch_session_tool(&b).await;
        assert_eq!((err.code(), calls), ("mcp_connect_requires_local_operator", 0));
    }

    /// The allow-list is checked first: a binding that does not list the tool
    /// is told so, not told about connect grants.
    #[tokio::test]
    async fn open_world_gate_runs_after_the_allow_list() {
        let mut b = session_binding(McpBindingKind::App("ci".into()), false, false);
        b.tool_allowlist.clear();
        let (err, calls) = dispatch_session_tool(&b).await;
        assert_eq!((err.code(), calls), ("mcp_tool_not_allowed", 0));
    }

    /// A pairing with both grants passes the gate; with no route for the
    /// test-only tool, request building is what refuses it.
    #[tokio::test]
    async fn open_world_tool_passes_the_gate_for_a_confirmed_pairing() {
        let mut b = session_binding(McpBindingKind::Pairing("p".into()), true, true);
        b.reveal_allowed = true; // may coexist with connect (owner decision)
        let (err, calls) = dispatch_session_tool(&b).await;
        assert_eq!((err.code(), calls), ("mcp_unknown_tool", 0));
    }

    /// The connect flags gate only open-world tools: an ordinary tool on a
    /// binding without them is unaffected.
    #[tokio::test]
    async fn closed_world_tools_ignore_the_connect_flags() {
        let b = binding(&["bv_resource_describe"], &["resources/*"]);
        assert!(!b.connect_allowed && !b.confirm_connect);
        let backend = FakeBackend::default().with("resources/resources/db1", json!({ "hostname": "db1" }));
        let p = principal();
        let guard = SingleUseGuard::new();
        let mut args = Map::new();
        args.insert("name".into(), json!("db1"));
        assert!(dispatcher::call("bv_resource_describe", args, None, &ctx(&b, &backend, &p, &guard)).await.is_ok());
    }

    #[test]
    fn args_hash_is_stable_and_key_order_independent() {
        let mut a = Map::new();
        a.insert("command".into(), json!("uptime"));
        a.insert("resource".into(), json!("web-01"));
        let mut b = Map::new();
        b.insert("resource".into(), json!("web-01"));
        b.insert("command".into(), json!("uptime"));
        assert_eq!(dispatcher::args_hash(&a), dispatcher::args_hash(&b));
        assert_eq!(dispatcher::args_hash(&a).len(), 64);
        b.insert("command".into(), json!("uptime "));
        assert_ne!(dispatcher::args_hash(&a), dispatcher::args_hash(&b), "one byte of the command changes it");
    }

    #[tokio::test]
    async fn resource_describe_takes_a_single_segment_name() {
        let b = binding(&["bv_resource_describe"], &["resources/*"]);
        let backend = FakeBackend::default();
        let p = principal();
        let guard = SingleUseGuard::new();
        for name in ["db1/history", "a/b"] {
            let mut args = Map::new();
            args.insert("name".into(), json!(name));
            let err =
                dispatcher::call("bv_resource_describe", args, None, &ctx(&b, &backend, &p, &guard)).await.unwrap_err();
            assert_eq!(err.code(), "mcp_invalid_argument", "name {name:?}");
        }
        assert!(backend.calls.lock().unwrap().is_empty());
    }
}
