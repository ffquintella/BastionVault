//! The `sql_*` rolling-upgrade write gate on a standalone vault (T124,
//! features/sql-browser.md §13): open from the first unseal, reported at
//! `sys/policy-schema`, and `sql_*` policy and share writes go through the
//! real handlers. The closed-gate paths need a cluster topology and are
//! covered in `bv-kernel` (`sql_write_gate_tests.rs`).

use std::sync::Arc;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::json;

use super::kernel_policy_deny::{user, write, write_policy};
use crate::{
    core::Core,
    modules::{
        identity::EntityStore,
        policy::{
            policy_store::{DEFAULT_POLICY, SHARED_ACCESS_POLICY},
            sql_write_gate::{NODE_HOST_ABI_MINOR, NODE_POLICY_SCHEMA, SQL_MIN_HOST_ABI_MINOR, SQL_POLICY_SCHEMA},
        },
    },
    test_utils::{new_unseal_test_bastion_vault, test_read_api, test_write_api},
};

/// The kernel keeps its own copy of the host ABI minor (it sits below
/// `bv_plugin_manifest`); a node must never report an ABI it does not serve.
#[test]
fn node_host_abi_minor_matches_the_manifest_host() {
    assert_eq!(NODE_HOST_ABI_MINOR, bv_plugin_manifest::HOST_ABI_MINOR);
    assert!(NODE_HOST_ABI_MINOR >= SQL_MIN_HOST_ABI_MINOR);
    assert!(NODE_POLICY_SCHEMA >= SQL_POLICY_SCHEMA);
}

async fn stored_rules(core: &Arc<Core>, root: &str, name: &str) -> serde_json::Value {
    let path = format!("sys/policy/{name}");
    test_read_api(core.as_ref(), root, &path, true).await.unwrap().unwrap().data.unwrap()["rules"].clone()
}

async fn entity_of(core: &Arc<Core>, name: &str) -> String {
    let entities = EntityStore::new(core).await.unwrap();
    entities.get_by_alias_ns("userpass/", name, "").await.unwrap().expect("entity after login").id
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_sql_write_gate_is_open_on_a_standalone_vault() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("test_sql_write_gate_standalone").await;

    let data = test_read_api(core.as_ref(), &root, "sys/policy-schema", true).await.unwrap().unwrap().data.unwrap();
    assert_eq!(data["sql_capabilities_writable"], json!(true));
    assert_eq!(data["latched"], json!(true));
    assert_eq!(data["opened_by"], json!("standalone"));
    assert_eq!(data["membership"], json!("standalone"));
    assert_eq!(data["this_node"]["host_abi_minor"], json!(NODE_HOST_ABI_MINOR));
    assert_eq!(data["baselines"], json!({ "default": "with-sql", "shared-access": "with-sql" }));
    let nodes = data["nodes"].as_array().unwrap();
    assert_eq!(nodes.len(), 1, "{nodes:?}");
    assert_eq!((nodes[0]["node"].clone(), nodes[0]["qualifies"].clone()), (json!("standalone"), json!(true)));

    // The stored baselines are the full bundled texts.
    assert_eq!(stored_rules(&core, &root, "default").await, json!(DEFAULT_POLICY));
    assert_eq!(stored_rules(&core, &root, "shared-access").await, json!(SHARED_ACCESS_POLICY));

    // A `sql_*` policy and a `sql_*` share are written through the handlers.
    write_policy(
        &core,
        &root,
        "analysts",
        "path \"resources/resources/netrisk-db/sql/*\" {\n  capabilities = [\"sql_select\"]\n}\n",
    )
    .await;
    write(&core, &root, "sys/auth/pass", json!({ "type": "userpass" })).await;
    let ana_token = user(&core, &root, "ana", "default").await;
    let ana = entity_of(&core, "ana").await;
    let target = URL_SAFE_NO_PAD.encode("netrisk-db");
    let resp = test_write_api(
        core.as_ref(),
        &root,
        &format!("identity/sharing/by-target/resource/{target}/{ana}"),
        true,
        json!({ "target_kind": "resource", "target_path": "netrisk-db", "capabilities": "read,sql_select" })
            .as_object()
            .cloned(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(resp.data.unwrap()["capabilities"], json!(["read", "sql_select"]));

    // The status is an operator surface: `default` does not reach it.
    assert!(test_read_api(core.as_ref(), &ana_token, "sys/policy-schema", false).await.is_err());
}
