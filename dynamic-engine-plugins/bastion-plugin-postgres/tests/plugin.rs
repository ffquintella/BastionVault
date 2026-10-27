//! The built `bastion-plugin-postgres` binary through the testkit's process
//! harness (the host's wire protocol and capability gate), and its
//! `plugin.toml` through the host's manifest rules. No database needed.

use std::path::Path;

use bastion_plugin_testkit::TestHost;
use bv_plugin_manifest::PluginManifest;
use serde_json::{json, Value};

const EXE: &str = env!("CARGO_BIN_EXE_bastion-plugin-postgres");
const PASSWORD: &str = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6";
const ROOT: &str = "root-password-very-secret";
const USER: &str = "v-root-readonly-1793000000-0a1b2c3d";

fn exe() -> &'static Path {
    Path::new(EXE)
}

#[test]
fn the_manifest_passes_the_hosts_rules_with_minimal_capabilities() {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/plugin.toml")).unwrap();
    let m: PluginManifest = toml::from_str(&text).unwrap();
    m.validate().unwrap();
    assert!(m.is_dynamic());
    assert_eq!(m.engine_type.as_deref(), Some("database"));
    assert_eq!(m.version, env!("CARGO_PKG_VERSION"));
    let caps = &m.capabilities;
    assert!(caps.dynamic_lease_register && caps.dynamic_audit_emit && caps.dynamic_pool_checkout);
    assert!(!caps.log_emit && !caps.audit_emit && caps.allowed_hosts.is_empty() && !caps.long_lived);
    assert_eq!(caps.storage_prefix.as_deref(), Some(""));
}

/// `port=1` on loopback: refused at once, so generate fails on the target.
fn host() -> TestHost {
    let h = TestHost::builder("postgres")
        .storage_prefix("")
        .dynamic_lease_register(true)
        .dynamic_audit_emit(true)
        .dynamic_pool_checkout(true)
        .dynamic_connection("prod")
        .dynamic_connection("plain")
        .build();
    for (name, url) in
        [("prod", "host=127.0.0.1 port=1 dbname=app"), ("plain", "host=127.0.0.1 port=1 sslmode=disable")]
    {
        let conn = json!({ "connection_url": url, "username": "vault", "password": ROOT, "allowed_roles": "*" });
        let out = h.invoke_process(exe(), "write", &format!("config/{name}"), conn).unwrap();
        assert!(out.is_success(), "{:?}", out.response_json());
    }
    let role = json!({ "connection": "prod",
        "creation_statements": "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}'" });
    assert!(h.invoke_process(exe(), "write", "roles/readonly", role).unwrap().is_success());
    h
}

fn generate(connection: &str) -> Value {
    json!({
        "op": "dynamic.generate", "role": "readonly", "connection": connection,
        "statements": [format!("CREATE ROLE \"{USER}\" WITH LOGIN PASSWORD '{PASSWORD}'")],
        "credential": { "username": USER, "password": PASSWORD, "expiration": "2026-10-26T18:32:11Z" },
        "ttl_secs": 600,
    })
}

fn assert_clean(h: &TestHost, response: &[u8]) {
    let text = String::from_utf8_lossy(response).to_string();
    assert!(!text.contains(PASSWORD) && !text.contains(ROOT), "response: {text}");
    for line in h.process_stderr() {
        assert!(!line.contains(PASSWORD) && !line.contains(ROOT), "stderr: {line}");
    }
}

#[test]
fn config_and_roles_round_trip_without_the_root_credential() {
    let h = host();
    let read = h.invoke_process(exe(), "read", "config/prod", json!({})).unwrap();
    assert_eq!(read.data().unwrap()["connection_url"], "host=127.0.0.1 port=1 dbname=app");
    assert_clean(&h, &read.response);
    let refused = h
        .invoke_process(
            exe(),
            "write",
            "config/leaky",
            json!({ "connection_url": "postgres://vault:pw@db/app", "username": "vault", "password": ROOT }),
        )
        .unwrap();
    assert_eq!(refused.status(), 3);
    let role = h.invoke_process_dynamic(exe(), &json!({ "op": "dynamic.role", "role": "readonly" })).unwrap();
    assert_eq!(
        role.data().unwrap()["creation_statements"][0],
        "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}'"
    );
}

#[test]
fn an_unreachable_target_fails_the_generate_with_no_lease_and_no_leak() {
    let h = host();
    let out = h.invoke_process_dynamic(exe(), &generate("prod")).unwrap();
    assert_eq!(out.status(), 1, "{:?}", out.response_json());
    assert!(out.dynamic_leases.is_empty());
    let error = out.response_json().unwrap()["error"].as_str().unwrap().to_string();
    assert!(error.contains("postgres"), "{error}");
    assert_clean(&h, &out.response);
}

#[test]
fn sslmode_disable_is_refused_when_the_host_verifies_tls() {
    let h = host();
    let out = h.invoke_process_dynamic(exe(), &generate("plain")).unwrap();
    assert_eq!(out.status(), 3, "{:?}", out.response_json());
    assert!(out.response_json().unwrap()["error"].as_str().unwrap().contains("sslmode=disable"));
    assert!(out.dynamic_leases.is_empty());
}

#[test]
fn a_revoke_that_cannot_reach_the_target_fails_so_the_host_keeps_the_lease() {
    let h = host();
    let revoke = json!({ "op": "dynamic.revoke", "role": "readonly", "connection": "prod", "username": USER,
                         "statements": [], "internal": { "v": 1 } });
    let out = h.invoke_process_dynamic(exe(), &revoke).unwrap();
    assert_eq!(out.status(), 1);
    assert_clean(&h, &out.response);
}

/// Against a host with a `postgres` connector (`host_execute`), the binary
/// has the host run the statements over the wire protocol: the unreachable
/// `port=1` target is never dialled by the plugin, the lease is registered,
/// and neither the root secret nor the password leaves in clear.
#[test]
fn on_an_executing_host_the_binary_never_dials_and_the_host_runs_the_statements() {
    let h = TestHost::builder("postgres")
        .storage_prefix("")
        .dynamic_lease_register(true)
        .dynamic_audit_emit(true)
        .dynamic_pool_checkout(true)
        .dynamic_connection("prod")
        .dynamic_host_execute("postgres")
        .build();
    let conn = json!({ "connection_url": "host=127.0.0.1 port=1 dbname=app", "username": "vault",
                       "password": ROOT, "allowed_roles": "*" });
    assert!(h.invoke_process(exe(), "write", "config/prod", conn).unwrap().is_success());

    let out = h.invoke_process_dynamic(exe(), &generate("prod")).unwrap();
    assert!(out.is_success(), "{:?}", out.response_json());
    assert_eq!(out.dynamic_leases.len(), 1);
    assert_eq!(out.dynamic_executions.len(), 1, "{:?}", out.dynamic_executions);
    let e = &out.dynamic_executions[0];
    assert_eq!((e["op"].as_str(), e["kind"].as_str()), (Some("dynamic.generate"), Some("postgres")));
    assert_eq!((e["url"].as_str(), e["username"].as_str()), (Some("host=127.0.0.1 port=1 dbname=app"), Some("vault")));
    assert_clean(&h, &out.response);

    let revoke = json!({ "op": "dynamic.revoke", "role": "readonly", "connection": "prod", "username": USER,
                         "statements": [], "internal": { "v": 1 } });
    let out = h.invoke_process_dynamic(exe(), &revoke).unwrap();
    assert!(out.is_success(), "{:?}", out.response_json());
    assert_eq!(out.dynamic_executions.len(), 1);
    assert_clean(&h, &out.response);
}
