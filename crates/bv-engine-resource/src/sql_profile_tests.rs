//! Strict parsing of `sql` profiles, endpoints, bindings and settings
//! (features/sql-browser.md Testing Plan, "Kernel and host").

use super::*;

fn profile(sql: Value) -> Value {
    json!({
        "id": "netrisk-ro",
        "name": "Read-only",
        "protocol": "sql",
        "target": { "host": "DB1.example.net", "port": 3306 },
        "sql": sql,
        "credential_source": { "kind": "secret", "secret_id": "svc_netrisk_ro" },
    })
}

fn minimal_sql() -> Value {
    json!({ "ceiling": ["sql_select"] })
}

fn code(r: Result<SqlProfile, SqlRefusal>) -> &'static str {
    r.unwrap_err().code
}

#[test]
fn engines_and_default_ports() {
    let ports: Vec<(&str, u16)> = SqlEngine::ALL.iter().map(|e| (e.as_str(), e.default_port())).collect();
    assert_eq!(
        ports,
        vec![("postgresql", 5432), ("mysql", 3306), ("mariadb", 3306), ("mssql", 1433), ("oracle", 1521)]
    );
    for other in ["", "mongodb", "redis", "sqlite", "PostgreSQL", "other"] {
        assert_eq!(SqlEngine::parse(other), None, "{other}");
    }
}

#[test]
fn the_spec_example_parses() {
    let p = json!({
        "id": "netrisk-ro",
        "protocol": "sql",
        "label": "Read-only (svc_netrisk_ro)",
        "target": { "host": "apldc1vds0044", "port": 3306 },
        "sql": {
            "catalog": "netrisk",
            "instance": null,
            "tls": { "mode": "verify-full", "server_name": null, "ca_pem": null },
            "ceiling": ["sql_select"],
            "require_mfa": false,
            "step_up": ["sql_drop", "sql_admin", "sql_export", "sql_script"]
        },
        "credential_source": { "kind": "secret", "secret_id": "svc_netrisk_ro" }
    });
    let parsed = parse_sql_profile(&p, SqlEngine::Mysql).unwrap();
    assert_eq!(parsed.id, "netrisk-ro");
    assert_eq!(parsed.label.as_deref(), Some("Read-only (svc_netrisk_ro)"));
    assert_eq!(parsed.target_host.as_deref(), Some("apldc1vds0044"));
    assert_eq!(parsed.target_port, Some(3306));
    assert_eq!(parsed.catalog.as_deref(), Some("netrisk"));
    assert_eq!(parsed.tls.mode, SqlTlsMode::VerifyFull);
    assert_eq!(parsed.ceiling, vec![SqlCapability::Select]);
    assert!(!parsed.require_mfa);
    assert_eq!(parsed.step_up.len(), 4);
    assert_eq!(parsed.credential_source, SqlCredentialSource::Secret { secret_id: "svc_netrisk_ro".into() });
}

#[test]
fn defaults_are_the_secure_ones() {
    let parsed = parse_sql_profile(&profile(minimal_sql()), SqlEngine::Postgresql).unwrap();
    assert_eq!(parsed.tls, SqlTls { mode: SqlTlsMode::VerifyFull, server_name: None, ca_pem: None });
    assert!(!parsed.require_mfa);
    assert!(parsed.step_up.is_empty());
    assert_eq!(parsed.target_host.as_deref(), Some("db1.example.net"), "hosts are lower-cased");
    assert_eq!(parsed.label.as_deref(), Some("Read-only"), "`name` stands in for `label`");
}

/// The T101 precedent: anything unknown or wrongly typed in the `sql`
/// block fails the profile closed, never defaults.
#[test]
fn a_wrongly_typed_sql_block_fails_closed() {
    let bad_sql = [
        json!({ "ceiling": "sql_select" }),
        json!({ "ceiling": [] }),
        json!({ "ceiling": ["select"] }),
        json!({ "ceiling": ["sql_select", "sql_select"] }),
        json!({ "ceiling": ["SQL_SELECT"] }),
        json!({}),
        json!({ "ceiling": ["sql_select"], "require_mfa": "yes" }),
        json!({ "ceiling": ["sql_select"], "require_mfa": 1 }),
        json!({ "ceiling": ["sql_select"], "step_up": "sql_drop" }),
        json!({ "ceiling": ["sql_select"], "step_up": ["sql_nope"] }),
        json!({ "ceiling": ["sql_select"], "tls": "verify-full" }),
        json!({ "ceiling": ["sql_select"], "tls": { "mode": "prefer" } }),
        json!({ "ceiling": ["sql_select"], "tls": { "mode": "VERIFY-FULL" } }),
        json!({ "ceiling": ["sql_select"], "tls": { "mode": "verify-full", "insecure": true } }),
        json!({ "ceiling": ["sql_select"], "tls": { "server_name": "a b" } }),
        json!({ "ceiling": ["sql_select"], "tls": { "ca_pem": "not a pem" } }),
        json!({ "ceiling": ["sql_select"], "tls": { "mode": "disable", "ca_pem": "-----BEGIN CERTIFICATE-----\nx" } }),
        json!({ "ceiling": ["sql_select"], "catalog": 5 }),
        json!({ "ceiling": ["sql_select"], "catalog": "a\u{0}b" }),
        json!({ "ceiling": ["sql_select"], "enforcement": "classifier-only" }),
        json!({ "ceiling": ["sql_select"], "instance": "SQLEXPRESS" }),
    ];
    for sql in bad_sql {
        assert_eq!(code(parse_sql_profile(&profile(sql.clone()), SqlEngine::Postgresql)), "invalid_profile", "{sql}");
    }
}

/// Keys that belong to other protocols (or to the spec's `sql` block) are
/// refused at the top level rather than silently ignored.
#[test]
fn unknown_or_misplaced_profile_keys_fail_closed() {
    let mut p = profile(minimal_sql());
    for (key, value) in [
        ("require_mfa", json!(true)),
        ("target_host", json!("db2")),
        ("agent_access", json!("allow")),
        ("kind", json!("rustion")),
        ("username", json!("sa")),
        ("is_default", json!("yes")),
    ] {
        p[key] = value.clone();
        assert_eq!(code(parse_sql_profile(&p, SqlEngine::Postgresql)), "invalid_profile", "{key}={value}");
        p.as_object_mut().unwrap().remove(key);
    }
    let targets = [
        json!("db1:5432"),
        json!({ "host": "db1/x" }),
        json!({ "port": 0 }),
        json!({ "port": "5432" }),
        json!({ "port": 70000 }),
        json!({ "host": "db1", "user": "x" }),
    ];
    for target in targets {
        p["target"] = target.clone();
        assert_eq!(code(parse_sql_profile(&p, SqlEngine::Postgresql)), "invalid_profile", "{target}");
    }
}

/// `secret` and `dynamic` are the only sources; `dynamic` parses (it is
/// reserved, refused at release) and everything else refuses.
#[test]
fn credential_sources_are_secret_or_reserved_dynamic() {
    let mut p = profile(minimal_sql());
    for source in [
        json!(null),
        json!({ "kind": "provider", "provider": "self-accounts" }),
        json!({ "kind": "ssh-engine" }),
        json!({ "kind": "secret" }),
        json!({ "kind": "secret", "secret_id": "" }),
        json!({ "kind": "secret", "secret_id": "a/b" }),
        json!({ "kind": "secret", "secret_id": "x", "password": "inline" }),
        json!({ "kind": "dynamic", "role": "ro" }),
    ] {
        p["credential_source"] = source.clone();
        assert_eq!(code(parse_sql_profile(&p, SqlEngine::Postgresql)), "invalid_profile", "{source}");
    }
    p["credential_source"] = json!({ "kind": "dynamic", "mount": "db-pg/", "role": "netrisk-ro" });
    assert_eq!(
        parse_sql_profile(&p, SqlEngine::Postgresql).unwrap().credential_source,
        SqlCredentialSource::Dynamic { mount: "db-pg/".into(), role: "netrisk-ro".into() }
    );
}

#[test]
fn a_named_instance_is_sql_server_only() {
    let sql = json!({ "ceiling": ["sql_select"], "instance": "SQLEXPRESS" });
    let parsed = parse_sql_profile(&profile(sql.clone()), SqlEngine::Mssql).unwrap();
    assert_eq!(parsed.instance.as_deref(), Some("SQLEXPRESS"));
    for e in [SqlEngine::Postgresql, SqlEngine::Mysql, SqlEngine::Mariadb, SqlEngine::Oracle] {
        assert_eq!(code(parse_sql_profile(&profile(sql.clone()), e)), "invalid_profile", "{e:?}");
    }
}

#[test]
fn a_non_sql_profile_is_refused_as_such() {
    for p in [json!({ "id": "p", "protocol": "ssh" }), json!({ "id": "p" }), json!({ "id": "p", "protocol": "SQL" })] {
        assert_eq!(code(parse_sql_profile(&p, SqlEngine::Postgresql)), "profile_not_sql", "{p}");
    }
    assert_eq!(code(parse_sql_profile(&json!("sql"), SqlEngine::Postgresql)), "invalid_profile");
}

#[test]
fn the_mfa_flag_is_read_fail_closed() {
    let p = |sql: Value| json!({ "protocol": "sql", "sql": sql });
    assert!(!sql_gate_flag(&p(json!({ "ceiling": ["sql_select"] }))));
    assert!(!sql_gate_flag(&p(json!({ "require_mfa": false }))));
    assert!(!sql_gate_flag(&p(json!({ "require_mfa": null }))));
    assert!(sql_gate_flag(&p(json!({ "require_mfa": true }))));
    assert!(sql_gate_flag(&p(json!({ "require_mfa": "false" }))), "a malformed flag gates");
    assert!(sql_gate_flag(&json!({ "protocol": "sql", "sql": "x" })));
    assert!(!sql_gate_flag(&json!({ "protocol": "ssh", "sql": { "require_mfa": true } })));
}

#[test]
fn endpoints_resolve_from_the_profile_then_the_record_then_the_engine() {
    let meta = |v: Value| v.as_object().cloned().unwrap();
    let bare = parse_sql_profile(
        &json!({ "id": "p", "protocol": "sql", "sql": { "ceiling": ["sql_select"] },
                 "credential_source": { "kind": "secret", "secret_id": "s" } }),
        SqlEngine::Oracle,
    )
    .unwrap();
    let ep = |m: Value| resolve_endpoint(&bare, &meta(m), SqlEngine::Oracle).map(|e| e.to_string());
    assert_eq!(ep(json!({ "hostname": "ORA1.corp", "ip_address": "10.0.0.9" })).unwrap(), "ora1.corp:1521");
    assert_eq!(ep(json!({ "ip_address": "10.0.0.9", "port": 1522 })).unwrap(), "10.0.0.9:1522");
    assert_eq!(ep(json!({ "hostname": "", "ip_address": "fd00::5", "port": "1600" })).unwrap(), "[fd00::5]:1600");
    assert_eq!(ep(json!({ "hostname": "ora1", "port": "" })).unwrap(), "ora1:1521");
    for bad in [
        json!({}),
        json!({ "hostname": "ora 1" }),
        json!({ "hostname": "ora1", "port": "x" }),
        json!({ "hostname": "ora1", "port": 70000 }),
        json!({ "hostname": 5 }),
    ] {
        assert_eq!(ep(bad.clone()).unwrap_err().code, "endpoint_unresolvable", "{bad}");
    }
    let pinned = parse_sql_profile(&profile(minimal_sql()), SqlEngine::Mysql).unwrap();
    let e = resolve_endpoint(&pinned, &meta(json!({ "hostname": "elsewhere", "port": 1 })), SqlEngine::Mysql).unwrap();
    assert_eq!(e.to_string(), "db1.example.net:3306");
}

#[test]
fn bindings_parse_strictly() {
    let ok = |s: &str| SqlEndpoint::parse(s).unwrap_or_else(|| panic!("{s}"));
    assert_eq!(ok("DB.example:5432"), SqlEndpoint { host: "db.example".into(), port: 5432 });
    assert_eq!(ok("[::1]:1433").to_string(), "[::1]:1433");
    for bad in ["", "db", "db:", "db:0", "db:65536", ":5432", "db :1", "::1:5432", "[::1]5432", "a/b:1", "db:x"] {
        assert!(SqlEndpoint::parse(bad).is_none(), "{bad:?}");
    }
    assert_eq!(bound_endpoints(None), Err(BindingError::Unbound));
    assert_eq!(bound_endpoints(Some(&json!([]))), Err(BindingError::Unbound));
    assert_eq!(bound_endpoints(Some(&json!(["db:1", "x"]))), Err(BindingError::Invalid));
    assert_eq!(bound_endpoints(Some(&json!({ "host": "db" }))), Err(BindingError::Invalid));
    assert_eq!(bound_endpoints(Some(&json!(["db:1", "DB2:2"]))).unwrap().len(), 2);

    let body = |v: Value| v.as_object().cloned().unwrap();
    assert!(validate_sql_endpoint_on_write(&body(json!({ "password": "x" }))).is_ok());
    assert!(validate_sql_endpoint_on_write(&body(json!({ "sql_endpoint": null }))).is_ok());
    assert!(validate_sql_endpoint_on_write(&body(json!({ "sql_endpoint": ["db:5432"] }))).is_ok());
    assert!(validate_sql_endpoint_on_write(&body(json!({ "sql_endpoint": "db" }))).is_err());
    assert!(validate_sql_endpoint_on_write(&body(json!({ "sql_endpoint": 5432 }))).is_err());
}

#[test]
fn the_type_configuration_can_turn_sql_off() {
    let offered = |v: Value| sql_offered_by_type(Some(&v));
    assert_eq!(sql_offered_by_type(None), Ok(true), "the built-in block offers it");
    assert_eq!(offered(json!({ "id": "database" })), Ok(true));
    assert_eq!(offered(json!({ "connect": { "enabled": true } })), Ok(true));
    assert_eq!(offered(json!({ "connect": { "protocols": ["ssh", "sql"] } })), Ok(true));
    assert_eq!(offered(json!({ "connect": { "enabled": false, "protocols": ["sql"] } })), Ok(false));
    assert_eq!(offered(json!({ "connect": { "protocols": ["ssh"] } })), Ok(false));
    assert_eq!(offered(json!({ "connect": { "protocols": "sql" } })), Ok(false));
    assert!(offered(json!({ "connect": { "enabled": "yes" } })).is_err());
    assert!(offered(json!({ "connect": [] })).is_err());
}

#[test]
fn enforcement_defaults_to_database_first() {
    let m = |v: Value| v.as_object().cloned().unwrap();
    assert_eq!(parse_resource_settings(&m(json!({}))).unwrap().enforcement, SqlEnforcement::DatabaseFirst);
    assert_eq!(
        parse_resource_settings(&m(json!({ "sql": { "enforcement": "classifier-only" } }))).unwrap().enforcement,
        SqlEnforcement::ClassifierOnly
    );
    for bad in [
        json!({ "sql": "classifier-only" }),
        json!({ "sql": { "enforcement": "off" } }),
        json!({ "sql": { "enforcement": "database-first", "journal": "full" } }),
    ] {
        assert_eq!(parse_resource_settings(&m(bad.clone())).unwrap_err().code, "invalid_resource_settings", "{bad}");
    }
}

#[test]
fn a_secret_login_never_echoes_its_value() {
    let planted = "Pl4nted-S3cret-value";
    let body = json!({ "username": "svc", "password": planted, "sql_endpoint": "db:5432", "notes": "x" });
    let ok = parse_secret_login(body.to_string().as_bytes()).unwrap();
    assert_eq!((ok.username.as_str(), ok.password.as_str()), ("svc", planted));
    assert_eq!(ok.sql_endpoint, Some(json!("db:5432")));
    for bad in [
        json!({ "username": "svc" }),
        json!({ "password": planted }),
        json!({ "username": "", "password": planted }),
        json!({ "username": "svc", "password": 5 }),
        json!({ "username": planted, "password": [planted] }),
    ] {
        let e = parse_secret_login(bad.to_string().as_bytes()).err().unwrap();
        assert_eq!(e.code, "credential_invalid");
        assert!(!e.to_string().contains(planted), "{e}");
    }
}

#[test]
fn the_objects_parameter_is_strict() {
    assert_eq!(parse_objects_param("").unwrap(), vec![]);
    assert_eq!(
        parse_objects_param("netrisk/public/users,def/netrisk/a%2Fb%2Cc%25").unwrap(),
        vec![("netrisk".into(), "public".into(), "users".into()), ("def".into(), "netrisk".into(), "a/b,c%".into())]
    );
    for bad in ["a/b", "a/b/c/d", "a/b/c,", "a/b/%zz", "a/b/%2"] {
        assert!(parse_objects_param(bad).is_err(), "{bad}");
    }
    let many = vec!["c/s/o"; MAX_PRIVILEGE_OBJECTS + 1].join(",");
    assert!(parse_objects_param(&many).is_err());
    let enough = vec!["c/s/o"; MAX_PRIVILEGE_OBJECTS].join(",");
    assert_eq!(parse_objects_param(&enough).unwrap().len(), MAX_PRIVILEGE_OBJECTS);
    assert!((MAX_PRIVILEGE_OBJECTS + 2) * SqlCapability::ALL.len() <= crate::kernel_api::policy::SQL_MAX_CHECKS);
}
