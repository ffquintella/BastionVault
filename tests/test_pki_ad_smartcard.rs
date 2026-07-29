//! Windows / Active Directory smart-card logon certificate profile.
//!
//! Covers the three things a Windows KDC needs in a PKINIT client
//! certificate that RFC 5280 has no opinion about, and that the PKI engine
//! could not emit before this landed:
//!
//! 1. The UPN as a `subjectAltName` `otherName` (OID 1.3.6.1.4.1.311.20.2.3,
//!    value a UTF8String) — how the KDC maps the cert to an AD account.
//! 2. The Smart Card Logon EKU (1.3.6.1.4.1.311.20.2.2).
//! 3. The `szOID_NTDS_CA_SECURITY_EXT` SID extension (1.3.6.1.4.1.311.25.2)
//!    required for KB5014754 strong certificate mapping — mandatory since
//!    the September 2025 update removed the `StrongCertificateBindingEnforcement`
//!    fallback to Compatibility mode.
//!
//! Coverage:
//! - Every knob is closed by default: a role that does not opt in refuses
//!   `upn_sans` / `ad_sid` rather than quietly dropping them.
//! - An opted-in role produces a cert carrying all three, with exactly one
//!   `subjectAltName` extension (two would make the cert invalid — the UPN
//!   has to join the DNS/IP names in the existing extension, not add a
//!   second one).
//! - `ad_sid` resolution order: request body overrides the role default.
//! - The realm allow-list is enforced.
//! - Malformed SIDs and malformed EKU OIDs are refused at role-write time.
//! - The ML-DSA (PQC) issuer path emits the same profile as the classical
//!   one — the two builders are separate code paths and must not drift.
//! - A role without the knobs emits exactly the profile it did before, so
//!   existing deployments see no change.

use std::{collections::HashMap, env, fs};

use bastion_vault::{
    core::{Core, SealConfig},
    logical::{Operation, Request},
    storage, BastionVault,
};
use go_defer::defer;
use serde_json::{json, Map, Value};
use x509_parser::prelude::*;

const UPN_OID: &str = "1.3.6.1.4.1.311.20.2.3";
const SID_EXT_OID: &str = "1.3.6.1.4.1.311.25.2";
const SID_OTHER_NAME_OID: &str = "1.3.6.1.4.1.311.25.2.1";
const SMARTCARD_LOGON_EKU_OID: &str = "1.3.6.1.4.1.311.20.2.2";

#[maybe_async::maybe_async]
async fn write(
    core: &Core,
    token: &str,
    path: &str,
    body: Map<String, Value>,
) -> Result<Option<Map<String, Value>>, String> {
    let mut req = Request::new(path);
    req.operation = Operation::Write;
    req.client_token = token.to_string();
    req.body = Some(body);
    core.handle_request(&mut req)
        .await
        .map(|r| r.and_then(|x| x.data))
        .map_err(|e| format!("{e:?}"))
}

#[maybe_async::maybe_async]
async fn write_ok(core: &Core, token: &str, path: &str, body: Map<String, Value>) -> Map<String, Value> {
    write(core, token, path, body)
        .await
        .unwrap_or_else(|e| panic!("write {path}: {e}"))
        .unwrap_or_else(|| panic!("write {path}: empty response"))
}

fn boot(tag: &str) -> (BastionVault, std::path::PathBuf) {
    use rand::RngExt;
    let n: u32 = rand::rng().random();
    let dir = env::temp_dir().join(format!("bastion_vault_pki_adsc_{tag}_{n:08x}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let mut conf: HashMap<String, Value> = HashMap::new();
    conf.insert("path".into(), Value::String(dir.to_string_lossy().into_owned()));
    let backend = storage::new_backend("file", &conf).unwrap();
    let bvault = BastionVault::new(backend, None).unwrap();
    (bvault, dir)
}

#[maybe_async::maybe_async]
async fn boot_unsealed(tag: &str) -> (BastionVault, std::path::PathBuf, String) {
    let (bvault, dir) = boot(tag);
    let seal = SealConfig { secret_shares: 5, secret_threshold: 3 };
    let init = bvault.init(&seal).await.unwrap();
    for i in 0..seal.secret_threshold {
        bvault.unseal(&[&init.secret_shares[i as usize]]).await.unwrap();
    }
    let token = init.root_token.clone();
    let core = bvault.core.load();
    write(&core, &token, "sys/mounts/pki/", json!({"type": "pki"}).as_object().unwrap().clone())
        .await
        .expect("mount pki");
    (bvault, dir, token)
}

fn pem_first_der(pem_text: &str) -> Vec<u8> {
    // `::pem` — `x509_parser::prelude` re-exports a `pem` module that
    // would otherwise shadow the crate.
    ::pem::parse(pem_text.as_bytes()).expect("PEM parse").into_contents()
}

/// Pull the certificate PEM out of an `pki/issue/...` response.
fn cert_pem(resp: &Map<String, Value>) -> String {
    resp.get("certificate").and_then(|v| v.as_str()).expect("certificate in response").to_string()
}

/// Every UPN carried as an `otherName` SAN, decoded from the UTF8String.
///
/// Also asserts the `otherName` type-id is the Microsoft UPN OID and that
/// the value really is a UTF8String (tag 0x0C) — Microsoft's own guidance
/// calls out raw / non-UTF8 encodings as a common cause of AD refusing an
/// otherwise well-formed certificate.
fn upn_sans(der: &[u8]) -> Vec<String> {
    let (_, parsed) = X509Certificate::from_der(der).expect("parse cert");
    let san_exts: Vec<_> = parsed
        .extensions()
        .iter()
        .filter(|e| e.oid.to_id_string() == "2.5.29.17")
        .collect();
    assert!(
        san_exts.len() <= 1,
        "a certificate must carry at most one subjectAltName extension, found {}",
        san_exts.len()
    );

    let Ok(Some(san)) = parsed.subject_alternative_name() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for name in &san.value.general_names {
        if let GeneralName::OtherName(oid, bytes) = name {
            if oid.to_id_string() != UPN_OID {
                continue;
            }
            // `bytes` is the `[0] EXPLICIT <value>` that follows the OID.
            // Unwrap the explicit tag, then the UTF8String.
            assert_eq!(bytes[0], 0xA0, "UPN otherName value must be [0] EXPLICIT");
            let inner = &bytes[2..];
            assert_eq!(
                inner[0], 0x0C,
                "UPN otherName value must be a UTF8String (tag 0x0C), got {:#04x}",
                inner[0]
            );
            let len = inner[1] as usize;
            out.push(String::from_utf8(inner[2..2 + len].to_vec()).expect("UPN is valid UTF-8"));
        }
    }
    out
}

/// The SID carried in the `szOID_NTDS_CA_SECURITY_EXT` extension, if present.
///
/// Asserts the full nesting Windows expects — `GeneralNames { otherName {
/// szOID_NTDS_OBJECTSID, [0] OCTET STRING } }` — rather than just grepping
/// the bytes for the SID text, so a structurally wrong extension that
/// happens to contain the right string still fails.
fn ad_sid(der: &[u8]) -> Option<String> {
    let (_, parsed) = X509Certificate::from_der(der).expect("parse cert");
    let ext = parsed.extensions().iter().find(|e| e.oid.to_id_string() == SID_EXT_OID)?;
    assert!(!ext.critical, "the AD SID extension must be non-critical");

    // extn_value is the DER of a GeneralNames (SEQUENCE OF GeneralName).
    let v = ext.value;
    assert_eq!(v[0], 0x30, "SID extension value must be a SEQUENCE (GeneralNames)");
    let general_name = &v[2..];
    assert_eq!(general_name[0], 0xA0, "the single GeneralName must be otherName ([0])");

    let after_tag = &general_name[2..];
    let (rest, oid) = x509_parser::der_parser::oid::Oid::from_der(after_tag).expect("otherName OID");
    assert_eq!(
        oid.to_id_string(),
        SID_OTHER_NAME_OID,
        "the otherName inside the SID extension must use szOID_NTDS_OBJECTSID"
    );
    assert_eq!(rest[0], 0xA0, "SID otherName value must be [0] EXPLICIT");
    let inner = &rest[2..];
    assert_eq!(
        inner[0], 0x04,
        "the SID must be an OCTET STRING (tag 0x04), got {:#04x}",
        inner[0]
    );
    let len = inner[1] as usize;
    Some(String::from_utf8(inner[2..2 + len].to_vec()).expect("SID is ASCII"))
}

/// The CRL distribution point URIs embedded in the cert.
fn crl_dp_uris(der: &[u8]) -> Vec<String> {
    let (_, parsed) = X509Certificate::from_der(der).expect("parse cert");
    let mut out = Vec::new();
    for ext in parsed.extensions() {
        if let ParsedExtension::CRLDistributionPoints(dps) = ext.parsed_extension() {
            for dp in dps.iter() {
                if let Some(DistributionPointName::FullName(names)) = &dp.distribution_point {
                    for name in names {
                        if let GeneralName::URI(uri) = name {
                            out.push(uri.to_string());
                        }
                    }
                }
            }
        }
    }
    out
}

fn eku_oids(der: &[u8]) -> Vec<String> {
    let (_, parsed) = X509Certificate::from_der(der).expect("parse cert");
    let mut out = Vec::new();
    for ext in parsed.extensions() {
        if let ParsedExtension::ExtendedKeyUsage(eku) = ext.parsed_extension() {
            if eku.client_auth {
                out.push("1.3.6.1.5.5.7.3.2".to_string());
            }
            if eku.server_auth {
                out.push("1.3.6.1.5.5.7.3.1".to_string());
            }
            for other in &eku.other {
                out.push(other.to_id_string());
            }
        }
    }
    out
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_ad_smartcard_profile_classical() {
    let (bvault, dir, token) = boot_unsealed("classical").await;
    defer! ( let _ = fs::remove_dir_all(&dir); );
    let core = bvault.core.load();

    write_ok(
        &core,
        &token,
        "pki/root/generate/internal",
        json!({"common_name": "AD SC Root", "key_type": "ec", "ttl": "8760h"}).as_object().unwrap().clone(),
    )
    .await;

    // A role that has NOT opted in: the AD knobs must be refused, not
    // silently ignored. A silently-dropped UPN produces a cert that looks
    // fine and never authenticates — the worst possible failure mode.
    write(
        &core,
        &token,
        "pki/roles/plain",
        json!({"key_type": "ec", "allow_any_name": true, "ttl": "24h"}).as_object().unwrap().clone(),
    )
    .await
    .expect("write plain role");

    let denied_upn = write(
        &core,
        &token,
        "pki/issue/plain",
        json!({"common_name": "felipe", "upn_sans": "felipe@corp.example.com"})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await;
    assert!(denied_upn.is_err(), "upn_sans must be refused when allow_upn_sans=false");

    let denied_sid = write(
        &core,
        &token,
        "pki/issue/plain",
        json!({"common_name": "felipe", "ad_sid": "S-1-5-21-1-2-3-512"}).as_object().unwrap().clone(),
    )
    .await;
    assert!(denied_sid.is_err(), "ad_sid must be refused when allow_ad_sid=false");

    // Baseline: the un-opted-in role still issues a normal cert with no
    // UPN SAN and no SID extension.
    let plain = write_ok(
        &core,
        &token,
        "pki/issue/plain",
        json!({"common_name": "plain.example.com"}).as_object().unwrap().clone(),
    )
    .await;
    let plain_der = pem_first_der(&cert_pem(&plain));
    assert!(upn_sans(&plain_der).is_empty(), "no UPN SAN on a role that didn't ask for one");
    assert!(ad_sid(&plain_der).is_none(), "no SID extension on a role that didn't ask for one");
    assert!(
        !eku_oids(&plain_der).contains(&SMARTCARD_LOGON_EKU_OID.to_string()),
        "no Smart Card Logon EKU unless requested"
    );
    assert!(
        crl_dp_uris(&plain_der).is_empty(),
        "no CDP before pki/config/urls is configured — existing mounts must see no change"
    );

    // Configure the mount's CRL distribution point. A domain controller
    // needs a reachable CRL for the logon certificate; this config existed
    // but was never embedded in issued leaves.
    write(
        &core,
        &token,
        "pki/config/urls",
        json!({"crl_distribution_points": "http://pki.corp.example.com/bastionvault.crl"})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await
    .expect("write config/urls");

    // Now the smart-card role. `smartcardlogon` is a friendly alias for
    // the Microsoft OID; `ext_key_usage_oids` carries a raw OID to prove
    // that channel works too (1.3.6.1.5.2.3.4 = id-pkinit-KPClientAuth).
    write(
        &core,
        &token,
        "pki/roles/adsc",
        json!({
            "key_type": "ec",
            "allow_any_name": true,
            "ttl": "8h",
            "server_flag": false,
            "client_flag": true,
            "ext_key_usage": "clientauth,smartcardlogon",
            "ext_key_usage_oids": "1.3.6.1.5.2.3.4",
            "allow_upn_sans": true,
            "allowed_upn_domains": "corp.example.com",
            "allow_ad_sid": true,
            "ad_sid": "S-1-5-21-1004336348-1177238915-682003330-1001"
        })
        .as_object()
        .unwrap()
        .clone(),
    )
    .await
    .expect("write adsc role");

    // Issue with a UPN and a DNS SAN together — the UPN must join the
    // existing SAN extension, not create a second one.
    let issued = write_ok(
        &core,
        &token,
        "pki/issue/adsc",
        json!({
            "common_name": "felipe",
            "alt_names": "felipe.corp.example.com",
            "upn_sans": "felipe@corp.example.com"
        })
        .as_object()
        .unwrap()
        .clone(),
    )
    .await;
    let der = pem_first_der(&cert_pem(&issued));

    assert_eq!(
        upn_sans(&der),
        vec!["felipe@corp.example.com".to_string()],
        "the UPN must appear as an otherName SAN"
    );
    // The DNS SAN must survive alongside it.
    let (_, parsed) = X509Certificate::from_der(&der).unwrap();
    let san = parsed.subject_alternative_name().unwrap().unwrap();
    assert!(
        san.value.general_names.iter().any(
            |n| matches!(n, GeneralName::DNSName(d) if *d == "felipe.corp.example.com")
        ),
        "the DNS SAN must coexist with the UPN otherName"
    );

    assert_eq!(
        crl_dp_uris(&der),
        vec!["http://pki.corp.example.com/bastionvault.crl".to_string()],
        "the configured CRL distribution point must be embedded in the leaf"
    );

    let ekus = eku_oids(&der);
    assert!(
        ekus.contains(&SMARTCARD_LOGON_EKU_OID.to_string()),
        "Smart Card Logon EKU missing, got {ekus:?}"
    );
    assert!(ekus.contains(&"1.3.6.1.5.5.7.3.2".to_string()), "Client Auth EKU missing, got {ekus:?}");
    assert!(
        ekus.contains(&"1.3.6.1.5.2.3.4".to_string()),
        "raw OID from ext_key_usage_oids missing, got {ekus:?}"
    );
    assert!(
        !ekus.contains(&"1.3.6.1.5.5.7.3.1".to_string()),
        "server_flag=false must not emit Server Auth, got {ekus:?}"
    );

    // The role-level default SID applies when the request omits one.
    assert_eq!(
        ad_sid(&der).as_deref(),
        Some("S-1-5-21-1004336348-1177238915-682003330-1001"),
        "role-level ad_sid should be emitted when the request omits it"
    );

    // A request-body SID overrides the role default.
    let overridden = write_ok(
        &core,
        &token,
        "pki/issue/adsc",
        json!({
            "common_name": "felipe",
            "upn_sans": "felipe@corp.example.com",
            "ad_sid": "S-1-5-21-1004336348-1177238915-682003330-2002"
        })
        .as_object()
        .unwrap()
        .clone(),
    )
    .await;
    assert_eq!(
        ad_sid(&pem_first_der(&cert_pem(&overridden))).as_deref(),
        Some("S-1-5-21-1004336348-1177238915-682003330-2002"),
        "request-body ad_sid must win over the role default"
    );

    // The realm allow-list is enforced.
    let wrong_realm = write(
        &core,
        &token,
        "pki/issue/adsc",
        json!({"common_name": "felipe", "upn_sans": "felipe@other.example.com"})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await;
    assert!(wrong_realm.is_err(), "a realm outside allowed_upn_domains must be refused");

    // A malformed UPN is refused.
    for bad in ["felipe", "@corp.example.com", "a@b@corp.example.com"] {
        let res = write(
            &core,
            &token,
            "pki/issue/adsc",
            json!({"common_name": "felipe", "upn_sans": bad}).as_object().unwrap().clone(),
        )
        .await;
        assert!(res.is_err(), "malformed UPN `{bad}` must be refused");
    }

    // A malformed SID is refused at issue time.
    for bad in ["S-2-5-18", "X-1-5-18", "S-1-5-abc", "S-1"] {
        let res = write(
            &core,
            &token,
            "pki/issue/adsc",
            json!({"common_name": "felipe", "ad_sid": bad}).as_object().unwrap().clone(),
        )
        .await;
        assert!(res.is_err(), "malformed SID `{bad}` must be refused");
    }
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_ad_smartcard_role_write_validation() {
    let (bvault, dir, token) = boot_unsealed("rolewrite").await;
    defer! ( let _ = fs::remove_dir_all(&dir); );
    let core = bvault.core.load();

    // A malformed EKU OID must be caught at role-write time — an operator
    // finding out at issue time (or worse, from a Windows logon failure)
    // is a bad debugging experience.
    let bad_oid = write(
        &core,
        &token,
        "pki/roles/badoid",
        json!({"key_type": "ec", "ext_key_usage_oids": "1.3.6.1.4.1.311..2"})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await;
    assert!(bad_oid.is_err(), "a doubled dot in an EKU OID must be refused at role write");

    let not_oid = write(
        &core,
        &token,
        "pki/roles/badoid2",
        json!({"key_type": "ec", "ext_key_usage_oids": "smartcard-logon"}).as_object().unwrap().clone(),
    )
    .await;
    assert!(not_oid.is_err(), "a non-OID in ext_key_usage_oids must be refused at role write");

    // A role default SID must be well-formed...
    let bad_sid = write(
        &core,
        &token,
        "pki/roles/badsid",
        json!({"key_type": "ec", "allow_ad_sid": true, "ad_sid": "S-9-nope"})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await;
    assert!(bad_sid.is_err(), "a malformed role-level ad_sid must be refused at role write");

    // ...and setting one without enabling the extension is a
    // contradiction worth surfacing rather than silently ignoring.
    let sid_without_flag = write(
        &core,
        &token,
        "pki/roles/sidnoflag",
        json!({"key_type": "ec", "ad_sid": "S-1-5-21-1-2-3-512"}).as_object().unwrap().clone(),
    )
    .await;
    assert!(sid_without_flag.is_err(), "ad_sid without allow_ad_sid must be refused");

    // The happy path still writes.
    write(
        &core,
        &token,
        "pki/roles/good",
        json!({
            "key_type": "ec",
            "ext_key_usage_oids": "1.3.6.1.4.1.311.20.2.2",
            "allow_ad_sid": true,
            "ad_sid": "s-1-5-21-1-2-3-512"
        })
        .as_object()
        .unwrap()
        .clone(),
    )
    .await
    .expect("valid AD role should write");

    // The stored SID is normalised to an upper-case `S-` prefix, because
    // Windows compares the extension against the account SID.
    let mut req = Request::new("pki/roles/good");
    req.operation = Operation::Read;
    req.client_token = token.clone();
    let role = core.handle_request(&mut req).await.unwrap().and_then(|r| r.data).unwrap();
    assert_eq!(role.get("ad_sid").and_then(|v| v.as_str()), Some("S-1-5-21-1-2-3-512"));
}

/// The ML-DSA issuer path assembles DER by hand rather than via `rcgen`,
/// so it is a genuinely separate implementation of the same profile. If
/// the two drift, a PQC-backed AD deployment breaks in a way no classical
/// test would catch.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_ad_smartcard_profile_ml_dsa() {
    let (bvault, dir, token) = boot_unsealed("mldsa").await;
    defer! ( let _ = fs::remove_dir_all(&dir); );
    let core = bvault.core.load();

    write_ok(
        &core,
        &token,
        "pki/root/generate/internal",
        json!({"common_name": "AD SC PQC Root", "key_type": "ml-dsa-65", "ttl": "8760h"})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await;

    write(
        &core,
        &token,
        "pki/config/urls",
        json!({"crl_distribution_points": "http://pki.corp.example.com/pqc.crl"})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await
    .expect("write config/urls");

    write(
        &core,
        &token,
        "pki/roles/adsc-pqc",
        json!({
            "key_type": "ml-dsa-65",
            "allow_any_name": true,
            "ttl": "8h",
            "server_flag": false,
            "client_flag": true,
            "ext_key_usage": "clientauth,smartcardlogon",
            "allow_upn_sans": true,
            "allow_ad_sid": true
        })
        .as_object()
        .unwrap()
        .clone(),
    )
    .await
    .expect("write pqc role");

    let issued = write_ok(
        &core,
        &token,
        "pki/issue/adsc-pqc",
        json!({
            "common_name": "felipe",
            "alt_names": "felipe.corp.example.com",
            "upn_sans": "felipe@corp.example.com",
            "ad_sid": "S-1-5-21-1004336348-1177238915-682003330-3003"
        })
        .as_object()
        .unwrap()
        .clone(),
    )
    .await;
    let der = pem_first_der(&cert_pem(&issued));

    assert_eq!(
        upn_sans(&der),
        vec!["felipe@corp.example.com".to_string()],
        "the ML-DSA path must emit the UPN otherName too"
    );
    assert_eq!(
        ad_sid(&der).as_deref(),
        Some("S-1-5-21-1004336348-1177238915-682003330-3003"),
        "the ML-DSA path must emit the SID extension too"
    );
    assert_eq!(
        crl_dp_uris(&der),
        vec!["http://pki.corp.example.com/pqc.crl".to_string()],
        "the ML-DSA path must embed the configured CRL distribution point too"
    );

    let ekus = eku_oids(&der);
    assert!(
        ekus.contains(&SMARTCARD_LOGON_EKU_OID.to_string()),
        "the ML-DSA path must emit the Smart Card Logon EKU, got {ekus:?}"
    );
    assert!(ekus.contains(&"1.3.6.1.5.5.7.3.2".to_string()), "Client Auth EKU missing, got {ekus:?}");
    assert!(
        !ekus.contains(&"1.3.6.1.5.5.7.3.1".to_string()),
        "server_flag=false must not emit Server Auth, got {ekus:?}"
    );
}
