//! `rfc822Name` subjectAltName entries — S/MIME person certificates.
//!
//! Before this landed the engine could not emit an `rfc822Name` at all:
//! `alt_names` turned an address into a **dNSName containing an `@`**, and
//! an `rfc822Name` sitting in a caller-supplied CSR was dropped without a
//! word. No certificate this engine issued could be used to sign mail.
//!
//! Coverage:
//! - Closed by default: a role that has not set `allow_email_sans` refuses
//!   `email_sans` rather than quietly omitting it, and issues exactly the
//!   certificate profile it did before (no SAN change at all).
//! - An opted-in role emits the address as an `rfc822Name` — asserted at
//!   the DER level via the parsed GeneralName, not by grepping bytes — in
//!   the *same* `subjectAltName` extension as the DNS and IP names. Two
//!   SAN extensions would make the certificate invalid.
//! - The `allowed_email_domains` allow-list is enforced, exactly and
//!   case-insensitively: a parent domain does not admit a subdomain.
//! - Malformed addresses are refused.
//! - `pki/sign/:role` carries an `rfc822Name` out of a CSR when the role
//!   permits it, and **refuses** the CSR when it does not — the behaviour
//!   change that replaces the old silent drop.
//! - `pki/sign-verbatim` carries the CSR's `rfc822Name` through, because
//!   "as stated in the CSR" is that path's whole contract, and an address
//!   in its request body reaches nothing — the path declares no
//!   `email_sans` field, since there is no role to authorise one.
//! - `pki/csr/generate` puts the address in the outgoing CSR, so an
//!   operator can get an S/MIME cert signed by an upstream CA.
//! - The ML-DSA (PQC) builder emits the same GeneralName as the classical
//!   one — they are separate hand-written code paths and must not drift.

use std::{collections::HashMap, env, fs};

use bastion_vault::{
    core::{Core, SealConfig},
    logical::{Operation, Request},
    storage, BastionVault,
};
use go_defer::defer;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};
use serde_json::{json, Map, Value};
use x509_parser::prelude::*;

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
    let dir = env::temp_dir().join(format!("bastion_vault_pki_email_{tag}_{n:08x}"));
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

fn cert_pem(resp: &Map<String, Value>) -> String {
    resp.get("certificate").and_then(|v| v.as_str()).expect("certificate in response").to_string()
}

/// Every `rfc822Name` in the certificate's SAN, plus the assertion that
/// there is at most one `subjectAltName` extension carrying them.
///
/// Reads the parsed `GeneralName::RFC822Name` rather than searching the
/// DER for the address text: an address emitted under the wrong context
/// tag (a dNSName, say — which is exactly what `alt_names` produced
/// before this feature) would still contain the right bytes while being
/// invisible to every mail client.
fn email_sans(der: &[u8]) -> Vec<String> {
    let (_, parsed) = X509Certificate::from_der(der).expect("parse cert");
    let san_exts: Vec<_> =
        parsed.extensions().iter().filter(|e| e.oid.to_id_string() == "2.5.29.17").collect();
    assert!(
        san_exts.len() <= 1,
        "a certificate must carry at most one subjectAltName extension, found {}",
        san_exts.len()
    );

    let Ok(Some(san)) = parsed.subject_alternative_name() else {
        return Vec::new();
    };
    san.value
        .general_names
        .iter()
        .filter_map(|name| match name {
            GeneralName::RFC822Name(addr) => Some(addr.to_string()),
            _ => None,
        })
        .collect()
}

fn dns_sans(der: &[u8]) -> Vec<String> {
    let (_, parsed) = X509Certificate::from_der(der).expect("parse cert");
    let Ok(Some(san)) = parsed.subject_alternative_name() else {
        return Vec::new();
    };
    san.value
        .general_names
        .iter()
        .filter_map(|name| match name {
            GeneralName::DNSName(d) => Some(d.to_string()),
            _ => None,
        })
        .collect()
}

/// The `rfc822Name`s a **CSR** requests, read out of its
/// `extensionRequest` attribute.
fn csr_email_sans(pem_text: &str) -> Vec<String> {
    let der = pem_first_der(pem_text);
    let (_, csr) =
        x509_parser::certification_request::X509CertificationRequest::from_der(&der).expect("parse CSR");
    let mut out = Vec::new();
    if let Some(exts) = csr.requested_extensions() {
        for ext in exts {
            if let ParsedExtension::SubjectAlternativeName(san) = ext {
                for name in &san.general_names {
                    if let GeneralName::RFC822Name(addr) = name {
                        out.push(addr.to_string());
                    }
                }
            }
        }
    }
    out
}

/// A locally-built CSR requesting one DNS SAN and the given addresses as
/// `rfc822Name`s — what a real S/MIME client submits.
fn csr_with_emails(cn: &str, emails: &[&str]) -> String {
    let kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::new(vec![cn.to_string()]).unwrap();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    params.distinguished_name = dn;
    for addr in emails {
        params.subject_alt_names.push(rcgen::SanType::Rfc822Name(
            rcgen::string::Ia5String::try_from(*addr).unwrap(),
        ));
    }
    params.serialize_request(&kp).unwrap().pem().unwrap()
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_email_sans_classical() {
    let (bvault, dir, token) = boot_unsealed("classical").await;
    defer! ( let _ = fs::remove_dir_all(&dir); );
    let core = bvault.core.load();

    write_ok(
        &core,
        &token,
        "pki/root/generate/internal",
        json!({"common_name": "S/MIME Root", "key_type": "ec", "ttl": "8760h"}).as_object().unwrap().clone(),
    )
    .await;

    // A role that has NOT opted in must refuse `email_sans` rather than
    // dropping it. A silently-omitted address produces a certificate that
    // looks fine and can never sign mail.
    write(
        &core,
        &token,
        "pki/roles/plain",
        json!({"key_type": "ec", "allow_any_name": true, "ttl": "24h"}).as_object().unwrap().clone(),
    )
    .await
    .expect("write plain role");

    let denied = write(
        &core,
        &token,
        "pki/issue/plain",
        json!({"common_name": "felipe", "email_sans": "felipe@fgv.br"}).as_object().unwrap().clone(),
    )
    .await;
    assert!(denied.is_err(), "email_sans must be refused when allow_email_sans=false");

    // Baseline: the un-opted-in role's certificate profile is unchanged.
    let plain = write_ok(
        &core,
        &token,
        "pki/issue/plain",
        json!({"common_name": "plain.example.com"}).as_object().unwrap().clone(),
    )
    .await;
    let plain_der = pem_first_der(&cert_pem(&plain));
    assert!(email_sans(&plain_der).is_empty(), "no rfc822Name on a role that didn't ask for one");

    // An opted-in role, narrowed to one mail domain.
    write(
        &core,
        &token,
        "pki/roles/person",
        json!({
            "key_type": "ec",
            "allow_any_name": true,
            "ttl": "24h",
            "ext_key_usage": "EmailProtection",
            "allow_email_sans": true,
            "allowed_email_domains": "fgv.br"
        })
        .as_object()
        .unwrap()
        .clone(),
    )
    .await
    .expect("write person role");

    let issued = write_ok(
        &core,
        &token,
        "pki/issue/person",
        json!({
            "common_name": "Felipe Quintella",
            "alt_names": "felipe.example.com",
            "email_sans": "felipe@fgv.br, felipe.quintella@fgv.br"
        })
        .as_object()
        .unwrap()
        .clone(),
    )
    .await;
    let der = pem_first_der(&cert_pem(&issued));
    assert_eq!(
        email_sans(&der),
        vec!["felipe@fgv.br".to_string(), "felipe.quintella@fgv.br".to_string()],
        "both addresses must be emitted as rfc822Name entries, in order"
    );
    // The DNS names still work, and the addresses did not leak into them
    // — the pre-feature failure mode was an address arriving as a dNSName.
    let dns = dns_sans(&der);
    assert!(dns.contains(&"felipe.example.com".to_string()));
    assert!(
        !dns.iter().any(|d| d.contains('@')),
        "an address must never be emitted as a dNSName, got {dns:?}"
    );

    // Domain allow-list: exact match, case-insensitive, subdomains not implied.
    let wrong_domain = write(
        &core,
        &token,
        "pki/issue/person",
        json!({"common_name": "felipe", "email_sans": "felipe@example.com"}).as_object().unwrap().clone(),
    )
    .await;
    assert!(wrong_domain.is_err(), "a domain off the allow-list must be refused");

    let subdomain = write(
        &core,
        &token,
        "pki/issue/person",
        json!({"common_name": "felipe", "email_sans": "felipe@mail.fgv.br"}).as_object().unwrap().clone(),
    )
    .await;
    assert!(subdomain.is_err(), "a subdomain of an allow-listed domain must not be implied");

    let upper = write_ok(
        &core,
        &token,
        "pki/issue/person",
        json!({"common_name": "felipe", "email_sans": "felipe@FGV.BR"}).as_object().unwrap().clone(),
    )
    .await;
    assert_eq!(
        email_sans(&pem_first_der(&cert_pem(&upper))),
        vec!["felipe@FGV.BR".to_string()],
        "the domain match is case-insensitive, and the address is emitted as given"
    );

    for bad in ["felipe", "@fgv.br", "felipe@", "a@b@fgv.br", "fe lipe@fgv.br"] {
        let resp = write(
            &core,
            &token,
            "pki/issue/person",
            json!({"common_name": "felipe", "email_sans": bad}).as_object().unwrap().clone(),
        )
        .await;
        assert!(resp.is_err(), "malformed address `{bad}` must be refused");
    }
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_email_sans_from_csr() {
    let (bvault, dir, token) = boot_unsealed("csr").await;
    defer! ( let _ = fs::remove_dir_all(&dir); );
    let core = bvault.core.load();

    write_ok(
        &core,
        &token,
        "pki/root/generate/internal",
        json!({"common_name": "S/MIME CSR Root", "key_type": "ec", "ttl": "8760h"})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await;

    let csr_pem = csr_with_emails("Felipe Quintella", &["felipe@fgv.br"]);

    // A role that does not permit email SANs must now REFUSE a CSR that
    // asks for one. Before this feature it accepted the CSR and dropped
    // the address — the caller got a certificate that was not the one
    // they asked for, with no signal that anything had happened.
    write(
        &core,
        &token,
        "pki/roles/strict",
        json!({"key_type": "ec", "allow_any_name": true, "ttl": "24h", "use_csr_sans": true})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await
    .expect("write strict role");

    let refused = write(
        &core,
        &token,
        "pki/sign/strict",
        json!({"csr": csr_pem, "ttl": "12h"}).as_object().unwrap().clone(),
    )
    .await;
    assert!(
        refused.is_err(),
        "a CSR requesting an rfc822Name must be refused by a role with allow_email_sans=false, not silently stripped"
    );

    // The same CSR against a role that permits it.
    write(
        &core,
        &token,
        "pki/roles/person",
        json!({
            "key_type": "ec",
            "allow_any_name": true,
            "ttl": "24h",
            "use_csr_sans": true,
            "allow_email_sans": true
        })
        .as_object()
        .unwrap()
        .clone(),
    )
    .await
    .expect("write person role");

    let signed = write_ok(
        &core,
        &token,
        "pki/sign/person",
        json!({"csr": csr_pem, "ttl": "12h"}).as_object().unwrap().clone(),
    )
    .await;
    assert_eq!(
        email_sans(&pem_first_der(&cert_pem(&signed))),
        vec!["felipe@fgv.br".to_string()],
        "the CSR's rfc822Name must survive sign/:role"
    );

    // With `use_csr_sans = false` the body supplies the addresses instead,
    // and the body field is refused when the role reads SANs from the CSR.
    let body_refused = write(
        &core,
        &token,
        "pki/sign/person",
        json!({"csr": csr_pem, "email_sans": "other@fgv.br"}).as_object().unwrap().clone(),
    )
    .await;
    assert!(
        body_refused.is_err(),
        "with use_csr_sans=true the body's email_sans would be ignored, so it must be refused"
    );

    write(
        &core,
        &token,
        "pki/roles/override",
        json!({
            "key_type": "ec",
            "allow_any_name": true,
            "ttl": "24h",
            "use_csr_sans": false,
            "use_csr_common_name": true,
            "allow_email_sans": true
        })
        .as_object()
        .unwrap()
        .clone(),
    )
    .await
    .expect("write override role");

    let overridden = write_ok(
        &core,
        &token,
        "pki/sign/override",
        json!({"csr": csr_pem, "email_sans": "override@fgv.br"}).as_object().unwrap().clone(),
    )
    .await;
    assert_eq!(
        email_sans(&pem_first_der(&cert_pem(&overridden))),
        vec!["override@fgv.br".to_string()],
        "use_csr_sans=false means the body's addresses replace the CSR's"
    );

    // sign-verbatim carries the CSR through as stated — including the
    // rfc822Name, which it used to be alone in dropping.
    let verbatim = write_ok(
        &core,
        &token,
        "pki/sign-verbatim",
        json!({"csr": csr_pem, "ttl": "12h"}).as_object().unwrap().clone(),
    )
    .await;
    assert_eq!(
        email_sans(&pem_first_der(&cert_pem(&verbatim))),
        vec!["felipe@fgv.br".to_string()],
        "sign-verbatim must carry the CSR's rfc822Name"
    );

    // …but its body cannot contribute one. `pki/sign-verbatim` does not
    // declare `email_sans` at all — there is no role to authorise an
    // address against — so an address in the body reaches nothing. The
    // property that matters is that it cannot be injected into the
    // certificate; `sign_flow` additionally refuses the field outright on
    // the one verbatim path that does route a request body
    // (`sign-request/:id/approve-verbatim`).
    let verbatim_injected = write_ok(
        &core,
        &token,
        "pki/sign-verbatim",
        json!({"csr": csr_pem, "email_sans": "injected@fgv.br"}).as_object().unwrap().clone(),
    )
    .await;
    assert_eq!(
        email_sans(&pem_first_der(&cert_pem(&verbatim_injected))),
        vec!["felipe@fgv.br".to_string()],
        "only the CSR's own rfc822Name may reach a verbatim certificate"
    );
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_email_sans_in_generated_csr() {
    let (bvault, dir, token) = boot_unsealed("gencsr").await;
    defer! ( let _ = fs::remove_dir_all(&dir); );
    let core = bvault.core.load();

    write_ok(
        &core,
        &token,
        "pki/root/generate/internal",
        json!({"common_name": "Outgoing CSR Root", "key_type": "ec", "ttl": "8760h"})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await;

    write(
        &core,
        &token,
        "pki/roles/person",
        json!({
            "key_type": "ec",
            "allow_any_name": true,
            "ttl": "24h",
            "allow_email_sans": true,
            "allowed_email_domains": "fgv.br"
        })
        .as_object()
        .unwrap()
        .clone(),
    )
    .await
    .expect("write person role");

    write(
        &core,
        &token,
        "pki/roles/plain",
        json!({"key_type": "ec", "allow_any_name": true, "ttl": "24h"}).as_object().unwrap().clone(),
    )
    .await
    .expect("write plain role");

    // The role gate applies to an outgoing CSR too: a request this mount's
    // own role would refuse should not leave the building.
    let refused = write(
        &core,
        &token,
        "pki/csr/generate",
        json!({"role": "plain", "common_name": "felipe", "email_sans": "felipe@fgv.br"})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await;
    assert!(refused.is_err(), "csr/generate must apply the role's allow_email_sans gate");

    let generated = write_ok(
        &core,
        &token,
        "pki/csr/generate",
        json!({
            "role": "person",
            "common_name": "Felipe Quintella",
            "email_sans": "felipe@fgv.br"
        })
        .as_object()
        .unwrap()
        .clone(),
    )
    .await;
    let csr = generated["csr"].as_str().expect("csr in response");
    assert_eq!(
        csr_email_sans(csr),
        vec!["felipe@fgv.br".to_string()],
        "the generated CSR must request the address as an rfc822Name"
    );
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_email_sans_pqc() {
    let (bvault, dir, token) = boot_unsealed("pqc").await;
    defer! ( let _ = fs::remove_dir_all(&dir); );
    let core = bvault.core.load();

    write_ok(
        &core,
        &token,
        "pki/root/generate/internal",
        json!({"common_name": "PQ S/MIME Root", "key_type": "ml-dsa-65", "ttl": "8760h"})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await;

    write(
        &core,
        &token,
        "pki/roles/person",
        json!({
            "key_type": "ml-dsa-65",
            "allow_any_name": true,
            "ttl": "24h",
            "allow_email_sans": true
        })
        .as_object()
        .unwrap()
        .clone(),
    )
    .await
    .expect("write pqc person role");

    // The ML-DSA builder assembles its SAN extension by hand rather than
    // through rcgen, so it is a genuinely separate encoder. It must
    // produce the same GeneralName as the classical path.
    let issued = write_ok(
        &core,
        &token,
        "pki/issue/person",
        json!({"common_name": "Felipe Quintella", "email_sans": "felipe@fgv.br"})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await;
    assert_eq!(
        email_sans(&pem_first_der(&cert_pem(&issued))),
        vec!["felipe@fgv.br".to_string()],
        "the ML-DSA builder must emit the same rfc822Name the classical one does"
    );
}
