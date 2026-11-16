//! SAML IdP tests: metadata shape, SP-initiated and IdP-initiated responses
//! verified with the SAML auth backend's own parser, validator and
//! signature verifier, tampering and signature-wrapping attempts it must
//! refuse, every request refusal with its audit event, the gate, key
//! rotation, the record version rules and a mutation check on the gate.

use std::{io::Write, sync::Arc};

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use bv_auth_saml::{
    response::parse_response,
    validate::{validate, ValidationInput, DEFAULT_CLOCK_SKEW_SECS},
    verify::{canonicalise_exclusive, parse_rsa_public_key_from_pem, verify_signed_assertion},
};
use chrono::{DateTime, Duration, Utc};
use serde_json::{json, Value};

use super::{
    store::{SamlConfigUpdate, SamlStore, SpWrite},
    *,
};
use crate::{
    posix::model::IdentityState,
    storage::Storage,
    test_support::{directory, Directory, FedEvents, MemStorage},
};

const IDP: &str = "https://vault.example.com/v2/idp/saml/metadata";
const SSO: &str = "https://vault.example.com/ui/saml/sso";
const SP: &str = "https://fgt.example.com/saml/metadata";
const ACS: &str = "https://fgt.example.com/saml/acs";
const ACS2: &str = "https://fgt.example.com/saml/acs2";
const PORTAL: &str = "https://portal.example.com/sp";
const PORTAL_ACS: &str = "https://portal.example.com/sp/acs";

struct Fx {
    dir: Directory,
    mem: Arc<MemStorage>,
    store: SamlStore,
    audit: FedEvents,
}

impl Fx {
    fn deps<'a>(&'a self, authorizer: &'a dyn Authorizer) -> SamlDeps<'a> {
        SamlDeps { authorizer, store: &self.store, audit: &self.audit }
    }

    async fn sso_as(&self, authorizer: &dyn Authorizer, entity: &str, input: &SsoInput) -> Result<SamlIssued, Refusal> {
        let cfg = self.store.config().await.unwrap();
        let caller = Caller { entity_id: entity, namespace: "", http: None };
        sso(&self.deps(authorizer), cfg.as_ref(), input, &caller, Utc::now()).await
    }

    async fn sso(&self, entity: &str, input: &SsoInput) -> Result<SamlIssued, Refusal> {
        self.sso_as(&self.dir.gate(), entity, input).await
    }

    async fn initiate(&self, entity: &str, sp: &str) -> Result<SamlIssued, Refusal> {
        let cfg = self.store.config().await.unwrap();
        let caller = Caller { entity_id: entity, namespace: "", http: None };
        initiate(&self.deps(&self.dir.gate()), cfg.as_ref(), sp, Some("rs-1".into()), None, &caller, Utc::now()).await
    }

    async fn cert(&self) -> String {
        self.store.keys.ensure(Utc::now()).await.unwrap().current().unwrap().cert_pem.clone()
    }

    fn reasons(&self) -> Vec<String> {
        self.audit
            .take()
            .iter()
            .map(|(n, f)| format!("{n}:{}", f.get("reason").and_then(Value::as_str).unwrap_or("issue")))
            .collect()
    }
}

async fn fixture() -> Fx {
    let dir = directory().await;
    let mem = MemStorage::new_arc();
    let store = SamlStore::new(mem.clone() as Arc<dyn Storage>);
    let now = Utc::now();
    let cfg = SamlConfigUpdate {
        enabled: Some(true),
        entity_id: Some(IDP.into()),
        sso_url: Some(SSO.into()),
        ..Default::default()
    };
    store.put_config(cfg, now).await.unwrap();
    for (name, entity, acs, idp_initiated) in
        [("fgt", SP, vec![ACS, ACS2], false), ("portal", PORTAL, vec![PORTAL_ACS], true)]
    {
        let w = SpWrite {
            name: name.into(),
            entity_id: Some(entity.into()),
            acs_urls: Some(acs.into_iter().map(String::from).collect()),
            environment: Some("prod".into()),
            allow_idp_initiated: Some(idp_initiated),
            description: None,
        };
        store.put_sp(&dir.authz, w, now).await.unwrap();
    }
    Fx { dir, mem, store, audit: FedEvents::default() }
}

/// An AuthnRequest; `attrs` is spliced into the root element.
fn authn_request(id: &str, issuer: &str, issued: DateTime<Utc>, attrs: &str) -> String {
    format!(
        r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{id}" Version="2.0" IssueInstant="{}" {attrs}><saml:Issuer>{issuer}</saml:Issuer><samlp:NameIDPolicy AllowCreate="true"/></samlp:AuthnRequest>"#,
        xml::instant(issued)
    )
}

fn redirect(xml: &str) -> String {
    let mut enc = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(xml.as_bytes()).unwrap();
    B64.encode(enc.finish().unwrap())
}

fn sso_input(xml: &str) -> SsoInput {
    SsoInput { saml_request: redirect(xml), binding: Binding::Redirect, relay_state: Some("rs-1".into()), roles: None }
}

fn good_request(id: &str) -> String {
    authn_request(id, SP, Utc::now(), &format!(r#"AssertionConsumerServiceURL="{ACS}" Destination="{SSO}""#))
}

/// What an SP does with the POSTed value: decode, parse, validate, verify.
fn sp_accepts(issued: &SamlIssued, cert_pem: &str, in_response_to: &str, now: i64) -> Result<(), String> {
    let xml = B64.decode(issued.saml_response.as_bytes()).map_err(|e| e.to_string())?;
    sp_accepts_xml(&xml, cert_pem, &issued.acs_url, in_response_to, now)
}

fn sp_accepts_xml(xml: &[u8], cert_pem: &str, acs: &str, in_response_to: &str, now: i64) -> Result<(), String> {
    let parsed = parse_response(xml).map_err(|e| e.to_string())?;
    let input = ValidationInput {
        expected_destination: acs,
        expected_issuer: IDP,
        expected_audience: SP,
        expected_in_response_to: in_response_to,
        now_unix: now as u64,
        clock_skew_secs: DEFAULT_CLOCK_SKEW_SECS,
    };
    validate(&parsed, &input).map_err(|e| e.to_string())?;
    let key = parse_rsa_public_key_from_pem(cert_pem).map_err(|e| e.to_string())?;
    verify_signed_assertion(&parsed, &key).map_err(|e| e.to_string())
}

fn decoded(issued: &SamlIssued) -> String {
    String::from_utf8(B64.decode(issued.saml_response.as_bytes()).unwrap()).unwrap()
}

// ─── Shapes ─────────────────────────────────────────────────────────

#[tokio::test]
async fn metadata_names_the_idp_its_certificate_and_both_bindings() {
    let fx = fixture().await;
    let ring = fx.store.keys.ensure(Utc::now()).await.unwrap();
    let md = xml::metadata(IDP, SSO, &ring, Utc::now()).unwrap();
    assert!(md.starts_with(&format!(r#"<md:EntityDescriptor xmlns:md="{}" entityID="{IDP}">"#, xml::NS_METADATA)));
    assert!(md.contains(r#"WantAuthnRequestsSigned="false""#));
    assert_eq!(md.matches(r#"<md:KeyDescriptor use="signing">"#).count(), 1);
    assert!(md.contains(&format!(r#"Binding="{}" Location="{SSO}""#, xml::BINDING_REDIRECT)));
    assert!(md.contains(&format!(r#"Binding="{}" Location="{SSO}""#, xml::BINDING_POST)));
    // Well-formed, and the certificate it carries is the signing key's.
    let mut reader = quick_xml::Reader::from_str(&md);
    loop {
        match reader.read_event().unwrap() {
            quick_xml::events::Event::Eof => break,
            _ => continue,
        }
    }
    let start = md.find("<ds:X509Certificate>").unwrap() + "<ds:X509Certificate>".len();
    let end = md.find("</ds:X509Certificate>").unwrap();
    parse_rsa_public_key_from_pem(&md[start..end]).unwrap();
    assert_eq!(&md[start..end], ring.current().unwrap().cert_base64());
}

#[tokio::test]
async fn the_assertion_is_emitted_in_canonical_form() {
    let now = Utc::now();
    let input = xml::AssertionInput {
        idp_entity_id: IDP,
        sp_entity_id: SP,
        acs_url: "https://fgt.example.com/saml/acs?a=1&b=2",
        in_response_to: Some("_req-1"),
        name_id: "alice",
        attributes: vec![("display_name", vec![r#"A & B <c> "d" 'e'"#.into()]), ("roles", vec!["ops".into()])],
        response_id: "_r1",
        assertion_id: "_a1",
        issue_instant: now,
        not_on_or_after: now + Duration::minutes(5),
    };
    let bytes = xml::unsigned_assertion(&input).unwrap();
    // Any exclusive-C14N implementation must reproduce exactly these bytes,
    // so the digest an SP computes is the one that was signed.
    assert_eq!(String::from_utf8(canonicalise_exclusive(bytes.as_bytes()).unwrap()).unwrap(), bytes);
    let mut bad = input;
    bad.name_id = "a\u{0}b";
    assert!(xml::unsigned_assertion(&bad).is_err(), "control characters are refused, not escaped");
}

// ─── Happy paths ────────────────────────────────────────────────────

#[tokio::test]
async fn sp_initiated_sso_yields_a_response_the_sp_verifier_accepts() {
    let fx = fixture().await;
    let issued = fx.sso("e-alice", &sso_input(&good_request("_req-1"))).await.unwrap();
    assert_eq!((issued.acs_url.as_str(), issued.relay_state.as_deref()), (ACS, Some("rs-1")));
    let cert = fx.cert().await;
    sp_accepts(&issued, &cert, "_req-1", Utc::now().timestamp()).unwrap();

    let parsed = parse_response(decoded(&issued).as_bytes()).unwrap();
    let a = parsed.assertion.unwrap();
    assert_eq!(a.name_id, "alice");
    assert_eq!(a.attributes["uid"], ["80000"]);
    assert_eq!(a.attributes["gid"], ["80000"]);
    assert_eq!(a.attributes["login"], ["alice"]);
    assert_eq!(a.attributes["roles"], ["ops", "readonly"]);
    assert_eq!(a.attributes["groups"], ["ops", "readonly"]);
    assert_eq!(a.attributes["environment"], ["prod"]);
    assert_eq!(a.attributes["display_name"], ["Alice & Co <ops>"]);
    assert_eq!(a.audience_restrictions, [SP]);
    let lifetime = bv_auth_saml::validate::parse_iso8601_utc(&a.not_on_or_after).unwrap()
        - bv_auth_saml::validate::parse_iso8601_utc(&a.not_before).unwrap();
    assert_eq!(lifetime, 300);
    let text = decoded(&issued);
    assert!(text.contains(&format!(r#"Recipient="{ACS}""#)) && text.contains(r#"InResponseTo="_req-1""#));

    // The second registered ACS URL, by exact match; POST binding too.
    let req = authn_request("_req-2", SP, Utc::now(), &format!(r#"AssertionConsumerServiceURL="{ACS2}""#));
    let post = SsoInput { saml_request: B64.encode(&req), binding: Binding::Post, relay_state: None, roles: None };
    let issued2 = fx.sso("e-alice", &post).await.unwrap();
    assert_eq!(issued2.acs_url, ACS2);
    sp_accepts(&issued2, &cert, "_req-2", Utc::now().timestamp()).unwrap();
    // No ACS URL in the request: the first registered one.
    let req = authn_request("_req-3", SP, Utc::now(), "");
    assert_eq!(fx.sso("e-alice", &sso_input(&req)).await.unwrap().acs_url, ACS);

    assert_eq!(fx.dir.issue_events.take(), ["idp.issue:saml:allow"; 3]);
    let events = fx.audit.take();
    assert_eq!(events.len(), 3);
    assert_eq!((events[0].0, events[0].1["assertion_id"].clone()), (events::RESPONSE, json!(issued.assertion_id)));
    let dumped = Value::Object(events[0].1.clone()).to_string();
    assert!(!dumped.contains(issued.saml_response.as_str()) && !dumped.contains("SignatureValue"));

    // The SP refuses it once it has expired.
    let late = Utc::now().timestamp() + 300 + DEFAULT_CLOCK_SKEW_SECS as i64 + 1;
    assert!(sp_accepts(&issued, &cert, "_req-1", late).unwrap_err().contains("expired"));
}

#[tokio::test]
async fn idp_initiated_sso_only_for_an_sp_that_allows_it() {
    let fx = fixture().await;
    let issued = fx.initiate("e-alice", "portal").await.unwrap();
    assert_eq!(issued.acs_url, PORTAL_ACS);
    let xml_text = decoded(&issued);
    assert!(!xml_text.contains("InResponseTo"), "unsolicited");
    let parsed = parse_response(xml_text.as_bytes()).unwrap();
    assert_eq!(parsed.destination, PORTAL_ACS);
    assert_eq!(parsed.assertion.as_ref().unwrap().audience_restrictions, [PORTAL]);
    let key = parse_rsa_public_key_from_pem(&fx.cert().await).unwrap();
    verify_signed_assertion(&parsed, &key).unwrap();

    assert_eq!(fx.initiate("e-alice", "fgt").await.err(), Some(Refusal::IdpInitiatedNotAllowed));
    assert_eq!(fx.initiate("e-alice", "ghost").await.err(), Some(Refusal::UnknownServiceProvider));
    assert_eq!(fx.initiate("e-dora", "portal").await.err(), Some(Refusal::Denied(DenyReason::IdentityDisabled)));
    assert_eq!(
        fx.reasons(),
        [
            "idp.saml.response:issue",
            "idp.saml.refused:idp_initiated_not_allowed",
            "idp.saml.refused:unknown_service_provider",
            "idp.saml.refused:issue_denied",
        ]
    );
}

// ─── Tampering and wrapping ─────────────────────────────────────────

#[tokio::test]
async fn tampered_and_wrapped_responses_fail_verification() {
    let fx = fixture().await;
    let issued = fx.sso("e-alice", &sso_input(&good_request("_req-x"))).await.unwrap();
    let cert = fx.cert().await;
    let now = Utc::now().timestamp();
    let original = decoded(&issued);
    let accepts = |xml: &str| sp_accepts_xml(xml.as_bytes(), &cert, ACS, "_req-x", now);
    accepts(&original).unwrap();

    let id = &issued.assertion_id;
    let start = original.find("<saml:Assertion").unwrap();
    let end = original.find("</saml:Assertion>").unwrap() + "</saml:Assertion>".len();
    let signed = &original[start..end];
    let sig_start = signed.find("<ds:Signature").unwrap();
    let sig_end = signed.find("</ds:Signature>").unwrap() + "</ds:Signature>".len();
    let unsigned = format!("{}{}", &signed[..sig_start], &signed[sig_end..]);
    let forged = unsigned.replace(">alice</saml:NameID>", ">mallory</saml:NameID>").replace(id.as_str(), "_forged");

    let cases = [
        ("name id changed", original.replace(">alice</saml:NameID>", ">mallory</saml:NameID>")),
        (
            "role added",
            original.replace(
                "<saml:AttributeValue>readonly</saml:AttributeValue>",
                "<saml:AttributeValue>superuser</saml:AttributeValue>",
            ),
        ),
        ("assertion id changed", original.replacen(&format!(r#"ID="{id}""#), r#"ID="_other""#, 1)),
        ("signature removed", original.replace(signed, &unsigned)),
        ("forged assertion after the signed one", original.replace(signed, &format!("{signed}{forged}"))),
        (
            "forged assertion carrying the signature and the signed id",
            original.replace(
                signed,
                &forged.replace("_forged", id).replacen(
                    "</saml:Issuer>",
                    &format!("</saml:Issuer>{}", &signed[sig_start..sig_end]),
                    1,
                ),
            ),
        ),
        ("signature moved to the response", {
            let r = original.replace(signed, &unsigned);
            r.replacen("</saml:Issuer>", &format!("</saml:Issuer>{}", &signed[sig_start..sig_end]), 1)
        }),
    ];
    for (what, xml) in cases {
        assert_ne!(xml, original, "{what}: the mutation applied");
        assert!(accepts(&xml).is_err(), "{what}: accepted");
    }

    // A response signed by another key is refused against the published one.
    fx.store.keys.rotate(3600, Utc::now()).await.unwrap();
    let other = fx.sso("e-alice", &sso_input(&good_request("_req-y"))).await.unwrap();
    assert!(sp_accepts(&other, &cert, "_req-y", now).is_err(), "old certificate, new key");
    sp_accepts(&other, &fx.cert().await, "_req-y", now).unwrap();
}

// ─── Request refusals ───────────────────────────────────────────────

#[tokio::test]
async fn sso_refuses_bad_requests_before_the_gate() {
    let fx = fixture().await;
    let now = Utc::now();
    let acs = |url: &str| format!(r#"AssertionConsumerServiceURL="{url}""#);
    let cases: Vec<(&str, SsoInput, Refusal)> = vec![
        ("acs slash", sso_input(&authn_request("_a", SP, now, &acs(&format!("{ACS}/")))), Refusal::AcsMismatch),
        (
            "acs other host",
            sso_input(&authn_request("_b", SP, now, &acs("https://evil.example.com/acs"))),
            Refusal::AcsMismatch,
        ),
        ("acs other sp", sso_input(&authn_request("_c", SP, now, &acs(PORTAL_ACS))), Refusal::AcsMismatch),
        (
            "unknown sp",
            sso_input(&authn_request("_d", "https://evil.example.com/sp", now, "")),
            Refusal::UnknownServiceProvider,
        ),
        (
            "destination",
            sso_input(&authn_request("_e", SP, now, r#"Destination="https://evil.example.com/sso""#)),
            Refusal::DestinationMismatch,
        ),
        ("too old", sso_input(&authn_request("_f", SP, now - Duration::seconds(400), "")), Refusal::RequestExpired),
        ("future", sso_input(&authn_request("_g", SP, now + Duration::seconds(120), "")), Refusal::RequestExpired),
        (
            "acs index",
            sso_input(&authn_request("_h", SP, now, r#"AssertionConsumerServiceIndex="1""#)),
            Refusal::Unsupported("acs_index_unsupported"),
        ),
        (
            "artifact binding",
            sso_input(&authn_request(
                "_i",
                SP,
                now,
                r#"ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact""#,
            )),
            Refusal::Unsupported("binding_unsupported"),
        ),
        (
            "force authn",
            sso_input(&authn_request("_j", SP, now, r#"ForceAuthn="true""#)),
            Refusal::Unsupported("force_authn_unsupported"),
        ),
        ("bad id", sso_input(&authn_request("1abc", SP, now, "")), Refusal::MalformedRequest("malformed_request_id")),
        (
            "version",
            sso_input(&authn_request("_k", SP, now, "").replace(r#"Version="2.0""#, r#"Version="1.1""#)),
            Refusal::MalformedRequest("unsupported_version"),
        ),
        (
            "doctype",
            sso_input(&format!("<!DOCTYPE x [<!ENTITY e \"x\">]>{}", authn_request("_l", SP, now, ""))),
            Refusal::MalformedRequest("doctype_not_allowed"),
        ),
        ("custom entity", sso_input(&authn_request("_m", "&e;", now, "")), Refusal::MalformedRequest("custom_entity")),
        (
            "two issuers",
            sso_input(
                &authn_request("_n", SP, now, "")
                    .replace("<samlp:NameIDPolicy", &format!("<saml:Issuer>{SP}</saml:Issuer><samlp:NameIDPolicy")),
            ),
            Refusal::MalformedRequest("multiple_issuers"),
        ),
        (
            "two roots",
            sso_input(&format!("{0}{0}", authn_request("_o", SP, now, ""))),
            Refusal::MalformedRequest("multiple_roots"),
        ),
        (
            "not an authn request",
            sso_input(&authn_request("_p", SP, now, "").replace("AuthnRequest", "LogoutRequest")),
            Refusal::MalformedRequest("not_an_authn_request"),
        ),
        (
            "wrong namespace",
            sso_input(&authn_request("_q", SP, now, "").replace("urn:oasis:names:tc:SAML:2.0:protocol", "urn:evil")),
            Refusal::MalformedRequest("not_an_authn_request"),
        ),
        (
            "not base64",
            SsoInput { saml_request: "%%%".into(), binding: Binding::Redirect, relay_state: None, roles: None },
            Refusal::MalformedRequest("request_not_base64"),
        ),
        (
            "not deflate",
            SsoInput { saml_request: B64.encode("plain"), binding: Binding::Redirect, relay_state: None, roles: None },
            Refusal::MalformedRequest("request_not_deflate"),
        ),
        (
            "inflation bomb",
            SsoInput {
                saml_request: redirect(&"<".repeat(200_000)),
                binding: Binding::Redirect,
                relay_state: None,
                roles: None,
            },
            Refusal::MalformedRequest("request_too_large"),
        ),
        (
            "relay state too long",
            SsoInput { relay_state: Some("r".repeat(81)), ..sso_input(&good_request("_r")) },
            Refusal::InvalidRelayState,
        ),
    ];
    for (what, input, want) in cases {
        assert_eq!(fx.sso("e-alice", &input).await.err(), Some(want), "{what}");
        assert_eq!(fx.reasons(), [format!("{}:{}", events::REFUSED, want.reason())], "{what}");
    }
    assert!(fx.dir.issue_events.take().is_empty(), "none of these reached the gate");

    // Replay: the same request answered once only.
    let req = sso_input(&good_request("_once"));
    fx.sso("e-alice", &req).await.unwrap();
    assert_eq!(fx.sso("e-alice", &req).await.err(), Some(Refusal::Replay));
    // Even after the configured window changes.
    let cfg = SamlConfigUpdate { request_max_age_secs: Some(900), ..Default::default() };
    fx.store.put_config(cfg, Utc::now()).await.unwrap();
    assert_eq!(fx.sso("e-alice", &req).await.err(), Some(Refusal::Replay));

    // Off: nothing is issued.
    fx.store.put_config(SamlConfigUpdate { enabled: Some(false), ..Default::default() }, Utc::now()).await.unwrap();
    assert_eq!(fx.sso("e-alice", &sso_input(&good_request("_off"))).await.err(), Some(Refusal::NotEnabled));
}

#[tokio::test]
async fn sso_denials_come_from_the_gate_and_are_audited() {
    let fx = fixture().await;
    let mut n = 0;
    let mut next = || {
        n += 1;
        good_request(&format!("_deny-{n}"))
    };
    let mut dba = sso_input(&next());
    dba.roles = Some(vec!["dba".into()]);
    for (entity, input, gate) in [
        ("e-dora", sso_input(&next()), DenyReason::IdentityDisabled),
        ("e-remy", sso_input(&next()), DenyReason::IdentityRemoved),
        ("e-nora", sso_input(&next()), DenyReason::NotEntitled),
        ("e-ghost", sso_input(&next()), DenyReason::NoIdentity),
        ("e-alice", dba, DenyReason::RoleNotEntitled),
    ] {
        assert_eq!(fx.sso(entity, &input).await.err(), Some(Refusal::Denied(gate)), "{entity}");
        assert_eq!(fx.dir.issue_events.take(), [format!("idp.issue-denied:saml:{}", gate.as_str())], "{entity}");
        let events = fx.audit.take();
        assert_eq!((events[0].0, events[0].1["gate_reason"].clone()), (events::REFUSED, json!(gate.as_str())));
    }
    // Disabled after an earlier success: refused at once.
    fx.sso("e-alice", &sso_input(&next())).await.unwrap();
    fx.dir.posix.transition("e-alice", IdentityState::Disabled, None).await.unwrap();
    let refused = fx.sso("e-alice", &sso_input(&next())).await.err();
    assert_eq!(refused, Some(Refusal::Denied(DenyReason::IdentityDisabled)));
}

#[tokio::test]
async fn a_response_whose_event_cannot_be_recorded_is_not_returned() {
    let fx = fixture().await;
    *fx.audit.refuse.lock().unwrap() = Some(events::RESPONSE);
    assert_eq!(fx.sso("e-alice", &sso_input(&good_request("_audit"))).await.err(), Some(Refusal::Internal));
}

/// Mutation check: skip the gate and the denied identities get signed
/// assertions, so the denials above depend on the gate call.
#[tokio::test]
async fn without_the_gate_the_denied_identities_would_get_assertions() {
    let fx = fixture().await;
    let skip = fx.dir.skip_gate();
    for (i, entity) in ["e-dora", "e-remy", "e-nora"].into_iter().enumerate() {
        let input = sso_input(&good_request(&format!("_skip-{i}")));
        assert!(fx.sso_as(&skip, entity, &input).await.is_ok(), "{entity}");
    }
}

// ─── Keys, registrations and records ────────────────────────────────

#[tokio::test]
async fn rotation_publishes_both_certificates_for_the_overlap() {
    let fx = fixture().await;
    let old = fx.cert().await;
    let now = Utc::now();
    let ring = fx.store.keys.rotate(3600, now).await.unwrap();
    let md = xml::metadata(IDP, SSO, &ring, now).unwrap();
    assert_eq!(md.matches("<md:KeyDescriptor").count(), 2);
    let later = xml::metadata(IDP, SSO, &ring, now + Duration::hours(2)).unwrap();
    assert_eq!(later.matches("<md:KeyDescriptor").count(), 1);
    assert!(!later.contains(&old.lines().filter(|l| !l.starts_with("-----")).collect::<String>()));
}

#[tokio::test]
async fn service_provider_registration_rules() {
    let fx = fixture().await;
    let w = |name: &str, entity: &str, acs: &[&str], env: &str| SpWrite {
        name: name.into(),
        entity_id: Some(entity.into()),
        acs_urls: Some(acs.iter().map(|s| s.to_string()).collect()),
        environment: Some(env.into()),
        allow_idp_initiated: None,
        description: None,
    };
    let now = Utc::now();
    let authz = &fx.dir.authz;
    for (what, write) in [
        ("http acs", w("x", "https://x.example.com", &["http://x.example.com/acs"], "prod")),
        ("fragment", w("x", "https://x.example.com", &["https://x.example.com/acs#f"], "prod")),
        ("no acs", w("x", "https://x.example.com", &[], "prod")),
        ("entity taken", w("x", SP, &["https://x.example.com/acs"], "prod")),
        ("bad entity", w("x", "not a uri", &["https://x.example.com/acs"], "prod")),
        ("unknown env", w("x", "https://x.example.com", &["https://x.example.com/acs"], "nowhere")),
        ("entity fixed", w("fgt", "https://new.example.com", &[ACS], "prod")),
        ("env fixed", w("fgt", SP, &[ACS], "dev")),
        ("bad name", w("Bad/Name", "https://y.example.com", &["https://y.example.com/acs"], "prod")),
    ] {
        assert!(fx.store.put_sp(authz, write, now).await.is_err(), "{what}");
    }
    // Deleting frees the entity id; the index never resolves to a stale SP.
    fx.store.delete_sp("fgt").await.unwrap();
    assert!(fx.store.sp_for_entity(SP).await.unwrap().is_none());
    fx.store.put_sp(authz, w("fgt2", SP, &[ACS], "prod"), now).await.unwrap();
    assert_eq!(fx.store.sp_for_entity(SP).await.unwrap().unwrap().name, "fgt2");

    for (field, value) in [("sso_url", "http://vault.example.com/sso"), ("entity_id", "has spaces")] {
        let mut u = SamlConfigUpdate::default();
        if field == "sso_url" {
            u.sso_url = Some(value.into());
        } else {
            u.entity_id = Some(value.into());
        }
        assert!(fx.store.put_config(u, now).await.is_err(), "{field}");
    }
    let u = SamlConfigUpdate { assertion_ttl_secs: Some(3600), ..Default::default() };
    assert!(fx.store.put_config(u, now).await.is_err(), "assertion lifetime above 10m");
}

#[tokio::test]
async fn records_refuse_unknown_versions_and_fields() {
    let fx = fixture().await;
    let mut cfg: Value = serde_json::from_slice(&fx.mem.raw_get("config").unwrap()).unwrap();
    cfg["version"] = json!(2);
    fx.mem.raw_put("config", &serde_json::to_vec(&cfg).unwrap());
    assert!(fx.store.config().await.is_err());
    let mut sp: Value = serde_json::from_slice(&fx.mem.raw_get("sps/fgt").unwrap()).unwrap();
    sp["acs_index"] = json!(0);
    fx.mem.raw_put("sps/fgt", &serde_json::to_vec(&sp).unwrap());
    assert!(fx.store.get_sp("fgt").await.is_err());
    assert!(fx.store.list_sps().await.is_err());
    sp.as_object_mut().unwrap().remove("acs_index");
    sp["version"] = json!(0);
    fx.mem.raw_put("sps/fgt", &serde_json::to_vec(&sp).unwrap());
    assert!(fx.store.get_sp("fgt").await.is_err());
}
