//! OIDC OP tests: discovery and JWKS read by an independent RP library,
//! the code + PKCE happy path verified by that library, every refusal with
//! its audit event, the gate at both steps, key rotation, the record
//! version rules and a mutation check showing the denials depend on the gate.

use std::sync::Arc;

use chrono::{Duration, Utc};
use openidconnect::{
    core::{CoreIdToken, CoreIdTokenVerifier, CoreJsonWebKeySet, CoreProviderMetadata},
    ClientId, IssuerUrl, Nonce,
};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use super::{
    jwt::{verify_rs256, JwtError},
    store::{ClientWrite, OidcConfigUpdate, OidcStore},
    *,
};
use crate::{
    posix::model::IdentityState,
    storage::Storage,
    test_support::{directory, Directory, FedEvents, MemStorage},
};

/// Launch sessions (T545), on this file's fixture.
mod launch_sessions;

const ISSUER: &str = "https://vault.example.com/v2/idp/oidc";
const REDIRECT: &str = "https://app.example.com/oidc/callback";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

struct Fx {
    dir: Directory,
    mem: Arc<MemStorage>,
    store: OidcStore,
    audit: FedEvents,
    secret: Zeroizing<String>,
    other_secret: Zeroizing<String>,
}

impl Fx {
    fn deps<'a>(&'a self, authorizer: &'a dyn Authorizer) -> OidcDeps<'a> {
        OidcDeps { authorizer, store: &self.store, audit: &self.audit }
    }

    async fn cfg(&self) -> Option<OidcConfig> {
        self.store.config().await.unwrap()
    }

    async fn authorize_as(
        &self,
        authorizer: &dyn Authorizer,
        entity: &str,
        ask: &AuthorizeRequest,
    ) -> Result<Authorized, Refusal> {
        let cfg = self.cfg().await;
        authorize(&self.deps(authorizer), cfg.as_ref(), ask, entity, "", None, Utc::now()).await
    }

    async fn authorize(&self, entity: &str, ask: &AuthorizeRequest) -> Result<Authorized, Refusal> {
        self.authorize_as(&self.dir.gate(), entity, ask).await
    }

    async fn token_at(&self, ask: &TokenRequest, now: chrono::DateTime<Utc>) -> Result<Issued, Refusal> {
        let cfg = self.cfg().await;
        token(&self.deps(&self.dir.gate()), cfg.as_ref(), ask, None, now).await
    }

    async fn token(&self, ask: &TokenRequest) -> Result<Issued, Refusal> {
        self.token_at(ask, Utc::now()).await
    }

    fn redeem(&self, code: &str) -> TokenRequest {
        TokenRequest {
            grant_type: "authorization_code".into(),
            code: Zeroizing::new(code.to_string()),
            redirect_uri: REDIRECT.into(),
            client_id: "app".into(),
            client_secret: self.secret.clone(),
            code_verifier: Zeroizing::new(VERIFIER.into()),
        }
    }

    fn codes_stored(&self) -> usize {
        self.mem.count_under("codes/")
    }

    fn reasons(&self) -> Vec<String> {
        self.audit
            .take()
            .iter()
            .map(|(n, f)| format!("{n}:{}", f.get("reason").and_then(Value::as_str).unwrap_or("issue")))
            .collect()
    }
}

fn ask() -> AuthorizeRequest {
    AuthorizeRequest {
        client_id: "app".into(),
        redirect_uri: REDIRECT.into(),
        response_type: "code".into(),
        scope: "openid profile email".into(),
        state: Some("st-123".into()),
        nonce: Some("n-0S6_WzA2Mj".into()),
        code_challenge: Some(s256(VERIFIER)),
        code_challenge_method: Some("S256".into()),
        roles: None,
    }
}

async fn fixture() -> Fx {
    let dir = directory().await;
    let mem = MemStorage::new_arc();
    let store = OidcStore::new(mem.clone() as Arc<dyn Storage>);
    let now = Utc::now();
    let cfg = OidcConfigUpdate { enabled: Some(true), issuer: Some(ISSUER.into()), ..Default::default() };
    store.put_config(cfg, now).await.unwrap();
    let mut secrets = Vec::new();
    for (name, env, uri) in [("app", "prod", REDIRECT), ("other", "prod", "https://other.example.com/cb")] {
        let w = ClientWrite {
            client_id: name.into(),
            environment: Some(env.into()),
            redirect_uris: Some(vec![uri.into()]),
            ..Default::default()
        };
        let (_, created, secret) = store.put_client(&dir.authz, w, now).await.unwrap();
        assert!(created);
        secrets.push(secret.expect("a new client gets a secret"));
    }
    let other_secret = secrets.pop().unwrap();
    let secret = secrets.pop().unwrap();
    Fx { dir, mem, store, audit: FedEvents::default(), secret, other_secret }
}

async fn jwks_of(fx: &Fx) -> Value {
    let ring = fx.store.keys.ensure(Utc::now()).await.unwrap();
    Value::Object(jwks(&ring, Utc::now()).unwrap())
}

// ─── Shapes ─────────────────────────────────────────────────────────

#[tokio::test]
async fn discovery_and_jwks_parse_in_an_rp_library() {
    let fx = fixture().await;
    let cfg = fx.cfg().await.unwrap();
    let doc = discovery(&cfg);
    let meta: CoreProviderMetadata = serde_json::from_value(Value::Object(doc.clone())).unwrap();
    assert_eq!(meta.issuer().as_str(), ISSUER);
    assert_eq!(meta.jwks_uri().as_str(), format!("{ISSUER}/jwks"));
    assert_eq!(meta.token_endpoint().unwrap().as_str(), format!("{ISSUER}/token"));
    assert_eq!(meta.authorization_endpoint().as_str(), format!("{ISSUER}/authorize"));
    assert_eq!(doc["response_types_supported"], json!(["code"]));
    assert_eq!(doc["code_challenge_methods_supported"], json!(["S256"]));
    assert_eq!(doc["id_token_signing_alg_values_supported"], json!(["RS256"]));
    assert_eq!(doc["grant_types_supported"], json!(["authorization_code"]), "no implicit, no refresh");
    assert_eq!(doc["request_uri_parameter_supported"], json!(false));

    let set = jwks_of(&fx).await;
    let keys = set["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1);
    let k = &keys[0];
    assert_eq!((k["kty"].as_str(), k["alg"].as_str(), k["use"].as_str()), (Some("RSA"), Some("RS256"), Some("sig")));
    assert!(k.get("d").is_none() && k.get("p").is_none(), "no private member");
    // `kid` is the RFC 7638 thumbprint: stable, derived from the key.
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine};
    use sha2::{Digest, Sha256};
    let canonical = format!(r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#, k["e"].as_str().unwrap(), k["n"].as_str().unwrap());
    assert_eq!(k["kid"].as_str().unwrap(), B64URL.encode(Sha256::digest(canonical.as_bytes())));
    assert_eq!(B64URL.decode(k["n"].as_str().unwrap()).unwrap().len(), 384, "RSA-3072");
    let _: CoreJsonWebKeySet = serde_json::from_value(set.clone()).unwrap();
    // Generated once: a second read returns the same key.
    assert_eq!(jwks_of(&fx).await, set);
}

// ─── Happy path ─────────────────────────────────────────────────────

#[tokio::test]
async fn code_flow_with_pkce_yields_an_id_token_an_rp_library_accepts() {
    let fx = fixture().await;
    let ok = fx.authorize("e-alice", &ask()).await.unwrap();
    let redirect = url::Url::parse(&ok.redirect_to).unwrap();
    assert!(ok.redirect_to.starts_with(&format!("{REDIRECT}?")));
    let q: std::collections::HashMap<String, String> = redirect.query_pairs().into_owned().collect();
    assert_eq!((q["code"].as_str(), q["state"].as_str()), (ok.code.as_str(), "st-123"));
    assert_eq!((ok.environment.as_str(), ok.roles.clone()), ("prod", vec!["ops".to_string(), "readonly".to_string()]));

    let issued = fx.token(&fx.redeem(&ok.code)).await.unwrap();
    assert_eq!(issued.scope, "openid profile", "unknown scopes are dropped");

    // An independent RP library verifies signature, iss, aud, exp and nonce.
    let set = jwks_of(&fx).await;
    let keyset: CoreJsonWebKeySet = serde_json::from_value(set.clone()).unwrap();
    let verifier = CoreIdTokenVerifier::new_public_client(
        ClientId::new("app".into()),
        IssuerUrl::new(ISSUER.into()).unwrap(),
        keyset,
    );
    let id_token: CoreIdToken = issued.id_token.parse().unwrap();
    let claims = id_token.claims(&verifier, &Nonce::new("n-0S6_WzA2Mj".into())).unwrap();
    assert_eq!(claims.subject().as_str(), "e-alice");
    assert_eq!(claims.preferred_username().unwrap().as_str(), "alice");
    assert!(id_token.claims(&verifier, &Nonce::new("other".into())).is_err(), "nonce is bound");
    let wrong_aud = CoreIdTokenVerifier::new_public_client(
        ClientId::new("other".into()),
        IssuerUrl::new(ISSUER.into()).unwrap(),
        serde_json::from_value(set.clone()).unwrap(),
    );
    assert!(id_token.claims(&wrong_aud, &Nonce::new("n-0S6_WzA2Mj".into())).is_err(), "aud is the client");

    // The vault's own claims.
    let (header, c) = verify_rs256(&issued.id_token, &set).unwrap();
    assert_eq!((header["kid"].as_str(), header["typ"].as_str()), (Some(issued.kid.as_str()), Some("JWT")));
    assert_eq!((c["uid"].as_u64(), c["gid"].as_u64()), (Some(80_000), Some(80_000)));
    assert_eq!(c["roles"], json!(["ops", "readonly"]));
    assert_eq!(c["groups"], json!(["ops", "readonly"]));
    assert_eq!(c["environment"], json!("prod"));
    assert_eq!(c["name"], json!("Alice & Co <ops>"));
    assert!(c["exp"].as_i64().unwrap() - c["iat"].as_i64().unwrap() == 300);
    let (at_header, at) = verify_rs256(&issued.access_token, &set).unwrap();
    assert_eq!((at_header["typ"].as_str(), at["client_id"].as_str()), (Some("at+jwt"), Some("app")));

    // The gate decided twice; the token event names the jti, not the token.
    assert_eq!(fx.dir.issue_events.take(), ["idp.issue:oidc-authorize:allow", "idp.issue:oidc:allow"]);
    let events = fx.audit.take();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].0, events::TOKEN);
    assert_eq!(events[0].1["jti"], json!(issued.jti));
    let dumped = Value::Object(events[0].1.clone()).to_string();
    assert!(!dumped.contains(issued.id_token.as_str()) && !dumped.contains(fx.secret.as_str()));
    assert_eq!(fx.codes_stored(), 0, "the code was consumed");

    // A role subset is honoured and asked again at the token step.
    let mut sub = ask();
    sub.roles = Some(vec!["readonly".into()]);
    let ok = fx.authorize("e-alice", &sub).await.unwrap();
    let issued = fx.token(&fx.redeem(&ok.code)).await.unwrap();
    assert_eq!(verify_rs256(&issued.id_token, &set).unwrap().1["roles"], json!(["readonly"]));
}

// ─── Authorization refusals ─────────────────────────────────────────

#[tokio::test]
async fn authorize_refuses_bad_requests_before_the_gate_and_never_redirects() {
    let fx = fixture().await;
    let cases: Vec<(&str, Box<dyn Fn(&mut AuthorizeRequest)>, Refusal)> = vec![
        ("unknown client", Box::new(|a| a.client_id = "ghost".into()), Refusal::InvalidClient),
        ("malformed client", Box::new(|a| a.client_id = "../app".into()), Refusal::InvalidClient),
        ("redirect prefix", Box::new(|a| a.redirect_uri = format!("{REDIRECT}/x")), Refusal::InvalidRedirectUri),
        ("redirect slash", Box::new(|a| a.redirect_uri = format!("{REDIRECT}/")), Refusal::InvalidRedirectUri),
        ("redirect query", Box::new(|a| a.redirect_uri = format!("{REDIRECT}?a=b")), Refusal::InvalidRedirectUri),
        (
            "redirect other host",
            Box::new(|a| a.redirect_uri = "https://evil.example.com/oidc/callback".into()),
            Refusal::InvalidRedirectUri,
        ),
        (
            "other client's uri",
            Box::new(|a| a.redirect_uri = "https://other.example.com/cb".into()),
            Refusal::InvalidRedirectUri,
        ),
        ("implicit", Box::new(|a| a.response_type = "token".into()), Refusal::UnsupportedResponseType),
        ("hybrid", Box::new(|a| a.response_type = "code id_token".into()), Refusal::UnsupportedResponseType),
        ("id_token only", Box::new(|a| a.response_type = "id_token".into()), Refusal::UnsupportedResponseType),
        ("no openid", Box::new(|a| a.scope = "profile".into()), Refusal::InvalidScope),
        ("no pkce", Box::new(|a| a.code_challenge = None), Refusal::InvalidRequest("pkce_required")),
        (
            "plain pkce",
            Box::new(|a| a.code_challenge_method = Some("plain".into())),
            Refusal::InvalidRequest("pkce_s256_required"),
        ),
        ("no method", Box::new(|a| a.code_challenge_method = None), Refusal::InvalidRequest("pkce_s256_required")),
        (
            "short challenge",
            Box::new(|a| a.code_challenge = Some("abc".into())),
            Refusal::InvalidRequest("malformed_code_challenge"),
        ),
        (
            "control in state",
            Box::new(|a| a.state = Some("a\r\nLocation: x".into())),
            Refusal::InvalidRequest("malformed_state_or_nonce"),
        ),
    ];
    for (what, mutate, want) in cases {
        let mut a = ask();
        mutate(&mut a);
        let got = fx.authorize("e-alice", &a).await.err();
        assert_eq!(got, Some(want), "{what}");
        let reasons = fx.reasons();
        assert_eq!(reasons, [format!("{}:{}", events::REFUSED, want.reason())], "{what}");
    }
    assert!(fx.dir.issue_events.take().is_empty(), "none of these reached the gate");
    assert_eq!(fx.codes_stored(), 0, "no code was minted");

    // Off: nothing is served.
    fx.store.put_config(OidcConfigUpdate { enabled: Some(false), ..Default::default() }, Utc::now()).await.unwrap();
    assert_eq!(fx.authorize("e-alice", &ask()).await.err(), Some(Refusal::NotEnabled));
}

#[tokio::test]
async fn authorize_denials_come_from_the_gate_and_are_audited() {
    let fx = fixture().await;
    let mut readonly_dev = ask();
    readonly_dev.roles = Some(vec!["dba".into()]);
    for (entity, a, gate) in [
        ("e-dora", ask(), DenyReason::IdentityDisabled),
        ("e-remy", ask(), DenyReason::IdentityRemoved),
        ("e-nora", ask(), DenyReason::NotEntitled),
        ("e-ghost", ask(), DenyReason::NoIdentity),
        ("e-alice", readonly_dev, DenyReason::RoleNotEntitled),
    ] {
        assert_eq!(fx.authorize(entity, &a).await.err(), Some(Refusal::Denied(gate)), "{entity}");
        let denied = fx.dir.issue_events.take();
        assert_eq!(denied, [format!("idp.issue-denied:oidc-authorize:{}", gate.as_str())], "{entity}");
        let events = fx.audit.take();
        assert_eq!(events[0].1["gate_reason"], json!(gate.as_str()));
    }
    assert_eq!(fx.codes_stored(), 0);
    assert!(matches!(RvError::from(Refusal::Denied(DenyReason::IdentityDisabled)), RvError::ErrResponseStatus(403, _)));
}

// ─── Token refusals ─────────────────────────────────────────────────

#[tokio::test]
async fn token_refuses_bad_clients_secrets_pkce_redirects_and_replays() {
    let fx = fixture().await;
    let code = fx.authorize("e-alice", &ask()).await.unwrap().code;

    // Client authentication comes first and does not burn the code.
    let mut r = fx.redeem(&code);
    r.client_secret = Zeroizing::new("not-the-secret".into());
    assert_eq!(fx.token(&r).await.err(), Some(Refusal::InvalidClient));
    r.client_secret = Zeroizing::new(String::new());
    assert_eq!(fx.token(&r).await.err(), Some(Refusal::InvalidClient));
    r.client_secret = fx.other_secret.clone();
    assert_eq!(fx.token(&r).await.err(), Some(Refusal::InvalidClient), "another client's secret");
    let mut r = fx.redeem(&code);
    r.client_id = "ghost".into();
    assert_eq!(fx.token(&r).await.err(), Some(Refusal::InvalidClient));
    let mut r = fx.redeem(&code);
    r.grant_type = "refresh_token".into();
    assert_eq!(fx.token(&r).await.err(), Some(Refusal::UnsupportedGrantType));
    assert_eq!(fx.codes_stored(), 1, "still redeemable");

    // From here each attempt consumes its code.
    let cases: Vec<(&str, Box<dyn Fn(&mut TokenRequest)>, &str)> = vec![
        ("wrong verifier", Box::new(|r| r.code_verifier = Zeroizing::new("x".repeat(43))), "pkce_verification_failed"),
        ("no verifier", Box::new(|r| r.code_verifier = Zeroizing::new(String::new())), "pkce_verification_failed"),
        ("redirect differs", Box::new(|r| r.redirect_uri = format!("{REDIRECT}/")), "redirect_uri_mismatch"),
    ];
    for (what, mutate, reason) in cases {
        let code = fx.authorize("e-alice", &ask()).await.unwrap().code;
        let mut r = fx.redeem(&code);
        mutate(&mut r);
        assert_eq!(fx.token(&r).await.err(), Some(Refusal::InvalidGrant(reason)), "{what}");
        assert_eq!(
            fx.token(&fx.redeem(&code)).await.err(),
            Some(Refusal::InvalidGrant("unknown_or_used_code")),
            "{what}"
        );
    }

    // A code minted for one client is refused to another.
    let mut other = ask();
    other.client_id = "other".into();
    other.redirect_uri = "https://other.example.com/cb".into();
    let other_code = fx.authorize("e-alice", &other).await.unwrap().code;
    assert_eq!(fx.token(&fx.redeem(&other_code)).await.err(), Some(Refusal::InvalidGrant("code_client_mismatch")));

    // Replay: the first redemption wins, the second is refused.
    fx.token(&fx.redeem(&code)).await.unwrap();
    assert_eq!(fx.token(&fx.redeem(&code)).await.err(), Some(Refusal::InvalidGrant("unknown_or_used_code")));
    // Garbage never reaches storage.
    for bad in ["", "abc", "123.", "x.y", &format!("{}.{}", "9".repeat(13), "a".repeat(43))] {
        assert_eq!(fx.token(&fx.redeem(bad)).await.err(), Some(Refusal::InvalidGrant("unknown_or_used_code")));
    }

    // Expired: 60 s by default.
    let code = fx.authorize("e-alice", &ask()).await.unwrap().code;
    let late = fx.token_at(&fx.redeem(&code), Utc::now() + Duration::seconds(61)).await;
    assert_eq!(late.err(), Some(Refusal::InvalidGrant("code_expired")));

    let events = fx.audit.take();
    assert!(events.iter().all(|(n, f)| *n == events::REFUSED || f["decision"] == "issue"));
    let text = Value::Array(events.iter().map(|(_, f)| Value::Object(f.clone())).collect()).to_string();
    assert!(!text.contains(fx.secret.as_str()) && !text.contains(code.as_str()), "no secret or code in events");
}

#[tokio::test]
async fn the_token_step_asks_the_gate_again() {
    let fx = fixture().await;
    let code = fx.authorize("e-alice", &ask()).await.unwrap().code;
    fx.dir.posix.transition("e-alice", IdentityState::Disabled, None).await.unwrap();
    let denied = fx.token(&fx.redeem(&code)).await.err();
    assert_eq!(denied, Some(Refusal::Denied(DenyReason::IdentityDisabled)));
    assert_eq!(
        fx.dir.issue_events.take(),
        ["idp.issue:oidc-authorize:allow", "idp.issue-denied:oidc:identity_disabled"]
    );

    // A role revoked between the two steps denies the whole token.
    fx.dir.posix.transition("e-alice", IdentityState::Active, None).await.unwrap();
    let code = fx.authorize("e-alice", &ask()).await.unwrap().code;
    let grant = crate::entitlement::store::EntitlementWrite {
        entity_id: "e-alice".into(),
        environment: "prod".into(),
        roles: vec!["ops".into()],
        not_after: None,
        source: crate::entitlement::model::EntitlementSource::Manual,
        granted_by: "root".into(),
    };
    fx.dir.authz.put_entitlement(&fx.dir.posix, grant, Utc::now()).await.unwrap();
    let denied = fx.token(&fx.redeem(&code)).await.err();
    assert_eq!(denied, Some(Refusal::Denied(DenyReason::RoleNotEntitled)));
}

#[tokio::test]
async fn a_token_whose_event_cannot_be_recorded_is_not_returned() {
    let fx = fixture().await;
    let code = fx.authorize("e-alice", &ask()).await.unwrap().code;
    *fx.audit.refuse.lock().unwrap() = Some(events::TOKEN);
    assert_eq!(fx.token(&fx.redeem(&code)).await.err(), Some(Refusal::Internal));
}

/// Mutation check: skip the gate and every denial above turns into a
/// token. The refusals in this file therefore depend on the gate call.
#[tokio::test]
async fn without_the_gate_the_denied_identities_would_get_codes() {
    let fx = fixture().await;
    let skip = fx.dir.skip_gate();
    for entity in ["e-dora", "e-remy", "e-nora"] {
        assert!(fx.authorize_as(&skip, entity, &ask()).await.is_ok(), "{entity}");
    }
    let code = fx.authorize("e-alice", &ask()).await.unwrap().code;
    fx.dir.posix.transition("e-alice", IdentityState::Disabled, None).await.unwrap();
    let cfg = fx.cfg().await;
    let issued = token(&fx.deps(&skip), cfg.as_ref(), &fx.redeem(&code), None, Utc::now()).await;
    assert!(issued.is_ok(), "a disabled identity would get a token");
}

// ─── Keys ───────────────────────────────────────────────────────────

#[tokio::test]
async fn rotation_keeps_the_old_key_published_for_the_overlap() {
    let fx = fixture().await;
    let code = fx.authorize("e-alice", &ask()).await.unwrap().code;
    let old = fx.token(&fx.redeem(&code)).await.unwrap();
    let now = Utc::now();
    assert!(fx.store.keys.rotate(60, now).await.is_err(), "overlap below 1h");
    let ring = fx.store.keys.rotate(3600, now).await.unwrap();
    let set = Value::Object(jwks(&ring, now).unwrap());
    let kids: Vec<&str> = set["keys"].as_array().unwrap().iter().map(|k| k["kid"].as_str().unwrap()).collect();
    assert_eq!(kids.len(), 2);
    assert_eq!(kids[1], old.kid, "current first, then the retired key");

    let code = fx.authorize("e-alice", &ask()).await.unwrap().code;
    let new = fx.token(&fx.redeem(&code)).await.unwrap();
    assert_eq!(new.kid, kids[0]);
    assert!(verify_rs256(&old.id_token, &set).is_ok(), "old tokens still verify during the overlap");
    assert!(verify_rs256(&new.id_token, &set).is_ok());

    let later = Value::Object(jwks(&ring, now + Duration::hours(2)).unwrap());
    assert_eq!(later["keys"].as_array().unwrap().len(), 1);
    assert_eq!(verify_rs256(&old.id_token, &later).err(), Some(JwtError::UnknownKey));
    // A forged signature is refused.
    let mut forged = new.id_token.to_string();
    forged.pop();
    forged.push(if new.id_token.ends_with('A') { 'B' } else { 'A' });
    assert!(verify_rs256(&forged, &later).is_err());
}

// ─── Records ────────────────────────────────────────────────────────

#[tokio::test]
async fn records_refuse_unknown_versions_and_fields() {
    let fx = fixture().await;
    let cfg = fx.mem.raw_get("config").unwrap();
    let mut v: Value = serde_json::from_slice(&cfg).unwrap();
    v["version"] = json!(2);
    fx.mem.raw_put("config", &serde_json::to_vec(&v).unwrap());
    assert!(fx.store.config().await.is_err(), "version 2");
    v["version"] = json!(1);
    v["surprise"] = json!(true);
    fx.mem.raw_put("config", &serde_json::to_vec(&v).unwrap());
    assert!(fx.store.config().await.is_err(), "unknown field");

    let client = fx.mem.raw_get("clients/app").unwrap();
    let mut c: Value = serde_json::from_slice(&client).unwrap();
    c["extra"] = json!("x");
    fx.mem.raw_put("clients/app", &serde_json::to_vec(&c).unwrap());
    assert!(fx.store.get_client("app").await.is_err());

    fx.store.keys.ensure(Utc::now()).await.unwrap();
    let ring = fx.mem.raw_get("keys").unwrap();
    let mut r: Value = serde_json::from_slice(&ring).unwrap();
    r["version"] = json!(3);
    fx.mem.raw_put("keys", &serde_json::to_vec(&r).unwrap());
    assert!(fx.store.keys.load().await.is_err());
    assert!(fx.store.keys.ensure(Utc::now()).await.is_err(), "an unreadable ring is never replaced");
    r["version"] = json!(1);
    let mut second = r["keys"][0].clone();
    second["kid"] = json!("other");
    r["keys"].as_array_mut().unwrap().push(second);
    fx.mem.raw_put("keys", &serde_json::to_vec(&r).unwrap());
    assert!(fx.store.keys.load().await.is_err(), "two current keys");
}

#[tokio::test]
async fn client_secrets_are_write_only_and_rotate() {
    let fx = fixture().await;
    let client = fx.store.get_client("app").await.unwrap().unwrap();
    let shown = Value::Object(client.to_map()).to_string();
    assert!(!shown.contains(fx.secret.as_str()) && !shown.contains(&client.secret_sha256));
    let raw = String::from_utf8(fx.mem.raw_get("clients/app").unwrap()).unwrap();
    assert!(!raw.contains(fx.secret.as_str()), "only the digest is stored");

    let w = ClientWrite { client_id: "app".into(), rotate_secret: true, ..Default::default() };
    let (_, created, fresh) = fx.store.put_client(&fx.dir.authz, w, Utc::now()).await.unwrap();
    assert!(!created);
    let fresh = fresh.unwrap();
    let code = fx.authorize("e-alice", &ask()).await.unwrap().code;
    assert_eq!(fx.token(&fx.redeem(&code)).await.err(), Some(Refusal::InvalidClient), "old secret");
    let mut r = fx.redeem(&code);
    r.client_secret = fresh;
    fx.token(&r).await.unwrap();

    // Registration rules.
    let bad = |uris: Vec<&str>| ClientWrite {
        client_id: "bad".into(),
        environment: Some("prod".into()),
        redirect_uris: Some(uris.into_iter().map(String::from).collect()),
        ..Default::default()
    };
    for uris in
        [vec!["http://app.example.com/cb"], vec!["https://app.example.com/cb#x"], vec![], vec![REDIRECT, REDIRECT]]
    {
        assert!(fx.store.put_client(&fx.dir.authz, bad(uris.clone()), Utc::now()).await.is_err(), "{uris:?}");
    }
    let mut w = bad(vec![REDIRECT]);
    w.environment = Some("nowhere".into());
    assert!(fx.store.put_client(&fx.dir.authz, w, Utc::now()).await.is_err());
    let w = ClientWrite { client_id: "app".into(), environment: Some("dev".into()), ..Default::default() };
    assert!(fx.store.put_client(&fx.dir.authz, w, Utc::now()).await.is_err(), "environment is fixed");

    for (issuer, ok) in [("http://vault.example.com", false), ("https://vault.example.com/", false), (ISSUER, true)] {
        let u = OidcConfigUpdate { issuer: Some(issuer.into()), ..Default::default() };
        assert_eq!(fx.store.put_config(u, Utc::now()).await.is_ok(), ok, "{issuer}");
    }
    let u = OidcConfigUpdate { id_token_ttl_secs: Some(7200), ..Default::default() };
    assert!(fx.store.put_config(u, Utc::now()).await.is_err());
}
