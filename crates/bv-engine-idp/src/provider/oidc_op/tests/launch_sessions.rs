//! Launch sessions (T545): mint, the browser's authorization request, the
//! token with PKCE, and every refusal (replay, expiry, client binding,
//! request checks, the gate at both steps, malformed input, records, audit).

use super::*;
use crate::provider::{
    federation::sha256_hex,
    oidc_op::{
        launch::{self, BrowserAuthorizeRequest, LaunchIssued, LaunchRequest},
        store::LAUNCH_SESSION_PREFIX,
    },
};

/// 43 base64url characters, the shape of a Web Application Connect launch id.
const LAUNCH_ID: &str = "L4unch-1d_of_a_host_session_0123456789abcde";

fn launch_ask() -> LaunchRequest {
    LaunchRequest { client_id: "app".into(), launch_id: Zeroizing::new(LAUNCH_ID.into()), roles: None, ttl_secs: None }
}

fn browser(secret: &str) -> BrowserAuthorizeRequest {
    BrowserAuthorizeRequest { launch_session: Zeroizing::new(secret.into()), authorize: ask() }
}

async fn mint_with(
    fx: &Fx,
    authorizer: &dyn Authorizer,
    entity: &str,
    l: &LaunchRequest,
) -> Result<LaunchIssued, Refusal> {
    let cfg = fx.cfg().await;
    launch::mint(&fx.deps(authorizer), cfg.as_ref(), l, entity, "", None, Utc::now()).await
}

async fn mint(fx: &Fx, entity: &str, l: &LaunchRequest) -> Result<LaunchIssued, Refusal> {
    mint_with(fx, &fx.dir.gate(), entity, l).await
}

async fn browse_with(
    fx: &Fx,
    authorizer: &dyn Authorizer,
    b: &BrowserAuthorizeRequest,
    now: DateTime<Utc>,
) -> Result<Authorized, Refusal> {
    let cfg = fx.cfg().await;
    launch::authorize(&fx.deps(authorizer), cfg.as_ref(), b, None, now).await
}

async fn browse(fx: &Fx, b: &BrowserAuthorizeRequest) -> Result<Authorized, Refusal> {
    browse_with(fx, &fx.dir.gate(), b, Utc::now()).await
}

fn sessions(fx: &Fx) -> usize {
    fx.mem.count_under(LAUNCH_SESSION_PREFIX)
}

fn events_text(events: &[(&'static str, serde_json::Map<String, Value>)]) -> String {
    Value::Array(events.iter().map(|(_, f)| Value::Object(f.clone())).collect()).to_string()
}

const UNKNOWN: Refusal = Refusal::LoginRequired("unknown_or_used_launch_session");

// ─── Happy path ─────────────────────────────────────────────────────

#[tokio::test]
async fn a_launch_session_signs_the_browser_in_once_end_to_end() {
    let fx = fixture().await;
    let minted = mint(&fx, "e-alice", &launch_ask()).await.unwrap();
    assert_eq!((minted.client_id.as_str(), minted.environment.as_str()), ("app", "prod"));
    assert_eq!(minted.roles, ["ops", "readonly"]);
    assert_eq!(minted.authorization_endpoint, format!("{ISSUER}/authorize"));
    assert_eq!(minted.cookie_origin, "https://vault.example.com");
    assert_eq!(minted.max_age_secs, launch::DEFAULT_TTL_SECS);
    assert_eq!(minted.launch_id_sha256, sha256_hex(LAUNCH_ID.as_bytes()));
    assert!((minted.expires_at - Utc::now()).num_seconds() <= 120);
    assert_eq!(sessions(&fx), 1);

    // Stored only as a digest: neither the secret, its random part nor the
    // launch id is anywhere in storage.
    let random = minted.secret.split_once('.').unwrap().1.to_string();
    assert_eq!(random.len(), 43, "256 random bits");
    for needle in [minted.secret.as_str(), random.as_str(), LAUNCH_ID] {
        assert!(!fx.mem.holds(needle.as_bytes()), "storage holds {needle}");
    }
    let keys = fx.mem.keys_under(LAUNCH_SESSION_PREFIX);
    assert!(keys[0].ends_with(&sha256_hex(minted.secret.as_bytes())));

    let ok = browse(&fx, &browser(&minted.secret)).await.unwrap();
    assert!(ok.redirect_to.starts_with(&format!("{REDIRECT}?")));
    let q: std::collections::HashMap<String, String> =
        url::Url::parse(&ok.redirect_to).unwrap().query_pairs().into_owned().collect();
    assert_eq!((q["code"].as_str(), q["state"].as_str()), (ok.code.as_str(), "st-123"));
    assert_eq!(ok.roles, ["ops", "readonly"]);
    assert_eq!(sessions(&fx), 0, "the session was consumed");

    // The RP redeems the code with its secret and PKCE verifier; an
    // independent RP library accepts the ID token.
    let issued = fx.token(&fx.redeem(&ok.code)).await.unwrap();
    let keyset: CoreJsonWebKeySet = serde_json::from_value(jwks_of(&fx).await).unwrap();
    let verifier = CoreIdTokenVerifier::new_public_client(
        ClientId::new("app".into()),
        IssuerUrl::new(ISSUER.into()).unwrap(),
        keyset,
    );
    let id_token: CoreIdToken = issued.id_token.parse().unwrap();
    let claims = id_token.claims(&verifier, &Nonce::new("n-0S6_WzA2Mj".into())).unwrap();
    assert_eq!(claims.subject().as_str(), "e-alice");

    // The gate decided at mint, at the code and at the token.
    assert_eq!(
        fx.dir.issue_events.take(),
        ["idp.issue:oidc-launch-session:allow", "idp.issue:oidc-authorize:allow", "idp.issue:oidc:allow"]
    );
    let events = fx.audit.take();
    let names: Vec<&str> = events.iter().map(|(n, _)| *n).collect();
    assert_eq!(names, [events::LAUNCH_SESSION, events::LAUNCH_SESSION_CONSUMED, events::TOKEN]);
    for (_, f) in &events[..2] {
        assert_eq!(f["session_id"], json!(minted.session_id));
        assert_eq!(f["launch_id_sha256"], json!(minted.launch_id_sha256));
    }
    assert_eq!(events[1].1["redirect_uri"], json!(REDIRECT));
    let text = events_text(&events);
    for secret in [minted.secret.as_str(), random.as_str(), LAUNCH_ID, ok.code.as_str(), issued.id_token.as_str()] {
        assert!(!text.contains(secret), "an audit event holds {secret}");
    }

    // Replay: the cookie works once.
    assert_eq!(browse(&fx, &browser(&minted.secret)).await.err(), Some(UNKNOWN));
    assert_eq!(fx.reasons(), [format!("{}:unknown_or_used_launch_session", events::REFUSED)]);
}

#[tokio::test]
async fn the_session_decides_the_roles_not_the_browser() {
    let fx = fixture().await;
    let mut l = launch_ask();
    l.roles = Some(vec!["readonly".into()]);
    let minted = mint(&fx, "e-alice", &l).await.unwrap();
    assert_eq!(minted.roles, ["readonly"]);
    let mut b = browser(&minted.secret);
    b.authorize.roles = Some(vec!["ops".into()]);
    let ok = browse(&fx, &b).await.unwrap();
    assert_eq!(ok.roles, ["readonly"], "a browser cannot widen the roles");
    let issued = fx.token(&fx.redeem(&ok.code)).await.unwrap();
    assert_eq!(verify_rs256(&issued.id_token, &jwks_of(&fx).await).unwrap().1["roles"], json!(["readonly"]));
}

// ─── Browser refusals ───────────────────────────────────────────────

#[tokio::test]
async fn any_refused_request_burns_the_session_and_never_redirects() {
    let fx = fixture().await;
    let mismatch = Refusal::LoginRequired("launch_session_client_mismatch");
    let cases: Vec<(&str, Box<dyn Fn(&mut AuthorizeRequest)>, Refusal)> = vec![
        (
            "unregistered redirect",
            Box::new(|a| a.redirect_uri = "https://evil.example.com/oidc/callback".into()),
            Refusal::InvalidRedirectUri,
        ),
        ("redirect prefix", Box::new(|a| a.redirect_uri = format!("{REDIRECT}/x")), Refusal::InvalidRedirectUri),
        ("redirect query", Box::new(|a| a.redirect_uri = format!("{REDIRECT}?next=x")), Refusal::InvalidRedirectUri),
        (
            "other client's uri",
            Box::new(|a| a.redirect_uri = "https://other.example.com/cb".into()),
            Refusal::InvalidRedirectUri,
        ),
        ("implicit", Box::new(|a| a.response_type = "token".into()), Refusal::UnsupportedResponseType),
        ("no openid", Box::new(|a| a.scope = "profile".into()), Refusal::InvalidScope),
        ("no pkce", Box::new(|a| a.code_challenge = None), Refusal::InvalidRequest("pkce_required")),
        (
            "plain pkce",
            Box::new(|a| a.code_challenge_method = Some("plain".into())),
            Refusal::InvalidRequest("pkce_s256_required"),
        ),
        (
            "short challenge",
            Box::new(|a| a.code_challenge = Some("abc".into())),
            Refusal::InvalidRequest("malformed_code_challenge"),
        ),
        (
            "header in state",
            Box::new(|a| a.state = Some("a\r\nLocation: https://evil.example.com".into())),
            Refusal::InvalidRequest("malformed_state_or_nonce"),
        ),
        ("unknown client", Box::new(|a| a.client_id = "ghost".into()), Refusal::InvalidClient),
        ("malformed client", Box::new(|a| a.client_id = "../app".into()), Refusal::InvalidClient),
        // Same environment, another relying party: the cookie is the app's.
        ("other client", Box::new(|a| a.client_id = "other".into()), mismatch),
    ];
    for (what, mutate, want) in cases {
        let minted = mint(&fx, "e-alice", &launch_ask()).await.unwrap();
        fx.audit.take();
        let mut b = browser(&minted.secret);
        mutate(&mut b.authorize);
        assert_eq!(browse(&fx, &b).await.err(), Some(want), "{what}");
        let events = fx.audit.take();
        assert_eq!(events.len(), 1, "{what}");
        let (name, f) = &events[0];
        assert_eq!(
            (*name, f["stage"].as_str(), f["reason"].as_str()),
            (events::REFUSED, Some("launch-session-authorize"), Some(want.reason())),
            "{what}"
        );
        assert_eq!(f["session_id"], json!(minted.session_id), "{what}");
        assert_eq!(f["entity_id"], json!("e-alice"), "{what}");
        assert_eq!(sessions(&fx), 0, "{what}: the session is burned");
        // Correcting the request does not bring it back.
        assert_eq!(browse(&fx, &browser(&minted.secret)).await.err(), Some(UNKNOWN), "{what}");
        fx.audit.take();
    }
    assert_eq!(fx.codes_stored(), 0, "no code was minted");
    let gate = fx.dir.issue_events.take();
    assert!(gate.iter().all(|e| e == "idp.issue:oidc-launch-session:allow"), "none reached the code gate: {gate:?}");
}

#[tokio::test]
async fn an_expired_session_is_refused_and_burned() {
    let fx = fixture().await;
    let mut l = launch_ask();
    l.ttl_secs = Some(launch::MIN_TTL_SECS);
    let minted = mint(&fx, "e-alice", &l).await.unwrap();
    let at_expiry = minted.expires_at;
    let late = browse_with(&fx, &fx.dir.gate(), &browser(&minted.secret), at_expiry).await;
    assert_eq!(late.err(), Some(Refusal::LoginRequired("launch_session_expired")));
    assert_eq!(sessions(&fx), 0);
    assert_eq!(browse(&fx, &browser(&minted.secret)).await.err(), Some(UNKNOWN));

    // Just before expiry it works.
    let minted = mint(&fx, "e-alice", &l).await.unwrap();
    let just_in_time = minted.expires_at - Duration::seconds(1);
    assert!(browse_with(&fx, &fx.dir.gate(), &browser(&minted.secret), just_in_time).await.is_ok());

    // Expired sessions are pruned by the next mint.
    let stale = mint(&fx, "e-alice", &l).await.unwrap();
    assert_eq!(sessions(&fx), 1);
    let cfg = fx.cfg().await;
    let later = Utc::now() + Duration::seconds(60);
    launch::mint(&fx.deps(&fx.dir.gate()), cfg.as_ref(), &l, "e-alice", "", None, later).await.unwrap();
    assert_eq!(sessions(&fx), 1, "the stale session was pruned");
    assert_eq!(browse(&fx, &browser(&stale.secret)).await.err(), Some(UNKNOWN));
}

#[tokio::test]
async fn a_session_does_not_follow_a_client_id_into_another_environment() {
    let fx = fixture().await;
    let minted = mint(&fx, "e-alice", &launch_ask()).await.unwrap();
    // The client is deleted and its id re-registered in `dev`, where alice
    // is also entitled: still not the relying party the session was for.
    fx.store.delete_client("app").await.unwrap().unwrap();
    let w = ClientWrite {
        client_id: "app".into(),
        environment: Some("dev".into()),
        redirect_uris: Some(vec![REDIRECT.into()]),
        ..Default::default()
    };
    fx.store.put_client(&fx.dir.authz, w, Utc::now()).await.unwrap();
    let got = browse(&fx, &browser(&minted.secret)).await.err();
    assert_eq!(got, Some(Refusal::LoginRequired("launch_session_client_mismatch")));
    assert_eq!(fx.codes_stored(), 0);
}

// ─── The gate at both steps ─────────────────────────────────────────

#[tokio::test]
async fn mint_denials_come_from_the_gate_and_store_nothing() {
    let fx = fixture().await;
    let mut dba = launch_ask();
    dba.roles = Some(vec!["dba".into()]);
    for (entity, l, gate) in [
        ("e-dora", launch_ask(), DenyReason::IdentityDisabled),
        ("e-remy", launch_ask(), DenyReason::IdentityRemoved),
        ("e-nora", launch_ask(), DenyReason::NotEntitled),
        ("e-ghost", launch_ask(), DenyReason::NoIdentity),
        ("e-alice", dba, DenyReason::RoleNotEntitled),
    ] {
        assert_eq!(mint(&fx, entity, &l).await.err(), Some(Refusal::Denied(gate)), "{entity}");
        assert_eq!(
            fx.dir.issue_events.take(),
            [format!("idp.issue-denied:{}:{}", launch::LAUNCH_PROVIDER, gate.as_str())],
            "{entity}"
        );
        let events = fx.audit.take();
        let f = &events[0].1;
        assert_eq!((f["stage"].as_str(), f["gate_reason"].as_str()), (Some("launch-session"), Some(gate.as_str())));
        assert_eq!(f["launch_id_sha256"], json!(sha256_hex(LAUNCH_ID.as_bytes())));
        assert!(!events_text(&events).contains(LAUNCH_ID));
    }
    assert_eq!(sessions(&fx), 0);
}

#[tokio::test]
async fn the_code_step_asks_the_gate_again() {
    let fx = fixture().await;
    let minted = mint(&fx, "e-alice", &launch_ask()).await.unwrap();
    fx.dir.posix.transition("e-alice", IdentityState::Disabled, None).await.unwrap();
    let denied = browse(&fx, &browser(&minted.secret)).await.err();
    assert_eq!(denied, Some(Refusal::Denied(DenyReason::IdentityDisabled)));
    assert_eq!(
        fx.dir.issue_events.take(),
        ["idp.issue:oidc-launch-session:allow", "idp.issue-denied:oidc-authorize:identity_disabled"]
    );
    assert_eq!((fx.codes_stored(), sessions(&fx)), (0, 0));

    // A role revoked between mint and use denies the whole request.
    fx.dir.posix.transition("e-alice", IdentityState::Active, None).await.unwrap();
    let minted = mint(&fx, "e-alice", &launch_ask()).await.unwrap();
    let grant = crate::entitlement::store::EntitlementWrite {
        entity_id: "e-alice".into(),
        environment: "prod".into(),
        roles: vec!["ops".into()],
        not_after: None,
        source: crate::entitlement::model::EntitlementSource::Manual,
        granted_by: "root".into(),
    };
    fx.dir.authz.put_entitlement(&fx.dir.posix, grant, Utc::now()).await.unwrap();
    let denied = browse(&fx, &browser(&minted.secret)).await.err();
    assert_eq!(denied, Some(Refusal::Denied(DenyReason::RoleNotEntitled)));
}

/// Mutation check: skip the gate and the denials above turn into a
/// session and a code. The refusals therefore depend on the gate calls.
#[tokio::test]
async fn without_the_gate_a_disabled_identity_would_sign_in() {
    let fx = fixture().await;
    let skip = fx.dir.skip_gate();
    assert!(mint_with(&fx, &skip, "e-dora", &launch_ask()).await.is_ok());
    let minted = mint(&fx, "e-alice", &launch_ask()).await.unwrap();
    fx.dir.posix.transition("e-alice", IdentityState::Disabled, None).await.unwrap();
    assert!(browse_with(&fx, &skip, &browser(&minted.secret), Utc::now()).await.is_ok());
}

// ─── Malformed input ────────────────────────────────────────────────

#[tokio::test]
async fn malformed_mint_requests_are_refused_before_the_gate() {
    let fx = fixture().await;
    let long = "a".repeat(129);
    for bad in [
        "",
        "too-short",
        long.as_str(),
        "has space in it and is long enough",
        "slash/in/the/launch/id/xx",
        "dot.in.the.launch.id.xxxx",
    ] {
        let l = LaunchRequest { launch_id: Zeroizing::new(bad.into()), ..launch_ask() };
        assert_eq!(
            mint(&fx, "e-alice", &l).await.err(),
            Some(Refusal::InvalidRequest("malformed_launch_id")),
            "{bad:?}"
        );
    }
    for ttl in [0, launch::MIN_TTL_SECS - 1, launch::MAX_TTL_SECS + 1, u64::MAX] {
        let l = LaunchRequest { ttl_secs: Some(ttl), ..launch_ask() };
        assert_eq!(mint(&fx, "e-alice", &l).await.err(), Some(Refusal::InvalidRequest("invalid_ttl")), "{ttl}");
    }
    for client in ["ghost", "../app", ""] {
        let l = LaunchRequest { client_id: client.into(), ..launch_ask() };
        assert_eq!(mint(&fx, "e-alice", &l).await.err(), Some(Refusal::InvalidClient), "{client:?}");
    }
    assert!(fx.dir.issue_events.take().is_empty(), "none of these reached the gate");
    assert_eq!(sessions(&fx), 0);
    for ttl in [launch::MIN_TTL_SECS, launch::MAX_TTL_SECS] {
        let l = LaunchRequest { ttl_secs: Some(ttl), ..launch_ask() };
        assert_eq!(mint(&fx, "e-alice", &l).await.unwrap().max_age_secs, ttl);
    }

    // Off: nothing is minted or accepted.
    let minted = mint(&fx, "e-alice", &launch_ask()).await.unwrap();
    fx.store.put_config(OidcConfigUpdate { enabled: Some(false), ..Default::default() }, Utc::now()).await.unwrap();
    assert_eq!(mint(&fx, "e-alice", &launch_ask()).await.err(), Some(Refusal::NotEnabled));
    assert_eq!(browse(&fx, &browser(&minted.secret)).await.err(), Some(Refusal::NotEnabled));
}

#[tokio::test]
async fn garbage_and_other_secrets_are_not_launch_sessions() {
    let fx = fixture().await;
    assert_eq!(browse(&fx, &browser("")).await.err(), Some(Refusal::LoginRequired("launch_session_missing")));
    let forged = format!("{}.{}", Utc::now().timestamp() + 60, "A".repeat(43));
    for bad in ["abc", "123.", "x.y", &format!("{}.{}", "9".repeat(13), "a".repeat(43)), forged.as_str()] {
        assert_eq!(browse(&fx, &browser(bad)).await.err(), Some(UNKNOWN), "{bad}");
    }

    // An authorization code is not a launch session, and the attempt does
    // not burn the code; a launch session is not a code either.
    let code = fx.authorize("e-alice", &ask()).await.unwrap().code;
    assert_eq!(browse(&fx, &browser(&code)).await.err(), Some(UNKNOWN));
    let minted = mint(&fx, "e-alice", &launch_ask()).await.unwrap();
    assert_eq!(fx.token(&fx.redeem(&minted.secret)).await.err(), Some(Refusal::InvalidGrant("unknown_or_used_code")));
    assert!(fx.token(&fx.redeem(&code)).await.is_ok(), "the code still redeems");
    assert!(browse(&fx, &browser(&minted.secret)).await.is_ok(), "the session still works");
}

// ─── Records and audit ──────────────────────────────────────────────

#[tokio::test]
async fn session_records_refuse_unknown_versions_and_fields() {
    let fx = fixture().await;
    for (field, value) in [("version", json!(2)), ("surprise", json!(true))] {
        let minted = mint(&fx, "e-alice", &launch_ask()).await.unwrap();
        let key = fx.mem.keys_under(LAUNCH_SESSION_PREFIX).pop().unwrap();
        let mut rec: Value = serde_json::from_slice(&fx.mem.raw_get(&key).unwrap()).unwrap();
        rec[field] = value;
        fx.mem.raw_put(&key, &serde_json::to_vec(&rec).unwrap());
        assert_eq!(browse(&fx, &browser(&minted.secret)).await.err(), Some(Refusal::Internal), "{field}");
        fx.mem.delete(&key).await.unwrap();
    }
    assert_eq!(fx.codes_stored(), 0);
}

#[tokio::test]
async fn a_session_or_code_whose_event_cannot_be_recorded_is_not_returned() {
    let fx = fixture().await;
    *fx.audit.refuse.lock().unwrap() = Some(events::LAUNCH_SESSION);
    assert_eq!(mint(&fx, "e-alice", &launch_ask()).await.err(), Some(Refusal::Internal));

    *fx.audit.refuse.lock().unwrap() = None;
    let minted = mint(&fx, "e-alice", &launch_ask()).await.unwrap();
    *fx.audit.refuse.lock().unwrap() = Some(events::LAUNCH_SESSION_CONSUMED);
    assert_eq!(browse(&fx, &browser(&minted.secret)).await.err(), Some(Refusal::Internal));
    assert_eq!(browse(&fx, &browser(&minted.secret)).await.err(), Some(UNKNOWN), "still consumed");
}

#[test]
fn login_required_is_a_401_with_the_oidc_error_code() {
    let r = Refusal::LoginRequired("launch_session_expired");
    assert_eq!((r.error_code(), r.status(), r.reason()), ("login_required", 401, "launch_session_expired"));
    assert!(matches!(RvError::from(r), RvError::ErrResponseStatus(401, m) if m.starts_with("login_required:")));
}
