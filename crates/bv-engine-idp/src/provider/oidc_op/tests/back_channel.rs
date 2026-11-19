//! The back channel (T546) under an independent RP library: `openidconnect`
//! discovers the OP and fetches the JWKS (checking status and content
//! type), redeems codes with `client_secret_basic` and `client_secret_post`
//! as form requests, verifies the ID token, and reads refusals as RFC 6749
//! §5.2 errors. Its HTTP client is the wire format bv-server sends.

use openidconnect::{
    core::{CoreClient, CoreClientAuthMethod, CoreErrorResponseType, CoreProviderMetadata, CoreTokenType},
    AuthType, AuthorizationCode, ClientSecret, EndpointMaybeSet, EndpointNotSet, EndpointSet, HttpRequest,
    HttpResponse, OAuth2TokenResponse, PkceCodeVerifier, RedirectUrl, RequestTokenError, StandardErrorResponse,
    TokenResponse,
};

use super::*;
use crate::provider::oidc_op::back_channel::{self, OAuthError};

fn header<'a>(req: &'a HttpRequest, name: &str) -> Option<&'a str> {
    req.headers().get(name).and_then(|v| v.to_str().ok())
}

/// The OP's three back-channel URLs, answered as bv-server answers them.
async fn serve(fx: &Fx, req: HttpRequest) -> Result<HttpResponse, std::io::Error> {
    let now = Utc::now();
    let answer = match (req.method().as_str(), req.uri().path()) {
        ("GET", "/v2/idp/oidc/.well-known/openid-configuration") => {
            back_channel::document_answer(&discovery(&fx.cfg().await.unwrap()), back_channel::DISCOVERY_CACHE_CONTROL)
        }
        ("GET", "/v2/idp/oidc/jwks") => {
            let ring = fx.store.keys.ensure(now).await.unwrap();
            back_channel::document_answer(&jwks(&ring, now).unwrap(), back_channel::JWKS_CACHE_CONTROL)
        }
        ("POST", "/v2/idp/oidc/token") => {
            match back_channel::parse_token_request(
                header(&req, "content-type"),
                header(&req, "authorization"),
                req.body(),
            ) {
                Err(e) => e.answer(),
                Ok(form) => match fx.token(&form.request).await {
                    Ok(issued) => back_channel::token_answer(&issued.response_data()).unwrap_or_else(|e| e.answer()),
                    Err(r) => OAuthError::from_flow(&RvError::from(r), form.auth).answer(),
                },
            }
        }
        other => panic!("the RP asked for {other:?}"),
    };
    let mut resp = openidconnect::http::Response::builder().status(answer.status);
    for (name, value) in &answer.headers {
        resp = resp.header(*name, value.as_str());
    }
    Ok(resp.body(answer.body.to_vec()).unwrap())
}

/// The client `from_provider_metadata` builds: auth and token URLs set.
type Rp = CoreClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointMaybeSet, EndpointMaybeSet>;

fn client(meta: &CoreProviderMetadata, secret: &str, auth: AuthType) -> Rp {
    CoreClient::from_provider_metadata(
        meta.clone(),
        ClientId::new("app".into()),
        Some(ClientSecret::new(secret.into())),
    )
    .set_redirect_uri(RedirectUrl::new(REDIRECT.into()).unwrap())
    .set_auth_type(auth)
}

fn server_error<RE: std::error::Error>(
    r: Result<impl std::fmt::Debug, RequestTokenError<RE, StandardErrorResponse<CoreErrorResponseType>>>,
) -> CoreErrorResponseType {
    match r {
        Err(RequestTokenError::ServerResponse(e)) => e.error().clone(),
        other => panic!("expected an RFC 6749 error response, got {other:?}"),
    }
}

#[tokio::test]
async fn a_standard_rp_library_discovers_redeems_and_verifies() {
    let fx = fixture().await;
    let fxr = &fx;
    let http = move |req: HttpRequest| async move { serve(fxr, req).await };

    let meta = CoreProviderMetadata::discover_async(IssuerUrl::new(ISSUER.into()).unwrap(), &http).await.unwrap();
    assert_eq!(meta.token_endpoint().unwrap().as_str(), format!("{ISSUER}/token"));
    assert_eq!(
        meta.token_endpoint_auth_methods_supported(),
        Some(&vec![CoreClientAuthMethod::ClientSecretBasic, CoreClientAuthMethod::ClientSecretPost])
    );
    assert_eq!(meta.jwks().keys().len(), 1, "the JWKS was fetched from jwks_uri");

    for (auth, label) in [(AuthType::BasicAuth, "basic"), (AuthType::RequestBody, "post")] {
        let rp = client(&meta, &fx.secret, auth);
        let ok = fx.authorize("e-alice", &ask()).await.unwrap();
        let redeem = || {
            rp.exchange_code(AuthorizationCode::new(ok.code.to_string()))
                .unwrap()
                .set_pkce_verifier(PkceCodeVerifier::new(VERIFIER.into()))
        };
        let tokens = redeem().request_async(&http).await.unwrap();
        assert_eq!(tokens.token_type(), &CoreTokenType::Bearer, "{label}");
        assert_eq!(tokens.expires_in(), Some(std::time::Duration::from_secs(300)), "{label}");
        let id_token = tokens.id_token().expect("an ID token");
        let claims = id_token.claims(&rp.id_token_verifier(), &Nonce::new("n-0S6_WzA2Mj".into())).unwrap();
        assert_eq!(claims.subject().as_str(), "e-alice", "{label}");
        assert_eq!(claims.preferred_username().unwrap().as_str(), "alice", "{label}");

        // The code works once.
        assert_eq!(server_error(redeem().request_async(&http).await), CoreErrorResponseType::InvalidGrant, "{label}");
    }

    // A wrong secret, by either method, is invalid_client; it does not
    // burn the code (the client authenticates first).
    let ok = fx.authorize("e-alice", &ask()).await.unwrap();
    for auth in [AuthType::BasicAuth, AuthType::RequestBody] {
        let rp = client(&meta, "not-the-secret", auth);
        let r = rp
            .exchange_code(AuthorizationCode::new(ok.code.to_string()))
            .unwrap()
            .set_pkce_verifier(PkceCodeVerifier::new(VERIFIER.into()))
            .request_async(&http)
            .await;
        assert_eq!(server_error(r), CoreErrorResponseType::InvalidClient);
    }
    // The other client's secret is the same answer.
    let rp = client(&meta, &fx.other_secret, AuthType::BasicAuth);
    let r = rp.exchange_code(AuthorizationCode::new(ok.code.to_string())).unwrap().request_async(&http).await;
    assert_eq!(server_error(r), CoreErrorResponseType::InvalidClient);

    // A wrong verifier is invalid_grant and burns the code.
    let rp = client(&meta, &fx.secret, AuthType::BasicAuth);
    let wrong = PkceCodeVerifier::new("x".repeat(43));
    let r = rp.exchange_code(AuthorizationCode::new(ok.code.to_string())).unwrap().set_pkce_verifier(wrong);
    assert_eq!(server_error(r.request_async(&http).await), CoreErrorResponseType::InvalidGrant);
    assert_eq!(fx.codes_stored(), 0);
}
