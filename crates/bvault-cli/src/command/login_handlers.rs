//! `bvault login -method=…` handlers.
//!
//! These implement [`LoginHandler`](crate::api::auth::LoginHandler): they read
//! a password off the terminal, build the login request, and POST it through
//! the HTTP [`Client`](crate::api::client::Client). None of that is engine
//! code — it never touches a barrier, a mount or a `VaultCtx` — and it was
//! only inside `src/modules/credential/*/cli.rs` because that is where the
//! backend it drives lives.
//!
//! Keeping them there would have dragged `crate::api` (and with it the HTTP
//! client, `rpassword` and stdin) under every auth-backend crate. They belong
//! with the CLI, which is where the registry that reads them
//! ([`LoginHandlers`](super::auth::LoginHandlers)) already was.
//!
//! The `cert` handler is the disabled stub from the OpenSSL-free build and
//! moved with the others.
//!
//! See roadmaps/workspace-decomposition.md § Phase 3.

use std::io::{self, Write};

use better_default::Default;
use rpassword::read_password;
use serde_json::{Map, Value};

use crate::{
    api::{
        auth::LoginHandler,
        client::Client,
        secret::{Secret, SecretAuth},
        HttpResponse,
    },
    bv_error_response, bv_error_string,
    errors::RvError,
    logical::field::FieldTrait,
};

#[derive(Default)]
pub struct TokenCliHandler;

impl LoginHandler for TokenCliHandler {
    fn auth(&self, client: &Client, data: &Map<String, Value>) -> Result<HttpResponse, RvError> {
        let mut token = data.get("token").and_then(Value::as_str).unwrap_or("").to_string();
        if token.is_empty() {
            let mut writer = io::stdout();
            write!(writer, "Token (will be hidden): ")?;
            writer.flush()?;
            let value = read_password().expect("Failed to read token");
            writeln!(writer)?;
            token = value;
        }

        token = token.trim().to_string();
        if token.is_empty() {
            return Err(bv_error_string!("a token must be passed to auth, please view the help for more information"));
        }

        let lookup = if let Some(lookup_value) = data.get("lookup") {
            lookup_value.as_bool_ex().ok_or(bv_error_string!("Failed to parse \"lookup\" as boolean"))?
        } else {
            true
        };

        if !lookup {
            let auth = SecretAuth { client_token: token.clone(), ..Default::default() };

            let resp = Secret { auth: Some(auth), ..Default::default() };
            let ret = HttpResponse {
                response_status: 200,
                response_data: Some(serde_json::to_value(resp)?),
                ..Default::default()
            };
            return Ok(ret);
        }

        let mut client = client.clone();
        client.token = token;

        let ret = client.token().lookup_self()?;
        let response_value = ret.response_data.ok_or(RvError::ErrResponseDataInvalid)?;
        let secret: Secret = serde_json::from_value(response_value)?;

        let auth = SecretAuth {
            client_token: secret.token_id()?,
            accessor: secret.token_accessor()?,
            policies: secret.token_policies()?,
            token_policies: secret.token_policies()?,
            metadata: secret.token_metadata()?,
            lease_duration: secret.token_ttl()?,
            renewable: secret.token_is_renewable()?,
            ..Default::default()
        };

        let resp = Secret { auth: Some(auth), ..Default::default() };
        let ret = HttpResponse {
            response_status: 200,
            response_data: Some(serde_json::to_value(resp)?),
            ..Default::default()
        };

        Ok(ret)
    }

    fn help(&self) -> String {
        let help = r#"
Usage: bvault login TOKEN [CONFIG K=V...]

The token auth method allows logging in directly with a token. This
can be a token from the "token-create" command or API. There are no
configuration options for this auth method.

Authenticate using a token:

    $ bvault login 96ddf4bc-d217-f3ba-f9bd-017055595017

Authenticate but do not lookup information about the token:

    $ bvault login token=96ddf4bc-d217-f3ba-f9bd-017055595017 lookup=false

This token usually comes from a different source such as the API or via the
built-in "bvault token create" command.

Configuration:

token=<string>
    The token to use for authentication. This is usually provided directly
    via the "bvault login" command.

lookup=<bool>
    If true, it performs a lookup of the token's metadata and policies."#;
        help.trim().to_string()
    }
}

#[derive(Default)]
pub struct UsesPassCliHandler {
    #[default("usepass".to_string())]
    pub default_mount: String,
}

impl LoginHandler for UsesPassCliHandler {
    fn auth(&self, client: &Client, data: &Map<String, Value>) -> Result<HttpResponse, RvError> {
        if data["username"].as_str().is_none() {
            return Err(bv_error_response!("'username' must be specified"));
        }
        let username = data["username"].as_str().unwrap();

        let mut password = data["password"].as_str().unwrap_or("").to_string();
        if password.is_empty() {
            let mut writer = io::stdout();
            write!(writer, "Password (will be hidden): ")?;
            writer.flush()?;
            let value = read_password().expect("Failed to read password");
            writeln!(writer)?;
            password = value;
        }

        let mut payload = serde_json::json!({
            "password": password,
        });
        // Forward an optional TOTP second factor when the caller supplies it
        // (required only for users with MFA enabled).
        if let Some(code) = data.get("totp_code").and_then(|v| v.as_str()) {
            if !code.is_empty() {
                payload["totp_code"] = Value::String(code.to_string());
            }
        }

        let mut mount = data["mount"].as_str().unwrap_or("");
        if mount.is_empty() {
            mount = &self.default_mount;
        }
        let path = format!("auth/{mount}/login/{username}");

        let logical = client.logical();

        logical.write(&path, payload.as_object().cloned())
    }

    fn help(&self) -> String {
        let help = r#"
Usage: bvault login -method=userpass [CONFIG K=V...]

The userpass auth method allows users to authenticate using BastionVault's internal user database.

Authenticate as "sally":

    $ bvault login -method=userpass username=sally
    Password (will be hidden):

Authenticate as "bob":

    $ bvault login -method=userpass username=bob password=password

Configuration:

password=<string>
    Password to use for authentication. If not provided, the CLI will prompt for this on stdin.

username=<string>
    Username to use for authentication.

totp_code=<string>
    TOTP second-factor code. Required only for users with MFA enabled."#;
        help.trim().to_string()
    }
}

/// The retired certificate auth method.
///
/// The legacy implementation depended on OpenSSL for X.509 validation, CRL
/// processing and extension inspection; it stays disabled until it is
/// redesigned on a non-OpenSSL trust model. Kept registered so
/// `bvault login -method=cert` fails with an explanation rather than
/// "unknown method".
#[derive(Default)]
pub struct CertAuthCliHandler;

impl LoginHandler for CertAuthCliHandler {
    fn auth(&self, _client: &Client, _data: &Map<String, Value>) -> Result<HttpResponse, RvError> {
        Err(bv_error_string!("cert auth is disabled in the OpenSSL-free build"))
    }

    fn help(&self) -> String {
        "Usage: bvault login -method=cert\n\nThe legacy cert auth method is disabled in the OpenSSL-free build."
            .to_string()
    }
}
