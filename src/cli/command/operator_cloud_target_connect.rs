//! `bvault operator cloud-target connect` — interactive OAuth
//! consent flow for the consumer-drive `FileTarget`s (OneDrive /
//! Google Drive / Dropbox).
//!
//! Orchestration:
//!
//!   1. Resolve the `OAuthProvider` for the requested target kind.
//!   2. Bind a loopback listener + compose the authorization URL
//!      (`ConsentSession::begin_consent`).
//!   3. Print the URL (and, by default, open it in the user's
//!      browser via `open` / `xdg-open` / `rundll32`).
//!   4. Block on the loopback callback.
//!   5. Exchange the authorization code for `{access, refresh}`
//!      tokens.
//!   6. Persist the refresh token to the destination named by
//!      `--credentials-ref` via the creds resolver's write side.
//!
//! The CLI itself does not need a running BastionVault server —
//! this is purely a client-side ceremony. The refresh token is
//! what gets persisted; later, when the `FileBackend` boots with
//! `target = "onedrive"` (etc.), the target reads that refresh
//! token and exchanges it for an access token on demand.
//!
//! Shipping the CLI now — before the OneDrive / Google Drive /
//! Dropbox targets (phases 4–6) — is deliberate: the consent flow
//! itself works against any of these providers end-to-end, so
//! operators can validate their `client_id` + scopes configuration
//! before the storage-path work lands.

use std::{process::Command, time::Duration};

use clap::Parser;

use crate::{
    cli::command::CommandExecutor,
    errors::RvError,
    storage::physical::file::{creds, oauth},
};

#[derive(Parser)]
#[command(
    author,
    version,
    about = "Run the OAuth consent flow for a cloud storage target",
    long_about = r#"Interactively connect a cloud storage target by running an OAuth
authorization-code flow with PKCE. On success, the returned refresh
token is written to the location named by --credentials-ref so the
running vault can consume it on subsequent starts.

Examples:

  # OneDrive, writing the refresh token to a local file:
  $ bvault operator cloud-target connect \
        --target=onedrive \
        --client-id=<your-app-client-id> \
        --credentials-ref=file:/etc/bvault/onedrive-refresh

  # Google Drive, printing the URL for a headless host (no browser):
  $ bvault operator cloud-target connect \
        --target=gdrive \
        --client-id=<your-app-client-id> \
        --credentials-ref=file:./gdrive-refresh \
        --no-browser

Notes:

  * BastionVault does not ship consumer-provider client secrets.
    Register your own OAuth application with the target provider
    and pass its --client-id here.
  * --credentials-ref uses the same URI grammar as the server config
    (file: / env: / inline: / keychain:). Only file: is writable
    today; the others return a clear error.
  * The flow uses PKCE; no --client-secret is needed unless your
    OAuth application is configured as a confidential client."#
)]
pub struct CloudTargetConnect {
    /// Target kind to connect: `onedrive` / `gdrive` / `dropbox`.
    #[arg(long, value_name = "KIND")]
    target: String,

    /// OAuth client ID (provider-registered application id).
    #[arg(long, value_name = "ID")]
    client_id: String,

    /// Optional OAuth client secret for confidential clients. Most
    /// distributed apps are public clients (PKCE only) and should
    /// leave this unset.
    #[arg(long, value_name = "SECRET")]
    client_secret: Option<String>,

    /// Where to persist the refresh token on success. Uses the
    /// same URI grammar as the server-config `credentials_ref`.
    #[arg(long, value_name = "REF")]
    credentials_ref: String,

    /// Loopback host for the consent callback listener. Default
    /// `127.0.0.1`. IPv6 deployments can pass `[::1]`.
    #[arg(long, value_name = "HOST", default_value = "127.0.0.1")]
    bind_host: String,

    /// Skip the browser-launch step and just print the URL. Useful
    /// on headless servers or when the user wants to copy the URL
    /// to a different machine's browser.
    #[arg(long, default_value_t = false)]
    no_browser: bool,

    /// How many seconds to wait for the browser callback. Default
    /// 5 minutes — enough time for the user to authenticate and
    /// consent without holding the listener open forever.
    #[arg(long, value_name = "SECS", default_value_t = 300)]
    timeout_secs: u64,
}

impl CommandExecutor for CloudTargetConnect {
    // Default `execute` provided by the trait prints errors and
    // exits with code 1. All the work lives in `main`.
    fn main(&self) -> Result<(), RvError> {
        self.run()
    }
}

impl CloudTargetConnect {
    fn run(&self) -> Result<(), RvError> {
        let provider = oauth::well_known_provider(&self.target)?;
        let creds_obj = oauth::OAuthCredentials {
            client_id: self.client_id.clone(),
            client_secret: self.client_secret.clone(),
        };

        // Fixed loopback port so the redirect URI is stable and
        // matches whatever the user registered at the provider's
        // dev console. See `oauth::DEFAULT_LOOPBACK_PORT`.
        let session = oauth::begin_consent(
            &provider,
            &creds_obj,
            &self.bind_host,
            Some(oauth::DEFAULT_LOOPBACK_PORT),
        )?;
        let listener_addr = session
            .listener_addr()
            .map_err(|e| RvError::ErrString(format!("cloud-target connect: local_addr: {e}")))?;
        let consent_url = session.consent_url.clone();
        let redirect_uri = session.redirect_uri.clone();
        let verifier = session.verifier.clone();

        println!("Opening consent URL for target `{}`:", self.target);
        println!("  {}", consent_url);
        println!(
            "Waiting for the browser callback on {}...",
            listener_addr
        );

        if !self.no_browser {
            if let Err(e) = open_browser(consent_url.as_str()) {
                // Soft failure: fall back to the printed URL. The
                // user can copy/paste if the auto-launch fails.
                eprintln!(
                    "Note: could not open browser automatically ({e}). \
                     Copy the URL above into your browser manually."
                );
            }
        } else {
            println!("(--no-browser set; open the URL above in your browser manually.)");
        }

        let callback = session.wait_for_callback(Duration::from_secs(self.timeout_secs))?;
        println!("Callback received — exchanging authorization code for tokens...");

        let token_response =
            oauth::exchange_code(&provider, &creds_obj, &callback.code, &verifier, &redirect_uri)?;

        let refresh_token = token_response.refresh_token.as_deref().ok_or_else(|| {
            RvError::ErrString(format!(
                "cloud-target connect: provider returned no refresh_token \
                 (check that the `offline_access` scope is granted and \
                 that your OAuth application is configured for a refresh \
                 token; for Google you may need --target=gdrive which \
                 automatically sets access_type=offline)"
            ))
        })?;

        creds::persist(&self.credentials_ref, refresh_token.as_bytes())?;

        println!(
            "Success — refresh token persisted to `{}`.",
            self.credentials_ref
        );
        if let Some(secs) = token_response.expires_in {
            println!("Access token valid for ~{secs} seconds; vault will refresh on demand.");
        }
        Ok(())
    }
}

/// Best-effort cross-platform browser launcher. Returns `Err` when
/// no launcher is available; the caller treats that as a soft
/// failure and prints the URL for manual handling.
fn open_browser(url: &str) -> Result<(), RvError> {
    #[cfg(target_os = "macos")]
    let cmd = {
        let mut c = Command::new("open");
        c.arg(url);
        c
    };
    #[cfg(target_os = "windows")]
    let cmd = {
        // `rundll32 url.dll,FileProtocolHandler` is the documented
        // non-shell variant; avoids `cmd /c start`'s argument-
        // escaping pitfalls (URLs with `&` get mangled by `start`).
        let mut c = Command::new("rundll32");
        c.arg("url.dll,FileProtocolHandler").arg(url);
        c
    };
    #[cfg(all(unix, not(target_os = "macos")))]
    let cmd = {
        let mut c = Command::new("xdg-open");
        c.arg(url);
        c
    };
    let mut cmd = cmd;
    cmd.spawn()
        .map(|_| ())
        .map_err(|e| RvError::ErrString(format!("browser launcher: {e}")))
}
