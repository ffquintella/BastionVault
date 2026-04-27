//! `bv-ssh-helper` — target-host helper for the BastionVault SSH OTP
//! mode (Phase 2 of the SSH secret engine).
//!
//! How it slots in
//! ===============
//!
//! Operators install this binary on each managed host and wire it into
//! PAM via `pam_exec`:
//!
//! ```text
//! # /etc/pam.d/sshd
//! auth requisite pam_exec.so quiet expose_authtok /usr/local/sbin/bv-ssh-helper
//! ```
//!
//! `pam_exec` pipes the password the user typed into our stdin (because
//! of `expose_authtok`); we POST it to BastionVault's `/v1/ssh/verify`,
//! and exit 0 on success / non-zero on failure. SSH then treats the
//! auth as accepted (or rejected) accordingly.
//!
//! Configuration
//! =============
//!
//! Read from environment first, falling back to a small TOML-ish
//! `KEY=VALUE` file. The defaults assume root owns `/etc/bv-ssh-helper.conf`
//! mode `0600`; this file holds the BastionVault address and a
//! restricted token (a policy authorising only `ssh/verify`).
//!
//! ```text
//! BV_VAULT_ADDR=https://bvault.internal:8200
//! BV_VAULT_TOKEN=s.…
//! BV_VAULT_MOUNT=ssh             # default `ssh`
//! BV_VAULT_CACERT=/etc/ssl/bv.pem # optional pinned CA
//! ```
//!
//! What's deliberately tiny
//! ========================
//!
//! No retry loop, no backoff, no caching. A failed verify means the
//! user's auth fails this attempt; sshd handles retry semantics. The
//! helper has no persistent state and no log file of its own — it
//! writes a single line to stderr that PAM forwards to syslog.

use std::{
    env, fs,
    io::{self, Read},
    process::ExitCode,
    time::Duration,
};

const DEFAULT_CONF_PATH: &str = "/etc/bv-ssh-helper.conf";
const DEFAULT_MOUNT: &str = "ssh";

struct Config {
    addr: String,
    token: String,
    mount: String,
    cacert: Option<String>,
}

fn load_config() -> Result<Config, String> {
    // Step 1: load any KEY=VALUE pairs from the conf file (if it
    // exists). Step 2: env vars override on top — the env layer is how
    // testing scripts inject without writing the file.
    let conf_path = env::var("BV_SSH_HELPER_CONFIG").unwrap_or_else(|_| DEFAULT_CONF_PATH.into());
    let mut from_file = std::collections::HashMap::new();
    if let Ok(s) = fs::read_to_string(&conf_path) {
        for line in s.lines() {
            let l = line.trim();
            if l.is_empty() || l.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = l.split_once('=') {
                from_file.insert(k.trim().to_string(), v.trim().trim_matches('"').to_string());
            }
        }
    }

    let pick = |key: &str| -> Option<String> {
        env::var(key).ok().or_else(|| from_file.get(key).cloned())
    };

    let addr = pick("BV_VAULT_ADDR")
        .ok_or_else(|| "BV_VAULT_ADDR not set (env or conf file)".to_string())?;
    let token = pick("BV_VAULT_TOKEN")
        .ok_or_else(|| "BV_VAULT_TOKEN not set (env or conf file)".to_string())?;
    let mount = pick("BV_VAULT_MOUNT").unwrap_or_else(|| DEFAULT_MOUNT.to_string());
    let cacert = pick("BV_VAULT_CACERT");

    Ok(Config {
        addr: addr.trim_end_matches('/').to_string(),
        token,
        mount: mount.trim_matches('/').to_string(),
        cacert,
    })
}

fn read_otp_from_stdin() -> Result<String, String> {
    // PAM passes the password through stdin null-terminated when
    // `expose_authtok` is set. Strip the trailing NUL / newline.
    let mut buf = String::new();
    io::stdin()
        .read_to_string(&mut buf)
        .map_err(|e| format!("read stdin: {e}"))?;
    let trimmed = buf
        .trim_end_matches(|c: char| c == '\0' || c == '\n' || c == '\r')
        .to_string();
    if trimmed.is_empty() {
        return Err("empty OTP on stdin".into());
    }
    Ok(trimmed)
}

fn verify(cfg: &Config, otp: &str) -> Result<(), String> {
    let url = format!("{}/v1/{}/verify", cfg.addr, cfg.mount);

    let builder = ureq::config::Config::builder()
        .timeout_global(Some(Duration::from_secs(10)))
        .http_status_as_error(false);
    // CA pinning: when the operator provides a CA bundle, we point
    // ureq's TLS provider at it. Passing the path through is enough
    // for native-tls / rustls integrations that read PEM bundles via
    // env; the helper deliberately doesn't crack open the file
    // itself so the plumbing stays minimal.
    if let Some(ca) = &cfg.cacert {
        // ureq 3.x doesn't expose a per-request CA option; the
        // ergonomic path is to set the standard `SSL_CERT_FILE` env
        // var that rustls-native-certs honours. Doing it here keeps
        // the helper self-contained.
        env::set_var("SSL_CERT_FILE", ca);
    }
    let agent: ureq::Agent = builder.build().into();

    let body = serde_json::json!({ "otp": otp });
    let resp = agent
        .post(&url)
        .header("X-Vault-Token", cfg.token.as_str())
        .send_json(body)
        .map_err(|e| format!("verify request failed: {e}"))?;

    let status = resp.status().as_u16();
    if !(200..300).contains(&status) {
        // Don't echo the body — it may surface error text that
        // accidentally reveals which OTPs are live. Status code is
        // enough for syslog / fail2ban to act on.
        return Err(format!("verify rejected (HTTP {status})"));
    }
    Ok(())
}

fn main() -> ExitCode {
    let cfg = match load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("bv-ssh-helper: config: {e}");
            return ExitCode::from(2);
        }
    };

    let otp = match read_otp_from_stdin() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("bv-ssh-helper: input: {e}");
            return ExitCode::from(3);
        }
    };

    match verify(&cfg, &otp) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("bv-ssh-helper: {e}");
            ExitCode::from(1)
        }
    }
}
