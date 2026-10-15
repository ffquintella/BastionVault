//! The untrusted-certificate question a web session window asks the
//! operator (features/web-application-connect.md §8.2, T139). Text only:
//! the dialog is native (the page cannot draw over or answer it), and the
//! decision is the gate's (`TlsPinGate::operator_override`).
//!
//! Only the WKWebView shim asks (T139), so off macOS nothing here is called.
//!
//! Server-chosen text (subject, issuer, the platform's reason, which names
//! the host) appears here and nowhere else: it is never logged or audited.

// Only the macOS WKWebView shim calls into this module (T139).
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use chrono::{DateTime, Utc};

use super::web::WebOrigin;
use super::web_tls_pin::PresentedCertificate;

/// Longest platform reason shown; it is server-influenced.
const MAX_REASON_CHARS: usize = 300;

pub const PROMPT_TITLE: &str = "Untrusted TLS certificate";
pub const CONTINUE_LABEL: &str = "Continue";
pub const CANCEL_LABEL: &str = "Don't Continue";

/// What the question says.
pub struct PromptFacts<'a> {
    pub origin: &'a WebOrigin,
    /// The leaf certificate, when it could be read.
    pub leaf: Option<&'a PresentedCertificate>,
    /// The platform's reason for rejecting the certificate.
    pub platform_reason: Option<&'a str>,
    /// Unix seconds, to say "expired" rather than print a date to compare.
    pub now: i64,
    /// A form or http-auth session: accepting sends the stored credential.
    pub fills_credential: bool,
}

fn date(ts: i64) -> String {
    DateTime::<Utc>::from_timestamp(ts, 0).map(|d| d.format("%Y-%m-%d").to_string()).unwrap_or_else(|| ts.to_string())
}

fn bounded(s: &str) -> String {
    let s = s.trim();
    if s.chars().count() <= MAX_REASON_CHARS {
        s.to_string()
    } else {
        let mut cut: String = s.chars().take(MAX_REASON_CHARS).collect();
        cut.push('\u{2026}');
        cut
    }
}

pub fn prompt_message(f: &PromptFacts<'_>) -> String {
    let mut m = format!("{} presented a TLS certificate this computer does not trust.\n", f.origin);
    if let Some(reason) = f.platform_reason.filter(|r| !r.trim().is_empty()) {
        m.push_str(&format!("\n{}\n", bounded(reason)));
    }
    match f.leaf {
        Some(leaf) => {
            m.push('\n');
            if leaf.not_after < f.now {
                m.push_str(&format!("Expired: {}\n", date(leaf.not_after)));
            } else if leaf.not_before > f.now {
                m.push_str(&format!("Not valid before: {}\n", date(leaf.not_before)));
            } else {
                m.push_str(&format!("Valid until: {}\n", date(leaf.not_after)));
            }
            if leaf.self_issued {
                m.push_str("Self-signed\n");
            }
            m.push_str(&format!("Subject: {}\n", leaf.subject));
            m.push_str(&format!("Issued by: {}\n", leaf.issuer));
            m.push_str(&format!("Key fingerprint: {}\n", leaf.pin));
        }
        None => m.push_str("\nThe certificate could not be read.\n"),
    }
    m.push_str(
        "\nSomeone intercepting the connection would present a certificate like this one. Continue only if \
         you have checked the key fingerprint with whoever runs the server.\n",
    );
    m.push_str(&format!(
        "\nContinue accepts this exact key for {} until this session closes. It is not saved.",
        f.origin
    ));
    if f.fills_credential {
        m.push_str(" BastionVault will then sign in by sending the stored credential to this server.");
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(not_before: i64, not_after: i64) -> PresentedCertificate {
        PresentedCertificate {
            depth: 0,
            pin: "sha256:ab".into(),
            pin_base64: "qw==".into(),
            subject: "CN=km.example.com".into(),
            issuer: "CN=Example CA".into(),
            not_before,
            not_after,
            self_issued: false,
            ca: false,
        }
    }

    #[test]
    fn the_message_names_the_key_the_scope_and_the_credential() {
        let o = WebOrigin::parse_config("https://km.example.com", false).unwrap();
        let l = leaf(1_700_000_000, 1_754_000_000);
        let m = prompt_message(&PromptFacts {
            origin: &o,
            leaf: Some(&l),
            platform_reason: Some("“km.example.com” certificate is expired"),
            now: 1_790_000_000,
            fills_credential: true,
        });
        assert!(m.starts_with("https://km.example.com presented"), "{m}");
        assert!(m.contains("Expired: 2025-07-31"), "{m}");
        assert!(m.contains("Key fingerprint: sha256:ab"), "{m}");
        assert!(m.contains("until this session closes"), "{m}");
        assert!(m.contains("sending the stored credential"), "{m}");
    }

    #[test]
    fn an_open_session_promises_no_credential_and_long_reasons_are_cut() {
        let o = WebOrigin::parse_config("https://km.example.com", false).unwrap();
        let l = leaf(1_800_000_000, 1_900_000_000);
        let long = "x".repeat(1_000);
        let m = prompt_message(&PromptFacts {
            origin: &o,
            leaf: Some(&l),
            platform_reason: Some(&long),
            now: 1_790_000_000,
            fills_credential: false,
        });
        assert!(!m.contains("credential"), "{m}");
        assert!(m.contains("Not valid before:"), "{m}");
        assert!(!m.contains(&"x".repeat(301)), "reason is bounded");
        let unread = prompt_message(&PromptFacts {
            origin: &o,
            leaf: None,
            platform_reason: None,
            now: 0,
            fills_credential: false,
        });
        assert!(unread.contains("could not be read"), "{unread}");
    }
}
