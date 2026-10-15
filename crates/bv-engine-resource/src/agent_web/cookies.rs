//! The per-call cookie jar of an agent fetch (§6.3 "Request headers"):
//! cookies a target sets during one call — a login redirect, a session
//! started by an answered challenge — go back to that same origin on the
//! call's next request, and the jar is dropped with the call.
//!
//! Deliberately smaller than a browser's: cookies are host-only (kept per
//! exact origin, whatever `Domain` says), sent on every path of that origin,
//! and never leave the vault — no cookie, `Set-Cookie` or cookie value is
//! returned, and every value long enough to be a session id is handed to the
//! scrubber, so a page that echoes one cannot carry it to the model.

use std::collections::HashMap;

use zeroize::Zeroizing;

/// Cookies kept per origin; more are ignored.
pub const MAX_COOKIES_PER_ORIGIN: usize = 32;
/// Longest `name=value` kept.
pub const MAX_COOKIE_BYTES: usize = 4096;
/// Values at least this long are scrubbed from page text and transcripts:
/// shorter ones (`1`, `true`, `en`) would redact ordinary words.
pub const MIN_SCRUBBED_COOKIE_BYTES: usize = 8;

#[derive(Default)]
pub struct CookieJar {
    by_origin: HashMap<String, Vec<(String, Zeroizing<String>)>>,
    /// Every value seen that is long enough to scrub.
    seen_values: Vec<Zeroizing<String>>,
}

impl std::fmt::Debug for CookieJar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Names only: a value is a session.
        let names: Vec<(&String, Vec<&String>)> =
            self.by_origin.iter().map(|(o, c)| (o, c.iter().map(|(n, _)| n).collect())).collect();
        f.debug_struct("CookieJar").field("names", &names).finish()
    }
}

impl CookieJar {
    /// Take the `Set-Cookie` header values one response to `origin` carried.
    pub fn absorb<'a>(&mut self, origin: &str, set_cookies: impl IntoIterator<Item = &'a str>) {
        for header in set_cookies {
            let mut attrs = header.split(';');
            let Some((name, value)) = attrs.next().and_then(|pair| pair.split_once('=')) else { continue };
            let (name, value) = (name.trim(), value.trim().trim_matches('"'));
            if name.is_empty() || name.len() + value.len() + 1 > MAX_COOKIE_BYTES {
                continue;
            }
            if value.len() >= MIN_SCRUBBED_COOKIE_BYTES && !self.seen_values.iter().any(|v| v.as_str() == value) {
                self.seen_values.push(Zeroizing::new(value.to_string()));
            }
            let expired = attrs.any(|a| {
                a.trim()
                    .split_once('=')
                    .is_some_and(|(k, v)| k.trim().eq_ignore_ascii_case("max-age") && v.trim().starts_with(['0', '-']))
            });
            let jar = self.by_origin.entry(origin.to_string()).or_default();
            jar.retain(|(n, _)| n != name);
            if !expired && !value.is_empty() && jar.len() < MAX_COOKIES_PER_ORIGIN {
                jar.push((name.to_string(), Zeroizing::new(value.to_string())));
            }
        }
    }

    /// The `Cookie` header for a request to `origin`, if it has any.
    pub fn header_for(&self, origin: &str) -> Option<Zeroizing<String>> {
        let jar = self.by_origin.get(origin).filter(|j| !j.is_empty())?;
        let line: Vec<String> = jar.iter().map(|(n, v)| format!("{n}={}", v.as_str())).collect();
        Some(Zeroizing::new(line.join("; ")))
    }

    /// Every value long enough to scrub, for the call's scrubber.
    pub fn into_seen_values(self) -> Vec<Zeroizing<String>> {
        self.seen_values
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookies_go_back_to_their_own_origin_only() {
        let mut jar = CookieJar::default();
        jar.absorb("https://app", ["sid=abcdef0123456789; Path=/; HttpOnly; Secure", "lang=en"]);
        assert_eq!(jar.header_for("https://app").unwrap().as_str(), "sid=abcdef0123456789; lang=en");
        assert!(jar.header_for("https://other").is_none(), "host-only, whatever Domain says");
        // Replaced by name, and deleted by Max-Age=0.
        jar.absorb("https://app", ["sid=zzzzzzzzzzzz", "lang=; Max-Age=0"]);
        assert_eq!(jar.header_for("https://app").unwrap().as_str(), "sid=zzzzzzzzzzzz");
        let seen = jar.into_seen_values();
        let seen: Vec<&str> = seen.iter().map(|v| v.as_str()).collect();
        assert_eq!(seen, vec!["abcdef0123456789", "zzzzzzzzzzzz"], "short values are not scrub needles");
    }

    #[test]
    fn the_jar_is_bounded_and_never_prints_a_value() {
        let mut jar = CookieJar::default();
        let many: Vec<String> = (0..40).map(|i| format!("c{i}=v{i}")).collect();
        jar.absorb("https://app", many.iter().map(String::as_str));
        assert_eq!(jar.header_for("https://app").unwrap().split("; ").count(), MAX_COOKIES_PER_ORIGIN);
        let huge = format!("big={}", "x".repeat(MAX_COOKIE_BYTES));
        jar.absorb("https://b", [huge.as_str(), "noequals", "=novalue"]);
        assert!(jar.header_for("https://b").is_none());
        jar.absorb("https://c", ["sid=supersecretvalue"]);
        assert!(!format!("{jar:?}").contains("supersecretvalue"));
    }
}
