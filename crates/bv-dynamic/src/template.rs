//! Statement templating, run by the host and never by a plugin.
//!
//! Six tokens exist (`{{name}}`, `{{password}}`, `{{expiration}}`, `{{role}}`,
//! `{{display_name}}`, `{{entity_id}}`); anything else between braces, or an
//! unbalanced pair, is refused. Injection safety is by construction, not by
//! (dialect-specific) escaping: a substituted value must match a per-token
//! character set with no quote, backslash, `$`, `;`, space or comment opener.

use std::fmt;

/// Longest template accepted, in bytes.
pub const MAX_TEMPLATE_LEN: usize = 16 * 1024;
/// Longest substituted value, in bytes.
pub const MAX_VALUE_LEN: usize = 128;

/// The tokens a template may name, in the order the spec lists them.
pub const ALLOWED_TOKENS: [&str; 6] = ["name", "password", "expiration", "role", "display_name", "entity_id"];

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TemplateError {
    #[error("unknown token `{0}`: only {{{{name}}}}, {{{{password}}}}, {{{{expiration}}}}, {{{{role}}}}, {{{{display_name}}}} and {{{{entity_id}}}} are expanded")]
    UnknownToken(String),
    #[error("unterminated `{{{{` at byte {0}")]
    Unterminated(usize),
    #[error("stray `}}}}` at byte {0}")]
    StrayClose(usize),
    #[error("`{{{{{0}}}}}` is not allowed in this statement")]
    TokenNotAllowed(&'static str),
    #[error("the value for `{{{{{0}}}}}` contains characters that cannot be substituted safely")]
    UnsafeValue(&'static str),
    #[error("the statement is empty")]
    Empty,
    #[error("the statement exceeds {MAX_TEMPLATE_LEN} bytes")]
    TooLong,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Token {
    Name,
    Password,
    Expiration,
    Role,
    DisplayName,
    EntityId,
}

impl Token {
    fn parse(raw: &str) -> Option<Self> {
        Some(match raw {
            "name" => Self::Name,
            "password" => Self::Password,
            "expiration" => Self::Expiration,
            "role" => Self::Role,
            "display_name" => Self::DisplayName,
            "entity_id" => Self::EntityId,
            _ => return None,
        })
    }

    fn label(self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::Password => "password",
            Self::Expiration => "expiration",
            Self::Role => "role",
            Self::DisplayName => "display_name",
            Self::EntityId => "entity_id",
        }
    }

    /// The characters a value for this token may contain.
    fn allows(self, c: char) -> bool {
        match self {
            // RFC 3339 in UTC: `2026-10-26T18:32:11Z`.
            Self::Expiration => c.is_ascii_digit() || matches!(c, '-' | ':' | 'T' | 'Z'),
            // URL-safe base64, and UUIDs.
            Self::Password | Self::EntityId => c.is_ascii_alphanumeric() || matches!(c, '-' | '_'),
            Self::Name | Self::Role | Self::DisplayName => {
                c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@')
            }
        }
    }
}

enum Piece<'a> {
    Literal(&'a str),
    Token(Token),
}

fn parse(template: &str) -> Result<Vec<Piece<'_>>, TemplateError> {
    if template.trim().is_empty() {
        return Err(TemplateError::Empty);
    }
    if template.len() > MAX_TEMPLATE_LEN {
        return Err(TemplateError::TooLong);
    }
    let mut pieces = Vec::new();
    let mut rest = template;
    let mut offset = 0usize;
    loop {
        let open = rest.find("{{");
        let close = rest.find("}}");
        match (open, close) {
            (None, None) => {
                if !rest.is_empty() {
                    pieces.push(Piece::Literal(rest));
                }
                return Ok(pieces);
            }
            (None, Some(c)) => return Err(TemplateError::StrayClose(offset + c)),
            (Some(o), Some(c)) if c < o => return Err(TemplateError::StrayClose(offset + c)),
            (Some(o), _) => {
                if o > 0 {
                    pieces.push(Piece::Literal(&rest[..o]));
                }
                let after = &rest[o + 2..];
                let end = after.find("}}").ok_or(TemplateError::Unterminated(offset + o))?;
                let raw = &after[..end];
                if raw.contains("{{") {
                    return Err(TemplateError::Unterminated(offset + o));
                }
                let token = Token::parse(raw.trim()).ok_or_else(|| TemplateError::UnknownToken(raw.to_string()))?;
                pieces.push(Piece::Token(token));
                let consumed = o + 2 + end + 2;
                offset += consumed;
                rest = &rest[consumed..];
            }
        }
    }
}

/// Check a template without values: tokens in the allowlist, braces balanced,
/// and `{{password}}` only where `allow_password` is set (creation statements;
/// a revocation or renewal statement has no business carrying the credential).
pub fn validate(template: &str, allow_password: bool) -> Result<(), TemplateError> {
    for piece in parse(template)? {
        if let Piece::Token(Token::Password) = piece {
            if !allow_password {
                return Err(TemplateError::TokenNotAllowed("password"));
            }
        }
    }
    Ok(())
}

/// [`validate`], and every token one of `allowed` (a root-rotation statement
/// names only `{{name}}` and `{{password}}`).
pub fn validate_only(template: &str, allowed: &[&'static str]) -> Result<(), TemplateError> {
    for piece in parse(template)? {
        if let Piece::Token(token) = piece {
            if !allowed.contains(&token.label()) {
                return Err(TemplateError::TokenNotAllowed(token.label()));
            }
        }
    }
    Ok(())
}

/// The values a template is expanded with. `Debug` never prints the password.
#[derive(Clone, Copy)]
pub struct TemplateVars<'a> {
    pub name: &'a str,
    pub password: &'a str,
    pub expiration: &'a str,
    pub role: &'a str,
    pub display_name: &'a str,
    pub entity_id: &'a str,
}

impl fmt::Debug for TemplateVars<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TemplateVars")
            .field("name", &self.name)
            .field("password", &"<redacted>")
            .field("expiration", &self.expiration)
            .field("role", &self.role)
            .field("display_name", &self.display_name)
            .field("entity_id", &self.entity_id)
            .finish()
    }
}

impl TemplateVars<'_> {
    fn value(&self, token: Token) -> &str {
        match token {
            Token::Name => self.name,
            Token::Password => self.password,
            Token::Expiration => self.expiration,
            Token::Role => self.role,
            Token::DisplayName => self.display_name,
            Token::EntityId => self.entity_id,
        }
    }
}

/// Whether `value` may be substituted for `token`: empty (a root token has no
/// entity), or in the token's character set, at most [`MAX_VALUE_LEN`] bytes
/// and free of `--` (a comment opener in a bare SQL context).
fn check_value(token: Token, value: &str) -> Result<(), TemplateError> {
    if value.len() > MAX_VALUE_LEN || value.contains("--") || !value.chars().all(|c| token.allows(c)) {
        return Err(TemplateError::UnsafeValue(token.label()));
    }
    Ok(())
}

/// Expand `template` with `vars`. Only the tokens the template names are
/// checked, so an unused value never blocks a render.
pub fn render(template: &str, vars: &TemplateVars<'_>) -> Result<String, TemplateError> {
    let pieces = parse(template)?;
    let mut out = String::with_capacity(template.len() + 64);
    for piece in pieces {
        match piece {
            Piece::Literal(text) => out.push_str(text),
            Piece::Token(token) => {
                let value = vars.value(token);
                check_value(token, value)?;
                out.push_str(value);
            }
        }
    }
    Ok(out)
}

/// Reduce a caller-influenced value (a token's display name, a role name) to
/// characters [`render`] accepts: anything else becomes `_`, runs of `-`
/// collapse to one, and the result is cut to `max` characters.
pub fn sanitize_value(raw: &str, max: usize) -> String {
    let mut out = String::with_capacity(raw.len().min(max));
    let mut count = 0usize;
    for c in raw.chars() {
        if count >= max {
            break;
        }
        let mapped = if c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '@' | '-') { c } else { '_' };
        if mapped == '-' && out.ends_with('-') {
            continue;
        }
        out.push(mapped);
        count += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars() -> TemplateVars<'static> {
        TemplateVars {
            name: "v-alice-ro-1793000000-0a1b2c3d",
            password: "AbCdEfGh_ijklmnop-QRSTUVWXyz0123",
            expiration: "2026-10-26T18:32:11Z",
            role: "readonly",
            display_name: "userpass-alice",
            entity_id: "5f0c1a2b-3c4d-4e5f-8a9b-0c1d2e3f4a5b",
        }
    }

    #[test]
    fn expands_every_allowed_token() {
        let t = r#"CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; -- {{role}} {{display_name}} {{entity_id}}"#;
        let out = render(t, &vars()).unwrap();
        assert_eq!(
            out,
            "CREATE ROLE \"v-alice-ro-1793000000-0a1b2c3d\" WITH LOGIN PASSWORD 'AbCdEfGh_ijklmnop-QRSTUVWXyz0123' \
             VALID UNTIL '2026-10-26T18:32:11Z'; -- readonly userpass-alice 5f0c1a2b-3c4d-4e5f-8a9b-0c1d2e3f4a5b"
        );
        assert_eq!(ALLOWED_TOKENS.len(), 6);
    }

    #[test]
    fn whitespace_inside_braces_is_tolerated() {
        assert_eq!(render("GRANT x TO {{ name }}", &vars()).unwrap(), "GRANT x TO v-alice-ro-1793000000-0a1b2c3d");
    }

    #[test]
    fn unknown_token_is_refused() {
        for t in ["{{username}}", "{{name|upper}}", "{{ }}", "{{env.HOME}}", "{{NAME}}"] {
            assert!(matches!(render(t, &vars()), Err(TemplateError::UnknownToken(_))), "{t}");
            assert!(matches!(validate(t, true), Err(TemplateError::UnknownToken(_))), "{t}");
        }
    }

    #[test]
    fn unbalanced_braces_are_refused() {
        assert!(matches!(render("x {{name", &vars()), Err(TemplateError::Unterminated(2))));
        assert!(matches!(render("x }} y", &vars()), Err(TemplateError::StrayClose(2))));
        assert!(matches!(render("{{ {{name}} }}", &vars()), Err(TemplateError::Unterminated(0))));
        assert!(matches!(render("   ", &vars()), Err(TemplateError::Empty)));
        assert!(matches!(render(&"x".repeat(MAX_TEMPLATE_LEN + 1), &vars()), Err(TemplateError::TooLong)));
    }

    #[test]
    fn password_only_where_allowed() {
        assert!(validate("ALTER ROLE \"{{name}}\" PASSWORD '{{password}}'", true).is_ok());
        assert_eq!(
            validate("DROP ROLE \"{{name}}\"; -- {{password}}", false),
            Err(TemplateError::TokenNotAllowed("password"))
        );
        assert!(validate("DROP ROLE \"{{name}}\"", false).is_ok());
    }

    /// The injection attempts a caller can make, through the role name in the
    /// request path and the token's display name: every one is refused at
    /// substitution, whatever quoting the template author chose.
    #[test]
    fn injection_through_caller_values_is_refused() {
        let attacks = [
            "x'; DROP TABLE users; --",
            "x\"; DROP ROLE admin; --",
            "a--b",
            "a\\'b",
            "$$; DROP TABLE t; $$",
            "a b",
            "a\nb",
            "a\0b",
            "a/*b*/",
            "a`b",
        ];
        for attack in attacks {
            let mut v = vars();
            v.display_name = attack;
            assert_eq!(
                render("GRANT r TO \"{{display_name}}\"", &v),
                Err(TemplateError::UnsafeValue("display_name")),
                "{attack:?}"
            );
            let mut v = vars();
            v.role = attack;
            assert_eq!(render("COMMENT '{{role}}'", &v), Err(TemplateError::UnsafeValue("role")), "{attack:?}");
        }
        // An unused unsafe value does not block a render.
        let mut v = vars();
        v.display_name = "x'; DROP TABLE users; --";
        assert!(render("GRANT r TO \"{{name}}\"", &v).is_ok());
    }

    #[test]
    fn generated_values_are_checked_too() {
        let mut v = vars();
        v.password = "abc'def";
        assert_eq!(render("'{{password}}'", &v), Err(TemplateError::UnsafeValue("password")));
        let mut v = vars();
        v.expiration = "2026-10-26 18:32:11'";
        assert_eq!(render("'{{expiration}}'", &v), Err(TemplateError::UnsafeValue("expiration")));
        let long = "a".repeat(MAX_VALUE_LEN + 1);
        let mut v = vars();
        v.name = &long;
        assert_eq!(render("{{name}}", &v), Err(TemplateError::UnsafeValue("name")));
    }

    #[test]
    fn sanitize_maps_unsafe_characters() {
        assert_eq!(sanitize_value("x'; DROP TABLE users; --", 64), "x___DROP_TABLE_users__-");
        assert_eq!(sanitize_value("oidc-alice@example.com", 64), "oidc-alice@example.com");
        assert_eq!(sanitize_value("a---b", 64), "a-b");
        assert_eq!(sanitize_value("abcdef", 3), "abc");
        // Whatever comes out is accepted by the renderer.
        let s = sanitize_value("évil\"--$$;\\", 64);
        let mut v = vars();
        v.display_name = &s;
        assert!(render("{{display_name}}", &v).is_ok(), "{s}");
    }

    #[test]
    fn debug_never_prints_the_password() {
        let rendered = format!("{:?}", vars());
        assert!(!rendered.contains("AbCdEfGh"), "{rendered}");
        assert!(rendered.contains("<redacted>"));
    }
}
