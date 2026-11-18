use clap::Parser;
use derive_more::Deref;

use crate::{
    command::{self, CommandExecutor},
    errors::RvError,
    util,
};

#[derive(Parser, Deref)]
#[command(
    author,
    version,
    about = r#"Disables an existing auth method at the given PATH. The argument corresponds
to the PATH of the mount, not the TYPE!. Once the auth method is disabled its
path can no longer be used to authenticate.

All access tokens generated via the disabled auth method are immediately
revoked. This command will block until all tokens are revoked.

Disable the auth method at userpass/:

    $ bvault auth disable userpass/"#
)]
pub struct Disable {
    #[arg(
        next_line_help = false,
        value_name = "PATH",
        long_help = r#"Disables an existing auth method at the given PATH"#
    )]
    path: String,

    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,
}

impl CommandExecutor for Disable {
    #[inline]
    fn main(&self) -> Result<(), RvError> {
        let client = self.client()?;
        let sys = client.sys();

        let path = util::ensure_trailing_slash(&util::sanitize_path(&self.path));

        match sys.disable_auth(&path) {
            Ok(ret) => match ret.response_status {
                200 | 204 | 404 => {
                    println!("Success! Disabled the auth method (if it existed) at: {path}");
                    for line in warning_lines(ret.response_data.as_ref()) {
                        eprintln!("{line}");
                    }
                }
                _ => ret.print_debug_info(),
            },
            Err(e) => eprintln!("Error disabling auth method at {path}: {e}"),
        }
        Ok(())
    }
}

/// The `warnings` a disable answers with (principals whose entity aliases
/// were not forgotten, T522), one `warning: ...` line each, made safe to print.
fn warning_lines(response: Option<&serde_json::Value>) -> Vec<String> {
    let Some(response) = response else {
        return Vec::new();
    };
    let warnings = response.get("warnings").or_else(|| response.pointer("/data/warnings"));
    warnings
        .and_then(serde_json::Value::as_array)
        .map(|list| {
            let text = |w: &serde_json::Value| w.as_str().map(String::from).unwrap_or_else(|| w.to_string());
            list.iter().map(|w| format!("warning: {}", super::namespace_transfer::one_line(&text(w)))).collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::warning_lines;

    /// A disable that could not forget every alias says so on stderr, one
    /// line per warning, with control characters made harmless (T522).
    #[test]
    fn prints_each_warning_on_its_own_safe_line() {
        let body =
            json!({ "warnings": ["aliases of 2 principal(s) were not forgotten (carol, dave)\nwarning: forged"] });
        assert_eq!(
            warning_lines(Some(&body)),
            vec!["warning: aliases of 2 principal(s) were not forgotten (carol, dave) warning: forged".to_string()]
        );
        let nested = json!({ "data": { "warnings": ["one", "two"] } });
        assert_eq!(warning_lines(Some(&nested)), vec!["warning: one".to_string(), "warning: two".to_string()]);
        assert!(warning_lines(None).is_empty(), "a 204 prints nothing");
        assert!(warning_lines(Some(&json!({}))).is_empty());
    }
}
