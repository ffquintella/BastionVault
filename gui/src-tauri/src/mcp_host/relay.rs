//! `bastion-vault-gui --mcp-stdio`: the command an AI assistant is
//! configured to launch. It starts no window and no Tauri runtime: it
//! connects to the running app's owner-only socket, relays stdin/stdout
//! lines both ways, and exits. No token or secret is passed on its command
//! line or in its environment -- the app decides everything.
//!
//! When the app is not running, its server is off or the vault is locked,
//! it says so on stderr (stdout is the MCP channel) and exits non-zero, so
//! the assistant reports a failed server instead of hanging.

use std::ffi::OsString;
use std::path::PathBuf;

pub const FLAG: &str = "--mcp-stdio";
const SOCKET_FLAG: &str = "--socket";

// sysexits(3), as the CLI uses. Three of them only a Unix relay can reach.
const EX_USAGE: i32 = 64;
const EX_UNAVAILABLE: i32 = 69;
#[cfg(unix)]
const EX_IOERR: i32 = 74;
#[cfg(unix)]
const EX_TEMPFAIL: i32 = 75;
#[cfg(unix)]
const EX_NOPERM: i32 = 77;

#[derive(Debug, PartialEq)]
pub struct RelayArgs {
    /// Overrides the default socket path -- for a setup where the assistant
    /// and the app see different `XDG_CONFIG_HOME`/`HOME` values.
    pub socket: Option<PathBuf>,
}

/// `None` unless this process was started as the relay (`--mcp-stdio` as
/// its first argument); then the parsed arguments or a usage error.
pub fn parse(args: &[OsString]) -> Option<Result<RelayArgs, String>> {
    if args.get(1).map(|a| a.as_os_str()) != Some(FLAG.as_ref()) {
        return None;
    }
    let mut socket = None;
    let mut rest = args[2..].iter();
    while let Some(arg) = rest.next() {
        if arg.as_os_str() == SOCKET_FLAG && socket.is_none() {
            match rest.next() {
                Some(path) if !path.is_empty() => socket = Some(PathBuf::from(path)),
                _ => return Some(Err(format!("{SOCKET_FLAG} needs a path"))),
            }
        } else {
            return Some(Err(format!("unexpected argument `{}`", arg.to_string_lossy())));
        }
    }
    Some(Ok(RelayArgs { socket }))
}

/// The relay's `main`: `None` if this is not a relay invocation (start the
/// app), else the exit status.
pub fn main(args: Vec<OsString>) -> Option<i32> {
    let parsed = parse(&args)?;
    Some(match parsed {
        Err(e) => {
            eprintln!("bastionvault: {e}\nusage: bastion-vault-gui {FLAG} [{SOCKET_FLAG} <path>]");
            EX_USAGE
        }
        Ok(args) => run(args),
    })
}

#[cfg(unix)]
fn run(args: RelayArgs) -> i32 {
    use bv_mcp::local::uds::{relay, RelayEnd, RelayError};

    let path = match args.socket.map(Ok).unwrap_or_else(super::default_socket_path) {
        Ok(path) => path,
        Err(e) => {
            eprintln!("bastionvault: cannot locate the BastionVault app's socket: {e}");
            return EX_UNAVAILABLE;
        }
    };
    match relay(&path, std::io::stdin(), std::io::stdout().lock()) {
        Ok(RelayEnd::ClientClosed) => 0,
        Ok(RelayEnd::ServerClosed) => {
            eprintln!(
                "bastionvault: BastionVault closed the connection: its AI-assistant server was turned off, or the \
                 vault was locked or signed out. Unlock it and reconnect."
            );
            EX_TEMPFAIL
        }
        Err(RelayError::NotRunning { path, reason }) => {
            eprintln!(
                "bastionvault: the BastionVault app is not serving AI assistants at {} ({reason}).\nOpen BastionVault, \
                 unlock your vault and turn on Settings > AI Assistants > Serve AI assistants, then reconnect.",
                path.display()
            );
            EX_UNAVAILABLE
        }
        Err(RelayError::ForeignServer { path }) => {
            eprintln!("bastionvault: {} is served by another user; refusing to connect.", path.display());
            EX_NOPERM
        }
        Err(RelayError::Io(e)) => {
            eprintln!("bastionvault: relay failed: {e}");
            EX_IOERR
        }
    }
}

#[cfg(not(unix))]
fn run(_args: RelayArgs) -> i32 {
    eprintln!("bastionvault: {FLAG} needs Unix domain sockets, which this platform's build does not support yet");
    EX_UNAVAILABLE
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<OsString> {
        std::iter::once("bastion-vault-gui").chain(list.iter().copied()).map(OsString::from).collect()
    }

    #[test]
    fn only_a_leading_flag_makes_this_process_a_relay() {
        assert_eq!(parse(&args(&[])), None, "a plain launch starts the app");
        assert_eq!(parse(&args(&["--other"])), None);
        assert_eq!(parse(&args(&["something", FLAG])), None, "the flag must come first");
        assert_eq!(parse(&args(&[FLAG])), Some(Ok(RelayArgs { socket: None })));
        assert_eq!(
            parse(&args(&[FLAG, "--socket", "/tmp/x.sock"])),
            Some(Ok(RelayArgs { socket: Some(PathBuf::from("/tmp/x.sock")) }))
        );
    }

    #[test]
    fn anything_else_after_the_flag_is_a_usage_error() {
        assert!(matches!(parse(&args(&[FLAG, "--socket"])), Some(Err(_))));
        assert!(matches!(parse(&args(&[FLAG, "--socket", ""])), Some(Err(_))));
        assert!(matches!(parse(&args(&[FLAG, "--token", "x"])), Some(Err(_))));
        assert!(matches!(parse(&args(&[FLAG, "--socket", "/a", "--socket", "/b"])), Some(Err(_))));
        assert_eq!(main(args(&[FLAG, "--bogus"])), Some(EX_USAGE));
        assert_eq!(main(args(&[])), None);
    }

    #[cfg(unix)]
    #[test]
    fn with_nothing_serving_the_relay_exits_unavailable() {
        let dir = PathBuf::from(format!("/tmp/bvgui-{}", &bv_mcp::pairing::new_pairing_id()[..8]));
        let socket = dir.join("none.sock");
        let code = main(args(&[FLAG, "--socket", socket.to_str().unwrap()]));
        assert_eq!(code, Some(EX_UNAVAILABLE));
        std::fs::remove_dir_all(dir).ok();
    }
}
