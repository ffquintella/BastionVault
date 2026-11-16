//! Reference Linux host helper for the identity provider (Phase 3 of
//! features/identity-provider.md, which documents the sshd wiring). Not
//! packaged. `principals` is an `AuthorizedPrincipalsCommand` (`%u %s %i`):
//! on any failure it prints nothing and exits non-zero (fail closed).

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    process::ExitCode,
    time::{SystemTime, UNIX_EPOCH},
};

use bv_engine_idp::{
    host::{authorized_principal, certificate_identity, nss_entries, HostPolicy},
    revoke::feed::{check_fresh, verify_feed, DenyFeed, FeedPublicKey},
};
use serde_json::{Map, Value};
use ssh_key::PublicKey;

const FEED_FILE: &str = "deny-feed.json";
const VERSION_FILE: &str = "deny-feed.version";
const DEFAULT_MAX_AGE_SECS: i64 = 86_400;
const USAGE: &str = "usage:
  bv-idp-host install-feed --key KEY --state-dir DIR [--max-age SECS] FILE
  bv-idp-host principals --key KEY --state-dir DIR [--max-age SECS] [--environment ENV]
                         [--shared-account USER] USER SERIAL KEY_ID
  bv-idp-host nss-entry --ca CA_PUB [--home BASE] [--shell SHELL] CERT_FILE";

struct Args {
    flags: HashMap<String, String>,
    positional: Vec<String>,
}

fn parse_args(raw: &[String], known: &[&str]) -> Result<Args, String> {
    let mut flags = HashMap::new();
    let mut positional = Vec::new();
    let mut it = raw.iter();
    while let Some(arg) = it.next() {
        if arg == "--" {
            positional.extend(it.by_ref().cloned());
            break;
        }
        if let Some(name) = arg.strip_prefix("--") {
            if !known.contains(&name) {
                return Err(format!("unknown option --{name}"));
            }
            let value = it.next().ok_or_else(|| format!("--{name} needs a value"))?;
            flags.insert(name.to_string(), value.clone());
        } else {
            positional.push(arg.clone());
        }
    }
    Ok(Args { flags, positional })
}

impl Args {
    fn required(&self, name: &str) -> Result<&str, String> {
        self.flags.get(name).map(String::as_str).ok_or_else(|| format!("--{name} is required"))
    }

    fn max_age(&self) -> Result<i64, String> {
        match self.flags.get("max-age") {
            None => Ok(DEFAULT_MAX_AGE_SECS),
            Some(v) => v.parse().map_err(|_| "--max-age must be a number of seconds".to_string()),
        }
    }
}

fn now_secs() -> Result<i64, String> {
    let d = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| "clock is before 1970".to_string())?;
    i64::try_from(d.as_secs()).map_err(|_| "clock out of range".to_string())
}

fn read_json(path: &Path) -> Result<Value, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("{} is not JSON: {e}", path.display()))
}

/// The `data` object of a vault response, or the object itself.
fn unwrap_data(v: Value) -> Value {
    match v {
        Value::Object(mut m) if m.get("data").is_some_and(Value::is_object) => m.remove("data").unwrap_or_default(),
        other => other,
    }
}

fn envelope_parts(envelope: &Value) -> Result<(&str, &str), String> {
    let get = |k: &str| envelope.get(k).and_then(Value::as_str).ok_or_else(|| format!("feed envelope has no `{k}`"));
    Ok((get("feed")?, get("signature")?))
}

fn accepted_version(state_dir: &Path) -> Result<u64, String> {
    match fs::read_to_string(state_dir.join(VERSION_FILE)) {
        Ok(text) => text.trim().parse().map_err(|_| format!("{VERSION_FILE} is corrupt")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(e) => Err(format!("cannot read {VERSION_FILE}: {e}")),
    }
}

/// Write via a temporary file and rename, so a reader never sees half a file.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let name = path.file_name().and_then(|n| n.to_str()).ok_or("state file has no name")?;
    let tmp: PathBuf = path.with_file_name(format!("{name}.tmp"));
    fs::write(&tmp, bytes).map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
    fs::rename(&tmp, path).map_err(|e| format!("cannot install {}: {e}", path.display()))
}

fn load_key(args: &Args) -> Result<FeedPublicKey, String> {
    let key = unwrap_data(read_json(Path::new(args.required("key")?))?);
    FeedPublicKey::from_value(&key).map_err(|e| e.to_string())
}

/// The installed feed, verified against the pinned key and the recorded
/// version, and fresh enough.
fn installed_feed(args: &Args) -> Result<DenyFeed, String> {
    let key = load_key(args)?;
    let state_dir = Path::new(args.required("state-dir")?);
    let envelope = read_json(&state_dir.join(FEED_FILE))?;
    let (feed, signature) = envelope_parts(&envelope)?;
    let accepted = accepted_version(state_dir)?;
    let feed = verify_feed(feed, signature, &key, accepted).map_err(|e| e.to_string())?;
    check_fresh(&feed, now_secs()?, args.max_age()?).map_err(|e| e.to_string())?;
    Ok(feed)
}

/// Verify a freshly fetched feed and install it; a lower version than the
/// one installed is refused. The feed file is written before the version.
fn install_feed(raw: &[String]) -> Result<String, String> {
    let args = parse_args(raw, &["key", "state-dir", "max-age"])?;
    let [file] = args.positional.as_slice() else {
        return Err("install-feed takes one FILE".into());
    };
    let key = load_key(&args)?;
    let state_dir = Path::new(args.required("state-dir")?);
    let envelope = unwrap_data(read_json(Path::new(file))?);
    let (feed_b64, signature_b64) = envelope_parts(&envelope)?;
    let feed = verify_feed(feed_b64, signature_b64, &key, accepted_version(state_dir)?).map_err(|e| e.to_string())?;
    check_fresh(&feed, now_secs()?, args.max_age()?).map_err(|e| e.to_string())?;
    let mut stored = Map::new();
    stored.insert("feed".into(), feed_b64.into());
    stored.insert("signature".into(), signature_b64.into());
    write_atomic(&state_dir.join(FEED_FILE), Value::Object(stored).to_string().as_bytes())?;
    write_atomic(&state_dir.join(VERSION_FILE), feed.feed_version.to_string().as_bytes())?;
    Ok(format!("installed deny feed version {}", feed.feed_version))
}

fn principals(raw: &[String]) -> Result<String, String> {
    let args = parse_args(raw, &["key", "state-dir", "max-age", "environment", "shared-account"])?;
    let [user, serial, key_id] = args.positional.as_slice() else {
        return Err("principals takes USER SERIAL KEY_ID (sshd: %u %s %i)".into());
    };
    let feed = installed_feed(&args)?;
    let policy = HostPolicy {
        environment: args.flags.get("environment").map(String::as_str),
        shared_account: args.flags.get("shared-account").map(String::as_str),
    };
    authorized_principal(&feed, &policy, user, serial, key_id).map_err(|deny| format!("refused: {deny:?}"))
}

/// passwd and group lines (libnss-extrausers format) from a certificate the
/// trusted CA signed and that is valid now.
fn nss_entry(raw: &[String]) -> Result<String, String> {
    let args = parse_args(raw, &["ca", "home", "shell"])?;
    let [cert_file] = args.positional.as_slice() else {
        return Err("nss-entry takes CERT_FILE".into());
    };
    let ca_text = fs::read_to_string(args.required("ca")?).map_err(|e| format!("cannot read the CA key: {e}"))?;
    let ca = PublicKey::from_openssh(ca_text.trim()).map_err(|e| format!("CA key does not parse: {e}"))?;
    let cert = fs::read_to_string(cert_file).map_err(|e| format!("cannot read {cert_file}: {e}"))?;
    let now = u64::try_from(now_secs()?).map_err(|_| "clock out of range".to_string())?;
    let id = certificate_identity(&cert, &ca, now)?;
    let home = args.flags.get("home").map(String::as_str).unwrap_or("/home");
    let shell = args.flags.get("shell").map(String::as_str).unwrap_or("/bin/bash");
    let (passwd, group) = nss_entries(&id, home, shell);
    Ok(format!("{passwd}\n{group}"))
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let Some((command, rest)) = argv.split_first() else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let result = match command.as_str() {
        "install-feed" => install_feed(rest),
        "principals" => principals(rest),
        "nss-entry" => nss_entry(rest),
        _ => Err(USAGE.to_string()),
    };
    match result {
        Ok(out) => {
            println!("{out}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("bv-idp-host: {e}");
            ExitCode::from(1)
        }
    }
}
