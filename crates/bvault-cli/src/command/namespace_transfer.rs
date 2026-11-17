//! `bvault transfer copy|move`: carry one resource or KV secret to another
//! namespace through `POST /v2/sys/namespace-transfer/{copy|move}`.

use clap::{Args, Parser, Subcommand, ValueEnum};
use derive_more::Deref;
use serde_json::{json, Map, Value};
use sysexits::ExitCode;

use crate::{
    command::{self, CommandExecutor},
    errors::RvError,
    EXIT_CODE_INSUFFICIENT_PARAMS,
};

#[derive(Parser)]
#[command(
    author,
    version,
    about = "Copy or move a resource or KV secret to another namespace",
    long_about = r#"Copies or moves one resource or KV v2 secret, with its versions, shares,
asset-group membership and (for a resource) its change history, to
another namespace. The server does the work with your token, so you need
the rights the API documents (docs/api.md, "Namespace transfer").

Please see the individual subcommand help for detailed usage information."#
)]
pub struct Transfer {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    Copy(Copy),
    Move(Move),
}

impl Commands {
    pub fn execute(&mut self) -> ExitCode {
        match self {
            Commands::Copy(copy) => copy.execute(),
            Commands::Move(mv) => mv.execute(),
        }
    }
}

impl Transfer {
    #[inline]
    pub fn execute(&mut self) -> ExitCode {
        if let Some(ref mut cmd) = &mut self.command {
            return cmd.execute();
        }

        EXIT_CODE_INSUFFICIENT_PARAMS
    }
}

const LOCATION_HELP: &str = r#"SOURCE and DESTINATION are written <mount>/<path>: the text before the
first slash is the mount (one segment), the rest is the item's path. The
namespace is never part of them; name it with --source-namespace and
--destination-namespace (default: the root namespace, "").

Copy the resource db1 (mount "resources", the path is the resource name)
from namespace team-a to team-b:

    $ bvault transfer copy --kind resource \
        --source-namespace team-a --destination-namespace team-b \
        resources/db1 resources/db1

Move the KV v2 secret app/db from mount "secret" in team-a to the same
path in team-b, renaming it if that path is taken:

    $ bvault transfer move --kind kv-secret --on-conflict rename \
        --source-namespace team-a --destination-namespace team-b \
        secret/app/db secret/app/db

Warnings go to stderr as warning[<code>]: <subject>: <message>. The exit
code is 0 when the transfer succeeded, even with warnings."#;

#[derive(ValueEnum, Copy, Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    Resource,
    KvSecret,
}

#[derive(ValueEnum, Copy, Clone, Debug, PartialEq, Eq)]
pub enum OnConflict {
    Refuse,
    Rename,
    Overwrite,
}

#[derive(Args, Deref)]
pub struct TransferArgs {
    #[arg(long, value_enum, value_name = "KIND", help = "What to transfer: resource or kv-secret.")]
    kind: Kind,

    #[arg(index = 1, required = true, value_name = "SOURCE", help = "The source, as <mount>/<path>.")]
    source: String,

    #[arg(index = 2, required = true, value_name = "DESTINATION", help = "The destination, as <mount>/<path>.")]
    destination: String,

    #[arg(long, value_name = "NAMESPACE", default_value = "", help = "Namespace of the source (default: root).")]
    source_namespace: String,

    #[arg(long, value_name = "NAMESPACE", default_value = "", help = "Namespace of the destination (default: root).")]
    destination_namespace: String,

    #[arg(
        long,
        value_enum,
        value_name = "POLICY",
        default_value = "refuse",
        help = "When the destination exists: refuse, rename or overwrite (delete first, not atomic)."
    )]
    on_conflict: OnConflict,

    #[arg(long, help = "Check everything and report the plan, but write nothing.")]
    dry_run: bool,

    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,
}

#[derive(Parser, Deref)]
#[command(author, version, about = "Copy a resource or KV secret to another namespace", long_about = LOCATION_HELP)]
pub struct Copy {
    #[deref]
    #[command(flatten)]
    args: TransferArgs,
}

#[derive(Parser, Deref)]
#[command(
    author,
    version,
    about = "Move a resource or KV secret to another namespace",
    long_about = LOCATION_HELP
)]
pub struct Move {
    #[deref]
    #[command(flatten)]
    args: TransferArgs,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Op {
    Copy,
    Move,
}

/// Where the transfer's output goes: the summary on stdout, every warning on stderr.
#[derive(Debug, Default, PartialEq, Eq)]
struct Rendered {
    stdout: String,
    stderr: Vec<String>,
}

impl CommandExecutor for Copy {
    fn main(&self) -> Result<(), RvError> {
        run(Op::Copy, &self.args)
    }
}

impl CommandExecutor for Move {
    fn main(&self) -> Result<(), RvError> {
        run(Op::Move, &self.args)
    }
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Kind::Resource => "resource",
            Kind::KvSecret => "kv-secret",
        }
    }
}

impl OnConflict {
    fn as_str(self) -> &'static str {
        match self {
            OnConflict::Refuse => "refuse",
            OnConflict::Rename => "rename",
            OnConflict::Overwrite => "overwrite",
        }
    }
}

impl Op {
    fn route(self) -> &'static str {
        match self {
            Op::Copy => "copy",
            Op::Move => "move",
        }
    }
}

fn run(op: Op, args: &TransferArgs) -> Result<(), RvError> {
    // Validate and build the body before anything is sent or printed.
    let body = build_body(args)?;
    if let Some(notice) = overwrite_notice(args.on_conflict, args.dry_run) {
        eprintln!("{notice}");
    }

    let client = args.client()?;
    let resp = client.request_write(format!("/v2/sys/namespace-transfer/{}", op.route()), Some(body))?;
    let data = resp.response_data.unwrap_or(Value::Null);
    if resp.response_status != 200 {
        let detail = data.get("error").and_then(Value::as_str).unwrap_or("no error message in the response");
        return Err(RvError::ErrString(format!(
            "{} of {} failed (HTTP {}): {}",
            op.route(),
            args.kind.as_str(),
            resp.response_status,
            one_line(detail)
        )));
    }

    let out = render(op, args, &data);
    print!("{}", out.stdout);
    for line in &out.stderr {
        eprintln!("{line}");
    }
    Ok(())
}

/// Trim the slashes around a positional and split it at the first one: the
/// mount is one segment, the item's path is everything after it.
fn split_location(location: &str) -> Result<(String, String), RvError> {
    match location.trim_matches('/').split_once('/') {
        Some((mount, path)) if !mount.is_empty() && !path.trim_matches('/').is_empty() => {
            Ok((mount.to_string(), path.trim_matches('/').to_string()))
        }
        _ => Err(RvError::ErrString(format!(
            "'{location}' is not a location: write it as <mount>/<path> (the namespace goes in --source-namespace / \
             --destination-namespace)"
        ))),
    }
}

fn place(namespace: &str, location: &str) -> Result<Value, RvError> {
    let (mount, path) = split_location(location)?;
    Ok(json!({ "namespace": namespace.trim_matches('/'), "mount": mount, "path": path }))
}

/// The request body of `POST /v2/sys/namespace-transfer/{copy|move}` (docs/api.md).
fn build_body(args: &TransferArgs) -> Result<Map<String, Value>, RvError> {
    let mut body = Map::new();
    body.insert("kind".into(), json!(args.kind.as_str()));
    body.insert("source".into(), place(&args.source_namespace, &args.source)?);
    body.insert("destination".into(), place(&args.destination_namespace, &args.destination)?);
    body.insert("on_conflict".into(), json!(args.on_conflict.as_str()));
    body.insert("dry_run".into(), json!(args.dry_run));
    Ok(body)
}

fn overwrite_notice(on_conflict: OnConflict, dry_run: bool) -> Option<&'static str> {
    (on_conflict == OnConflict::Overwrite && !dry_run).then_some(
        "warning: --on-conflict overwrite deletes the destination item first and is not atomic; \
         if the import then fails, the destination stays deleted",
    )
}

/// Server text is shown on one line with control characters replaced, so a
/// message cannot move the cursor or forge a second `warning[...]` line.
fn one_line(text: &str) -> String {
    text.chars().map(|c| if c.is_control() { ' ' } else { c }).collect()
}

fn show_place(namespace: &str, mount: &str, path: &str) -> String {
    let rest = format!("{}/{}", mount.trim_matches('/'), path.trim_matches('/'));
    match namespace.trim_matches('/') {
        "" => rest,
        ns => format!("{ns}/{rest}"),
    }
}

fn show_response_place(place: &Value) -> Option<String> {
    let field = |name: &str| place.get(name).and_then(Value::as_str);
    Some(show_place(field("namespace")?, field("mount")?, field("path")?))
}

/// Counts for stdout, then one `warning[<code>]: <subject>: <message>` per warning for stderr.
fn render(op: Op, args: &TransferArgs, response: &Value) -> Rendered {
    let (source_mount, source_path) = split_or_raw(&args.source);
    let source = show_place(&args.source_namespace, source_mount, source_path);
    let destination = response.get("destination").and_then(show_response_place).unwrap_or_else(|| {
        let (mount, path) = split_or_raw(&args.destination);
        show_place(&args.destination_namespace, mount, path)
    });
    let kind = args.kind.as_str();
    let (verb, past) = match op {
        Op::Copy => ("copy", "Copied"),
        Op::Move => ("move", "Moved"),
    };

    let mut stdout = String::new();
    if args.dry_run {
        stdout.push_str(&format!(
            "Dry run: nothing was written. Plan: {verb} {kind} {source} to {destination}, carrying:\n"
        ));
    } else {
        stdout.push_str(&format!("Success! {past} {kind} {source} to {destination}.\n"));
    }
    let count = |name: &str| response.pointer(&format!("/transferred/{name}")).and_then(Value::as_u64).unwrap_or(0);
    for name in ["secrets", "versions", "history", "shares"] {
        stdout.push_str(&format!("  {name}: {}\n", count(name)));
    }

    let stderr = response
        .get("warnings")
        .and_then(Value::as_array)
        .map(|warnings| {
            warnings
                .iter()
                .map(|w| {
                    let text = |name: &str| one_line(w.get(name).and_then(Value::as_str).unwrap_or(""));
                    format!("warning[{}]: {}: {}", text("code"), text("subject"), text("message"))
                })
                .collect()
        })
        .unwrap_or_default();

    Rendered { stdout, stderr }
}

/// `<mount>` and `<path>` of a location already checked by [`build_body`]; the
/// raw text when it was not splittable (never reached on the success path).
fn split_or_raw(location: &str) -> (&str, &str) {
    location.trim_matches('/').split_once('/').unwrap_or((location, ""))
}

#[cfg(test)]
mod test {
    use super::*;

    fn parse_copy(extra: &[&str]) -> Copy {
        let mut argv = vec!["copy"];
        argv.extend_from_slice(extra);
        Copy::try_parse_from(argv).expect("parses")
    }

    #[test]
    fn parses_locations_and_flags() {
        let c = parse_copy(&["--kind", "resource", "resources/db1", "resources/db2"]);
        assert_eq!(c.kind, Kind::Resource);
        assert_eq!(c.source, "resources/db1");
        assert_eq!(c.source_namespace, "");
        assert_eq!(c.destination_namespace, "");
        assert_eq!(c.on_conflict, OnConflict::Refuse);
        assert!(!c.dry_run);
        assert_eq!(split_location("secret/app/db").unwrap(), ("secret".to_string(), "app/db".to_string()));
        assert_eq!(split_location("/secret/app/db/").unwrap(), ("secret".to_string(), "app/db".to_string()));
        assert!(split_location("secret").is_err());
        assert!(split_location("secret/").is_err());
        assert!(split_location("").is_err());

        let c = parse_copy(&[
            "--kind",
            "kv-secret",
            "--source-namespace",
            "team-a",
            "--destination-namespace",
            "team-b/sub",
            "--on-conflict",
            "rename",
            "--dry-run",
            "secret/app/db",
            "kv/db",
        ]);
        assert_eq!(c.kind, Kind::KvSecret);
        assert_eq!(c.source_namespace, "team-a");
        assert_eq!(c.destination_namespace, "team-b/sub");
        assert_eq!(c.on_conflict, OnConflict::Rename);
        assert!(c.dry_run);
        for (word, want) in [("refuse", OnConflict::Refuse), ("overwrite", OnConflict::Overwrite)] {
            let c = parse_copy(&["--kind", "resource", "--on-conflict", word, "a/b", "a/c"]);
            assert_eq!(c.on_conflict, want);
        }
        let m = Move::try_parse_from(["move", "--kind", "resource", "a/b", "a/c"]).expect("move parses");
        assert_eq!(m.source, "a/b");
    }

    #[test]
    fn invalid_kind_or_on_conflict_is_rejected() {
        assert!(Copy::try_parse_from(["copy", "--kind", "file", "a/b", "a/c"]).is_err());
        assert!(Copy::try_parse_from(["copy", "a/b", "a/c"]).is_err(), "--kind is required");
        assert!(Copy::try_parse_from(["copy", "--kind", "resource", "--on-conflict", "merge", "a/b", "a/c"]).is_err());
        assert!(Copy::try_parse_from(["copy", "--kind", "resource", "a/b"]).is_err(), "destination is required");
        let c = parse_copy(&["--kind", "resource", "onlymount", "a/c"]);
        assert!(build_body(&c).is_err(), "a location without a path is refused before any request");
    }

    #[test]
    fn registered_under_transfer() {
        use clap::Parser as _;
        let argv = ["bvault", "transfer", "move", "--kind", "resource", "resources/a", "resources/b"];
        assert!(crate::Cli::try_parse_from(argv).is_ok());
    }

    #[test]
    fn request_body_matches_api_shape() {
        let c = parse_copy(&[
            "--kind",
            "kv-secret",
            "--source-namespace",
            "/team-a/",
            "--destination-namespace",
            "team-b",
            "--on-conflict",
            "overwrite",
            "secret/app/db",
            "secret/app/db2",
        ]);
        let body = Value::Object(build_body(&c).unwrap());
        assert_eq!(
            body,
            json!({
                "kind": "kv-secret",
                "source": { "namespace": "team-a", "mount": "secret", "path": "app/db" },
                "destination": { "namespace": "team-b", "mount": "secret", "path": "app/db2" },
                "on_conflict": "overwrite",
                "dry_run": false
            })
        );
        let c = parse_copy(&["--kind", "resource", "--dry-run", "resources/db1", "resources/db1"]);
        let body = Value::Object(build_body(&c).unwrap());
        assert_eq!(body["kind"], "resource");
        assert_eq!(body["on_conflict"], "refuse");
        assert_eq!(body["dry_run"], true);
        assert_eq!(body["source"]["namespace"], "");
    }

    fn sample_response(dry_run: bool) -> Value {
        json!({
            "transferred": { "secrets": 2, "versions": 5, "history": 4, "shares": 1 },
            "warnings": [
                { "code": "policies-not-carried", "subject": "team-a/resources/db1", "message": "policies stay behind" },
                { "code": "renamed", "subject": "db1", "message": "written as db1-2\nsecond line" }
            ],
            "dry_run": dry_run,
            "destination": { "namespace": "team-b", "mount": "resources", "path": "db1-2" }
        })
    }

    #[test]
    fn prints_warnings_and_exits_zero() {
        let c = parse_copy(&["--kind", "resource", "--source-namespace", "team-a", "resources/db1", "resources/db1"]);
        let out = render(Op::Copy, &c, &sample_response(false));
        assert!(
            out.stdout.contains("Success! Copied resource team-a/resources/db1 to team-b/resources/db1-2"),
            "{}",
            out.stdout
        );
        for count in ["secrets: 2", "versions: 5", "history: 4", "shares: 1"] {
            assert!(out.stdout.contains(count), "{count} in {}", out.stdout);
        }
        assert!(!out.stdout.contains("warning["), "warnings never go to stdout");
        assert_eq!(
            out.stderr,
            vec![
                "warning[policies-not-carried]: team-a/resources/db1: policies stay behind".to_string(),
                "warning[renamed]: db1: written as db1-2 second line".to_string(),
            ]
        );
        let m = Move::try_parse_from(["move", "--kind", "kv-secret", "secret/a", "secret/b"]).unwrap();
        let out = render(Op::Move, &m, &sample_response(false));
        assert!(out.stdout.contains("Success! Moved kv-secret"), "{}", out.stdout);
    }

    #[test]
    fn dry_run_says_nothing_was_written() {
        let c = parse_copy(&["--kind", "resource", "--dry-run", "resources/db1", "resources/db1"]);
        let out = render(Op::Copy, &c, &sample_response(true));
        assert!(out.stdout.contains("Dry run: nothing was written."), "{}", out.stdout);
        assert!(!out.stdout.contains("Success!"), "{}", out.stdout);
        assert!(out.stdout.contains("secrets: 2"), "the plan carries counts: {}", out.stdout);
        assert_eq!(out.stderr.len(), 2, "a dry run still reports every warning");
    }

    #[test]
    fn overwrite_prints_non_atomic_notice() {
        let notice = overwrite_notice(OnConflict::Overwrite, false).expect("overwrite warns");
        assert!(notice.contains("deletes the destination") && notice.contains("not atomic"), "{notice}");
        assert!(overwrite_notice(OnConflict::Overwrite, true).is_none(), "a dry run deletes nothing");
        assert!(overwrite_notice(OnConflict::Refuse, false).is_none());
        assert!(overwrite_notice(OnConflict::Rename, false).is_none());
    }
}
