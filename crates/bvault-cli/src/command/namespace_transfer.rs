//! `bvault transfer copy|move`: carry one resource or KV secret to another
//! namespace through `POST /v2/sys/namespace-transfer/{copy|move}`.

use clap::{Args, Parser, Subcommand, ValueEnum};
use derive_more::Deref;
use serde_json::{json, Map, Value};
use sysexits::ExitCode;

use crate::{
    api::Client,
    command::{self, CommandExecutor},
    errors::RvError,
    kernel_api::namespace::NAMESPACE_HEADER,
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
first slash is the mount, the rest is the item's path. The namespace is
never part of them; name it with --source-namespace and
--destination-namespace (default: the root namespace, "").

The request itself runs in the root namespace unless you pass
--namespace <path>, which sets the X-BastionVault-Namespace header. It
serves a token born in that namespace whose policy there names
sys/namespace-transfer/copy and/or .../move exactly (the grant counts only
in the token's own namespace; a child_visible token can also reach its
descendants, between any two of them, never a sibling or an ancestor), and
a ROOT sign-in assigned
to it whose root-namespace policy grants update on sys/namespace-transfer/*
(docs/cli-reference.md).

For a mount whose name has a slash, name the mount with --source-mount /
--destination-mount; the positional on that side is then the whole path
(--source-mount team/kv, positional app/db: mount team/kv, path app/db).

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
        value_name = "NAMESPACE",
        default_value = "",
        help = "Namespace the request runs in (default: root); sets the X-BastionVault-Namespace header."
    )]
    namespace: String,

    #[arg(
        long,
        value_name = "MOUNT",
        help = "Mount of the source, for a slash-named mount (SOURCE is then the path)."
    )]
    source_mount: Option<String>,

    #[arg(
        long,
        value_name = "MOUNT",
        help = "Mount of the destination, for a slash-named mount (DESTINATION is then the path)."
    )]
    destination_mount: Option<String>,

    #[arg(
        long,
        value_enum,
        value_name = "POLICY",
        default_value = "refuse",
        help = "When the destination exists: refuse, rename or overwrite (import first; if the name is taken, \
                delete it and import again; not atomic)."
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
    let (destination_mount, destination_path) = display_parts(args.destination_mount.as_deref(), &args.destination);
    let destination = show_place(&args.destination_namespace, &destination_mount, &destination_path);
    if let Some(notice) = overwrite_notice(args.on_conflict, args.dry_run, &destination) {
        eprintln!("{notice}");
    }

    let client = transfer_client(args)?;
    let resp = client.request_write(format!("/v2/sys/namespace-transfer/{}", op.route()), Some(body))?;
    let data = resp.response_data.unwrap_or(Value::Null);
    if let Some(err) = status_error(op, args.kind, resp.response_status, &data) {
        return Err(err);
    }

    let out = render(op, args, &data);
    print!("{}", out.stdout);
    for line in &out.stderr {
        eprintln!("{line}");
    }
    Ok(())
}

/// The headers the transfer request adds: the namespace the request itself
/// runs in (not the source's or destination's); none for the root namespace.
fn request_headers(namespace: &str) -> Vec<(&'static str, String)> {
    match namespace.trim_matches('/') {
        "" => Vec::new(),
        ns => vec![(NAMESPACE_HEADER, ns.to_string())],
    }
}

/// The HTTP client for the transfer, with [`request_headers`] applied.
fn transfer_client(args: &TransferArgs) -> Result<Client, RvError> {
    let mut client = args.client()?;
    for (name, value) in request_headers(&args.namespace) {
        client = client.add_header(name, &value);
    }
    Ok(client)
}

/// Trim the slashes around a positional and split it at the first one: the
/// mount is the first segment, the item's path is everything after it.
fn split_location(location: &str) -> Result<(String, String), RvError> {
    match location.trim_matches('/').split_once('/') {
        Some((mount, path)) if !mount.is_empty() && !path.trim_matches('/').is_empty() => {
            Ok((mount.to_string(), path.trim_matches('/').to_string()))
        }
        _ => Err(RvError::ErrString(format!(
            "'{location}' is not a location: write it as <mount>/<path>, or name the mount with --source-mount / \
             --destination-mount and give only the path (the namespace goes in --source-namespace / \
             --destination-namespace)"
        ))),
    }
}

/// The mount and path of one side: with a mount override the whole positional is
/// the path, otherwise [`split_location`] splits it.
fn resolve_location(mount: Option<&str>, location: &str) -> Result<(String, String), RvError> {
    let Some(mount) = mount else {
        return split_location(location);
    };
    let (mount, path) = (mount.trim_matches('/'), location.trim_matches('/'));
    if mount.is_empty() || path.is_empty() {
        return Err(RvError::ErrString(format!(
            "'{location}' with mount '{mount}': both a mount and a path are required"
        )));
    }
    Ok((mount.to_string(), path.to_string()))
}

fn place(namespace: &str, mount: Option<&str>, location: &str) -> Result<Value, RvError> {
    let (mount, path) = resolve_location(mount, location)?;
    Ok(json!({ "namespace": namespace.trim_matches('/'), "mount": mount, "path": path }))
}

/// The error for a non-200 answer, with the server's own text (`error`, or
/// the first of `errors`) on one line; `None` for a 200.
fn status_error(op: Op, kind: Kind, status: u16, data: &Value) -> Option<RvError> {
    if status == 200 {
        return None;
    }
    let detail = data
        .get("error")
        .and_then(Value::as_str)
        .or_else(|| data.pointer("/errors/0").and_then(Value::as_str))
        .map_or_else(|| "no error message in the response".to_string(), one_line);
    Some(RvError::ErrString(format!("{} of {} failed (HTTP {status}): {detail}", op.route(), kind.as_str())))
}

/// The request body of `POST /v2/sys/namespace-transfer/{copy|move}` (docs/api.md).
fn build_body(args: &TransferArgs) -> Result<Map<String, Value>, RvError> {
    let mut body = Map::new();
    body.insert("kind".into(), json!(args.kind.as_str()));
    body.insert("source".into(), place(&args.source_namespace, args.source_mount.as_deref(), &args.source)?);
    body.insert(
        "destination".into(),
        place(&args.destination_namespace, args.destination_mount.as_deref(), &args.destination)?,
    );
    body.insert("on_conflict".into(), json!(args.on_conflict.as_str()));
    body.insert("dry_run".into(), json!(args.dry_run));
    Ok(body)
}

fn overwrite_notice(on_conflict: OnConflict, dry_run: bool, destination: &str) -> Option<String> {
    (on_conflict == OnConflict::Overwrite && !dry_run).then(|| {
        format!(
            "warning[overwrite-not-atomic]: {}: overwrite tries the import first; if the name is taken it \
             deletes the destination and imports again; not atomic: if that import fails, the destination \
             stays deleted",
            one_line(destination)
        )
    })
}

/// Server text is shown on one line with control characters replaced, and the
/// invisible Unicode format and bidi characters removed, so a message cannot
/// move the cursor, forge a second `warning[...]` line or reorder what follows.
pub(crate) fn one_line(text: &str) -> String {
    text.chars().filter(|c| !is_invisible_format(*c)).map(|c| if c.is_control() { ' ' } else { c }).collect()
}

/// Zero-width and directional marks (U+200B-200F), line and paragraph
/// separators (U+2028-2029), bidi embeddings, overrides and isolates
/// (U+202A-202E, U+2066-2069), word joiner and invisible operators
/// (U+2060-2064), the Arabic letter mark (U+061C) and the BOM (U+FEFF).
/// U+200C/U+200D go too: names in Persian, Indic or emoji-ZWJ scripts show altered.
fn is_invisible_format(c: char) -> bool {
    matches!(
        c,
        '\u{061C}'
            | '\u{200B}'..='\u{200F}'
            | '\u{2028}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}'
            | '\u{FEFF}'
    )
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
    let (source_mount, source_path) = display_parts(args.source_mount.as_deref(), &args.source);
    let source = show_place(&args.source_namespace, &source_mount, &source_path);
    let destination = response.get("destination").and_then(show_response_place).unwrap_or_else(|| {
        let (mount, path) = display_parts(args.destination_mount.as_deref(), &args.destination);
        show_place(&args.destination_namespace, &mount, &path)
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

/// Mount and path for display, from a location [`build_body`] already
/// accepted; the raw text when it cannot be resolved (not reached on success).
fn display_parts(mount: Option<&str>, location: &str) -> (String, String) {
    resolve_location(mount, location).unwrap_or_else(|_| (String::new(), location.to_string()))
}

#[cfg(test)]
pub(super) mod test {
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
    fn renders_counts_on_stdout_and_warnings_on_stderr() {
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
        let notice = overwrite_notice(OnConflict::Overwrite, false, "team-b/resources/db1").expect("overwrite warns");
        assert!(notice.starts_with("warning[overwrite-not-atomic]: team-b/resources/db1: "), "{notice}");
        assert!(notice.contains("tries the import first"), "{notice}");
        assert!(notice.contains("if the name is taken it deletes the destination and imports again"), "{notice}");
        assert!(notice.contains("not atomic") && !notice.contains("deletes the destination first"), "{notice}");
        assert!(overwrite_notice(OnConflict::Overwrite, true, "x/y").is_none(), "a dry run deletes nothing");
        assert!(overwrite_notice(OnConflict::Refuse, false, "x/y").is_none());
        assert!(overwrite_notice(OnConflict::Rename, false, "x/y").is_none());
    }

    #[test]
    fn mount_overrides_make_the_positional_the_path() {
        let body = |extra: &[&str]| {
            let mut argv = vec!["--kind", "kv-secret"];
            argv.extend_from_slice(extra);
            Value::Object(build_body(&parse_copy(&argv)).unwrap())
        };
        let b = body(&["--source-mount", "team/kv", "app/db", "secret/app/db"]);
        assert_eq!(b["source"]["mount"], "team/kv");
        assert_eq!(b["source"]["path"], "app/db");
        assert_eq!(b["destination"]["mount"], "secret", "the other side still splits");
        assert_eq!(b["destination"]["path"], "app/db");

        let b = body(&["--destination-mount", "/team/kv/", "secret/app/db", "app/db"]);
        assert_eq!(b["source"]["mount"], "secret");
        assert_eq!(b["destination"]["mount"], "team/kv");
        assert_eq!(b["destination"]["path"], "app/db");

        let b = body(&["--source-mount", "a/b", "--destination-mount", "c/d", "x/y/z", "p"]);
        assert_eq!(b["source"], json!({ "namespace": "", "mount": "a/b", "path": "x/y/z" }));
        assert_eq!(b["destination"], json!({ "namespace": "", "mount": "c/d", "path": "p" }));

        let c = parse_copy(&["--kind", "kv-secret", "--source-mount", "kv", "", "secret/a"]);
        assert!(build_body(&c).is_err(), "an override needs a path");
        let c = parse_copy(&["--kind", "kv-secret", "--source-mount", "/", "a", "secret/a"]);
        assert!(build_body(&c).is_err(), "an override needs a mount");
        let c = parse_copy(&["--kind", "kv-secret", "app", "secret/a"]);
        assert!(build_body(&c).is_err(), "no override: a positional without a path is still refused");
        assert!(split_location("secret").unwrap_err().to_string().contains("--source-mount"));
    }

    #[test]
    fn failures_carry_the_servers_message_on_one_line() {
        let err =
            |status: u16, data: Value| status_error(Op::Move, Kind::KvSecret, status, &data).map(|e| e.to_string());
        assert_eq!(err(200, json!({ "error": "ignored" })), None);
        let e = err(409, json!({ "error": "secret/a: a secret already exists" })).unwrap();
        assert!(e.contains("move of kv-secret failed (HTTP 409): secret/a: a secret already exists"), "{e}");
        let e = err(429, json!({ "errors": ["rate limit exceeded"] })).unwrap();
        assert!(e.contains("(HTTP 429): rate limit exceeded"), "{e}");
        let e = err(500, json!({ "other": 1 })).unwrap();
        assert!(e.contains("(HTTP 500): no error message in the response"), "{e}");
        let e = err(502, Value::Null).unwrap();
        assert!(e.contains("(HTTP 502)"), "{e}");
        let e = err(400, json!({ "error": "bad\nwarning[x]: forged\u{1b}[2J" })).unwrap();
        assert!(!e.contains('\n') && !e.contains('\u{1b}'), "{e:?}");
        assert!(!e.contains("secret-value"), "only the server's text is shown");
    }
    #[test]
    fn namespace_flag_is_parsed_and_defaults_to_root() {
        assert_eq!(parse_copy(&["--kind", "resource", "a/b", "a/c"]).namespace, "");
        let c = parse_copy(&["--kind", "resource", "--namespace", "team-a/sub", "a/b", "a/c"]);
        assert_eq!(c.namespace, "team-a/sub");
        let m = Move::try_parse_from(["move", "--kind", "resource", "--namespace", "t", "a/b", "a/c"]).unwrap();
        assert_eq!(m.namespace, "t");
        // It is the request's namespace, apart from the two it names in the body.
        let c = parse_copy(&["--kind", "resource", "--namespace", "ops", "--source-namespace", "a", "x/y", "x/z"]);
        let body = Value::Object(build_body(&c).unwrap());
        assert_eq!(body["source"]["namespace"], "a");
        assert_eq!(body["destination"]["namespace"], "");
        assert!(body.get("namespace").is_none(), "the header, never the body, carries it: {body}");
    }

    #[test]
    fn request_headers_name_the_namespace_or_nothing() {
        assert!(request_headers("").is_empty(), "the default sends no header");
        assert!(request_headers("/").is_empty());
        assert_eq!(request_headers("team-a"), vec![(NAMESPACE_HEADER, "team-a".to_string())]);
        assert_eq!(request_headers("/team-a/sub/"), vec![(NAMESPACE_HEADER, "team-a/sub".to_string())]);
        assert_eq!(NAMESPACE_HEADER, "x-bastionvault-namespace");
    }

    /// A one-request HTTP server answering `status` with `reply` as JSON; the
    /// request head it received (header names lower-cased) arrives on the channel.
    pub(in crate::command) fn fake_vault(status: u16, reply: Value) -> (String, std::sync::mpsc::Receiver<String>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut received = Vec::new();
            let mut chunk = [0u8; 4096];
            let end = |bytes: &[u8]| bytes.windows(4).position(|w| w == b"\r\n\r\n");
            let (head_end, length) = loop {
                let n = stream.read(&mut chunk).unwrap_or(0);
                received.extend_from_slice(&chunk[..n]);
                if let Some(at) = end(&received) {
                    let head = String::from_utf8_lossy(&received[..at]).to_lowercase();
                    let length = head.lines().find_map(|l| l.strip_prefix("content-length:")?.trim().parse().ok());
                    break (at + 4, length.unwrap_or(0usize));
                }
                if n == 0 {
                    return;
                }
            };
            while received.len() < head_end + length {
                match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => received.extend_from_slice(&chunk[..n]),
                }
            }
            let head = String::from_utf8_lossy(&received[..head_end]).to_lowercase();
            let _ = tx.send(head);
            let body = serde_json::to_vec(&reply).unwrap();
            let reply_head = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(reply_head.as_bytes());
            let _ = stream.write_all(&body);
        });
        (format!("http://{addr}"), rx)
    }

    fn copy_against(address: &str, extra: &[&str]) -> Copy {
        let mut argv = vec!["--address", address, "--token", "a-test-token", "--kind", "resource"];
        argv.extend_from_slice(extra);
        argv.extend_from_slice(&["resources/db1", "resources/db1"]);
        parse_copy(&argv)
    }

    #[test]
    fn the_namespace_header_is_sent_on_the_transfer_request() {
        let (addr, seen) = fake_vault(200, json!({ "data": {} }));
        let c = copy_against(&addr, &["--namespace", "team-a", "--destination-namespace", "team-b"]);
        let body = build_body(&c).unwrap();
        let resp = transfer_client(&c.args).unwrap().request_write("/v2/sys/namespace-transfer/copy", Some(body));
        assert_eq!(resp.unwrap().response_status, 200);
        let head = seen.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        assert!(head.starts_with("post /v2/sys/namespace-transfer/copy "), "{head}");
        assert!(head.contains("\r\nx-bastionvault-namespace: team-a\r\n"), "{head}");
        assert!(head.contains("x-bastionvault-token: a-test-token"), "{head}");
    }

    #[test]
    fn no_namespace_header_is_sent_by_default() {
        let (addr, seen) = fake_vault(200, json!({ "data": {} }));
        let c = copy_against(&addr, &["--destination-namespace", "team-b"]);
        let body = build_body(&c).unwrap();
        transfer_client(&c.args).unwrap().request_write("/v2/sys/namespace-transfer/copy", Some(body)).unwrap();
        let head = seen.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        assert!(!head.contains("x-bastionvault-namespace"), "{head}");
    }

    #[test]
    fn invisible_format_characters_are_removed_from_server_text() {
        assert_eq!(one_line("a\u{202E}b\u{200B}c\u{2066}d\u{FEFF}e\u{200F}f\u{2069}g"), "abcdefg");
        assert_eq!(one_line("x\u{200B}\u{200C}\u{200D}\u{200E}y\u{202A}\u{202B}\u{202C}\u{202D}z"), "xyz");
        assert_eq!(one_line("a\u{061C}b\u{2060}c\u{2061}\u{2062}\u{2063}\u{2064}d\u{2028}e\u{2029}f"), "abcdef");
        assert_eq!(one_line("tab\there\nnl\u{1b}[2J"), "tab here nl [2J", "control characters still become spaces");
        assert_eq!(one_line("plain ünïcode 日本"), "plain ünïcode 日本", "visible text is untouched");

        let mut response = sample_response(false);
        response["warnings"][0]["message"] = json!("safe\u{202E}desrever\u{2066}");
        let c = parse_copy(&["--kind", "resource", "resources/db1", "resources/db1"]);
        let out = render(Op::Copy, &c, &response);
        assert_eq!(out.stderr[0], "warning[policies-not-carried]: team-a/resources/db1: safedesrever");
        let e = status_error(Op::Copy, Kind::Resource, 400, &json!({ "error": "no\u{202E}pe" })).unwrap().to_string();
        assert!(e.ends_with("(HTTP 400): nope"), "{e}");
    }

    /// The exit path: `execute` maps `main()`'s `Ok` to exit 0 and any `Err`
    /// to exit 1, so a transfer that succeeded with warnings is `Ok`, and a
    /// refused one is an `Err` carrying the server's message.
    #[test]
    fn warnings_do_not_fail_the_command_and_a_refusal_does() {
        let (addr, _seen) = fake_vault(200, sample_response(false));
        let ok = copy_against(&addr, &["--namespace", "ops"]).main();
        assert!(ok.is_ok(), "a 200 with warnings is a success: {ok:?}");

        let (addr, _seen) = fake_vault(409, json!({ "error": "resources/db1: a resource already exists" }));
        let err = copy_against(&addr, &[]).main().unwrap_err().to_string();
        assert!(err.contains("copy of resource failed (HTTP 409): resources/db1: a resource already exists"), "{err}");
    }
}
