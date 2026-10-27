use clap::{Parser, Subcommand};
use derive_more::Deref;
use serde_json::{Map, Value};
use sysexits::ExitCode;

use crate::{
    command::{self, CommandExecutor},
    errors::RvError,
    EXIT_CODE_INSUFFICIENT_PARAMS, EXIT_CODE_OK,
};

/// `bvault operator hsm <subcommand>` — inspect the HSM seal and run the
/// pool ceremonies (features/hsm-pool-ha.md). Admin credentials come from a
/// TTY prompt or `env:VAR`, never from an argument.
#[derive(Parser)]
#[command(author, version, about = "Inspect the HSM seal and run HSM pool ceremonies (features/hsm-pool-ha.md)")]
pub struct Hsm {
    #[command(subcommand)]
    command: HsmCommands,
}

#[derive(Subcommand)]
pub enum HsmCommands {
    /// Show the HSM seal status: backend, members, epoch, replication and recovery posture.
    Status(HsmStatus),
    /// List the pool members the seal record holds.
    Members(HsmRead),
    /// Add or retire a pool member.
    #[command(subcommand)]
    Member(MemberCommands),
    /// Enroll, revoke or list pool nodes.
    #[command(subcommand)]
    Node(NodeCommands),
    /// Show the last repair run, or run the repair job now with `--run`.
    Repair(HsmRepair),
    /// New wrap keys on every active member and every set re-wrapped to the next epoch.
    RotateEpoch(HsmRotateEpoch),
    /// Move this node's per-node seal record onto the pool (loopback, `migrate_from` configured, after bootstrap).
    MigrateToPool(HsmMigrateToPool),
    /// Before `operator init` on a pool: attest both members and enroll this node (loopback only).
    Bootstrap(HsmBootstrap),
    /// Provision a factory-state device into the pool layout and write its attestation bundle (local, no server).
    Provision(HsmProvision),
    /// After losing both pool devices: submit the recovery shares and move the pool onto two new devices.
    Recover(HsmRecover),
}

#[derive(Subcommand)]
pub enum MemberCommands {
    /// Attest a provisioned device and add it as `joining` (needs its admin credential).
    Add(MemberAdd),
    /// Retire a member; repair then removes its copies.
    Retire(MemberRetire),
}

#[derive(Subcommand)]
pub enum NodeCommands {
    /// Enroll a node on every live member (needs every live member's admin credential).
    Add(NodeAdd),
    /// Revoke a node's device credentials (needs the admin credentials).
    Revoke(NodeRevoke),
    /// List enrolled and pending nodes.
    List(HsmRead),
}

impl Hsm {
    #[inline]
    pub fn execute(&mut self) -> ExitCode {
        match &mut self.command {
            HsmCommands::Status(c) => c.execute(),
            HsmCommands::Members(c) => c.run("/v2/sys/hsm/members"),
            HsmCommands::Member(MemberCommands::Add(c)) => c.execute(),
            HsmCommands::Member(MemberCommands::Retire(c)) => c.execute(),
            HsmCommands::Node(NodeCommands::Add(c)) => c.execute(),
            HsmCommands::Node(NodeCommands::Revoke(c)) => c.execute(),
            HsmCommands::Node(NodeCommands::List(c)) => c.run("/v2/sys/hsm/nodes"),
            HsmCommands::Repair(c) => c.execute(),
            HsmCommands::Bootstrap(c) => c.execute(),
            HsmCommands::RotateEpoch(c) => c.execute(),
            HsmCommands::MigrateToPool(c) => c.execute(),
            HsmCommands::Provision(c) => exit_code(c.run()),
            HsmCommands::Recover(c) => c.execute(),
        }
    }
}

/// Where each member's `bv-admin` credential comes from: `--admin hsm-a`
/// prompts on the TTY, `--admin hsm-a=env:VAR` reads the environment.
#[derive(clap::Args, Debug, Default)]
pub struct AdminArgs {
    /// `<member>` (prompted on the TTY) or `<member>=env:VAR`. Repeat per member.
    #[arg(long = "admin", value_name = "MEMBER[=env:VAR]")]
    admin: Vec<String>,
}

impl AdminArgs {
    fn credentials(&self) -> Result<Map<String, Value>, RvError> {
        read_admin_credentials(&self.admin, |member| {
            rpassword::prompt_password(format!("bv-admin credential for HSM pool member {member} (will not echo): "))
                .map_err(|e| RvError::ErrString(format!("reading the admin credential for {member}: {e}")))
        })
    }
}

/// One secret from `env:VAR`, or the TTY when `source` is empty. A literal
/// value is refused, as for `--admin`.
fn read_secret(what: &str, source: &str) -> Result<String, RvError> {
    let value = if source.is_empty() {
        rpassword::prompt_password(format!("{what} (will not echo): "))
            .map_err(|e| RvError::ErrString(format!("reading {what}: {e}")))?
    } else {
        let var = source.strip_prefix("env:").ok_or_else(|| {
            RvError::ErrString(format!("{what} comes from a TTY prompt or `env:VAR`, never from an argument"))
        })?;
        std::env::var(var).map_err(|_| RvError::ErrString(format!("env var {var} is not set")))?
    };
    if value.is_empty() {
        return Err(RvError::ErrString(format!("{what} is empty")));
    }
    Ok(value)
}

/// `NAME=FILE` bundle arguments, read into `{name: bundle JSON}`.
fn read_bundles(specs: &[String]) -> Result<Map<String, Value>, RvError> {
    let mut out = Map::new();
    for spec in specs {
        let (name, file) =
            spec.split_once('=').ok_or_else(|| RvError::ErrString(format!("--bundle {spec:?}: expected NAME=FILE")))?;
        let text = std::fs::read_to_string(file).map_err(|e| RvError::ErrString(format!("reading {file}: {e}")))?;
        out.insert(name.to_string(), Value::String(text));
    }
    Ok(out)
}

/// Resolve `--admin` specs. A literal value is refused: an argument is
/// visible in the process list and the shell history.
fn read_admin_credentials(
    specs: &[String],
    prompt: impl Fn(&str) -> Result<String, RvError>,
) -> Result<Map<String, Value>, RvError> {
    let mut out = Map::new();
    for spec in specs {
        let (member, credential) = match spec.split_once('=') {
            None => (spec.as_str(), prompt(spec)?),
            Some((member, source)) => match source.strip_prefix("env:") {
                Some(var) => {
                    (member, std::env::var(var).map_err(|_| RvError::ErrString(format!("env var {var} is not set")))?)
                }
                None => {
                    return Err(RvError::ErrString(format!(
                        "--admin {member}=…: admin credentials come from a TTY prompt (`--admin {member}`) or \
                         `env:VAR`, never from an argument"
                    )))
                }
            },
        };
        if member.is_empty() || credential.is_empty() {
            return Err(RvError::ErrString(format!("--admin {member:?}: empty member name or credential")));
        }
        out.insert(member.to_string(), Value::String(credential));
    }
    Ok(out)
}

fn print_response(resp: &crate::api::HttpResponse) {
    let body = resp.response_data.clone().unwrap_or(Value::Null);
    println!("{}", serde_json::to_string_pretty(&body).unwrap_or_else(|_| "{}".into()));
}

fn exit_code(result: Result<(), RvError>) -> ExitCode {
    match result {
        Ok(()) => EXIT_CODE_OK,
        Err(e) => {
            eprintln!("Error: {e}");
            EXIT_CODE_INSUFFICIENT_PARAMS
        }
    }
}

#[derive(Parser, Deref)]
#[command(author, version, about = "Show the HSM seal status")]
pub struct HsmStatus {
    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,
}

impl CommandExecutor for HsmStatus {
    #[inline]
    fn execute(&mut self) -> ExitCode {
        exit_code(self.main())
    }

    #[inline]
    fn main(&self) -> Result<(), RvError> {
        let client = self.client()?;
        print_response(&client.sys().hsm_status()?);
        Ok(())
    }
}

/// A read-only listing (`members`, `node list`).
#[derive(Parser, Deref)]
pub struct HsmRead {
    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,
}

impl HsmRead {
    fn run(&self, path: &str) -> ExitCode {
        exit_code(self.client().and_then(|c| c.request_read(path.to_string())).map(|resp| print_response(&resp)))
    }
}

#[derive(Parser, Deref)]
pub struct MemberAdd {
    /// Name of the new member (as the seal record will know it).
    name: String,
    /// The attestation bundle `provision` wrote (JSON file).
    #[arg(long)]
    bundle: std::path::PathBuf,
    /// The member's https:// mTLS gateway URL (yubihsm2).
    #[arg(long, default_value = "")]
    gateway: String,
    #[command(flatten)]
    admin: AdminArgs,
    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,
}

impl CommandExecutor for MemberAdd {
    fn execute(&mut self) -> ExitCode {
        exit_code(self.main())
    }

    fn main(&self) -> Result<(), RvError> {
        let bundle = std::fs::read_to_string(&self.bundle)
            .map_err(|e| RvError::ErrString(format!("reading {}: {e}", self.bundle.display())))?;
        let mut data = Map::new();
        data.insert("bundle".into(), Value::String(bundle));
        data.insert("gateway".into(), Value::String(self.gateway.clone()));
        data.insert("admin_credentials".into(), Value::Object(self.admin.credentials()?));
        let resp = self.client()?.request_write(format!("/v2/sys/hsm/members/{}", self.name), Some(data))?;
        print_response(&resp);
        Ok(())
    }
}

#[derive(Parser, Deref)]
pub struct MemberRetire {
    name: String,
    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,
}

impl CommandExecutor for MemberRetire {
    fn execute(&mut self) -> ExitCode {
        exit_code(self.main())
    }

    fn main(&self) -> Result<(), RvError> {
        let resp = self.client()?.request_write(format!("/v2/sys/hsm/members/{}/retire", self.name), None)?;
        print_response(&resp);
        Ok(())
    }
}

#[derive(Parser, Deref)]
pub struct NodeAdd {
    node_id: String,
    /// The node's transport key fingerprint, as the node logged it; confirm
    /// it out of band before enrolling.
    #[arg(long)]
    fingerprint: String,
    #[command(flatten)]
    admin: AdminArgs,
    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,
}

impl CommandExecutor for NodeAdd {
    fn execute(&mut self) -> ExitCode {
        exit_code(self.main())
    }

    fn main(&self) -> Result<(), RvError> {
        let mut data = Map::new();
        data.insert("transport_fp".into(), Value::String(self.fingerprint.clone()));
        data.insert("admin_credentials".into(), Value::Object(self.admin.credentials()?));
        let resp = self.client()?.request_write(format!("/v2/sys/hsm/nodes/{}", self.node_id), Some(data))?;
        print_response(&resp);
        Ok(())
    }
}

#[derive(Parser, Deref)]
pub struct NodeRevoke {
    node_id: String,
    #[command(flatten)]
    admin: AdminArgs,
    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,
}

impl CommandExecutor for NodeRevoke {
    fn execute(&mut self) -> ExitCode {
        exit_code(self.main())
    }

    fn main(&self) -> Result<(), RvError> {
        let mut data = Map::new();
        data.insert("admin_credentials".into(), Value::Object(self.admin.credentials()?));
        let resp = self.client()?.request_delete(format!("/v2/sys/hsm/nodes/{}", self.node_id), Some(data))?;
        print_response(&resp);
        Ok(())
    }
}

#[derive(Parser, Deref)]
pub struct HsmRepair {
    /// Run the repair job now instead of showing the last run.
    #[arg(long)]
    run: bool,
    #[command(flatten)]
    admin: AdminArgs,
    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,
}

impl CommandExecutor for HsmRepair {
    fn execute(&mut self) -> ExitCode {
        exit_code(self.main())
    }

    fn main(&self) -> Result<(), RvError> {
        let client = self.client()?;
        let resp = if self.run {
            let mut data = Map::new();
            data.insert("admin_credentials".into(), Value::Object(self.admin.credentials()?));
            client.request_write("/v2/sys/hsm/repair".to_string(), Some(data))?
        } else {
            client.request_read("/v2/sys/hsm/repair".to_string())?
        };
        print_response(&resp);
        Ok(())
    }
}

#[derive(Parser, Deref)]
pub struct HsmRotateEpoch {
    #[command(flatten)]
    admin: AdminArgs,
    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,
}

impl CommandExecutor for HsmRotateEpoch {
    fn execute(&mut self) -> ExitCode {
        exit_code(self.main())
    }

    fn main(&self) -> Result<(), RvError> {
        let mut data = Map::new();
        data.insert("admin_credentials".into(), Value::Object(self.admin.credentials()?));
        print_response(&self.client()?.request_write("/v2/sys/hsm/rotate-epoch".to_string(), Some(data))?);
        Ok(())
    }
}

#[derive(Parser, Deref)]
pub struct HsmMigrateToPool {
    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,
}

impl CommandExecutor for HsmMigrateToPool {
    fn execute(&mut self) -> ExitCode {
        exit_code(self.main())
    }

    fn main(&self) -> Result<(), RvError> {
        print_response(&self.client()?.request_write("/v2/sys/hsm/migrate-to-pool".to_string(), None)?);
        Ok(())
    }
}

#[derive(Parser, Deref)]
pub struct HsmBootstrap {
    /// `MEMBER=FILE`: the attestation bundle `provision` wrote for each member.
    #[arg(long = "bundle", value_name = "MEMBER=FILE")]
    bundles: Vec<String>,
    #[command(flatten)]
    admin: AdminArgs,
    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,
}

impl CommandExecutor for HsmBootstrap {
    fn execute(&mut self) -> ExitCode {
        exit_code(self.main())
    }

    fn main(&self) -> Result<(), RvError> {
        let mut data = Map::new();
        data.insert("bundles".into(), Value::Object(read_bundles(&self.bundles)?));
        data.insert("admin_credentials".into(), Value::Object(self.admin.credentials()?));
        let resp = self.client()?.request_write("/v2/sys/hsm/bootstrap".to_string(), Some(data))?;
        print_response(&resp);
        Ok(())
    }
}

/// `operator hsm recover` (T454 phase 5). Shares come from `--share env:VAR`
/// or hidden TTY prompts, never from an argument; each one is submitted on
/// its own, then the new members and their admin credentials.
#[derive(Parser, Deref)]
pub struct HsmRecover {
    /// `NAME=FILE`: a new member and the attestation bundle `provision` wrote for it. Repeat per member.
    #[arg(long = "member", value_name = "NAME=FILE")]
    members: Vec<String>,
    /// `NAME=URL`: the https:// mTLS gateway of a new yubihsm2 member.
    #[arg(long = "gateway", value_name = "NAME=URL")]
    gateways: Vec<String>,
    /// `env:VAR` holding one recovery share (hex). Repeat per share; without it the shares are prompted on the TTY.
    #[arg(long = "share", value_name = "env:VAR")]
    shares: Vec<String>,
    /// Discard the shares submitted so far, and nothing else.
    #[arg(long)]
    reset: bool,
    #[command(flatten)]
    admin: AdminArgs,
    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,
}

const RECOVER_PATH: &str = "/v2/sys/hsm/recover";

/// The `data` of a successful `recover` response, or the server's refusal.
fn recover_step(client: &crate::api::Client, body: Map<String, Value>) -> Result<Value, RvError> {
    let resp = client.request_write(RECOVER_PATH.to_string(), Some(body))?;
    let data = resp.response_data.clone().unwrap_or(Value::Null);
    if resp.response_status != 200 {
        let why = data.get("error").and_then(|e| e.as_str()).unwrap_or("refused").to_string();
        return Err(RvError::ErrString(format!("{RECOVER_PATH}: {why}")));
    }
    Ok(data.get("data").cloned().unwrap_or(data))
}

/// `NAME=VALUE` arguments into a map; a missing `=` is refused.
fn name_values(flag: &str, specs: &[String]) -> Result<Map<String, Value>, RvError> {
    let mut out = Map::new();
    for spec in specs {
        let (name, value) =
            spec.split_once('=').ok_or_else(|| RvError::ErrString(format!("--{flag} {spec:?}: expected NAME=VALUE")))?;
        out.insert(name.to_string(), Value::String(value.to_string()));
    }
    Ok(out)
}

impl CommandExecutor for HsmRecover {
    fn execute(&mut self) -> ExitCode {
        exit_code(self.main())
    }

    fn main(&self) -> Result<(), RvError> {
        let client = self.client()?;
        if self.reset {
            let mut body = Map::new();
            body.insert("reset".into(), Value::Bool(true));
            println!("{}", serde_json::to_string_pretty(&recover_step(&client, body)?).unwrap_or_default());
            return Ok(());
        }
        // Everything that can fail locally fails before a share is sent.
        let bundles = read_bundles(&self.members)?;
        if bundles.is_empty() {
            return Err(RvError::ErrString("give each new member as --member NAME=FILE".into()));
        }
        let gateways = name_values("gateway", &self.gateways)?;
        let admin = self.admin.credentials()?;
        let mut members = Map::new();
        for (name, bundle) in bundles {
            let mut member = Map::new();
            member.insert("bundle".into(), bundle);
            member.insert("gateway".into(), gateways.get(&name).cloned().unwrap_or(Value::String(String::new())));
            members.insert(name, Value::Object(member));
        }

        let mut submitted = 0usize;
        loop {
            let source = match self.shares.get(submitted) {
                Some(spec) => spec.as_str(),
                None if !self.shares.is_empty() => {
                    return Err(RvError::ErrString(format!("{submitted} share(s) given; the ceremony needs more")))
                }
                None => "",
            };
            let share = zeroize::Zeroizing::new(read_secret(&format!("recovery share {}", submitted + 1), source)?);
            let mut body = Map::new();
            body.insert("share".into(), Value::String(share.trim().to_string()));
            let progress = recover_step(&client, body)?;
            submitted += 1;
            eprintln!("share accepted: {} of {}", progress["progress"], progress["threshold"]);
            if progress["ready"] == Value::Bool(true) {
                break;
            }
        }

        let mut body = Map::new();
        body.insert("members".into(), Value::Object(members));
        body.insert("admin_credentials".into(), Value::Object(admin));
        println!("{}", serde_json::to_string_pretty(&recover_step(&client, body)?).unwrap_or_default());
        Ok(())
    }
}

/// Runs on the HSM host, against the device directly; the vault is not involved.
#[derive(Parser)]
pub struct HsmProvision {
    /// Mock device state file (dev and homolog builds with `hsm_mock`).
    #[arg(long, conflicts_with = "connector")]
    mock_state_path: Option<String>,
    /// Serial a new mock device takes.
    #[arg(long, requires = "mock_state_path")]
    serial: Option<String>,
    /// `yubihsm-connector` URL on this host (`http://127.0.0.1:12345`) or `usb`.
    #[arg(long)]
    connector: Option<String>,
    /// Accept a device that is not in factory state if its layout verifies.
    #[arg(long)]
    adopt: bool,
    /// `env:VAR` for the factory key's password; the published default if absent.
    #[arg(long, default_value = "")]
    factory_password: String,
    /// `env:VAR` for the new `bv-admin` password; prompted on the TTY if absent.
    #[arg(long, default_value = "")]
    admin_password: String,
    /// Where to write the attestation bundle (JSON, no secrets).
    #[arg(long)]
    out: std::path::PathBuf,
}

impl HsmProvision {
    fn run(&self) -> Result<(), RvError> {
        let factory = if self.factory_password.is_empty() {
            bastion_vault::hsm::admin::FACTORY_PASSWORD.to_string()
        } else {
            read_secret("the factory key password", &self.factory_password)?
        };
        let admin = zeroize::Zeroizing::new(read_secret("the new bv-admin password", &self.admin_password)?);
        let objects = bastion_vault::hsm::HsmObjectIds::default();
        let bundle = match (&self.mock_state_path, &self.connector) {
            (Some(path), None) => provision_mock(path, self.serial.as_deref(), &factory, &admin, &objects, self.adopt)?,
            (None, Some(connector)) => provision_yubihsm2(connector, &factory, &admin, &objects, self.adopt)?,
            _ => return Err(RvError::ErrString("give exactly one of --mock-state-path and --connector".into())),
        };
        let json = serde_json::to_string_pretty(&bundle).map_err(|e| RvError::ErrString(e.to_string()))?;
        std::fs::write(&self.out, json)
            .map_err(|e| RvError::ErrString(format!("writing {}: {e}", self.out.display())))?;
        println!("provisioned {}; attestation bundle written to {}", bundle.serial, self.out.display());
        Ok(())
    }
}

#[cfg(feature = "hsm_mock")]
fn provision_mock(
    path: &str,
    serial: Option<&str>,
    factory: &str,
    admin: &str,
    objects: &bastion_vault::hsm::HsmObjectIds,
    adopt: bool,
) -> Result<bastion_vault::hsm::ceremony::AttestationBundle, RvError> {
    bastion_vault::hsm::refuse_mock_in_production()?;
    let serial = serial.ok_or_else(|| RvError::ErrString("--serial is required for a mock device".into()))?;
    let device =
        bastion_vault::hsm::mock::MockHsmDevice::open_factory(path, serial, bastion_vault::hsm::clock::monotonic())?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| RvError::ErrString(e.to_string()))?;
    runtime.block_on(device.provision(factory, admin, objects, adopt))
}

#[cfg(not(feature = "hsm_mock"))]
fn provision_mock(
    _: &str,
    _: Option<&str>,
    _: &str,
    _: &str,
    _: &bastion_vault::hsm::HsmObjectIds,
    _: bool,
) -> Result<bastion_vault::hsm::ceremony::AttestationBundle, RvError> {
    Err(RvError::ErrString("this build has no mock HSM (feature `hsm_mock`)".into()))
}

#[cfg(feature = "hsm_yubihsm2")]
fn provision_yubihsm2(
    connector: &str,
    factory: &str,
    admin: &str,
    objects: &bastion_vault::hsm::HsmObjectIds,
    adopt: bool,
) -> Result<bastion_vault::hsm::ceremony::AttestationBundle, RvError> {
    bastion_vault::hsm::yubihsm2::provision(connector, factory, admin, objects, adopt)
}

#[cfg(not(feature = "hsm_yubihsm2"))]
fn provision_yubihsm2(
    _: &str,
    _: &str,
    _: &str,
    _: &bastion_vault::hsm::HsmObjectIds,
    _: bool,
) -> Result<bastion_vault::hsm::ceremony::AttestationBundle, RvError> {
    Err(RvError::ErrString("this build has no YubiHSM 2 support (feature `hsm_yubihsm2`)".into()))
}

#[cfg(test)]
mod test {
    use super::{name_values, read_admin_credentials, read_bundles, read_secret};
    use crate::{errors::RvError, test_utils::TestHttpServer};

    /// The recovery route exists under v2 only, takes no token, and refuses
    /// an unsealed node (and a non-HSM seal) without echoing the body.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_hsm_recover_is_refused_on_an_unsealed_or_non_hsm_vault() {
        let server = TestHttpServer::new_with_prometheus("test_hsm_recover_refused", true).await;
        let secret = "ab".repeat(65);
        let body = serde_json::json!({ "share": secret });
        let out = server.write("v2/sys/hsm/recover", body.as_object().cloned(), None);
        let status = out.as_ref().map(|(s, _)| *s).unwrap_or(0);
        assert!(status == 400 || out.is_err(), "{out:?}");
        if let Ok((_, body)) = &out {
            assert!(body.to_string().contains("unsealed"), "{body}");
            assert!(!body.to_string().contains(&secret), "the share is never echoed");
        }
        let v1 = server.write("v1/sys/hsm/recover", body.as_object().cloned(), None);
        assert!(v1.as_ref().map(|(s, _)| *s == 404 || *s == 405).unwrap_or(true), "v1 is frozen: {v1:?}");
    }

    #[test]
    fn recovery_shares_never_come_from_an_argument() {
        let err = read_secret("recovery share 1", "abcdef").unwrap_err();
        assert!(err.to_string().contains("never from an argument") && !err.to_string().contains("abcdef"));
        assert!(name_values("gateway", &["hsm-c".into()]).is_err());
        assert_eq!(name_values("gateway", &["hsm-c=https://c:8250".into()]).unwrap()["hsm-c"], "https://c:8250");
    }

    /// With no `hsm` seal configured, the status endpoint reports the classic
    /// Shamir provider (auto_unseal = false) and the current seal state.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_hsm_status_defaults_to_shamir() {
        // `new_with_prometheus` uses a version-less URL prefix so a `v2/…`
        // path resolves to `/v2/…` (plain `new` prepends `/v1`).
        let server = TestHttpServer::new_with_prometheus("test_hsm_status_defaults_to_shamir", true).await;
        let resp = server.read("v2/sys/hsm/status", Some(&server.root_token)).unwrap().1;
        assert_eq!(resp.get("type").and_then(|v| v.as_str()), Some("shamir"));
        assert_eq!(resp.get("auto_unseal").and_then(|v| v.as_bool()), Some(false));
        assert_eq!(resp.get("sealed").and_then(|v| v.as_bool()), Some(false));
        assert_eq!(resp.get("initialized").and_then(|v| v.as_bool()), Some(true));
    }

    /// The pool ceremony routes exist under v2 only, and refuse a vault whose
    /// seal is not an HSM seal with a 400 rather than a server error.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_hsm_pool_routes_are_v2_only_and_need_an_hsm_seal() {
        let server = TestHttpServer::new_with_prometheus("test_hsm_pool_routes_v2_only", true).await;
        for path in ["v2/sys/hsm/members", "v2/sys/hsm/nodes", "v2/sys/hsm/repair"] {
            let (status, body) = server.read(path, Some(&server.root_token)).unwrap();
            assert_eq!(status, 400, "{path}: {body:?}");
            assert!(body.to_string().contains("not an HSM seal"), "{path}: {body:?}");
        }
        // v1 is frozen: no such route (an error, or a 404).
        let body = serde_json::json!({ "admin_credentials": { "hsm-a": "x" } });
        let rotate = server.write("v2/sys/hsm/rotate-epoch", body.as_object().cloned(), Some(&server.root_token));
        assert!(rotate.as_ref().map(|(s, _)| *s == 400).unwrap_or(true), "{rotate:?}");
        let migrate = server.write("v2/sys/hsm/migrate-to-pool", None, None);
        assert!(migrate.as_ref().map(|(s, _)| *s == 400 || *s == 403).unwrap_or(true), "{migrate:?}");
        let v1 = server.read("v1/sys/hsm/members", Some(&server.root_token));
        assert!(v1.as_ref().map(|(s, _)| *s == 404).unwrap_or(true), "{v1:?}");
        let anonymous = server.read("v2/sys/hsm/members", None);
        assert!(anonymous.as_ref().map(|(s, _)| *s == 400 || *s == 403).unwrap_or(true), "{anonymous:?}");
    }

    #[test]
    fn admin_credentials_never_come_from_an_argument() {
        let refuse = |_: &str| -> Result<String, RvError> { panic!("no prompt expected") };
        let err = read_admin_credentials(&["hsm-a=hunter2".into()], refuse).unwrap_err();
        assert!(err.to_string().contains("never from an argument") && !err.to_string().contains("hunter2"));
        std::env::set_var("BV_TEST_HSM_ADMIN_A", "from-env");
        let creds = read_admin_credentials(&["hsm-a=env:BV_TEST_HSM_ADMIN_A".into()], refuse).unwrap();
        assert_eq!(creds["hsm-a"], "from-env");
        let prompted = read_admin_credentials(&["hsm-b".into()], |m| Ok(format!("typed-for-{m}"))).unwrap();
        assert_eq!(prompted["hsm-b"], "typed-for-hsm-b");
        assert!(read_admin_credentials(&["hsm-b".into()], |_| Ok(String::new())).is_err(), "empty refused");
        assert!(read_admin_credentials(&["hsm-c=env:BV_TEST_HSM_UNSET_VAR".into()], refuse).is_err());
    }

    #[test]
    fn provision_and_bootstrap_inputs_are_strict() {
        let err = read_secret("the new bv-admin password", "hunter2").unwrap_err();
        assert!(err.to_string().contains("never from an argument") && !err.to_string().contains("hunter2"));
        std::env::set_var("BV_TEST_HSM_ADMIN_PW", "pw");
        assert_eq!(read_secret("x", "env:BV_TEST_HSM_ADMIN_PW").unwrap(), "pw");
        assert!(read_bundles(&["no-equals-sign".into()]).is_err());
        assert!(read_bundles(&["hsm-a=/nonexistent/bundle.json".into()]).is_err());
    }

    /// Bootstrap needs an HSM seal and an uninitialized vault; this test
    /// server is initialized with the Shamir seal, so it is refused.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_hsm_bootstrap_is_refused_once_initialized() {
        let server = TestHttpServer::new_with_prometheus("test_hsm_bootstrap_refused", true).await;
        let body = serde_json::json!({ "admin_credentials": { "hsm-a": "x" }, "bundles": {} });
        let out = server.write("v2/sys/hsm/bootstrap", body.as_object().cloned(), None);
        let status = out.as_ref().map(|(s, _)| *s).unwrap_or(0);
        assert!(status == 400 || status == 403 || out.is_err(), "{out:?}");
        if let Ok((_, body)) = &out {
            assert!(!body.to_string().contains("\"x\""), "credentials are never echoed");
        }
    }
}
