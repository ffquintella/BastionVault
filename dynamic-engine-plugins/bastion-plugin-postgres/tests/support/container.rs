//! A throwaway database container for live tests, driven through the `docker`
//! or `podman` CLI (std only, no new dependencies).
//!
//! * Engine: `docker` or `podman` on PATH; `BV_TEST_CONTAINER_ENGINE` forces one.
//! * The container binds a random host port on 127.0.0.1 only, and its root
//!   password is random and never printed (it reaches the engine through the
//!   child's environment, not argv).
//! * [`PgContainer`] removes the container in `Drop` (`<engine> rm -f`), so a
//!   panicking test cleans up too. A SIGKILL of the test process cannot be
//!   covered; such containers carry the label `bv-test=bastion-plugin-postgres`
//!   for a manual `docker ps -a --filter label=bv-test`.
//!
//! No usable engine is reported as `Err(Unavailable)`; the caller decides
//! between skipping and failing (see `BV_TEST_REQUIRE_CONTAINER` in `live.rs`).
// Not every test that includes this module uses every item.
#![allow(dead_code)]

use std::io::Read;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

/// Pinned image tag for the live test.
pub const POSTGRES_IMAGE: &str = "postgres:16";
pub const POSTGRES_USER: &str = "postgres";

/// Why no container could be started. `Unavailable` is the skippable case
/// (no engine, daemon unreachable); `Failed` is a real error once an engine
/// was usable.
#[derive(Debug)]
pub enum ContainerError {
    Unavailable(String),
    Failed(String),
}

impl std::fmt::Display for ContainerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContainerError::Unavailable(m) | ContainerError::Failed(m) => f.write_str(m),
        }
    }
}

fn run(engine: &str, args: &[&str]) -> std::io::Result<Output> {
    Command::new(engine).args(args).stdin(Stdio::null()).output()
}

/// Pick an engine and check its daemon answers.
pub fn detect_engine() -> Result<String, ContainerError> {
    let candidates: Vec<String> = match std::env::var("BV_TEST_CONTAINER_ENGINE") {
        Ok(forced) if forced == "docker" || forced == "podman" => vec![forced],
        Ok(other) => {
            return Err(ContainerError::Failed(format!(
                "BV_TEST_CONTAINER_ENGINE must be `docker` or `podman`, got `{other}`"
            )))
        }
        Err(_) => vec!["docker".into(), "podman".into()],
    };
    let mut notes = Vec::new();
    for engine in candidates {
        match run(&engine, &["info", "--format", "{{.ServerVersion}}"]) {
            Ok(out) if out.status.success() => return Ok(engine),
            Ok(out) => notes.push(format!(
                "`{engine}` is installed but its daemon is unreachable ({})",
                String::from_utf8_lossy(&out.stderr).lines().next().unwrap_or("no detail").trim()
            )),
            Err(e) => notes.push(format!("`{engine}` not usable: {e}")),
        }
    }
    Err(ContainerError::Unavailable(notes.join("; ")))
}

/// Random lowercase hex from the OS; falls back to std's per-process random
/// hasher keys where /dev/urandom does not exist. Enough for a throwaway
/// loopback-only container, not a key generator.
pub fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    let from_os = std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut buf)).is_ok();
    if !from_os {
        use std::hash::{BuildHasher, Hasher};
        for chunk in buf.chunks_mut(8) {
            let mut h = std::collections::hash_map::RandomState::new().build_hasher();
            h.write_u128(
                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0),
            );
            let v = h.finish().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// A running Postgres container; removed on drop.
pub struct PgContainer {
    engine: String,
    name: String,
    pub host: &'static str,
    pub port: u16,
    pub user: &'static str,
    password: String,
}

impl PgContainer {
    /// Start `postgres:16` on 127.0.0.1:<random port>. Returns once the
    /// container is running; use [`PgContainer::wait_ready`] before connecting.
    pub fn start() -> Result<Self, ContainerError> {
        let engine = detect_engine()?;
        let name = format!(
            "bv-test-pg-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
            random_hex(3)
        );
        let password = random_hex(16);
        // Built before `docker run` so a failure half way still removes it.
        let mut guard = PgContainer {
            engine: engine.clone(),
            name: name.clone(),
            host: "127.0.0.1",
            port: 0,
            user: POSTGRES_USER,
            password: password.clone(),
        };
        // `-e POSTGRES_PASSWORD` without a value takes it from the child's
        // environment: the secret never appears in argv / `ps`.
        let out = Command::new(&engine)
            .args(["run", "-d", "--name", &name, "--label", "bv-test=bastion-plugin-postgres"])
            .args(["-p", "127.0.0.1::5432", "-e", "POSTGRES_PASSWORD", POSTGRES_IMAGE])
            .env("POSTGRES_PASSWORD", &password)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| ContainerError::Failed(format!("`{engine} run` could not start: {e}")))?;
        if !out.status.success() {
            return Err(ContainerError::Failed(format!(
                "`{engine} run {POSTGRES_IMAGE}` failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        let mapped = run(&engine, &["port", &name, "5432/tcp"])
            .map_err(|e| ContainerError::Failed(format!("`{engine} port`: {e}")))?;
        let text = String::from_utf8_lossy(&mapped.stdout);
        guard.port = text
            .lines()
            .find_map(|l| l.trim().rsplit(':').next().and_then(|p| p.parse::<u16>().ok()))
            .ok_or_else(|| ContainerError::Failed(format!("could not read the mapped port from `{}`", text.trim())))?;
        Ok(guard)
    }

    pub fn password(&self) -> &str {
        &self.password
    }

    /// libpq-style target, without credentials.
    pub fn url(&self) -> String {
        format!("host={} port={} dbname=postgres sslmode=disable", self.host, self.port)
    }

    fn running(&self) -> bool {
        run(&self.engine, &["inspect", "-f", "{{.State.Running}}", &self.name])
            .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "true")
            .unwrap_or(false)
    }

    /// Poll `probe` (a real login, supplied by the caller) until it succeeds,
    /// the container dies, or `timeout` passes.
    pub fn wait_ready(&self, timeout: Duration, mut probe: impl FnMut() -> bool) -> Result<(), String> {
        let deadline = Instant::now() + timeout;
        loop {
            if probe() {
                return Ok(());
            }
            if !self.running() {
                return Err(format!("container {} exited before becoming ready; {}", self.name, self.log_tail()));
            }
            if Instant::now() >= deadline {
                return Err(format!("container {} not ready after {timeout:?}; {}", self.name, self.log_tail()));
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }

    fn log_tail(&self) -> String {
        match run(&self.engine, &["logs", "--tail", "10", &self.name]) {
            Ok(o) => format!("last logs: {}", String::from_utf8_lossy(&o.stderr).replace('\n', " | ").trim()),
            Err(_) => "no logs".into(),
        }
    }
}

impl Drop for PgContainer {
    fn drop(&mut self) {
        // Best effort: nothing useful to do if removal fails during unwind.
        let _ = run(&self.engine, &["rm", "-f", "-v", &self.name]);
    }
}
