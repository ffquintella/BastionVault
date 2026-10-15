//! The vault-side SSH client behind `bv_resource_ssh_exec`
//! (`features/mcp-brokered-sessions.md` §5.2-5.3): a small wrapper around
//! russh that can do exactly one thing.
//!
//! **One channel, one `exec`, nothing else.** On each connection it opens one
//! `session` channel and sends one `exec` request carrying the confirmed
//! bytes, then `EOF` (there is no stdin). It never sends `pty-req`, `shell`,
//! `env`, `x11-req`, `auth-agent-req`, `subsystem`, `tcpip-forward` or
//! `direct-tcpip`, and it refuses every channel the server tries to open
//! towards it (agent, X11, forwarded or direct TCP, a session). For a
//! password or stored-key login this wrapper *is* the command binding — the
//! target cannot enforce it — so it is kept small enough to read whole, and
//! a test against a recording server asserts the sequence.
//!
//! **Host key first.** The server key is checked against the profile's pin in
//! `check_server_key`, during the handshake, before any authentication: a
//! password is never sent to a host that is not the pinned one.
//!
//! **Bounded.** Connect and authentication share a budget inside the call's
//! deadline; output is capped jointly across stdout and stderr, drained up to
//! a limit, then the channel is closed; at the deadline the command is sent
//! `KILL` (best effort) and the connection is closed. An abort signal (token
//! revoked, kill switch) ends the session the same way, from any phase.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use base64::Engine as _;
use bv_kernel_api::mcp_events::AbortCause;
use bv_mcp::untrusted::{CappedStreams, CaptureState};
use bv_utils::destination_policy::CheckedTarget;
use russh::{
    client::{self, Msg, Session},
    keys::{Certificate, HashAlg, PrivateKey, PrivateKeyWithHashAlg, PublicKey},
    Channel, ChannelMsg, ChannelOpenFailure, Disconnect, Sig,
};
use tokio::{sync::watch, time::Instant};
use zeroize::Zeroizing;

/// Index of stdout in the captures.
pub const STDOUT: usize = 0;
/// Index of stderr (`extended_data` type 1) in the captures.
pub const STDERR: usize = 1;

/// How the vault logs in. Every variant holds its secret in memory that is
/// wiped when it drops.
pub enum SshLogin {
    /// A `secret` source's password.
    Password { username: String, password: Zeroizing<String> },
    /// A `secret` source's stored private key, decoded.
    StoredKey { username: String, key: Arc<PrivateKey> },
    /// An ephemeral key and the certificate the SSH engine signed for it.
    Certificate { username: String, key: Arc<PrivateKey>, cert: Box<Certificate> },
}

impl SshLogin {
    /// The `login` field of results, events and transcripts.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Password { .. } => "password",
            Self::StoredKey { .. } => "stored-key",
            Self::Certificate { .. } => "certificate",
        }
    }

    fn username(&self) -> &str {
        match self {
            Self::Password { username, .. } | Self::StoredKey { username, .. } | Self::Certificate { username, .. } => {
                username
            }
        }
    }
}

/// One session to run.
pub struct ExecSpec {
    /// The checked addresses; nothing else is dialed.
    pub target: CheckedTarget,
    /// SHA-256 of the pinned host key.
    pub host_key_sha256: [u8; 32],
    pub login: SshLogin,
    /// The confirmed command, verbatim.
    pub command: String,
    /// Budget for TCP connect, handshake and authentication.
    pub connect_budget: Duration,
    /// When the whole call ends.
    pub deadline: Instant,
    /// Output bytes kept for the model, stdout and stderr jointly.
    pub output_limit: usize,
    /// Bytes read and discarded past `output_limit` before the channel is
    /// closed.
    pub drain_limit: usize,
    /// Bytes per stream kept for the transcript.
    pub transcript_stream_limit: usize,
}

/// One stream as the transcript keeps it: its start, up to the transcript
/// limit, independently of the model's joint cap.
#[derive(Debug, Default, Clone)]
pub struct TranscriptCapture {
    pub bytes: Vec<u8>,
    pub truncated: bool,
}

/// What a session that reached the target did.
pub struct ExecReport {
    /// `SHA256:<base64>` of the server key, as checked.
    pub host_key_fingerprint: String,
    pub exit_status: Option<u32>,
    pub exit_signal: Option<String>,
    /// The deadline passed while the command ran; it was sent `KILL`.
    pub timed_out: bool,
    /// Cut short by revocation or the kill switch (`None` for a timeout,
    /// which `timed_out` reports).
    pub aborted: Option<AbortCause>,
    /// The model's copy: both streams, capped jointly.
    pub model: CappedStreams,
    /// The transcript's copy, per stream.
    pub transcript: [TranscriptCapture; 2],
}

/// Why a session could not run its command.
#[derive(Debug)]
pub enum ExecError {
    /// The server's key is not the pinned one. Nothing was authenticated.
    HostKeyMismatch { observed: String },
    /// The connect budget ran out before the session was authenticated.
    ConnectTimeout,
    /// No checked address accepted a TCP connection.
    Connect(String),
    /// The server refused the login.
    AuthRejected,
    /// The server refused to open the channel or to run the command.
    ExecRejected,
    /// Revoked or switched off before the command was sent.
    Aborted(AbortCause),
    /// Anything else the SSH layer reported.
    Protocol(String),
}

impl std::fmt::Display for ExecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HostKeyMismatch { observed } => {
                write!(f, "the target's host key {observed} is not the pinned one; nothing was sent")
            }
            Self::ConnectTimeout => write!(f, "connecting and authenticating took longer than the connect budget"),
            Self::Connect(e) => write!(f, "no checked address accepted the connection: {e}"),
            Self::AuthRejected => write!(f, "the target refused the login"),
            Self::ExecRejected => write!(f, "the target refused to run the command"),
            Self::Aborted(cause) => write!(f, "the session was aborted before the command ran ({cause:?})"),
            Self::Protocol(e) => write!(f, "SSH protocol error: {e}"),
        }
    }
}

/// `SHA256:<base64, unpadded>`, the OpenSSH fingerprint form a pin uses.
pub fn sha256_fingerprint(digest: &[u8]) -> String {
    format!("SHA256:{}", base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest))
}

/// The client half of the handshake: the pin check, and a refusal of every
/// channel the server offers.
struct Client {
    pinned: [u8; 32],
    observed: Arc<Mutex<Option<String>>>,
}

impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(&mut self, key: &PublicKey) -> Result<bool, Self::Error> {
        let digest = key.fingerprint(HashAlg::Sha256).sha256().unwrap_or_default();
        if let Ok(mut seen) = self.observed.lock() {
            *seen = Some(sha256_fingerprint(&digest));
        }
        Ok(digest == self.pinned)
    }

    // Server-initiated channels are all refused. russh's defaults accept
    // them; a broker that only runs one command has no use for any.
    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        _channel: Channel<Msg>,
        _connected_address: &str,
        _connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: client::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.reject(ChannelOpenFailure::AdministrativelyProhibited).await;
        Ok(())
    }

    async fn server_channel_open_forwarded_streamlocal(
        &mut self,
        _channel: Channel<Msg>,
        _socket_path: &str,
        reply: client::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.reject(ChannelOpenFailure::AdministrativelyProhibited).await;
        Ok(())
    }

    async fn server_channel_open_agent_forward(
        &mut self,
        _channel: Channel<Msg>,
        reply: client::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.reject(ChannelOpenFailure::AdministrativelyProhibited).await;
        Ok(())
    }

    async fn server_channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: client::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.reject(ChannelOpenFailure::AdministrativelyProhibited).await;
        Ok(())
    }

    async fn server_channel_open_direct_tcpip(
        &mut self,
        _channel: Channel<Msg>,
        _host_to_connect: &str,
        _port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: client::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.reject(ChannelOpenFailure::AdministrativelyProhibited).await;
        Ok(())
    }

    async fn server_channel_open_direct_streamlocal(
        &mut self,
        _channel: Channel<Msg>,
        _socket_path: &str,
        reply: client::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.reject(ChannelOpenFailure::AdministrativelyProhibited).await;
        Ok(())
    }

    async fn server_channel_open_x11(
        &mut self,
        _channel: Channel<Msg>,
        _originator_address: &str,
        _originator_port: u32,
        reply: client::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.reject(ChannelOpenFailure::AdministrativelyProhibited).await;
        Ok(())
    }
}

/// Resolves to the abort cause once one is signalled; never resolves when
/// the sender is gone without one.
async fn aborted(abort: &mut watch::Receiver<Option<AbortCause>>) -> AbortCause {
    loop {
        if let Some(cause) = *abort.borrow_and_update() {
            return cause;
        }
        if abort.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

fn signal_name(sig: &Sig) -> String {
    match sig {
        Sig::Custom(name) => name.clone(),
        other => format!("{other:?}"),
    }
}

/// Connect to the first checked address that accepts, and authenticate.
/// Takes the login by value: it is dropped — its secret wiped — as soon as
/// authentication is over, whatever the outcome.
async fn connect_and_login(
    target: &CheckedTarget,
    pinned: [u8; 32],
    login: SshLogin,
    deadline: Instant,
    observed: Arc<Mutex<Option<String>>>,
) -> Result<client::Handle<Client>, ExecError> {
    let mut last_err = String::from("no address to dial");
    let mut stream = None;
    for addr in target.addrs() {
        match tokio::net::TcpStream::connect(addr).await {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(e) => last_err = format!("{addr}: {e}"),
        }
    }
    let stream = stream.ok_or(ExecError::Connect(last_err))?;
    let _ = stream.set_nodelay(true);

    let config = Arc::new(client::Config {
        inactivity_timeout: Some(deadline.saturating_duration_since(Instant::now()) + Duration::from_secs(5)),
        ..Default::default()
    });
    let handler = Client { pinned, observed: observed.clone() };
    let mut handle = match client::connect_stream(config, stream, handler).await {
        Ok(h) => h,
        Err(e) => {
            let seen = observed.lock().ok().and_then(|g| g.clone());
            return Err(match seen {
                // The handshake reached the key check and it failed: the
                // key is not the pinned one.
                Some(fp) if !fingerprint_matches(&fp, &pinned) => ExecError::HostKeyMismatch { observed: fp },
                _ => ExecError::Protocol(e.to_string()),
            });
        }
    };

    let username = login.username().to_string();
    let result = match &login {
        SshLogin::Password { password, .. } => {
            // russh copies the password into its own message; ours is
            // wiped when the login drops, right after the session ends.
            handle.authenticate_password(username, password.as_str()).await
        }
        SshLogin::StoredKey { key, .. } => {
            let hash = if key.algorithm().is_rsa() {
                handle.best_supported_rsa_hash().await.map_err(|e| ExecError::Protocol(e.to_string()))?.flatten()
            } else {
                None
            };
            handle.authenticate_publickey(username, PrivateKeyWithHashAlg::new(key.clone(), hash)).await
        }
        SshLogin::Certificate { key, cert, .. } => {
            handle.authenticate_openssh_cert(username, key.clone(), (**cert).clone()).await
        }
    }
    .map_err(|e| ExecError::Protocol(e.to_string()))?;
    drop(login);
    if !result.success() {
        return Err(ExecError::AuthRejected);
    }
    Ok(handle)
}

fn fingerprint_matches(fp: &str, pinned: &[u8; 32]) -> bool {
    fp == sha256_fingerprint(pinned)
}

/// Run one session. `abort` carries a cause when the caller's watcher finds
/// the token revoked or the kill switch off.
pub async fn run(spec: ExecSpec, mut abort: watch::Receiver<Option<AbortCause>>) -> Result<ExecReport, ExecError> {
    let ExecSpec {
        target,
        host_key_sha256,
        login,
        command,
        connect_budget,
        deadline,
        output_limit,
        drain_limit,
        transcript_stream_limit,
    } = spec;
    let observed = Arc::new(Mutex::new(None));
    let connect_deadline = (Instant::now() + connect_budget).min(deadline);
    let login_fut = connect_and_login(&target, host_key_sha256, login, deadline, observed.clone());
    let handle = tokio::select! {
        biased;
        cause = aborted(&mut abort) => return Err(ExecError::Aborted(cause)),
        connected = tokio::time::timeout_at(connect_deadline, login_fut) => {
            match connected {
                Ok(result) => result?,
                Err(_) => return Err(ExecError::ConnectTimeout),
            }
        }
    };
    let host_key_fingerprint = observed.lock().ok().and_then(|g| g.clone()).unwrap_or_default();

    let mut report = ExecReport {
        host_key_fingerprint,
        exit_status: None,
        exit_signal: None,
        timed_out: false,
        aborted: None,
        model: CappedStreams::new(2, output_limit, drain_limit),
        transcript: Default::default(),
    };

    let limits = ChannelLimits { deadline, transcript_stream_limit };
    let outcome = exec_on_one_channel(&handle, &command, &limits, &mut abort, &mut report).await;
    // Whatever happened, the connection ends here.
    let _ = handle.disconnect(Disconnect::ByApplication, "", "en").await;
    outcome.map(|()| report)
}

/// The single channel: open, `exec`, `EOF`, read until the server closes
/// it, the deadline passes, the drain limit is spent or an abort arrives.
struct ChannelLimits {
    deadline: Instant,
    transcript_stream_limit: usize,
}

async fn exec_on_one_channel(
    handle: &client::Handle<Client>,
    command: &str,
    limits: &ChannelLimits,
    abort: &mut watch::Receiver<Option<AbortCause>>,
    report: &mut ExecReport,
) -> Result<(), ExecError> {
    let mut channel = handle.channel_open_session().await.map_err(|_| ExecError::ExecRejected)?;
    channel.exec(true, command.as_bytes()).await.map_err(|e| ExecError::Protocol(e.to_string()))?;
    channel.eof().await.map_err(|e| ExecError::Protocol(e.to_string()))?;

    let mut confirmed = false;
    loop {
        tokio::select! {
            biased;
            cause = aborted(abort) => {
                let _ = channel.signal(Sig::KILL).await;
                let _ = channel.close().await;
                report.aborted = Some(cause);
                return Ok(());
            }
            _ = tokio::time::sleep_until(limits.deadline) => {
                let _ = channel.signal(Sig::KILL).await;
                let _ = channel.close().await;
                report.timed_out = true;
                return Ok(());
            }
            msg = channel.wait() => {
                let Some(msg) = msg else { return Ok(()) };
                let state = match msg {
                    ChannelMsg::Success => {
                        confirmed = true;
                        CaptureState::Capturing
                    }
                    ChannelMsg::Failure if !confirmed => return Err(ExecError::ExecRejected),
                    ChannelMsg::Data { data } => record(report, limits, STDOUT, &data),
                    ChannelMsg::ExtendedData { data, ext: 1 } => record(report, limits, STDERR, &data),
                    ChannelMsg::ExitStatus { exit_status } => {
                        report.exit_status = Some(exit_status);
                        CaptureState::Capturing
                    }
                    ChannelMsg::ExitSignal { signal_name: sig, .. } => {
                        report.exit_signal = Some(signal_name(&sig));
                        CaptureState::Capturing
                    }
                    ChannelMsg::Close => return Ok(()),
                    // EOF, window adjustments, other extended-data types:
                    // nothing to keep.
                    _ => CaptureState::Capturing,
                };
                if state == CaptureState::Exhausted {
                    let _ = channel.close().await;
                    return Ok(());
                }
            }
        }
    }
}

fn record(report: &mut ExecReport, limits: &ChannelLimits, stream: usize, data: &[u8]) -> CaptureState {
    let kept = &mut report.transcript[stream];
    let room = limits.transcript_stream_limit.saturating_sub(kept.bytes.len());
    if data.len() > room {
        kept.truncated = true;
    }
    kept.bytes.extend_from_slice(&data[..data.len().min(room)]);
    report.model.push(stream, data)
}

#[cfg(test)]
mod tests {
    use std::{
        net::IpAddr,
        time::{SystemTime, UNIX_EPOCH},
    };

    use bv_utils::destination_policy::{DestinationPolicy, SystemResolver, TargetCidrs};
    use russh::keys::{ssh_key::certificate::Builder, Algorithm};

    use super::*;
    use crate::agent_ssh::test_server::{ScriptedReply, TestServerConfig, TestSshServer};

    /// Requests the vault's client must never make.
    const FORBIDDEN: &[&str] = &[
        "pty_request",
        "shell_request",
        "env_request",
        "x11_request",
        "agent_request",
        "subsystem_request",
        "tcpip_forward",
        "direct_tcpip",
        "channel_open_x11",
    ];

    fn loopback(server: &TestSshServer) -> CheckedTarget {
        // The test seam: loopback is always denied in production.
        DestinationPolicy::new(TargetCidrs::default(), [], [])
            .permit_loopback_for_tests()
            .resolve_and_check(&SystemResolver, &IpAddr::from([127, 0, 0, 1]).to_string(), server.addr().port())
            .expect("the seam admits loopback")
    }

    fn spec(server: &TestSshServer, login: SshLogin, command: &str, timeout: Duration) -> ExecSpec {
        ExecSpec {
            target: loopback(server),
            host_key_sha256: server.host_key_sha256(),
            login,
            command: command.to_string(),
            connect_budget: Duration::from_secs(10),
            deadline: Instant::now() + timeout,
            output_limit: 64 * 1024,
            drain_limit: 1 << 20,
            transcript_stream_limit: 1 << 20,
        }
    }

    fn password(pw: &str) -> SshLogin {
        SshLogin::Password { username: "ops".into(), password: Zeroizing::new(pw.into()) }
    }

    fn no_abort() -> (watch::Sender<Option<AbortCause>>, watch::Receiver<Option<AbortCause>>) {
        watch::channel(None)
    }

    fn password_server(reply: ScriptedReply) -> TestServerConfig {
        let mut config = TestServerConfig::new(move |_| reply.clone());
        config.passwords.push(("ops".into(), "hunter2".into()));
        config
    }

    fn count(events: &[String], prefix: &str) -> usize {
        events.iter().filter(|e| e.starts_with(prefix)).count()
    }

    /// §5.2: one `session` channel, one `exec` with the confirmed bytes,
    /// `EOF`, and nothing else — no PTY, shell, env, X11, agent, subsystem
    /// or forwarding — and a channel the server opens back is refused.
    #[tokio::test(flavor = "multi_thread")]
    async fn one_channel_one_exec_and_nothing_else() {
        let server = TestSshServer::start(password_server(ScriptedReply {
            stdout: b" 10:00 up 3 days\n".to_vec(),
            exit_status: Some(0),
            probe_agent_channel: true,
            ..Default::default()
        }))
        .await;
        let (_tx, rx) = no_abort();
        let report = run(spec(&server, password("hunter2"), "uptime", Duration::from_secs(10)), rx).await.unwrap();
        assert_eq!(report.exit_status, Some(0));
        assert!(!report.timed_out && report.aborted.is_none());
        assert_eq!(report.model.stream(STDOUT).kept(), b" 10:00 up 3 days\n");
        assert_eq!(report.host_key_fingerprint, server.host_key_fingerprint());

        // Give the server's script task a moment to record its probe.
        tokio::time::sleep(Duration::from_millis(200)).await;
        let events = server.events();
        assert_eq!(count(&events, "channel_open_session"), 1, "{events:?}");
        assert_eq!(events.iter().filter(|e| e.starts_with("exec:")).cloned().collect::<Vec<_>>(), vec!["exec:uptime"]);
        assert_eq!(count(&events, "channel_eof"), 1, "EOF is sent: there is no stdin; {events:?}");
        for forbidden in FORBIDDEN {
            assert_eq!(count(&events, forbidden), 0, "{forbidden} in {events:?}");
        }
        assert!(events.contains(&"server_opened_agent_channel:false".to_string()), "{events:?}");
        assert_eq!(count(&events, "auth_password:ops:"), 1, "{events:?}");
    }

    /// The pin is checked during the handshake, before authentication: a
    /// mismatch sends no password at all.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_host_key_mismatch_sends_no_credential() {
        let server = TestSshServer::start(password_server(ScriptedReply::default())).await;
        let mut s = spec(&server, password("hunter2"), "uptime", Duration::from_secs(10));
        s.host_key_sha256 = [7u8; 32];
        let (_tx, rx) = no_abort();
        match run(s, rx).await {
            Err(ExecError::HostKeyMismatch { observed }) => assert_eq!(observed, server.host_key_fingerprint()),
            other => panic!("expected a host key mismatch, got {:?}", other.err()),
        }
        let events = server.events();
        assert_eq!(count(&events, "auth_"), 0, "nothing was authenticated: {events:?}");
        assert_eq!(count(&events, "exec:"), 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_wrong_password_is_rejected_and_nothing_runs() {
        let server = TestSshServer::start(password_server(ScriptedReply::default())).await;
        let (_tx, rx) = no_abort();
        assert!(matches!(
            run(spec(&server, password("wrong"), "uptime", Duration::from_secs(10)), rx).await,
            Err(ExecError::AuthRejected)
        ));
        assert_eq!(count(&server.events(), "exec:"), 0);
    }

    /// A stored key and a CA-signed certificate both authenticate, and the
    /// certificate's critical options reach the server as signed.
    #[tokio::test(flavor = "multi_thread")]
    async fn stored_keys_and_certificates_authenticate() {
        let user_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let ca = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let reply = ScriptedReply { stdout: b"ok\n".to_vec(), exit_status: Some(0), ..Default::default() };
        let mut config = TestServerConfig::new(move |_| reply.clone());
        config.authorized_keys.push(("ops".into(), user_key.public_key().clone()));
        config.trusted_ca = Some(ca.public_key().clone());
        let server = TestSshServer::start(config).await;

        let (_tx, rx) = no_abort();
        let login = SshLogin::StoredKey { username: "ops".into(), key: Arc::new(user_key) };
        let report = run(spec(&server, login, "id", Duration::from_secs(10)), rx).await.unwrap();
        assert_eq!(report.exit_status, Some(0));

        let ephemeral = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let mut builder = Builder::new_with_random_nonce(
            &mut rand::rng(),
            ephemeral.public_key().key_data().clone(),
            now - 5,
            now + 60,
        )
        .unwrap();
        builder.serial(1).unwrap();
        builder.key_id("agent").unwrap();
        builder.valid_principal("ops").unwrap();
        builder.critical_option("force-command", "id").unwrap();
        let cert = builder.sign(&ca).unwrap();
        let (_tx, rx) = no_abort();
        let login = SshLogin::Certificate { username: "ops".into(), key: Arc::new(ephemeral), cert: Box::new(cert) };
        let report = run(spec(&server, login, "id", Duration::from_secs(10)), rx).await.unwrap();
        assert_eq!(report.exit_status, Some(0));
        let events = server.events();
        assert!(
            events.iter().any(|e| e.starts_with("auth_cert:ops:options[force-command=id]:extensions[]")),
            "{events:?}"
        );
    }

    /// At the deadline the command is sent `KILL`, the channel closed, and
    /// the report says `timed_out`.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_deadline_kills_the_command() {
        let server = TestSshServer::start(password_server(ScriptedReply {
            delay: Some(Duration::from_secs(30)),
            exit_status: Some(0),
            ..Default::default()
        }))
        .await;
        let (_tx, rx) = no_abort();
        let started = std::time::Instant::now();
        let report = run(spec(&server, password("hunter2"), "sleep 30", Duration::from_secs(2)), rx).await.unwrap();
        assert!(report.timed_out && report.exit_status.is_none());
        assert!(started.elapsed() < Duration::from_secs(10), "{:?}", started.elapsed());
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(count(&server.events(), "signal:KILL"), 1, "{:?}", server.events());
    }

    /// An abort (token revoked, kill switch) ends a running command at once.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_abort_ends_a_running_command() {
        let server = TestSshServer::start(password_server(ScriptedReply {
            delay: Some(Duration::from_secs(30)),
            ..Default::default()
        }))
        .await;
        let (tx, rx) = no_abort();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let _ = tx.send(Some(AbortCause::TokenRevoked));
            // Keep the sender alive past the abort.
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let started = std::time::Instant::now();
        let report = run(spec(&server, password("hunter2"), "sleep 30", Duration::from_secs(20)), rx).await.unwrap();
        assert_eq!(report.aborted, Some(AbortCause::TokenRevoked));
        assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
    }

    /// stdout and stderr share one cap; past it, reading stops at the drain
    /// limit and the channel is closed.
    #[tokio::test(flavor = "multi_thread")]
    async fn output_is_capped_jointly_then_drained() {
        let server = TestSshServer::start(password_server(ScriptedReply {
            stdout: vec![b'a'; 3000],
            stderr: vec![b'b'; 3000],
            exit_status: Some(0),
            ..Default::default()
        }))
        .await;
        let mut s = spec(&server, password("hunter2"), "yes", Duration::from_secs(10));
        s.output_limit = 4000;
        s.drain_limit = 1 << 20;
        let (_tx, rx) = no_abort();
        let report = run(s, rx).await.unwrap();
        let out = report.model.stream(STDOUT);
        let err = report.model.stream(STDERR);
        assert_eq!((out.kept().len(), err.kept().len()), (3000, 1000));
        assert_eq!((out.seen(), err.seen()), (3000, 3000));
        assert!(err.truncated() && !out.truncated());
        assert_eq!(report.transcript[STDERR].bytes.len(), 3000, "the transcript keeps more than the model");

        let server = TestSshServer::start(password_server(ScriptedReply {
            stdout: vec![b'z'; 200_000],
            exit_status: Some(0),
            ..Default::default()
        }))
        .await;
        let mut s = spec(&server, password("hunter2"), "yes", Duration::from_secs(10));
        s.output_limit = 1000;
        s.drain_limit = 16 * 1024;
        let (_tx, rx) = no_abort();
        let report = run(s, rx).await.unwrap();
        let out = report.model.stream(STDOUT);
        assert_eq!(out.kept().len(), 1000);
        assert!(out.truncated());
        assert!(out.seen() < 200_000, "reading stopped at the drain limit: {}", out.seen());
    }
}
