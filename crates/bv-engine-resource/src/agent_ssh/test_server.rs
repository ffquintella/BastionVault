//! An in-process SSH server for tests of the agent SSH executor: it accepts
//! the logins it is told to, answers each `exec` from a script, and records
//! **every** request a client makes, so a test can assert that the vault's
//! client sends one `exec` on one channel and nothing else
//! (`features/mcp-brokered-sessions.md` §5.2, "Testing requirements").
//!
//! Compiled only for tests (`cfg(test)`, or the `test-support` feature, which
//! only the facade's dev-dependency turns on). It listens on loopback, which
//! the destination policy refuses unless a test opens its seam.

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use russh::{
    keys::{Algorithm, Certificate, HashAlg, PrivateKey, PublicKey},
    server::{self, Auth, Msg, Session},
    Channel, ChannelId, Pty, Sig,
};

/// What the server does with one `exec`.
#[derive(Debug, Clone, Default)]
pub struct ScriptedReply {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// `None` sends no exit status.
    pub exit_status: Option<u32>,
    /// Wait this long before answering at all (a command that hangs).
    pub delay: Option<Duration>,
    /// Try to open an agent channel back to the client first, and record
    /// whether the client accepted it.
    pub probe_agent_channel: bool,
}

type Responder = Arc<dyn Fn(&str) -> ScriptedReply + Send + Sync>;

/// What the server accepts and how it answers.
#[derive(Clone)]
pub struct TestServerConfig {
    /// `(user, password)` pairs accepted for password logins.
    pub passwords: Vec<(String, String)>,
    /// `(user, key)` pairs accepted for public-key logins.
    pub authorized_keys: Vec<(String, PublicKey)>,
    /// A CA whose user certificates are accepted for their principals.
    pub trusted_ca: Option<PublicKey>,
    pub responder: Responder,
}

impl TestServerConfig {
    /// Accepts nothing; echoes nothing.
    pub fn new(responder: impl Fn(&str) -> ScriptedReply + Send + Sync + 'static) -> Self {
        Self { passwords: Vec::new(), authorized_keys: Vec::new(), trusted_ca: None, responder: Arc::new(responder) }
    }

    /// Generate a fresh Ed25519 key, authorize it for `user`, and return
    /// the private half in OpenSSH format (what a stored `secret` holds).
    pub fn new_authorized_key(&mut self, user: &str) -> String {
        let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("user key");
        self.authorized_keys.push((user.to_string(), key.public_key().clone()));
        key.to_openssh(russh::keys::ssh_key::LineEnding::LF).expect("openssh").to_string()
    }

    /// Trust user certificates signed by this CA (an OpenSSH public key
    /// line, as an SSH engine's `config/ca` reports it).
    pub fn trust_ca_openssh(&mut self, public_key: &str) {
        self.trusted_ca = Some(PublicKey::from_openssh(public_key.trim()).expect("CA public key"));
    }
}

/// A host key fingerprint that matches no server: a valid pin for a test
/// that needs a mismatch.
pub fn unrelated_host_key_fingerprint() -> String {
    let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("key");
    super::exec::sha256_fingerprint(&key.public_key().fingerprint(HashAlg::Sha256).sha256().expect("sha256"))
}

/// A running server. Dropping it stops accepting connections.
pub struct TestSshServer {
    addr: SocketAddr,
    host_key: PublicKey,
    events: Arc<Mutex<Vec<String>>>,
    accept: tokio::task::JoinHandle<()>,
}

impl Drop for TestSshServer {
    fn drop(&mut self) {
        self.accept.abort();
    }
}

impl TestSshServer {
    /// Start on `127.0.0.1:<ephemeral>` with a fresh Ed25519 host key.
    pub async fn start(config: TestServerConfig) -> Self {
        let host_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("host key");
        let public = host_key.public_key().clone();
        let server_config = Arc::new(server::Config {
            keys: vec![host_key],
            auth_rejection_time: Duration::from_millis(5),
            auth_rejection_time_initial: Some(Duration::from_millis(0)),
            inactivity_timeout: Some(Duration::from_secs(120)),
            ..Default::default()
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let events = Arc::new(Mutex::new(Vec::new()));
        let shared = events.clone();
        let accept = tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let handler = Handler { config: config.clone(), events: shared.clone() };
                let server_config = server_config.clone();
                tokio::spawn(async move {
                    if let Ok(session) = server::run_stream(server_config, socket, handler).await {
                        let _ = session.await;
                    }
                });
            }
        });
        Self { addr, host_key: public, events, accept }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The host key's OpenSSH fingerprint, `SHA256:<base64>`: what a pin is.
    pub fn host_key_fingerprint(&self) -> String {
        super::exec::sha256_fingerprint(&self.host_key_sha256())
    }

    /// The host key's SHA-256 digest.
    pub fn host_key_sha256(&self) -> [u8; 32] {
        self.host_key.fingerprint(HashAlg::Sha256).sha256().expect("sha256")
    }

    /// Every request recorded so far, in order.
    pub fn events(&self) -> Vec<String> {
        self.events.lock().map(|e| e.clone()).unwrap_or_default()
    }
}

struct Handler {
    config: TestServerConfig,
    events: Arc<Mutex<Vec<String>>>,
}

impl Handler {
    fn record(&self, event: impl Into<String>) {
        if let Ok(mut e) = self.events.lock() {
            e.push(event.into());
        }
    }
}

impl server::Handler for Handler {
    type Error = russh::Error;

    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        self.record(format!("auth_none:{user}"));
        Ok(Auth::reject())
    }

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        // The password itself is recorded so a test can prove one was, or
        // was not, ever sent.
        self.record(format!("auth_password:{user}:{password}"));
        let ok = self.config.passwords.iter().any(|(u, p)| u == user && p == password);
        Ok(if ok { Auth::Accept } else { Auth::reject() })
    }

    /// Any key may be offered: the decision is made once the signature is
    /// proved, in `auth_publickey` or `auth_openssh_certificate` (russh asks
    /// this with a certificate's embedded key too).
    async fn auth_publickey_offered(&mut self, _user: &str, _key: &PublicKey) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn auth_publickey(&mut self, user: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
        self.record(format!("auth_publickey:{user}"));
        let ok = self.config.authorized_keys.iter().any(|(u, k)| u == user && k.key_data() == key.key_data());
        Ok(if ok { Auth::Accept } else { Auth::reject() })
    }

    async fn auth_openssh_certificate(&mut self, user: &str, cert: &Certificate) -> Result<Auth, Self::Error> {
        let options: Vec<String> = cert.critical_options().iter().map(|(k, v)| format!("{k}={v}")).collect();
        let extensions: Vec<&str> = cert.extensions().keys().map(String::as_str).collect();
        self.record(format!(
            "auth_cert:{user}:options[{}]:extensions[{}]:validity={}",
            options.join(","),
            extensions.join(","),
            cert.valid_before().saturating_sub(cert.valid_after())
        ));
        let trusted = self.config.trusted_ca.as_ref().is_some_and(|ca| cert.signature_key() == ca.key_data());
        let principal = cert.valid_principals().iter().any(|p| p == user);
        Ok(if trusted && principal { Auth::Accept } else { Auth::reject() })
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.record(format!("channel_open_session:{}", channel.id()));
        reply.accept().await;
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        _channel: Channel<Msg>,
        host: &str,
        port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.record(format!("direct_tcpip:{host}:{port}"));
        reply.accept().await;
        Ok(())
    }

    async fn channel_open_x11(
        &mut self,
        _channel: Channel<Msg>,
        _originator_address: &str,
        _originator_port: u32,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.record("channel_open_x11");
        reply.accept().await;
        Ok(())
    }

    async fn pty_request(
        &mut self,
        _channel: ChannelId,
        _term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(Pty, u32)],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.record("pty_request");
        Ok(())
    }

    async fn x11_request(
        &mut self,
        _channel: ChannelId,
        _single_connection: bool,
        _protocol: &str,
        _cookie: &str,
        _screen: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.record("x11_request");
        Ok(())
    }

    async fn env_request(
        &mut self,
        _channel: ChannelId,
        name: &str,
        _value: &str,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.record(format!("env_request:{name}"));
        Ok(())
    }

    async fn shell_request(&mut self, _channel: ChannelId, _session: &mut Session) -> Result<(), Self::Error> {
        self.record("shell_request");
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        _channel: ChannelId,
        name: &str,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.record(format!("subsystem_request:{name}"));
        Ok(())
    }

    async fn agent_request(&mut self, _channel: ChannelId, _session: &mut Session) -> Result<bool, Self::Error> {
        self.record("agent_request");
        Ok(false)
    }

    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        self.record(format!("tcpip_forward:{address}:{port}"));
        Ok(false)
    }

    async fn signal(&mut self, _channel: ChannelId, signal: Sig, _session: &mut Session) -> Result<(), Self::Error> {
        self.record(format!("signal:{signal:?}"));
        Ok(())
    }

    async fn channel_eof(&mut self, _channel: ChannelId, _session: &mut Session) -> Result<(), Self::Error> {
        self.record("channel_eof");
        Ok(())
    }

    async fn channel_close(&mut self, _channel: ChannelId, _session: &mut Session) -> Result<(), Self::Error> {
        self.record("channel_close");
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let command = String::from_utf8_lossy(data).into_owned();
        self.record(format!("exec:{command}"));
        session.channel_success(channel)?;
        let reply = (self.config.responder)(&command);
        let handle = session.handle();
        let events = self.events.clone();
        tokio::spawn(async move {
            if reply.probe_agent_channel {
                let opened = handle.channel_open_agent().await.is_ok();
                if let Ok(mut e) = events.lock() {
                    e.push(format!("server_opened_agent_channel:{opened}"));
                }
            }
            if let Some(delay) = reply.delay {
                tokio::time::sleep(delay).await;
            }
            for chunk in reply.stdout.chunks(16 * 1024) {
                if handle.data(channel, chunk.to_vec()).await.is_err() {
                    return;
                }
            }
            for chunk in reply.stderr.chunks(16 * 1024) {
                if handle.extended_data(channel, 1, chunk.to_vec()).await.is_err() {
                    return;
                }
            }
            if let Some(status) = reply.exit_status {
                let _ = handle.exit_status_request(channel, status).await;
            }
            let _ = handle.eof(channel).await;
            let _ = handle.close(channel).await;
        });
        Ok(())
    }
}
