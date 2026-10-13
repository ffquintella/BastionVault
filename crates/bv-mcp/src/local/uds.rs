//! The owner-only Unix-socket transport: the kernel's word on who is
//! connecting, a socket file nobody else can open, a listener a host can
//! stop, and the stdio relay a client process uses to reach it.

use std::{
    collections::HashMap,
    fs,
    io::{BufReader, ErrorKind, Read, Write},
    net::Shutdown,
    os::unix::{
        fs::{FileTypeExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread::JoinHandle,
    time::Duration,
};

use bv_errors::RvError;

use super::{
    lock,
    server::{run_line_session, ConnInfo, ConnectionSlot, LocalServer},
};
use crate::pairing::{self, Transport};

fn err(message: impl Into<String>) -> RvError {
    RvError::ErrString(message.into())
}

/// The uid on the far end of a connected Unix socket, from the kernel.
#[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
pub fn peer_uid(stream: &UnixStream) -> Option<u32> {
    use std::os::unix::io::AsRawFd;
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: `fd` is a live socket owned by `stream`; `uid`/`gid` are
    // valid out-pointers for the duration of the call.
    let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    (rc == 0).then_some(uid)
}

#[cfg(target_os = "linux")]
pub fn peer_uid(stream: &UnixStream) -> Option<u32> {
    use std::os::unix::io::AsRawFd;
    // SAFETY: zeroed `ucred` is a valid plain-data value; `getsockopt`
    // writes at most `len` bytes into it.
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `fd` is a live socket owned by `stream`; `cred` and `len` are
    // valid for the duration of the call and `len` is `cred`'s size.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };
    (rc == 0).then_some(cred.uid)
}

#[cfg(not(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "linux"
)))]
pub fn peer_uid(_stream: &UnixStream) -> Option<u32> {
    // No way to prove who is connecting: nobody is admitted.
    None
}

pub fn current_uid() -> u32 {
    // SAFETY: `geteuid` has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// The pre-read gate. A peer whose uid the kernel cannot confirm equals
/// `expected` is dropped before a single byte is read from it.
pub fn peer_is(stream: &UnixStream, expected: u32) -> Option<u32> {
    peer_uid(stream).filter(|uid| *uid == expected)
}

pub fn serve_connection(server: &LocalServer, stream: UnixStream, expected_uid: u32) {
    let Some(uid) = peer_is(&stream, expected_uid) else {
        return; // dropped: nothing was read
    };
    let conn = ConnInfo { transport: Transport::Uds, peer_uid: Some(uid), preauthenticated: None };
    let Ok(write_half) = stream.try_clone() else { return };
    let _ = run_line_session(server, &conn, BufReader::new(stream), write_half);
}

/// Bind a 0600 socket. A stale socket file from a dead server is
/// replaced; a live one, or a non-socket, is an error.
pub fn bind_private_socket(path: &Path) -> Result<UnixListener, RvError> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        pairing::create_private_dir(dir)?;
    }
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => {
            if UnixStream::connect(path).is_ok() {
                return Err(err(format!("{} is already being served", path.display())));
            }
            fs::remove_file(path)?;
        }
        Ok(_) => return Err(err(format!("{} exists and is not a socket; refusing to replace it", path.display()))),
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    // No umask games: it is process-global, so tightening it around `bind`
    // races every other thread that creates a file or directory. The
    // socket is narrowed to 0600 immediately after binding instead. The
    // window is harmless in practice -- connecting to a Unix socket needs
    // write permission, which the default umask withholds from other
    // users; a directory we created is 0700; and every connection is
    // uid-checked before a byte is read regardless.
    let listener = UnixListener::bind(path).map_err(|e| {
        if e.kind() == ErrorKind::InvalidInput {
            // `sockaddr_un.sun_path` is ~104 bytes on macOS and 108 on
            // Linux; the OS error for overflowing it says nothing useful.
            err(format!(
                "{} is too long for a Unix socket path (limit is about 100 bytes); choose a shorter --socket path",
                path.display()
            ))
        } else {
            RvError::from(e)
        }
    })?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

/// Serves `listener` until the process ends -- the CLI's foreground server.
pub fn run(server: Arc<LocalServer>, listener: UnixListener, expected_uid: u32) {
    let active = Arc::new(AtomicUsize::new(0));
    for conn in listener.incoming() {
        let Ok(stream) = conn else { continue };
        let Some(slot) = ConnectionSlot::acquire(&active) else {
            continue;
        };
        let server = server.clone();
        let _ = std::thread::Builder::new().name("mcp-uds".into()).spawn(move || {
            let _slot = slot;
            serve_connection(&server, stream, expected_uid);
        });
    }
}

// ── a stoppable listener (the desktop app) ───────────────────────────────

/// How long the accept loop sleeps between polls of a quiet socket. Bounds
/// how long [`SocketServer::stop`] waits for the loop to notice.
const ACCEPT_POLL: Duration = Duration::from_millis(100);

/// The live connections, so a stop can cut them off rather than wait for
/// each client to hang up.
#[derive(Default)]
struct Connections {
    next_id: AtomicU64,
    open: Mutex<HashMap<u64, UnixStream>>,
}

impl Connections {
    fn track(&self, stream: &UnixStream) -> Option<u64> {
        let clone = stream.try_clone().ok()?;
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        lock(&self.open).insert(id, clone);
        Some(id)
    }

    fn forget(&self, id: u64) {
        lock(&self.open).remove(&id);
    }

    fn cut_all(&self) {
        for (_, stream) in lock(&self.open).drain() {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }
}

/// A Unix-socket server a host can stop: on [`Self::stop`] (or drop) the
/// [`LocalServer`] is shut down -- every minted token forgotten -- each live
/// connection is cut, the accept loop ends and the socket file is removed.
/// The CLI serves until it is killed and uses [`run`] instead.
pub struct SocketServer {
    path: PathBuf,
    server: Arc<LocalServer>,
    stop: Arc<AtomicBool>,
    connections: Arc<Connections>,
    accept: Option<JoinHandle<()>>,
}

impl SocketServer {
    /// Binds `path` owner-only (see [`bind_private_socket`]) and starts
    /// accepting connections from this process's own uid.
    pub fn start(server: Arc<LocalServer>, path: &Path) -> Result<Self, RvError> {
        let listener = bind_private_socket(path)?;
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let connections = Arc::new(Connections::default());
        let expected_uid = current_uid();

        let accept = {
            let (server, stop, connections) = (server.clone(), stop.clone(), connections.clone());
            std::thread::Builder::new()
                .name("mcp-uds-accept".into())
                .spawn(move || accept_loop(server, listener, expected_uid, stop, connections))?
        };
        Ok(Self { path: path.to_path_buf(), server, stop, connections, accept: Some(accept) })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Stops serving. Returns the vault accessors of the tokens the server
    /// had minted (see [`LocalServer::shutdown`]) so the host can revoke
    /// them; the tokens themselves never leave the server.
    pub fn stop(mut self) -> Vec<String> {
        self.halt()
    }

    fn halt(&mut self) -> Vec<String> {
        self.stop.store(true, Ordering::SeqCst);
        // Refuse first, then cut: a message already being handled finishes
        // as a refusal and its answer has nowhere to go.
        let accessors = self.server.shutdown();
        self.connections.cut_all();
        if let Some(accept) = self.accept.take() {
            let _ = accept.join();
        }
        if fs::symlink_metadata(&self.path).is_ok_and(|m| m.file_type().is_socket()) {
            let _ = fs::remove_file(&self.path);
        }
        accessors
    }
}

impl Drop for SocketServer {
    fn drop(&mut self) {
        if self.accept.is_some() {
            self.halt();
        }
    }
}

fn accept_loop(
    server: Arc<LocalServer>,
    listener: UnixListener,
    expected_uid: u32,
    stop: Arc<AtomicBool>,
    connections: Arc<Connections>,
) {
    let active = Arc::new(AtomicUsize::new(0));
    while !stop.load(Ordering::SeqCst) {
        let stream = match listener.accept() {
            Ok((stream, _)) => stream,
            // Nothing waiting (`WouldBlock`), or a transient failure such as
            // running out of descriptors: try again after a beat either way.
            Err(_) => {
                std::thread::sleep(ACCEPT_POLL);
                continue;
            }
        };
        // Accepted sockets inherit non-blocking mode on some platforms.
        if stream.set_nonblocking(false).is_err() {
            continue;
        }
        let Some(slot) = ConnectionSlot::acquire(&active) else {
            continue;
        };
        let Some(id) = connections.track(&stream) else {
            continue;
        };
        // Raised between the loop check and `track`: `cut_all` may already
        // have run and missed this one.
        if stop.load(Ordering::SeqCst) {
            connections.forget(id);
            break;
        }
        let (for_thread, registry) = (server.clone(), connections.clone());
        let spawned = std::thread::Builder::new().name("mcp-uds".into()).spawn(move || {
            let _slot = slot;
            serve_connection(&for_thread, stream, expected_uid);
            registry.forget(id);
        });
        if spawned.is_err() {
            // The closure, and the stream with it, was dropped; drop the
            // tracked clone too so the client sees the connection close.
            connections.forget(id);
        }
    }
}

// ── the stdio relay (a client process reaching a running server) ─────────

#[derive(Debug)]
pub enum RelayError {
    /// Nothing is serving at the path: the host is not running, or its
    /// server is off.
    NotRunning {
        path: PathBuf,
        reason: String,
    },
    /// Something is serving at the path, but the kernel says it is not this
    /// user. Never talked to.
    ForeignServer {
        path: PathBuf,
    },
    Io(std::io::Error),
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RelayError::NotRunning { path, reason } => write!(f, "nothing is serving {} ({reason})", path.display()),
            RelayError::ForeignServer { path } => {
                write!(f, "{} is served by another user; refusing to talk to it", path.display())
            }
            RelayError::Io(e) => write!(f, "relay failed: {e}"),
        }
    }
}

impl std::error::Error for RelayError {}

/// How a relay ended.
#[derive(Debug, PartialEq, Eq)]
pub enum RelayEnd {
    /// The client closed its input and the server finished answering.
    ClientClosed,
    /// The server closed the connection while the client was still there:
    /// it was stopped (the vault was locked, signed out of, or the server
    /// turned off).
    ServerClosed,
}

/// Connects to the server at `path` and copies `input` to it and its answers
/// to `output` until one side closes. The server is uid-checked first, the
/// same pre-read gate the server applies to its clients: a socket served by
/// anyone but this user is never written to.
pub fn relay<R, W>(path: &Path, input: R, mut output: W) -> Result<RelayEnd, RelayError>
where
    R: Read + Send + 'static,
    W: Write,
{
    let stream = connect(path)?;
    let client_closed = Arc::new(AtomicBool::new(false));
    let mut to_server = stream.try_clone().map_err(RelayError::Io)?;
    {
        let client_closed = client_closed.clone();
        std::thread::Builder::new()
            .name("mcp-relay-in".into())
            .spawn(move || {
                let mut input = input;
                let _ = std::io::copy(&mut input, &mut to_server);
                client_closed.store(true, Ordering::SeqCst);
                let _ = to_server.shutdown(Shutdown::Write);
            })
            .map_err(RelayError::Io)?;
    }

    let mut from_server = stream;
    let mut buf = [0u8; 8192];
    loop {
        let n = match from_server.read(&mut buf) {
            Ok(n) => n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            // A reset is the server going away mid-conversation.
            Err(e) if e.kind() == ErrorKind::ConnectionReset => 0,
            Err(e) => return Err(RelayError::Io(e)),
        };
        if n == 0 {
            return Ok(if client_closed.load(Ordering::SeqCst) {
                RelayEnd::ClientClosed
            } else {
                RelayEnd::ServerClosed
            });
        }
        output.write_all(&buf[..n]).map_err(RelayError::Io)?;
        output.flush().map_err(RelayError::Io)?;
    }
}

fn connect(path: &Path) -> Result<UnixStream, RelayError> {
    let not_running = |reason: String| RelayError::NotRunning { path: path.to_path_buf(), reason };
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => {}
        Ok(_) => return Err(not_running("it is not a socket".to_string())),
        Err(e) if e.kind() == ErrorKind::NotFound => return Err(not_running("no socket there".to_string())),
        Err(e) => return Err(not_running(e.to_string())),
    }
    let stream = UnixStream::connect(path).map_err(|e| match e.kind() {
        ErrorKind::ConnectionRefused | ErrorKind::NotFound => {
            not_running("a stale socket; nothing is listening".into())
        }
        _ => not_running(e.to_string()),
    })?;
    if peer_is(&stream, current_uid()).is_none() {
        return Err(RelayError::ForeignServer { path: path.to_path_buf() });
    }
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use super::*;
    use crate::local::server::tests::{
        bare, data_code, grant, initialize, paired_rig, request, rig, stdio, Rig, MINTED,
    };
    use crate::local::PairingDecision;
    use crate::pairing::new_pairing_id;

    /// Short and under /tmp on purpose: a socket path must fit in
    /// `sun_path`, and macOS's per-user temp dir alone nearly does not.
    fn short_socket_dir() -> PathBuf {
        PathBuf::from(format!("/tmp/bvmcp-{}", &new_pairing_id()[..8]))
    }

    #[test]
    fn peer_uid_of_a_local_pair_is_our_own() {
        let (a, _b) = UnixStream::pair().unwrap();
        assert_eq!(peer_uid(&a), Some(current_uid()));
        assert!(peer_is(&a, current_uid()).is_some());
    }

    #[test]
    fn a_peer_with_a_different_uid_is_dropped_before_any_byte_is_read() {
        let rig = paired_rig("uds-gate", false);
        let forwards_before = lock(&rig.link.forwards).len();
        let (server_end, mut client_end) = UnixStream::pair().unwrap();
        // The client speaks first, as a hostile or confused peer would.
        client_end.write_all(&request(5, "tools/list", json!({}))).unwrap();
        client_end.write_all(b"\n").unwrap();

        let wrong = current_uid().wrapping_add(1);
        serve_connection(&rig.server, server_end, wrong);

        // Dropping a socket with unread data is an orderly EOF on macOS but
        // a connection reset on Linux; either way the peer is cut off and
        // gets no answer.
        let mut reply = String::new();
        match client_end.read_to_string(&mut reply) {
            Ok(_) => assert!(reply.is_empty(), "a rejected peer gets EOF, not an answer: {reply:?}"),
            Err(e) => assert_eq!(e.kind(), ErrorKind::ConnectionReset, "{e}"),
        }
        assert!(reply.is_empty(), "nothing was answered: {reply:?}");
        assert_eq!(lock(&rig.link.forwards).len(), forwards_before, "nothing reached the vault");
    }

    #[test]
    fn a_matching_peer_is_served_and_recorded_with_its_uid() {
        let rig = rig("uds-ok");
        *lock(&rig.prompt.approve) = Some(Some(PairingDecision::Approved(grant())));
        let (server_end, mut client_end) = UnixStream::pair().unwrap();
        client_end.write_all(&request(7, "tools/list", json!({}))).unwrap();
        client_end.write_all(b"\n").unwrap();
        client_end.shutdown(Shutdown::Write).unwrap();

        serve_connection(&rig.server, server_end, current_uid());

        let mut reply = String::new();
        client_end.read_to_string(&mut reply).unwrap();
        assert!(reply.contains("\"relayed\":true"), "{reply}");
        let records = rig.server.store().load().unwrap();
        assert_eq!(records[0].peer_uid, Some(current_uid()));
        assert_eq!(records[0].transport, "uds");
    }

    #[test]
    fn the_socket_is_created_owner_only_and_a_live_one_is_not_replaced() {
        let dir = short_socket_dir();
        let path = dir.join("mcp.sock");
        let listener = bind_private_socket(&path).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
        assert!(bind_private_socket(&path).is_err(), "a socket in use must not be stolen");
        drop(listener);
        assert!(bind_private_socket(&path).is_ok(), "a stale socket file is replaced");
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn an_over_long_socket_path_gets_an_actionable_error() {
        let dir = short_socket_dir();
        let path = dir.join("x".repeat(200));
        let err = bind_private_socket(&path).unwrap_err().to_string();
        assert!(err.contains("too long for a Unix socket path"), "{err}");
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn a_regular_file_is_never_replaced_by_the_socket() {
        let dir = std::env::temp_dir().join(format!("bv-mcp-sock-file-{}", new_pairing_id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("precious.txt");
        fs::write(&path, b"keep me").unwrap();
        assert!(bind_private_socket(&path).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"keep me");
        fs::remove_dir_all(dir).ok();
    }

    // ── the stoppable server and the relay, end to end ───────────────────

    fn lines(out: &[u8]) -> Vec<Value> {
        out.split(|b| *b == b'\n').filter(|l| !l.is_empty()).map(|l| serde_json::from_slice(l).unwrap()).collect()
    }

    fn started(rig: &Rig) -> (SocketServer, PathBuf) {
        let dir = short_socket_dir();
        let path = dir.join("mcp-gui.sock");
        let server = SocketServer::start(rig.server.clone(), &path).unwrap();
        (server, dir)
    }

    #[test]
    fn the_relay_carries_a_whole_handshake_through_the_socket_server() {
        let rig = rig("relay-ok");
        *lock(&rig.prompt.approve) = Some(Some(PairingDecision::Approved(grant())));
        let (server, dir) = started(&rig);

        let input = [
            String::from_utf8(initialize(0, "2025-11-25")).unwrap(),
            json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }).to_string(),
            String::from_utf8(bare(1, "tools/list", json!({}))).unwrap(),
        ]
        .join("\n")
            + "\n";
        let mut out = Vec::new();
        let end = relay(server.path(), std::io::Cursor::new(input.into_bytes()), &mut out).unwrap();
        assert_eq!(end, RelayEnd::ClientClosed);
        let replies = lines(&out);
        assert_eq!(replies.len(), 2, "{replies:?}");
        assert_eq!(replies[0]["result"]["serverInfo"]["name"], json!("bastionvault"));
        assert_eq!(replies[1]["result"]["relayed"], json!(true));

        let records = rig.server.store().load().unwrap();
        assert_eq!((records[0].transport.as_str(), records[0].peer_uid), ("uds", Some(current_uid())));
        assert!(!String::from_utf8_lossy(&out).contains(MINTED), "the minted token never reaches the client");

        let path = server.path().to_path_buf();
        let accessors = server.stop();
        assert_eq!(accessors.len(), 1);
        assert!(!path.exists(), "stopping removes the socket file");
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn the_relay_says_nothing_is_running_when_there_is_no_socket_or_a_stale_one() {
        let dir = short_socket_dir();
        let path = dir.join("mcp-gui.sock");
        let empty = std::io::Cursor::new(Vec::new());
        assert!(matches!(relay(&path, empty, Vec::new()), Err(RelayError::NotRunning { .. })));

        // A socket file whose listener is gone (the app crashed).
        drop(bind_private_socket(&path).unwrap());
        let empty = std::io::Cursor::new(Vec::new());
        match relay(&path, empty, Vec::new()) {
            Err(RelayError::NotRunning { reason, .. }) => assert!(reason.contains("stale"), "{reason}"),
            other => panic!("expected NotRunning, got {other:?}"),
        }
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn stopping_the_server_cuts_a_live_relay_and_reports_it_as_server_closed() {
        let rig = paired_rig("relay-cut", false);
        let (server, dir) = started(&rig);
        let path = server.path().to_path_buf();

        // Input that never ends, as an assistant that keeps its pipe open.
        let (keep_open, held) = UnixStream::pair().unwrap();
        let relayed = std::thread::spawn(move || relay(&path, keep_open, Vec::new()));
        // Wait until the server has the connection, then stop it.
        for _ in 0..100 {
            if !lock(&server.connections.open).is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = server.stop();
        let end = relayed.join().unwrap().unwrap();
        assert_eq!(end, RelayEnd::ServerClosed);
        drop(held);
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn a_stopped_server_refuses_and_its_socket_is_gone() {
        let rig = paired_rig("relay-stopped", false);
        let (server, dir) = started(&rig);
        let path = server.path().to_path_buf();
        drop(server); // drop stops it too
        assert!(rig.server.is_shut_down());
        let empty = std::io::Cursor::new(Vec::new());
        assert!(matches!(relay(&path, empty, Vec::new()), Err(RelayError::NotRunning { .. })));

        // The LocalServer itself refuses anything still in flight.
        let resp = rig.server.handle_message(&stdio(), &request(9, "tools/list", json!({}))).unwrap();
        assert_eq!(data_code(&resp), "mcp_server_stopped");
        fs::remove_dir_all(dir).ok();
    }
}
