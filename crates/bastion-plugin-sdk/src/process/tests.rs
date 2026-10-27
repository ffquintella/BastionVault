//! The runner against a scripted host, over in-memory pipes.

use std::io::{Cursor, Read};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::Instant;

use super::*;

const PASSWORD: &str = "pw-never-in-debug";

#[derive(Default)]
struct TestPlugin {
    lifecycle: Mutex<Vec<Lifecycle>>,
}

impl ProcessPlugin for TestPlugin {
    fn handle(&self, inv: &Invocation, input: &[u8]) -> Response {
        match input {
            b"credential" => match inv.host().resource_sql_credential("db", "ro", "s-1") {
                Ok(c) => {
                    assert!(!format!("{c:?}").contains(PASSWORD));
                    assert_eq!(c.password.as_str(), PASSWORD);
                    Response::ok(format!("{}@{}", c.username, c.endpoint).into_bytes())
                }
                Err(e) => Response::err(5, e.to_string().into_bytes()),
            },
            b"slow" => {
                let start = Instant::now();
                while !inv.is_cancelled() && start.elapsed() < Duration::from_secs(10) {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Response::ok(if inv.is_cancelled() { b"cancelled".to_vec() } else { b"finished".to_vec() })
            }
            other => Response::ok(other.to_vec()),
        }
    }

    fn on_lifecycle(&self, event: Lifecycle) {
        self.lifecycle.lock().unwrap().push(event);
    }
}

/// A `Read` fed line by line from a channel; EOF when the sender drops.
struct ChannelReader {
    rx: Receiver<Vec<u8>>,
    buf: Cursor<Vec<u8>>,
}

impl Read for ChannelReader {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let n = self.buf.read(out)?;
            if n > 0 {
                return Ok(n);
            }
            match self.rx.recv() {
                Ok(next) => self.buf = Cursor::new(next),
                Err(_) => return Ok(0),
            }
        }
    }
}

/// A `Write` that forwards each complete line, parsed.
struct LineWriter {
    tx: Sender<Value>,
    pending: Vec<u8>,
}

impl Write for LineWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.pending.extend_from_slice(data);
        while let Some(i) = self.pending.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = self.pending.drain(..=i).collect();
            let _ = self.tx.send(serde_json::from_slice(&line).unwrap());
        }
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn line(v: Value) -> Vec<u8> {
    let mut l = serde_json::to_vec(&v).unwrap();
    l.push(b'\n');
    l
}

fn credential_reply(id: u64, invocation: Option<u64>) -> Value {
    let mut v = json!({"type": "host_reply", "id": id, "result": {
        "resource": "db", "profile": "ro", "secret_id": "svc", "endpoint": "db1:5432",
        "username": "svc", "password": PASSWORD}});
    if let Some(i) = invocation {
        v["invocation"] = json!(i);
    }
    v
}

fn recv(rx: &Receiver<Value>) -> Value {
    rx.recv_timeout(Duration::from_secs(5)).expect("a message from the plugin")
}

#[test]
fn single_shot_runs_one_invocation_with_inline_host_calls() {
    let mut input = Vec::new();
    input.extend(line(json!({"type": "init", "token": "t", "input": B64.encode("credential"), "plugin_name": "p"})));
    input.extend(line(credential_reply(1, None)));
    let (tx, rx) = channel();
    let plugin = Arc::new(TestPlugin::default());
    serve(plugin, Box::new(Cursor::new(input)), Box::new(LineWriter { tx, pending: vec![] }), false, "t").unwrap();
    let call = recv(&rx);
    assert_eq!(call["type"], "host_call");
    assert_eq!(call["method"], "resource_sql_credential");
    assert_eq!(call["params"], json!({"resource": "db", "profile": "ro", "session_ref": "s-1"}));
    assert!(call.get("invocation").is_none());
    let set = recv(&rx);
    assert_eq!(B64.decode(set["data_b64"].as_str().unwrap()).unwrap(), b"svc@db1:5432");
    assert_eq!(recv(&rx), json!({"type": "done", "status": 0}));
}

#[test]
fn serialized_long_lived_keeps_the_invoke_done_protocol() {
    let mut input = Vec::new();
    input.extend(line(json!({"type": "init", "plugin_name": "p"})));
    input.extend(line(json!({"type": "invoke", "id": 7, "input": B64.encode("hello")})));
    let (tx, rx) = channel();
    let plugin = Arc::new(TestPlugin::default());
    serve(plugin.clone(), Box::new(Cursor::new(input)), Box::new(LineWriter { tx, pending: vec![] }), true, "tok")
        .unwrap();
    assert_eq!(recv(&rx), json!({"type": "hello", "token": "tok"}));
    let done = recv(&rx);
    assert_eq!(done["type"], "invoke_done");
    assert_eq!(done["id"], 7);
    assert_eq!(B64.decode(done["data_b64"].as_str().unwrap()).unwrap(), b"hello");
    assert_eq!(*plugin.lifecycle.lock().unwrap(), vec![Lifecycle::Shutdown]);
}

/// Concurrency, routing by invocation, cancellation, ping and lifecycle on
/// the multiplexed protocol.
#[test]
fn multiplexed_protocol_end_to_end() {
    let (in_tx, in_rx) = channel::<Vec<u8>>();
    let (out_tx, out) = channel();
    let plugin = Arc::new(TestPlugin::default());
    let reader: Reader = Box::new(BufReader::new(ChannelReader { rx: in_rx, buf: Cursor::new(vec![]) }));
    let p = plugin.clone();
    let runner = std::thread::spawn(move || {
        serve(p, reader, Box::new(LineWriter { tx: out_tx, pending: vec![] }), true, "tok")
    });
    let send = |v: Value| in_tx.send(line(v)).unwrap();

    send(json!({"type": "init", "plugin_name": "p", "protocol": "multiplexed", "max_concurrent": 4}));
    assert_eq!(recv(&out), json!({"type": "hello", "token": "tok"}));

    send(json!({"type": "invoke", "id": 1, "input": B64.encode("slow")}));
    send(json!({"type": "invoke", "id": 2, "input": B64.encode("credential")}));
    let call = recv(&out);
    assert_eq!(call["type"], "host_call");
    assert_eq!(call["invocation"], 2, "the call names its own invocation");
    send(credential_reply(call["id"].as_u64().unwrap(), Some(2)));
    let done = recv(&out);
    assert_eq!((done["type"].as_str(), done["id"].as_u64()), (Some("done"), Some(2)), "2 finished while 1 runs");

    send(json!({"type": "ping", "nonce": 41}));
    assert_eq!(recv(&out), json!({"type": "pong", "nonce": 41}));

    send(json!({"type": "cancel", "id": 1}));
    let done = recv(&out);
    assert_eq!(done["id"], 1);
    assert_eq!(B64.decode(done["data_b64"].as_str().unwrap()).unwrap(), b"cancelled");

    send(json!({"type": "lifecycle", "event": "seal", "deadline_ms": 10_000}));
    assert_eq!(recv(&out), json!({"type": "lifecycle_ack", "event": "seal"}));

    drop(in_tx);
    runner.join().unwrap().unwrap();
    assert_eq!(*plugin.lifecycle.lock().unwrap(), vec![Lifecycle::Seal, Lifecycle::Shutdown]);
}

#[test]
fn host_errors_keep_their_code_and_detail() {
    let mut input = Vec::new();
    input.extend(line(json!({"type": "init", "token": "t", "input": B64.encode("credential"), "plugin_name": "p"})));
    input.extend(line(json!({"type": "host_reply_error", "id": 1,
        "error": "refused: endpoint_mismatch: the profile's endpoint is not bound"})));
    let (tx, rx) = channel();
    serve(Arc::new(TestPlugin::default()), Box::new(Cursor::new(input)), Box::new(LineWriter { tx, pending: vec![] }), false, "t")
        .unwrap();
    let _call = recv(&rx);
    let set = recv(&rx);
    let body = String::from_utf8(B64.decode(set["data_b64"].as_str().unwrap()).unwrap()).unwrap();
    assert_eq!(body, "refused: endpoint_mismatch: the profile's endpoint is not bound");
    assert_eq!(recv(&rx)["status"], 5);

    let e = HostCallError::from_reply("no_invocation");
    assert_eq!((e.code.as_str(), e.detail.as_str()), ("no_invocation", ""));
}
