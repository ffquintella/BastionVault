//! `kv_cache` reference plugin.
//!
//! Demonstrates the storage host capability. Treats the input as a
//! request of the form `<verb>\n<key>\n<value?>` where `<verb>` is one
//! of `GET` / `PUT` / `DEL` / `LIST`. Stores all values under the
//! plugin's barrier-encrypted scope (no operator-visible mount needed).
//!
//! Required manifest capabilities:
//!
//! ```json
//! { "log_emit": true, "storage_prefix": "" }
//! ```
//!
//! Build:
//!
//! ```text
//! cargo build --release \
//!     --target wasm32-wasip1 \
//!     --example kv_cache \
//!     -p bastion-plugin-sdk
//! ```

#![cfg_attr(target_arch = "wasm32", no_main)]

use bastion_plugin_sdk::{register, Host, HostError, LogLevel, Plugin, Request, Response};

struct KvCache;

impl Plugin for KvCache {
    fn handle(req: Request<'_>, host: &Host) -> Response {
        let raw = match core::str::from_utf8(req.input()) {
            Ok(s) => s,
            Err(_) => return Response::err(2, b"input not valid UTF-8".to_vec()),
        };
        let mut lines = raw.split('\n');
        let verb = lines.next().unwrap_or("");
        let key = lines.next().unwrap_or("");
        let value = lines.next().unwrap_or("");

        match verb {
            "GET" => match host.storage_get(key) {
                Ok(v) => Response::ok(v),
                Err(HostError::NotFound) => Response::err(1, b"not found".to_vec()),
                Err(HostError::Forbidden) => Response::err(2, b"forbidden".to_vec()),
                Err(_) => Response::err(3, b"storage error".to_vec()),
            },
            "PUT" => match host.storage_put(key, value.as_bytes()) {
                Ok(()) => {
                    host.log(LogLevel::Info, "kv_cache: stored value");
                    Response::ok_empty()
                }
                Err(_) => Response::err(3, b"storage error".to_vec()),
            },
            "DEL" => match host.storage_delete(key) {
                Ok(()) => Response::ok_empty(),
                Err(_) => Response::err(3, b"storage error".to_vec()),
            },
            "LIST" => match host.storage_list(key) {
                Ok(keys) => Response::ok(keys.join("\n").into_bytes()),
                Err(_) => Response::err(3, b"storage error".to_vec()),
            },
            _ => Response::err(2, b"unknown verb".to_vec()),
        }
    }
}

register!(KvCache);

#[cfg(not(target_arch = "wasm32"))]
fn main() {}
