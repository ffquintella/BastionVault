//! `echo` reference plugin.
//!
//! Demonstrates the simplest possible BastionVault plugin: read input,
//! log a line, return the input verbatim. The intended build is:
//!
//! ```text
//! cargo build --release \
//!     --target wasm32-wasip1 \
//!     --example echo \
//!     -p bastion-plugin-sdk
//! ```
//!
//! and the resulting `.wasm` (under `target/wasm32-wasip1/release/examples/echo.wasm`)
//! can be uploaded via `POST /v1/sys/plugins` or the GUI's Plugins page.
//!
//! Manifest defaults that pair with this binary:
//!
//! ```json
//! {
//!   "name": "echo",
//!   "version": "0.1.0",
//!   "plugin_type": "transform",
//!   "runtime": "wasm",
//!   "abi_version": "1.0",
//!   "capabilities": { "log_emit": true }
//! }
//! ```
//!
//! No storage / audit capabilities required.

#![cfg_attr(target_arch = "wasm32", no_main)]

use bastion_plugin_sdk::{register, Host, LogLevel, Plugin, Request, Response};

struct Echo;

impl Plugin for Echo {
    fn handle(req: Request<'_>, host: &Host) -> Response {
        host.log(LogLevel::Info, "echo: handling request");
        Response::ok(req.input().to_vec())
    }
}

register!(Echo);

// Required when targeting `wasm32-wasip1` because the WASI preview1
// target normally expects a `_start` entry. We turn off `main` via
// `no_main` and the SDK's `register!` macro handles the `bv_run`
// export the host actually calls. On non-wasm, `cargo build --example`
// expects a `main` so we provide an empty one.
#[cfg(not(target_arch = "wasm32"))]
fn main() {}
