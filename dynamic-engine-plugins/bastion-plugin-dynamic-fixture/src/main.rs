//! The fixture as a process plugin (the testkit spawns this binary).

#[cfg(not(target_arch = "wasm32"))]
fn main() {
    bastion_plugin_dynamic_sdk::process::run_main(bastion_plugin_dynamic_fixture::FakeEngine)
}

#[cfg(target_arch = "wasm32")]
fn main() {}
