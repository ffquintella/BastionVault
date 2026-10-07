//! Locate a plugin's compiled `.wasm` artifact without hard-coding
//! target paths in every test.
//!
//! Search order for `locate_wasm("my-plugin")` (file stem uses `_`, as
//! rustc names it):
//!
//! 1. `$BV_PLUGIN_WASM` — explicit override, used verbatim.
//! 2. `$CARGO_TARGET_DIR/<triple>/{release,debug}/`
//! 3. `<CARGO_MANIFEST_DIR>/target/<triple>/{release,debug}/` and each
//!    ancestor's `target/` (so a plugin inside a workspace finds the
//!    shared target dir).
//!
//! `<triple>` is tried as `wasm32-wasip1` then `wasm32-unknown-unknown`.
//! Release is preferred over debug because plugin tests are fuel-bound.

use std::path::{Path, PathBuf};

const TRIPLES: [&str; 2] = ["wasm32-wasip1", "wasm32-unknown-unknown"];
const PROFILES: [&str; 2] = ["release", "debug"];

/// Failure to find or read an artifact. The message lists every path
/// tried and the command that builds the artifact, so a missing build
/// is a one-glance fix rather than an `os error 2`.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct ArtifactError(String);

/// Locate `<crate_name>.wasm` (see module docs for the search order).
pub fn locate_wasm(crate_name: &str) -> Result<PathBuf, ArtifactError> {
    if let Ok(p) = std::env::var("BV_PLUGIN_WASM") {
        let p = PathBuf::from(p);
        return if p.is_file() {
            Ok(p)
        } else {
            Err(ArtifactError(format!("BV_PLUGIN_WASM={} is not a file", p.display())))
        };
    }
    let stem = crate_name.replace('-', "_");
    let mut roots: Vec<PathBuf> = Vec::new();
    if let Ok(t) = std::env::var("CARGO_TARGET_DIR") {
        roots.push(PathBuf::from(t));
    }
    if let Ok(dir) = std::env::var("CARGO_MANIFEST_DIR") {
        for anc in Path::new(&dir).ancestors() {
            roots.push(anc.join("target"));
        }
    }
    locate_in(&stem, &roots)
}

/// Same search as [`locate_wasm`] over explicit `target/` roots.
pub fn locate_in(stem: &str, roots: &[PathBuf]) -> Result<PathBuf, ArtifactError> {
    let mut tried = Vec::new();
    for root in roots {
        for triple in TRIPLES {
            for profile in PROFILES {
                let cand = root.join(triple).join(profile).join(format!("{stem}.wasm"));
                if cand.is_file() {
                    return Ok(cand);
                }
                tried.push(cand);
            }
        }
    }
    Err(ArtifactError(format!(
        "no `{stem}.wasm` found; build it with \
         `cargo build --target wasm32-wasip1 --release` or set BV_PLUGIN_WASM. Tried:\n{}",
        tried.iter().map(|p| format!("  {}", p.display())).collect::<Vec<_>>().join("\n")
    )))
}

/// [`locate_wasm`] + read the bytes.
pub fn load_wasm(crate_name: &str) -> Result<Vec<u8>, ArtifactError> {
    let p = locate_wasm(crate_name)?;
    std::fs::read(&p).map_err(|e| ArtifactError(format!("reading {}: {e}", p.display())))
}
