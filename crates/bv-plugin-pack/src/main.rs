//! `bv-plugin-pack` — pack a plugin.toml + plugin binary into a single
//! `.bvplugin` bundle. The GUI's Register modal detects the bundle by
//! its magic bytes and prefills every form field (name, version, type,
//! runtime, description, capabilities, config_schema) from the embedded
//! manifest, so operators don't have to retype anything that the
//! plugin author already declared.
//!
//! Works for both runtimes: a WASM plugin embeds the `.wasm` module; a
//! process plugin embeds the native executable. The host distinguishes
//! at registration time via `manifest.runtime`.
//!
//! ## Format (v1)
//!
//! ```text
//! offset 0:    "BVPL"        4 bytes magic
//! offset 4:    0x01          format version (u8)
//! offset 5:    [0,0,0]       reserved (must be zero)
//! offset 8:    u32 LE        manifest_json_length
//! offset 12:   <manifest>    JSON, length above
//! offset 12+m: <binary>      rest of file = plugin binary
//! ```
//!
//! The embedded manifest is JSON because the host's existing
//! `POST /v1/sys/plugins/<name>` endpoint consumes JSON; the packer
//! converts the source `plugin.toml` and recomputes `sha256` over the
//! binary so a tampered binary can't sneak past the bundle.

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use clap::Parser;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MAGIC: &[u8; 4] = b"BVPL";
const FORMAT_VERSION: u8 = 1;

#[derive(Parser, Debug)]
#[command(name = "bv-plugin-pack", version, about, long_about = None)]
struct Args {
    /// Path to the source manifest (TOML).
    #[arg(long)]
    manifest: PathBuf,

    /// Path to the compiled `.wasm` binary.
    #[arg(long)]
    binary: PathBuf,

    /// Output path. Defaults to `<binary stem>.bvplugin` next to `--binary`.
    #[arg(long)]
    out: Option<PathBuf>,
}

/// Mirrors `bastion_vault::plugins::manifest::ConfigField` exactly,
/// including `#[serde(skip_serializing_if = ...)]` on optional fields,
/// so the bundle's embedded manifest deserializes cleanly on the host
/// without per-field tolerance for `null`.
#[derive(Debug, Deserialize, Serialize)]
struct ConfigField {
    name: String,
    kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(default)]
    required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    default: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    options: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Default)]
struct Capabilities {
    #[serde(default)]
    log_emit: bool,
    #[serde(default)]
    audit_emit: bool,
    #[serde(default)]
    storage_prefix: Option<String>,
    #[serde(default)]
    allowed_keys: Vec<String>,
    #[serde(default)]
    allowed_hosts: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct Manifest {
    name: String,
    version: String,
    plugin_type: String,
    runtime: String,
    abi_version: String,
    sha256: String,
    size: u64,
    #[serde(default)]
    description: String,
    #[serde(default)]
    capabilities: Capabilities,
    #[serde(default)]
    config_schema: Vec<ConfigField>,
}

fn main() {
    let args = Args::parse();
    if let Err(e) = run(args) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    let toml_text = fs::read_to_string(&args.manifest)
        .map_err(|e| format!("reading manifest {}: {e}", args.manifest.display()))?;
    let mut manifest: Manifest = toml::from_str(&toml_text)
        .map_err(|e| format!("parsing manifest {}: {e}", args.manifest.display()))?;

    let binary = fs::read(&args.binary)
        .map_err(|e| format!("reading binary {}: {e}", args.binary.display()))?;

    let mut hasher = Sha256::new();
    hasher.update(&binary);
    let digest = hasher.finalize();
    let sha256 = digest.iter().map(|b| format!("{:02x}", b)).collect::<String>();

    if !manifest.sha256.is_empty()
        && !is_placeholder_sha(&manifest.sha256)
        && manifest.sha256 != sha256
    {
        return Err(format!(
            "manifest sha256 ({}) does not match the binary's actual sha256 ({}). \
             Either fix the manifest or remove the field so the packer fills it.",
            manifest.sha256, sha256,
        )
        .into());
    }
    manifest.sha256 = sha256;
    manifest.size = binary.len() as u64;

    let manifest_json = serde_json::to_vec(&manifest)?;
    let manifest_len = u32::try_from(manifest_json.len())
        .map_err(|_| "manifest larger than 4 GiB — not supported")?;

    let out = args.out.unwrap_or_else(|| {
        let mut p = args.binary.clone();
        p.set_extension("bvplugin");
        p
    });

    let mut f = fs::File::create(&out)
        .map_err(|e| format!("creating {}: {e}", out.display()))?;
    f.write_all(MAGIC)?;
    f.write_all(&[FORMAT_VERSION, 0, 0, 0])?;
    f.write_all(&manifest_len.to_le_bytes())?;
    f.write_all(&manifest_json)?;
    f.write_all(&binary)?;
    f.sync_all()?;

    println!(
        "wrote {} ({} byte header + {} byte manifest + {} byte binary)",
        out.display(),
        12,
        manifest_json.len(),
        binary.len(),
    );
    Ok(())
}

fn is_placeholder_sha(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b == b'0')
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read as _;

    #[test]
    fn placeholder_sha_detected() {
        assert!(is_placeholder_sha(&"0".repeat(64)));
        assert!(!is_placeholder_sha(&"a".repeat(64)));
        assert!(!is_placeholder_sha("0"));
    }

    #[test]
    fn round_trip_pack_then_parse() {
        let dir = tempdir();
        let manifest_path = dir.join("plugin.toml");
        let binary_path = dir.join("plugin.wasm");
        let out_path = dir.join("plugin.bvplugin");

        fs::write(
            &manifest_path,
            r#"
name = "totp"
version = "0.1.0"
plugin_type = "secret"
runtime = "wasm"
abi_version = "1.0"
sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
size = 0
description = "demo"

[capabilities]
log_emit = true
audit_emit = false

[[config_schema]]
name = "digits"
kind = "int"
default = "6"
"#,
        )
        .unwrap();
        fs::write(&binary_path, b"\x00asm\x01\x00\x00\x00").unwrap();

        run(Args {
            manifest: manifest_path,
            binary: binary_path,
            out: Some(out_path.clone()),
        })
        .unwrap();

        let mut bundle = Vec::new();
        fs::File::open(&out_path).unwrap().read_to_end(&mut bundle).unwrap();
        assert_eq!(&bundle[0..4], MAGIC);
        assert_eq!(bundle[4], FORMAT_VERSION);
        let mlen =
            u32::from_le_bytes(bundle[8..12].try_into().unwrap()) as usize;
        let manifest_json = &bundle[12..12 + mlen];
        let parsed: Manifest = serde_json::from_slice(manifest_json).unwrap();
        assert_eq!(parsed.name, "totp");
        assert_eq!(parsed.size, 8); // length of the fake "wasm" we wrote
        assert_ne!(parsed.sha256, "0".repeat(64));
        assert!(parsed.capabilities.log_emit);
        assert_eq!(parsed.config_schema.len(), 1);
        assert_eq!(parsed.config_schema[0].name, "digits");

        let wasm = &bundle[12 + mlen..];
        assert_eq!(wasm, b"\x00asm\x01\x00\x00\x00");
    }

    fn tempdir() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "bv-plugin-pack-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        fs::create_dir_all(&p).unwrap();
        p
    }
}
