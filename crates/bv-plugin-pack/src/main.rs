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

use bv_crypto::MlDsa65Provider;
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MAGIC: &[u8; 4] = b"BVPL";
const FORMAT_VERSION: u8 = 1;

#[derive(Parser, Debug)]
#[command(name = "bv-plugin-pack", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,

    // ── default-mode (pack) flags, kept top-level for backward compatibility ──
    #[arg(long)]
    manifest: Option<PathBuf>,

    #[arg(long)]
    binary: Option<PathBuf>,

    #[arg(long)]
    out: Option<PathBuf>,

    /// Hex-encoded ML-DSA-65 secret seed (32 bytes / 64 hex chars).
    /// When supplied, the packer signs the manifest+binary and bakes
    /// the signature + `signing_key` name into the embedded manifest.
    /// Pair with `--signing-key-name`.
    #[arg(long)]
    signing_seed_hex: Option<String>,

    /// Path to a file containing the hex-encoded seed (alternative to
    /// `--signing-seed-hex` so secrets don't end up in shell history).
    #[arg(long)]
    signing_seed_file: Option<PathBuf>,

    /// Publisher name to record on the manifest. Must match the
    /// allowlist entry registered on the host via
    /// `POST /v1/sys/plugins/publishers`.
    #[arg(long)]
    signing_key_name: Option<String>,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Generate a fresh ML-DSA-65 keypair for plugin signing. Writes
    /// `<out>.seed` (hex secret seed) and `<out>.pub` (hex public key).
    /// The seed file is the one to feed back into `--signing-seed-file`;
    /// the pub file is what you register as the publisher's allowlist
    /// entry.
    Keygen {
        /// Output path prefix. The tool writes `<out>.seed` + `<out>.pub`.
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Debug)]
struct PackArgs {
    manifest: PathBuf,
    binary: PathBuf,
    out: Option<PathBuf>,
    signing_seed_hex: Option<String>,
    signing_seed_file: Option<PathBuf>,
    signing_key_name: Option<String>,
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
    /// ML-DSA-65 signature over `sha256(binary) || canonical_manifest_json_without_signature`,
    /// hex-encoded. Filled in only when `--signing-seed-hex` /
    /// `--signing-seed-file` is supplied.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    signature: String,
    /// Publisher identifier, must match the host's allowlist entry.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    signing_key: String,
}

fn main() {
    let cli = Cli::parse();
    let result = match cli.cmd {
        Some(Cmd::Keygen { out }) => keygen(out),
        None => {
            let manifest = cli.manifest.expect(
                "--manifest is required when no subcommand is given (use `keygen` to mint signing keys)",
            );
            let binary = cli.binary.expect("--binary is required");
            run(PackArgs {
                manifest,
                binary,
                out: cli.out,
                signing_seed_hex: cli.signing_seed_hex,
                signing_seed_file: cli.signing_seed_file,
                signing_key_name: cli.signing_key_name,
            })
        }
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run(args: PackArgs) -> Result<(), Box<dyn std::error::Error>> {
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

    // Optional signing pass — runs *after* sha256/size are stamped so
    // the canonical message the host re-derives matches byte-for-byte.
    let seed = resolve_signing_seed(&args)?;
    if let Some(seed_bytes) = seed {
        let key_name = args
            .signing_key_name
            .clone()
            .ok_or("`--signing-key-name` is required when signing")?;
        manifest.signing_key = key_name;
        manifest.signature.clear();
        // Canonical message must match `verifier::signing_message`:
        //   sha256(binary) || canonical_manifest_json_without_signature
        let bin_digest = hasher_digest(&binary);
        let canonical = serde_json::to_vec(&manifest)?;
        let mut message = Vec::with_capacity(bin_digest.len() + canonical.len());
        message.extend_from_slice(&bin_digest);
        message.extend_from_slice(&canonical);
        let provider = MlDsa65Provider;
        let sig_bytes = provider
            .sign(&seed_bytes, &message, &[])
            .map_err(|e| format!("ml-dsa-65 sign: {e:?}"))?;
        manifest.signature = hex::encode(&sig_bytes);
    }

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
        "wrote {} ({} byte header + {} byte manifest + {} byte binary){}",
        out.display(),
        12,
        manifest_json.len(),
        binary.len(),
        if manifest.signature.is_empty() {
            ""
        } else {
            " — signed"
        },
    );
    Ok(())
}

fn hasher_digest(binary: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(binary);
    h.finalize().to_vec()
}

/// Resolve an ML-DSA-65 secret seed from one of the two CLI flags
/// (`--signing-seed-hex` or `--signing-seed-file`). Returns `Ok(None)`
/// when neither is supplied — the caller treats that as "skip the
/// signing step".
fn resolve_signing_seed(args: &PackArgs) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    let raw = match (&args.signing_seed_hex, &args.signing_seed_file) {
        (Some(_), Some(_)) => {
            return Err("supply --signing-seed-hex OR --signing-seed-file, not both".into())
        }
        (Some(s), None) => s.trim().to_string(),
        (None, Some(p)) => fs::read_to_string(p)
            .map_err(|e| format!("reading {}: {e}", p.display()))?
            .trim()
            .to_string(),
        (None, None) => return Ok(None),
    };
    let seed = hex::decode(&raw).map_err(|e| format!("seed must be hex: {e}"))?;
    if seed.len() != 32 {
        return Err(format!(
            "ML-DSA-65 seed must be 32 bytes (64 hex chars); got {} bytes",
            seed.len()
        )
        .into());
    }
    Ok(Some(seed))
}

fn keygen(out: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let provider = MlDsa65Provider;
    let kp = provider
        .generate_keypair()
        .map_err(|e| format!("keygen: {e:?}"))?;
    let seed_path = with_ext(&out, "seed");
    let pub_path = with_ext(&out, "pub");
    if let Some(parent) = seed_path.parent() {
        if !parent.as_os_str().is_empty() {
            let _ = fs::create_dir_all(parent);
        }
    }
    fs::write(&seed_path, hex::encode(kp.secret_seed()))
        .map_err(|e| format!("writing {}: {e}", seed_path.display()))?;
    fs::write(&pub_path, hex::encode(kp.public_key()))
        .map_err(|e| format!("writing {}: {e}", pub_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&seed_path, fs::Permissions::from_mode(0o600));
    }
    println!(
        "wrote {} (seed, keep secret) and {} (publisher pubkey, register on host)",
        seed_path.display(),
        pub_path.display()
    );
    Ok(())
}

fn with_ext(p: &std::path::Path, ext: &str) -> PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(".");
    s.push(ext);
    PathBuf::from(s)
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

        run(PackArgs {
            manifest: manifest_path,
            binary: binary_path,
            out: Some(out_path.clone()),
            signing_seed_hex: None,
            signing_seed_file: None,
            signing_key_name: None,
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
