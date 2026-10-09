//! `bv-plugin-pack test <bundle>` — offline verification of a
//! `.bvplugin` bundle: unpack it, re-derive everything the host checks
//! at registration, and smoke-invoke the embedded module through the
//! testkit. It never contacts a vault.
//!
//! Checks, in order (a failed *structural* check stops the run, since
//! later checks would be meaningless on a mangled bundle):
//!
//! 1. container: magic, format version, reserved bytes, manifest length
//! 2. manifest parses and passes `PluginManifest::validate`
//! 3. `abi_version` is accepted by `check_abi_compatibility`
//! 4. an embedded surface is present exactly when declared, validates,
//!    and matches `manifest.surface.sha256` / `size`
//! 5. `manifest.sha256` / `manifest.size` match the embedded binary
//! 6. every `app-module` client asset matches the embedded binary
//! 7. signature: verified against `--publisher-pub` when given; when the
//!    bundle is signed but no key is supplied it is reported as skipped
//!    (never silently "ok"); an unsigned bundle is reported as such
//! 8. smoke invoke through `bastion-plugin-testkit` with the manifest's
//!    own capabilities and config defaults

use std::collections::BTreeSet;

use bastion_plugin_testkit::TestHost;
use bv_plugin_manifest::{check_abi_compatibility, signing_message, PluginManifest, RuntimeKind};
use bv_plugin_surface::SurfaceManifest;
use fips204::ml_dsa_65 as fdsa;
use fips204::traits::{SerDes, Verifier};
use sha2::{Digest, Sha256};

const MAGIC: &[u8; 4] = b"BVPL";
const LEGACY_FORMAT_VERSION: u8 = 1;
const SURFACE_FORMAT_VERSION: u8 = 2;
const LEGACY_HEADER_LEN: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Pass,
    Fail,
    Skip,
}

#[derive(Debug)]
pub struct Check {
    pub name: &'static str,
    pub status: Status,
    pub detail: String,
}

#[derive(Debug, Default)]
pub struct Report {
    pub checks: Vec<Check>,
}

impl Report {
    fn push(&mut self, name: &'static str, status: Status, detail: impl Into<String>) {
        self.checks.push(Check { name, status, detail: detail.into() });
    }
    pub fn failed(&self) -> bool {
        self.checks.iter().any(|c| c.status == Status::Fail)
    }
}

/// What the smoke invocation sends and what it must return.
#[derive(Debug, Clone)]
pub struct SmokeOpts {
    pub op: String,
    pub path: String,
    pub data: serde_json::Value,
    /// When set, the plugin's `bv_run` status must equal this. When
    /// unset, any completed invocation passes (a plugin may legitimately
    /// reject an arbitrary smoke request); a trap, missing export or
    /// fuel exhaustion always fails.
    pub expect_status: Option<i32>,
}

impl Default for SmokeOpts {
    fn default() -> Self {
        Self { op: "read".into(), path: String::new(), data: serde_json::json!({}), expect_status: None }
    }
}

/// Borrowed sections of a structurally valid bundle.
pub struct BundleParts<'a> {
    pub manifest_json: &'a [u8],
    pub surface_json: Option<&'a [u8]>,
    pub binary: &'a [u8],
}

/// Split either the legacy v1 bundle or a surface-bearing v2 bundle.
pub fn unpack(bundle: &[u8]) -> Result<BundleParts<'_>, String> {
    if bundle.len() < LEGACY_HEADER_LEN || &bundle[0..4] != MAGIC {
        return Err("not a .bvplugin bundle (bad magic)".into());
    }
    if bundle[5..8] != [0, 0, 0] {
        return Err("reserved header bytes are non-zero".into());
    }
    let mlen = u32::from_le_bytes(bundle[8..12].try_into().expect("4 bytes")) as usize;
    match bundle[4] {
        LEGACY_FORMAT_VERSION => {
            let manifest_end = LEGACY_HEADER_LEN
                .checked_add(mlen)
                .filter(|end| *end <= bundle.len())
                .ok_or("manifest length runs past end of bundle")?;
            Ok(BundleParts {
                manifest_json: &bundle[LEGACY_HEADER_LEN..manifest_end],
                surface_json: None,
                binary: &bundle[manifest_end..],
            })
        }
        SURFACE_FORMAT_VERSION => {
            let manifest_end = LEGACY_HEADER_LEN
                .checked_add(mlen)
                .filter(|end| *end <= bundle.len())
                .ok_or("manifest length runs past end of bundle")?;
            let binary_len_end = manifest_end
                .checked_add(4)
                .filter(|end| *end <= bundle.len())
                .ok_or("bundle is missing the v2 binary length")?;
            let binary_len = u32::from_le_bytes(
                bundle[manifest_end..binary_len_end]
                    .try_into()
                    .expect("4 bytes"),
            ) as usize;
            let binary_end = binary_len_end
                .checked_add(binary_len)
                .filter(|end| *end <= bundle.len())
                .ok_or("binary length runs past end of bundle")?;
            let surface_len_end = binary_end
                .checked_add(4)
                .filter(|end| *end <= bundle.len())
                .ok_or("bundle is missing the v2 surface length")?;
            let surface_len = u32::from_le_bytes(
                bundle[binary_end..surface_len_end]
                    .try_into()
                    .expect("4 bytes"),
            ) as usize;
            let surface_end = surface_len_end
                .checked_add(surface_len)
                .filter(|end| *end <= bundle.len())
                .ok_or("surface length runs past end of bundle")?;
            if surface_end != bundle.len() {
                return Err("unsupported trailing sections in surface bundle".into());
            }
            Ok(BundleParts {
                manifest_json: &bundle[LEGACY_HEADER_LEN..manifest_end],
                surface_json: Some(&bundle[surface_len_end..surface_end]),
                binary: &bundle[binary_len_end..binary_end],
            })
        }
        version => Err(format!("unsupported bundle format version {version} (this tool reads v1 and v2)")),
    }
}

pub fn check_bundle(bundle: &[u8], publisher_pub: Option<&[u8]>, smoke: &SmokeOpts) -> Report {
    let mut r = Report::default();

    let parts = match unpack(bundle) {
        Ok(p) => {
            r.push(
                "container",
                Status::Pass,
                format!("{} byte surface, {} byte binary", p.surface_json.map_or(0, <[u8]>::len), p.binary.len()),
            );
            p
        }
        Err(e) => {
            r.push("container", Status::Fail, e);
            return r;
        }
    };

    let manifest: PluginManifest = match serde_json::from_slice(parts.manifest_json) {
        Ok(m) => m,
        Err(e) => {
            r.push("manifest", Status::Fail, format!("embedded manifest does not parse: {e}"));
            return r;
        }
    };
    match manifest.validate() {
        Ok(()) => r.push("manifest", Status::Pass, format!("{} {}", manifest.name, manifest.version)),
        Err(e) => {
            r.push("manifest", Status::Fail, e);
            return r;
        }
    }

    match check_abi_compatibility(&manifest.abi_version) {
        Ok(()) => r.push("abi", Status::Pass, manifest.abi_version.clone()),
        Err(e) => r.push("abi", Status::Fail, e),
    }

    check_surface(&mut r, &manifest, parts.surface_json);

    let binary = parts.binary;
    let actual_sha = hex::encode(Sha256::digest(binary));
    if manifest.sha256 != actual_sha {
        r.push(
            "binary-hash",
            Status::Fail,
            format!("manifest sha256 {} != binary sha256 {actual_sha}", manifest.sha256),
        );
    } else if manifest.size != binary.len() as u64 {
        r.push("binary-hash", Status::Fail, format!("manifest size {} != binary size {}", manifest.size, binary.len()));
    } else {
        r.push("binary-hash", Status::Pass, actual_sha.clone());
    }

    let bad_assets: Vec<&str> = manifest
        .client_assets
        .iter()
        .filter(|a| a.kind == "app-module" && (a.sha256 != actual_sha || a.size != binary.len() as u64))
        .map(|a| a.name.as_str())
        .collect();
    if bad_assets.is_empty() {
        r.push("client-assets", Status::Pass, format!("{} declared", manifest.client_assets.len()));
    } else {
        r.push(
            "client-assets",
            Status::Fail,
            format!("app-module asset(s) do not match the embedded binary: {}", bad_assets.join(", ")),
        );
    }

    check_signature(&mut r, &manifest, binary, publisher_pub);
    smoke_invoke(&mut r, &manifest, binary, smoke);
    r
}

fn check_surface(r: &mut Report, manifest: &PluginManifest, surface_json: Option<&[u8]>) {
    let (surface_ref, bytes) = match (&manifest.surface, surface_json) {
        (None, None) => {
            r.push("surface", Status::Skip, "bundle declares no management surface");
            return;
        }
        (Some(_), None) => {
            r.push("surface", Status::Fail, "manifest declares a surface but the bundle does not embed it");
            return;
        }
        (None, Some(_)) => {
            r.push("surface", Status::Fail, "bundle embeds a surface that the manifest does not declare");
            return;
        }
        (Some(surface_ref), Some(bytes)) => (surface_ref, bytes),
    };

    let actual_sha = hex::encode(Sha256::digest(bytes));
    if surface_ref.sha256 != actual_sha {
        r.push(
            "surface",
            Status::Fail,
            format!("manifest surface sha256 {} != embedded surface sha256 {actual_sha}", surface_ref.sha256),
        );
        return;
    }
    if surface_ref.size != bytes.len() as u64 {
        r.push(
            "surface",
            Status::Fail,
            format!("manifest surface size {} != embedded surface size {}", surface_ref.size, bytes.len()),
        );
        return;
    }
    let surface: SurfaceManifest = match serde_json::from_slice(bytes) {
        Ok(surface) => surface,
        Err(e) => {
            r.push("surface", Status::Fail, format!("embedded surface does not parse: {e}"));
            return;
        }
    };
    if surface.schema_version != surface_ref.schema_version {
        r.push(
            "surface",
            Status::Fail,
            format!(
                "embedded surface schema_version {} != manifest schema_version {}",
                surface.schema_version, surface_ref.schema_version
            ),
        );
        return;
    }
    let declared_assets: BTreeSet<&str> = manifest.client_assets.iter().map(|asset| asset.name.as_str()).collect();
    match surface.validate(&manifest.name, &declared_assets) {
        Ok(()) => r.push("surface", Status::Pass, actual_sha),
        Err(e) => r.push("surface", Status::Fail, format!("embedded surface failed validation: {e}")),
    }
}

fn check_signature(r: &mut Report, manifest: &PluginManifest, binary: &[u8], publisher_pub: Option<&[u8]>) {
    if manifest.signature.is_empty() {
        r.push("signature", Status::Skip, "bundle is unsigned");
        return;
    }
    let Some(pk) = publisher_pub else {
        r.push(
            "signature",
            Status::Skip,
            format!(
                "signed by `{}` but NOT verified: pass --publisher-pub-hex/--publisher-pub-file",
                manifest.signing_key
            ),
        );
        return;
    };
    let verdict = (|| -> Result<bool, String> {
        let sig = hex::decode(&manifest.signature).map_err(|e| format!("signature is not hex: {e}"))?;
        let pk_arr: [u8; fdsa::PK_LEN] =
            pk.try_into().map_err(|_| format!("publisher key must be {} bytes, got {}", fdsa::PK_LEN, pk.len()))?;
        let sig_arr: [u8; fdsa::SIG_LEN] = sig
            .as_slice()
            .try_into()
            .map_err(|_| format!("signature must be {} bytes, got {}", fdsa::SIG_LEN, sig.len()))?;
        let pk_obj = fdsa::PublicKey::try_from_bytes(pk_arr).map_err(|e| format!("publisher key: {e}"))?;
        Ok(pk_obj.verify(&signing_message(manifest, binary), &sig_arr, &[]))
    })();
    match verdict {
        Ok(true) => r.push("signature", Status::Pass, format!("ML-DSA-65 by `{}`", manifest.signing_key)),
        Ok(false) => r.push(
            "signature",
            Status::Fail,
            format!("does not verify against the supplied key (signing key name `{}`)", manifest.signing_key),
        ),
        Err(e) => r.push("signature", Status::Fail, e),
    }
}

fn smoke_invoke(r: &mut Report, manifest: &PluginManifest, binary: &[u8], smoke: &SmokeOpts) {
    if manifest.capabilities.app.is_declared() {
        // App modules import the `bvx.*` surface and are driven by the
        // client runtime, not `bv_run`; the `AppTestHost` harness in the
        // testkit is the right tool for those.
        r.push("smoke", Status::Skip, "app-module plugin: drive it with AppTestHost, not bv_run");
        return;
    }
    let caps = &manifest.capabilities;
    let mut b = TestHost::builder(manifest.name.clone()).log_emit(caps.log_emit).audit_emit(caps.audit_emit);
    if let Some(p) = &caps.storage_prefix {
        b = b.storage_prefix(p.clone());
    }
    for k in &caps.allowed_keys {
        b = b.allow_key(k.clone());
    }
    for f in &manifest.config_schema {
        if let Some(d) = &f.default {
            b = b.config(f.name.clone(), d.clone());
        }
    }
    let host = b.build();

    let result = match manifest.runtime {
        RuntimeKind::Wasm => host.invoke(binary, &smoke.op, &smoke.path, smoke.data.clone()),
        RuntimeKind::Process => match invoke_process(&host, binary, smoke) {
            Ok(v) => Ok(v),
            Err(SmokeSkip::Unsupported(why)) => {
                r.push("smoke", Status::Skip, why);
                return;
            }
            Err(SmokeSkip::Failed(e)) => {
                r.push("smoke", Status::Fail, e);
                return;
            }
        },
    };
    match result {
        Err(e) => r.push("smoke", Status::Fail, e.to_string()),
        Ok(out) => match smoke.expect_status {
            Some(want) if out.status() != want => {
                r.push("smoke", Status::Fail, format!("expected status {want}, plugin returned {}", out.status()))
            }
            _ => r.push("smoke", Status::Pass, format!("`{}` completed with status {}", smoke.op, out.status())),
        },
    }
}

enum SmokeSkip {
    // Only constructed by the non-unix `invoke_process` stub.
    #[cfg_attr(unix, allow(dead_code))]
    Unsupported(String),
    Failed(String),
}

#[cfg(unix)]
fn invoke_process(
    host: &TestHost,
    binary: &[u8],
    smoke: &SmokeOpts,
) -> Result<bastion_plugin_testkit::TestInvocation, SmokeSkip> {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("bv-plugin-pack-smoke-{}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|e| SmokeSkip::Failed(format!("staging dir: {e}")))?;
    let exe = dir.join("plugin");
    std::fs::write(&exe, binary).map_err(|e| SmokeSkip::Failed(format!("staging binary: {e}")))?;
    std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| SmokeSkip::Failed(format!("chmod: {e}")))?;
    let out = host
        .invoke_process(&exe, &smoke.op, &smoke.path, smoke.data.clone())
        .map_err(|e| SmokeSkip::Failed(e.to_string()));
    let _ = std::fs::remove_dir_all(&dir);
    out
}

#[cfg(not(unix))]
fn invoke_process(_: &TestHost, _: &[u8], _: &SmokeOpts) -> Result<bastion_plugin_testkit::TestInvocation, SmokeSkip> {
    Err(SmokeSkip::Unsupported("process-plugin smoke invoke is unix-only".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{run, PackArgs};
    use std::path::PathBuf;

    const ECHO_WAT: &str = r#"
    (module
      (import "bv" "set_response" (func $set_response (param i32 i32)))
      (memory (export "memory") 1)
      (global $next (mut i32) (i32.const 1024))
      (func (export "bv_alloc") (param $len i32) (result i32)
        (local $ptr i32)
        (local.set $ptr (global.get $next))
        (global.set $next (i32.add (global.get $next) (local.get $len)))
        (local.get $ptr))
      (func (export "bv_run") (param $ptr i32) (param $len i32) (result i32)
        (call $set_response (local.get $ptr) (local.get $len))
        (i32.const 0))
    )"#;

    const MANIFEST: &str = r#"
name = "echo"
version = "0.1.0"
plugin_type = "secret"
runtime = "wasm"
abi_version = "1.0"
sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
size = 0
description = "echo fixture"

[capabilities]
log_emit = true
"#;

    const SURFACE_MANIFEST: &str = r#"
name = "echo"
version = "0.1.0"
plugin_type = "secret"
runtime = "wasm"
abi_version = "1.0"
sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
size = 0
description = "echo fixture"

[capabilities]
log_emit = true

[surface]
schema_version = 1
sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
size = 0
"#;

    const SURFACE: &str = r#"{
      "schema_version": 1,
      "title": "Echo",
      "menus": [{
        "id": "echo.main",
        "label": "Echo",
        "section": "secrets",
        "route": "/plugin/echo/main"
      }],
      "pages": [{
        "route": "/plugin/echo/main",
        "title": "Echo",
        "components": []
      }]
    }"#;

    fn tempdir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("bv-pack-bt-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn pack(tag: &str, seed_hex: Option<&str>) -> Vec<u8> {
        let dir = tempdir(tag);
        std::fs::write(dir.join("plugin.toml"), MANIFEST).unwrap();
        // The testkit's `Module::new` accepts WebAssembly text, so the
        // fixture bundle can embed the WAT as its binary.
        std::fs::write(dir.join("plugin.wasm"), ECHO_WAT).unwrap();
        run(PackArgs {
            manifest: dir.join("plugin.toml"),
            binary: dir.join("plugin.wasm"),
            out: Some(dir.join("plugin.bvplugin")),
            signing_seed_hex: seed_hex.map(str::to_string),
            signing_seed_file: None,
            signing_key_name: seed_hex.map(|_| "acme".to_string()),
        })
        .unwrap();
        std::fs::read(dir.join("plugin.bvplugin")).unwrap()
    }

    fn pack_surface(tag: &str, seed_hex: Option<&str>) -> Vec<u8> {
        let dir = tempdir(tag);
        std::fs::write(dir.join("plugin.toml"), SURFACE_MANIFEST).unwrap();
        std::fs::write(dir.join("surface.json"), SURFACE).unwrap();
        std::fs::write(dir.join("plugin.wasm"), ECHO_WAT).unwrap();
        run(PackArgs {
            manifest: dir.join("plugin.toml"),
            binary: dir.join("plugin.wasm"),
            out: Some(dir.join("plugin.bvplugin")),
            signing_seed_hex: seed_hex.map(str::to_string),
            signing_seed_file: None,
            signing_key_name: seed_hex.map(|_| "acme".to_string()),
        })
        .unwrap();
        std::fs::read(dir.join("plugin.bvplugin")).unwrap()
    }

    fn status_of<'a>(r: &'a Report, name: &str) -> &'a Check {
        r.checks.iter().find(|c| c.name == name).unwrap_or_else(|| panic!("no check {name}"))
    }

    #[test]
    fn healthy_unsigned_bundle_passes_and_smoke_runs_the_module() {
        let bundle = pack("ok", None);
        let r = check_bundle(&bundle, None, &SmokeOpts::default());
        assert!(!r.failed(), "{r:?}");
        assert_eq!(status_of(&r, "smoke").status, Status::Pass);
        assert_eq!(status_of(&r, "binary-hash").status, Status::Pass);
        assert_eq!(status_of(&r, "signature").status, Status::Skip);
    }

    #[test]
    fn tampered_binary_fails_hash_check() {
        let mut bundle = pack("tamper", None);
        let last = bundle.len() - 1;
        bundle[last] ^= 0xff;
        let r = check_bundle(&bundle, None, &SmokeOpts::default());
        assert!(r.failed());
        assert_eq!(status_of(&r, "binary-hash").status, Status::Fail);
    }

    #[test]
    fn signed_surface_bundle_verifies_stamped_metadata_and_signature() {
        let provider = bv_crypto::MlDsa65Provider;
        let keypair = provider.generate_keypair().unwrap();
        let bundle = pack_surface("surface-signed", Some(&hex::encode(keypair.secret_seed())));

        let report = check_bundle(&bundle, Some(keypair.public_key()), &SmokeOpts::default());
        assert!(!report.failed(), "{report:?}");
        assert_eq!(status_of(&report, "surface").status, Status::Pass);
        assert_eq!(status_of(&report, "signature").status, Status::Pass);

        let parts = unpack(&bundle).unwrap();
        let manifest: PluginManifest = serde_json::from_slice(parts.manifest_json).unwrap();
        let surface_ref = manifest.surface.expect("surface reference");
        let surface = parts.surface_json.expect("embedded surface");
        assert_eq!(surface_ref.size, surface.len() as u64);
        assert_eq!(surface_ref.sha256, hex::encode(Sha256::digest(surface)));
    }

    #[test]
    fn tampered_surface_fails_its_hash_check() {
        let mut bundle = pack_surface("surface-tamper", None);
        let manifest_len = u32::from_le_bytes(bundle[8..12].try_into().unwrap()) as usize;
        let binary_len_start = LEGACY_HEADER_LEN + manifest_len;
        let binary_len = u32::from_le_bytes(
            bundle[binary_len_start..binary_len_start + 4]
                .try_into()
                .unwrap(),
        ) as usize;
        let surface_start = binary_len_start + 4 + binary_len + 4;
        bundle[surface_start] ^= 0x01;

        let report = check_bundle(&bundle, None, &SmokeOpts::default());
        assert!(report.failed());
        assert_eq!(status_of(&report, "surface").status, Status::Fail);
        assert_eq!(status_of(&report, "binary-hash").status, Status::Pass);
    }

    #[test]
    fn garbage_and_truncated_bundles_fail_at_container() {
        for bad in [&b""[..], b"NOPE0000000000", b"BVPL\x01\0\0\0\xff\xff\xff\xff"] {
            let r = check_bundle(bad, None, &SmokeOpts::default());
            assert!(r.failed());
            assert_eq!(r.checks.len(), 1);
            assert_eq!(r.checks[0].name, "container");
        }
    }

    #[test]
    fn expect_status_mismatch_fails_smoke() {
        let bundle = pack("status", None);
        let r = check_bundle(&bundle, None, &SmokeOpts { expect_status: Some(9), ..SmokeOpts::default() });
        assert_eq!(status_of(&r, "smoke").status, Status::Fail);
    }

    #[test]
    fn signature_verifies_with_right_key_and_fails_with_wrong_key() {
        let provider = bv_crypto::MlDsa65Provider;
        let kp = provider.generate_keypair().unwrap();
        let other = provider.generate_keypair().unwrap();
        let bundle = pack("sig", Some(&hex::encode(kp.secret_seed())));

        let none = check_bundle(&bundle, None, &SmokeOpts::default());
        assert_eq!(status_of(&none, "signature").status, Status::Skip);
        assert!(status_of(&none, "signature").detail.contains("NOT verified"));

        let ok = check_bundle(&bundle, Some(kp.public_key()), &SmokeOpts::default());
        assert_eq!(status_of(&ok, "signature").status, Status::Pass, "{ok:?}");

        let bad = check_bundle(&bundle, Some(other.public_key()), &SmokeOpts::default());
        assert_eq!(status_of(&bad, "signature").status, Status::Fail);
        assert!(bad.failed());
    }
}
