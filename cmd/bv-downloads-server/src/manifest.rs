//! `manifest.json` — parsing and validation.
//!
//! The manifest is the only source of truth for what this server will hand
//! out. Nothing on disk is servable unless the manifest names it, so parsing
//! here is also the security boundary: every path that ends up in the router's
//! allow-list has been through [`Manifest::validate`].
//!
//! Failure is always fatal and always names the offending entry. The container
//! does not guess, does not skip a bad entry, and does not fall back to
//! listing the directory — see features/packaging-distribution-website.md
//! § Security Considerations.

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Component, Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest, Sha256};

/// Target operating system. Closed enum: an unknown value is a parse error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    Linux,
    Macos,
    Windows,
}

impl Platform {
    /// Stable order the landing page presents the sections in.
    pub const ALL: [Platform; 3] = [Platform::Linux, Platform::Macos, Platform::Windows];

    pub fn label(self) -> &'static str {
        match self {
            Platform::Linux => "Linux",
            Platform::Macos => "macOS",
            Platform::Windows => "Windows",
        }
    }

    /// URL fragment / DOM id for the section.
    pub fn slug(self) -> &'static str {
        match self {
            Platform::Linux => "linux",
            Platform::Macos => "macos",
            Platform::Windows => "windows",
        }
    }
}

/// Target CPU architecture.
///
/// Both common spellings of each architecture are accepted because the four
/// packaging toolchains disagree: `cargo-deb` writes `amd64`, `rpmbuild`
/// writes `x86_64`, Apple writes `arm64`, and `uname -m` on Linux writes
/// `aarch64`. The landing page normalises them to one spelling for display.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Arch {
    Amd64,
    Arm64,
    #[serde(rename = "x86_64")]
    X86_64,
    #[serde(rename = "aarch64")]
    Aarch64,
}

impl Arch {
    /// The single spelling the index page presents.
    pub fn label(self) -> &'static str {
        match self {
            Arch::Amd64 | Arch::X86_64 => "x86-64",
            Arch::Arm64 | Arch::Aarch64 => "arm64",
        }
    }
}

/// What the artefact is: which half of the product, in which package format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    GuiDeb,
    GuiRpm,
    GuiPkg,
    GuiMsi,
    CliDeb,
    CliRpm,
    CliPkg,
    CliMsi,
}

impl Kind {
    /// Human-readable "who is this for / what do I do with it" label.
    pub fn label(self) -> &'static str {
        match self {
            Kind::GuiDeb => "Desktop GUI — Debian / Ubuntu package",
            Kind::GuiRpm => "Desktop GUI — RHEL / Fedora package",
            Kind::GuiPkg => "Desktop GUI — macOS installer",
            Kind::GuiMsi => "Desktop GUI — Windows installer",
            Kind::CliDeb => "bvault CLI — Debian / Ubuntu package",
            Kind::CliRpm => "bvault CLI — RHEL / Fedora package",
            Kind::CliPkg => "bvault CLI — macOS installer",
            Kind::CliMsi => "bvault CLI — Windows installer",
        }
    }

    /// MIME type the file handler pins for this artefact kind.
    pub fn mime(self) -> &'static str {
        match self {
            Kind::GuiDeb | Kind::CliDeb => mime::DEB,
            Kind::GuiRpm | Kind::CliRpm => mime::RPM,
            Kind::GuiPkg | Kind::CliPkg => mime::PKG,
            Kind::GuiMsi | Kind::CliMsi => mime::MSI,
        }
    }
}

/// The MIME types this server will ever emit. Kept in one place so the set is
/// auditable: there is no content sniffing and no `mime_guess` table, and
/// every response also carries `X-Content-Type-Options: nosniff`.
pub mod mime {
    pub const DEB: &str = "application/vnd.debian.binary-package";
    pub const RPM: &str = "application/x-rpm";
    pub const PKG: &str = "application/x-newton-compatible-pkg";
    pub const MSI: &str = "application/x-msi";
    pub const SIG: &str = "application/octet-stream";
    pub const PEM: &str = "application/x-pem-file";
    pub const JSON: &str = "application/json";
    pub const HTML: &str = "text/html; charset=utf-8";
    pub const TEXT: &str = "text/plain; charset=utf-8";
}

/// One downloadable artefact.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileEntry {
    pub platform: Platform,
    pub arch: Arch,
    pub kind: Kind,
    /// Bare file name, resolved under `<root>/v<version>/`.
    pub name: String,
    pub size: u64,
    /// Lowercase hex SHA-256 of the artefact.
    pub sha256: String,
    /// Root-relative path of the Cosign signature, e.g. `v0.4.0/x.deb.sig`.
    #[serde(default)]
    pub cosign_signature: Option<String>,
    /// Root-relative path of the Cosign certificate, e.g. `v0.4.0/x.deb.pem`.
    #[serde(default)]
    pub cosign_certificate: Option<String>,
}

/// The parsed `manifest.json`.
///
/// `deny_unknown_fields` is deliberate and has a forward-compatibility cost
/// worth stating: a manifest carrying a field a future phase adds will not
/// load in a container built today. That is the intended direction. The
/// manifest is versioned alongside the artefacts it describes, the closed
/// enums below already mean a new `kind` breaks an old reader, and the
/// alternative — silently ignoring a field whose whole purpose might be to
/// convey a signature or a deprecation — is exactly the quiet failure this
/// server is built to avoid. When a field is added, old containers must fail
/// loudly and be upgraded.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Release version *without* the leading `v`, e.g. `0.4.0`.
    pub version: String,
    /// Release date, rendered verbatim. Free-form so an operator cutting an
    /// internal rebuild is not forced into a date format we then have to
    /// re-validate.
    pub released: String,
    /// Optional: the matching server image reference, shown on the page.
    #[serde(default)]
    pub server_image: Option<String>,
    pub files: Vec<FileEntry>,
}

/// Everything that can go wrong between "the operator mounted a volume" and
/// "the server is ready to listen". Every variant names the offending entry —
/// an operator reading one line of container log must know which file to fix.
#[derive(Debug)]
pub enum ManifestError {
    Read { path: PathBuf, source: std::io::Error },
    Parse { path: PathBuf, source: serde_json::Error },
    EmptyVersion,
    BadVersion { version: String },
    BadName { name: String },
    BadRelativePath { entry: String, path: String },
    BadDigest { name: String, sha256: String },
    Missing { name: String, path: PathBuf },
    NotAFile { name: String, path: PathBuf },
    Escapes { name: String, path: PathBuf },
    DigestMismatch { name: String, expected: String, actual: String },
    DuplicateUrl { url: String },
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { path, source } => {
                write!(f, "cannot read manifest at {}: {source}", path.display())
            }
            Self::Parse { path, source } => {
                write!(f, "malformed manifest at {}: {source}", path.display())
            }
            Self::EmptyVersion => write!(f, "manifest `version` is empty"),
            Self::BadVersion { version } => write!(
                f,
                "manifest `version` {version:?} is not a bare version string \
                 (allowed characters: A-Z a-z 0-9 . _ + -)"
            ),
            Self::BadName { name } => write!(
                f,
                "file `name` {name:?} is not a bare file name \
                 (allowed characters: A-Z a-z 0-9 . _ + -)"
            ),
            Self::BadRelativePath { entry, path } => write!(
                f,
                "file {entry:?}: path {path:?} is not a safe root-relative path \
                 (no leading `/`, no `..`, no backslashes)"
            ),
            Self::BadDigest { name, sha256 } => write!(
                f,
                "file {name:?}: sha256 {sha256:?} is not 64 lowercase hex characters"
            ),
            Self::Missing { name, path } => write!(
                f,
                "file {name:?} is listed in the manifest but missing from disk at {}",
                path.display()
            ),
            Self::NotAFile { name, path } => write!(
                f,
                "file {name:?} at {} is not a regular file (directories and symlinks are refused)",
                path.display()
            ),
            Self::Escapes { name, path } => write!(
                f,
                "file {name:?} at {} resolves outside the served root",
                path.display()
            ),
            Self::DigestMismatch { name, expected, actual } => write!(
                f,
                "file {name:?}: manifest sha256 {expected} does not match the bytes on disk ({actual})"
            ),
            Self::DuplicateUrl { url } => {
                write!(f, "two manifest entries resolve to the same URL {url:?}")
            }
        }
    }
}

impl std::error::Error for ManifestError {}

/// One entry in the router's allow-list: a URL path this server will serve,
/// and the already-validated absolute file it maps to.
#[derive(Debug, Clone)]
pub struct Asset {
    /// URL path *without* the leading slash, e.g. `v0.4.0/bvault_0.4.0_amd64.deb`.
    pub url: String,
    /// Absolute, symlink-free path inside the served root.
    pub path: PathBuf,
    pub mime: &'static str,
    pub len: u64,
}

/// A manifest that has been checked against the filesystem.
#[derive(Debug)]
pub struct ValidatedManifest {
    pub manifest: Manifest,
    /// The raw bytes, served verbatim at `/manifest.json`. We echo the operator's
    /// file rather than re-serialising ours so a consumer that verifies a detached
    /// signature over the manifest sees the exact bytes that were signed.
    pub raw: Vec<u8>,
    pub assets: Vec<Asset>,
    /// Non-fatal problems worth a log line at startup.
    pub warnings: Vec<String>,
    /// Canonical served root.
    pub root: PathBuf,
}

impl Manifest {
    /// Parse `<root>/manifest.json`.
    pub fn load(root: &Path) -> Result<(Manifest, Vec<u8>), ManifestError> {
        let path = root.join("manifest.json");
        let raw = std::fs::read(&path).map_err(|source| ManifestError::Read {
            path: path.clone(),
            source,
        })?;
        let manifest = serde_json::from_slice(&raw).map_err(|source| ManifestError::Parse {
            path: path.clone(),
            source,
        })?;
        Ok((manifest, raw))
    }

    /// The `vX.Y.Z` directory the artefacts live in.
    pub fn version_dir(&self) -> String {
        format!("v{}", self.version)
    }
}

/// Parse and validate in one step. `verify_hashes` re-reads every artefact and
/// compares its SHA-256 against the manifest; it is off by default because a
/// full release directory is gigabytes and most operators would rather the
/// container start in a second.
pub fn load_and_validate(
    root: &Path,
    verify_hashes: bool,
) -> Result<ValidatedManifest, ManifestError> {
    let (manifest, raw) = Manifest::load(root)?;
    validate(manifest, raw, root, verify_hashes)
}

fn validate(
    manifest: Manifest,
    raw: Vec<u8>,
    root: &Path,
    verify_hashes: bool,
) -> Result<ValidatedManifest, ManifestError> {
    if manifest.version.trim().is_empty() {
        return Err(ManifestError::EmptyVersion);
    }
    if !is_safe_component(&manifest.version) {
        return Err(ManifestError::BadVersion {
            version: manifest.version.clone(),
        });
    }

    // Canonicalising the root once is what makes the escape check below
    // meaningful: every artefact path is canonicalised too, so a symlink
    // pointing anywhere outside this prefix is caught here rather than at
    // request time.
    let root = root.canonicalize().map_err(|source| ManifestError::Read {
        path: root.to_path_buf(),
        source,
    })?;

    let mut assets: Vec<Asset> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut warnings: Vec<String> = Vec::new();
    let version_dir = manifest.version_dir();

    for entry in &manifest.files {
        if !is_safe_component(&entry.name) {
            return Err(ManifestError::BadName {
                name: entry.name.clone(),
            });
        }
        if !is_hex64(&entry.sha256) {
            return Err(ManifestError::BadDigest {
                name: entry.name.clone(),
                sha256: entry.sha256.clone(),
            });
        }

        let url = format!("{version_dir}/{}", entry.name);
        let asset = resolve(&root, &url, &entry.name, entry.kind.mime(), verify_hashes, Some(&entry.sha256))?;
        if entry.size != asset.len {
            warnings.push(format!(
                "file {:?}: manifest size {} does not match the {} bytes on disk; \
                 the page shows the manifest value",
                entry.name, entry.size, asset.len
            ));
        }
        push_unique(&mut assets, &mut seen, asset)?;

        for (label, rel, mime) in [
            ("cosign_signature", entry.cosign_signature.as_deref(), mime::SIG),
            ("cosign_certificate", entry.cosign_certificate.as_deref(), mime::PEM),
        ] {
            let Some(rel) = rel else { continue };
            if !is_safe_relative(rel) {
                return Err(ManifestError::BadRelativePath {
                    entry: format!("{} ({label})", entry.name),
                    path: rel.to_string(),
                });
            }
            let asset = resolve(&root, rel, rel, mime, false, None)?;
            // A signature and a certificate may legitimately be shared between
            // entries, so a duplicate here is not an error — just skip it.
            if seen.insert(asset.url.clone()) {
                assets.push(asset);
            }
        }
    }

    warnings.extend(unlisted_files(&root, &version_dir, &seen));

    Ok(ValidatedManifest {
        manifest,
        raw,
        assets,
        warnings,
        root,
    })
}

fn push_unique(
    assets: &mut Vec<Asset>,
    seen: &mut BTreeSet<String>,
    asset: Asset,
) -> Result<(), ManifestError> {
    if !seen.insert(asset.url.clone()) {
        return Err(ManifestError::DuplicateUrl { url: asset.url });
    }
    assets.push(asset);
    Ok(())
}

/// Turn a root-relative URL path into a validated [`Asset`].
///
/// `name` is only used for error messages. The four checks are, in order:
/// the file exists, it is a regular file (not a directory and not a symlink),
/// it resolves inside the root, and — optionally — its bytes hash to what the
/// manifest claims.
fn resolve(
    root: &Path,
    url: &str,
    name: &str,
    mime: &'static str,
    verify_hash: bool,
    expected_sha256: Option<&str>,
) -> Result<Asset, ManifestError> {
    let joined = root.join(url);

    // `symlink_metadata` does not follow the final component, so a symlinked
    // artefact is refused outright rather than silently followed. Intermediate
    // components are covered by the canonical-prefix check below.
    let meta = std::fs::symlink_metadata(&joined).map_err(|_| ManifestError::Missing {
        name: name.to_string(),
        path: joined.clone(),
    })?;
    if !meta.is_file() {
        return Err(ManifestError::NotAFile {
            name: name.to_string(),
            path: joined,
        });
    }

    let canonical = joined.canonicalize().map_err(|_| ManifestError::Missing {
        name: name.to_string(),
        path: joined.clone(),
    })?;
    if !canonical.starts_with(root) {
        return Err(ManifestError::Escapes {
            name: name.to_string(),
            path: canonical,
        });
    }

    if verify_hash {
        if let Some(expected) = expected_sha256 {
            let actual = sha256_file(&canonical).map_err(|source| ManifestError::Read {
                path: canonical.clone(),
                source,
            })?;
            if actual != expected {
                return Err(ManifestError::DigestMismatch {
                    name: name.to_string(),
                    expected: expected.to_string(),
                    actual,
                });
            }
        }
    }

    Ok(Asset {
        url: url.to_string(),
        path: canonical,
        mime,
        len: meta.len(),
    })
}

/// Streaming SHA-256 so `--verify-hashes` does not pull a 400 MB installer
/// into memory.
pub fn sha256_file(path: &Path) -> std::io::Result<String> {
    use std::io::Read;

    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex_lower(&hasher.finalize()))
}

pub fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit((b >> 4) as u32, 16).expect("nibble is < 16"));
        out.push(char::from_digit((b & 0x0f) as u32, 16).expect("nibble is < 16"));
    }
    out
}

/// Files sitting in the release directory that the manifest does not mention.
/// Not fatal — an operator staging the next release in the same volume is a
/// normal thing to do — but they are invisible on the page, and silently
/// invisible is how "why can't my users download the msi?" happens.
fn unlisted_files(root: &Path, version_dir: &str, listed: &BTreeSet<String>) -> Vec<String> {
    let dir = root.join(version_dir);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        let url = format!("{version_dir}/{name}");
        if !listed.contains(&url) {
            out.push(format!(
                "{url} is present on disk but not in the manifest; it will not be served"
            ));
        }
    }
    out.sort();
    out
}

/// 64 lowercase hex characters, the only shape a SHA-256 may take here.
/// Uppercase is rejected on purpose: the page renders the value verbatim next
/// to a `sha256sum` command whose output is lowercase, and two spellings of
/// the same digest is exactly the kind of thing a user stops checking.
fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A single path component that is safe to put in a URL verbatim.
///
/// Deliberately stricter than "no `..`": the file handler matches request
/// paths byte-for-byte against this allow-list and does **not** percent-decode,
/// so restricting names to characters no browser will encode is what makes
/// that sound. It also rules out `.` and `..` for free.
fn is_safe_component(s: &str) -> bool {
    !s.is_empty()
        && s != "."
        && s != ".."
        && s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-'))
}

/// A root-relative path: one or more safe components joined by `/`.
fn is_safe_relative(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with('/')
        && !s.contains('\\')
        && Path::new(s)
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
        && s.split('/').all(is_safe_component)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Build a root with `manifest.json` plus the named files, each holding
    /// its own name as content so the hashes are deterministic.
    fn fixture(files: &[&str]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("v0.4.0")).expect("mkdir");
        for f in files {
            fs::write(dir.path().join(f), f.as_bytes()).expect("write");
        }
        dir
    }

    fn digest_of(content: &str) -> String {
        hex_lower(&Sha256::digest(content.as_bytes()))
    }

    fn write_manifest(root: &Path, json: &str) {
        fs::write(root.join("manifest.json"), json).expect("write manifest");
    }

    fn good_manifest() -> String {
        format!(
            r#"{{
  "version": "0.4.0",
  "released": "2026-06-01",
  "server_image": "ghcr.io/ffquintella/bastionvault:v0.4.0",
  "files": [
    {{
      "platform": "linux",
      "arch": "amd64",
      "kind": "cli-deb",
      "name": "bvault_0.4.0_amd64.deb",
      "size": {},
      "sha256": "{}",
      "cosign_signature": "v0.4.0/bvault_0.4.0_amd64.deb.sig"
    }}
  ]
}}"#,
            "v0.4.0/bvault_0.4.0_amd64.deb".len(),
            digest_of("v0.4.0/bvault_0.4.0_amd64.deb"),
        )
    }

    #[test]
    fn accepts_a_well_formed_manifest() {
        let dir = fixture(&[
            "v0.4.0/bvault_0.4.0_amd64.deb",
            "v0.4.0/bvault_0.4.0_amd64.deb.sig",
        ]);
        write_manifest(dir.path(), &good_manifest());

        let v = load_and_validate(dir.path(), true).expect("valid manifest");
        assert_eq!(v.manifest.version, "0.4.0");
        assert_eq!(v.manifest.files.len(), 1);
        let urls: Vec<_> = v.assets.iter().map(|a| a.url.as_str()).collect();
        assert_eq!(
            urls,
            vec![
                "v0.4.0/bvault_0.4.0_amd64.deb",
                "v0.4.0/bvault_0.4.0_amd64.deb.sig",
            ]
        );
        assert_eq!(v.assets[0].mime, mime::DEB);
        assert_eq!(v.assets[1].mime, mime::SIG);
        assert!(v.warnings.is_empty(), "unexpected warnings: {:?}", v.warnings);
    }

    #[test]
    fn rejects_a_manifest_without_a_version() {
        let dir = fixture(&[]);
        write_manifest(
            dir.path(),
            r#"{"released": "2026-06-01", "files": []}"#,
        );
        let err = load_and_validate(dir.path(), false).expect_err("missing version");
        assert!(
            matches!(err, ManifestError::Parse { .. }),
            "expected a parse error, got {err}"
        );
        assert!(err.to_string().contains("version"), "{err}");
    }

    #[test]
    fn rejects_an_unknown_kind() {
        let dir = fixture(&["v0.4.0/x.deb"]);
        write_manifest(
            dir.path(),
            &format!(
                r#"{{"version":"0.4.0","released":"d","files":[
                    {{"platform":"linux","arch":"amd64","kind":"gui-snap",
                      "name":"x.deb","size":1,"sha256":"{}"}}]}}"#,
                digest_of("v0.4.0/x.deb")
            ),
        );
        let err = load_and_validate(dir.path(), false).expect_err("unknown kind");
        let msg = err.to_string();
        assert!(msg.contains("gui-snap"), "{msg}");
        // One line, so a container log tail is enough to fix it.
        assert_eq!(msg.lines().count(), 1, "{msg}");
    }

    #[test]
    fn rejects_an_unknown_platform() {
        let dir = fixture(&["v0.4.0/x.deb"]);
        write_manifest(
            dir.path(),
            &format!(
                r#"{{"version":"0.4.0","released":"d","files":[
                    {{"platform":"freebsd","arch":"amd64","kind":"cli-deb",
                      "name":"x.deb","size":1,"sha256":"{}"}}]}}"#,
                digest_of("v0.4.0/x.deb")
            ),
        );
        let err = load_and_validate(dir.path(), false).expect_err("unknown platform");
        assert!(err.to_string().contains("freebsd"), "{err}");
    }

    #[test]
    fn accepts_both_spellings_of_each_arch() {
        for (spelling, expected) in [
            ("amd64", "x86-64"),
            ("x86_64", "x86-64"),
            ("arm64", "arm64"),
            ("aarch64", "arm64"),
        ] {
            let dir = fixture(&["v0.4.0/x.deb"]);
            write_manifest(
                dir.path(),
                &format!(
                    r#"{{"version":"0.4.0","released":"d","files":[
                        {{"platform":"linux","arch":"{spelling}","kind":"cli-deb",
                          "name":"x.deb","size":13,"sha256":"{}"}}]}}"#,
                    digest_of("v0.4.0/x.deb")
                ),
            );
            let v = load_and_validate(dir.path(), false)
                .unwrap_or_else(|e| panic!("arch {spelling}: {e}"));
            assert_eq!(v.manifest.files[0].arch.label(), expected);
        }
    }

    #[test]
    fn rejects_an_entry_whose_file_is_missing() {
        let dir = fixture(&[]);
        write_manifest(
            dir.path(),
            &format!(
                r#"{{"version":"0.4.0","released":"d","files":[
                    {{"platform":"linux","arch":"amd64","kind":"cli-deb",
                      "name":"gone.deb","size":1,"sha256":"{}"}}]}}"#,
                digest_of("nothing")
            ),
        );
        let err = load_and_validate(dir.path(), false).expect_err("missing file");
        let msg = err.to_string();
        assert!(msg.contains("gone.deb"), "{msg}");
        assert!(msg.contains("missing from disk"), "{msg}");
    }

    #[test]
    fn rejects_an_entry_whose_signature_is_missing() {
        let dir = fixture(&["v0.4.0/bvault_0.4.0_amd64.deb"]);
        write_manifest(dir.path(), &good_manifest());
        let err = load_and_validate(dir.path(), false).expect_err("missing signature");
        assert!(err.to_string().contains(".deb.sig"), "{err}");
    }

    #[test]
    fn rejects_a_traversing_name() {
        let dir = fixture(&["v0.4.0/x.deb"]);
        write_manifest(
            dir.path(),
            &format!(
                r#"{{"version":"0.4.0","released":"d","files":[
                    {{"platform":"linux","arch":"amd64","kind":"cli-deb",
                      "name":"../../etc/passwd","size":1,"sha256":"{}"}}]}}"#,
                digest_of("x")
            ),
        );
        let err = load_and_validate(dir.path(), false).expect_err("traversal");
        assert!(matches!(err, ManifestError::BadName { .. }), "{err}");
    }

    #[test]
    fn rejects_a_traversing_signature_path() {
        let dir = fixture(&["v0.4.0/x.deb"]);
        write_manifest(
            dir.path(),
            &format!(
                r#"{{"version":"0.4.0","released":"d","files":[
                    {{"platform":"linux","arch":"amd64","kind":"cli-deb",
                      "name":"x.deb","size":13,"sha256":"{}",
                      "cosign_signature":"../outside.sig"}}]}}"#,
                digest_of("v0.4.0/x.deb")
            ),
        );
        let err = load_and_validate(dir.path(), false).expect_err("traversal");
        assert!(matches!(err, ManifestError::BadRelativePath { .. }), "{err}");
    }

    #[test]
    #[cfg(unix)]
    fn rejects_a_symlinked_artefact_pointing_outside_the_root() {
        let outside = tempfile::tempdir().expect("tempdir");
        fs::write(outside.path().join("secret"), b"not yours").expect("write");

        let dir = fixture(&[]);
        std::os::unix::fs::symlink(
            outside.path().join("secret"),
            dir.path().join("v0.4.0").join("x.deb"),
        )
        .expect("symlink");
        write_manifest(
            dir.path(),
            &format!(
                r#"{{"version":"0.4.0","released":"d","files":[
                    {{"platform":"linux","arch":"amd64","kind":"cli-deb",
                      "name":"x.deb","size":9,"sha256":"{}"}}]}}"#,
                digest_of("not yours")
            ),
        );
        let err = load_and_validate(dir.path(), false).expect_err("symlink");
        assert!(
            matches!(err, ManifestError::NotAFile { .. }),
            "expected a regular-file refusal, got {err}"
        );
    }

    #[test]
    fn rejects_a_digest_that_does_not_match_the_bytes() {
        let dir = fixture(&["v0.4.0/x.deb"]);
        write_manifest(
            dir.path(),
            &format!(
                r#"{{"version":"0.4.0","released":"d","files":[
                    {{"platform":"linux","arch":"amd64","kind":"cli-deb",
                      "name":"x.deb","size":13,"sha256":"{}"}}]}}"#,
                digest_of("something else")
            ),
        );
        // Off by default the mismatch is invisible...
        assert!(load_and_validate(dir.path(), false).is_ok());
        // ...and --verify-hashes is what turns it into a refusal to start.
        let err = load_and_validate(dir.path(), true).expect_err("digest mismatch");
        assert!(matches!(err, ManifestError::DigestMismatch { .. }), "{err}");
    }

    #[test]
    fn rejects_a_malformed_digest() {
        let dir = fixture(&["v0.4.0/x.deb"]);
        write_manifest(
            dir.path(),
            r#"{"version":"0.4.0","released":"d","files":[
                {"platform":"linux","arch":"amd64","kind":"cli-deb",
                 "name":"x.deb","size":13,"sha256":"NOTHEX"}]}"#,
        );
        let err = load_and_validate(dir.path(), false).expect_err("bad digest");
        assert!(matches!(err, ManifestError::BadDigest { .. }), "{err}");
    }

    #[test]
    fn warns_about_files_on_disk_that_the_manifest_omits() {
        let dir = fixture(&[
            "v0.4.0/bvault_0.4.0_amd64.deb",
            "v0.4.0/bvault_0.4.0_amd64.deb.sig",
            "v0.4.0/forgotten.rpm",
        ]);
        write_manifest(dir.path(), &good_manifest());
        let v = load_and_validate(dir.path(), false).expect("valid");
        assert!(
            v.warnings.iter().any(|w| w.contains("forgotten.rpm")),
            "{:?}",
            v.warnings
        );
        assert!(
            !v.assets.iter().any(|a| a.url.contains("forgotten")),
            "an unlisted file must not become servable"
        );
    }

    #[test]
    fn warns_about_a_size_that_disagrees_with_disk() {
        let dir = fixture(&["v0.4.0/x.deb"]);
        write_manifest(
            dir.path(),
            &format!(
                r#"{{"version":"0.4.0","released":"d","files":[
                    {{"platform":"linux","arch":"amd64","kind":"cli-deb",
                      "name":"x.deb","size":999,"sha256":"{}"}}]}}"#,
                digest_of("v0.4.0/x.deb")
            ),
        );
        let v = load_and_validate(dir.path(), false).expect("valid");
        assert!(v.warnings.iter().any(|w| w.contains("999")), "{:?}", v.warnings);
    }

    #[test]
    fn rejects_unknown_manifest_fields() {
        let dir = fixture(&[]);
        write_manifest(
            dir.path(),
            r#"{"version":"0.4.0","released":"d","files":[],"upload_url":"http://x/"}"#,
        );
        let err = load_and_validate(dir.path(), false).expect_err("unknown field");
        assert!(err.to_string().contains("upload_url"), "{err}");
    }

    #[test]
    fn safe_component_rules() {
        assert!(is_safe_component("bvault_0.4.0_amd64.deb"));
        assert!(is_safe_component("BastionVault-0.4.0-arm64.pkg"));
        assert!(!is_safe_component(""));
        assert!(!is_safe_component("."));
        assert!(!is_safe_component(".."));
        assert!(!is_safe_component("a/b"));
        assert!(!is_safe_component("a b"));
        assert!(!is_safe_component("a%2e%2e"));
        assert!(!is_safe_component("a\\b"));
    }

    #[test]
    fn safe_relative_rules() {
        assert!(is_safe_relative("v0.4.0/x.deb.sig"));
        assert!(!is_safe_relative("/etc/passwd"));
        assert!(!is_safe_relative("../x"));
        assert!(!is_safe_relative("v0.4.0/../../x"));
        assert!(!is_safe_relative("v0.4.0//x"));
        assert!(!is_safe_relative("v0.4.0\\x"));
    }
}
