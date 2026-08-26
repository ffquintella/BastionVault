//! Askama template → the one static HTML page this server serves.
//!
//! The page is rendered **once, at startup**, and then handed out as a string.
//! Nothing about a request influences it, so there is no template evaluation
//! on the request path and no way for user input to reach the markup.
//!
//! CSS and the logo are inlined rather than served from a `/static/` route:
//! the route table in features/packaging-distribution-website.md § Design is
//! closed (`/`, `/manifest.json`, the artefact paths, `/healthz` — everything
//! else 404s), and inlining keeps it that way.
//!
//! Both assets are compiled in, so the binary renders a complete page with no
//! files beside it. Passing `--static-dir` *overrides* them, and an override
//! directory that does not contain both files is a hard startup error — a
//! misspelled `--static-dir` must not silently fall back to the built-in
//! branding and leave the operator wondering why their logo never appeared.

use std::fmt;
use std::path::{Path, PathBuf};

use askama::Template;
use base64::Engine as _;
use sha2::{Digest, Sha256};

use crate::manifest::{FileEntry, Platform, ValidatedManifest};

/// The brand assets that ship inside the binary. `deploy/downloads/static/`
/// is also copied into the container image as the editable reference copy an
/// operator starts from when they want their own branding.
const DEFAULT_STYLE: &str = include_str!("../../../deploy/downloads/static/style.css");
const DEFAULT_LOGO: &str = include_str!("../../../deploy/downloads/static/logo.svg");

/// The cosmetic platform-tab highlight. This is the *only* script on the page
/// and it is a compile-time constant, which is what lets the CSP pin it by
/// hash instead of opening the page up with `'unsafe-inline'`. The full file
/// list is already in the markup, so the page is complete without it.
const TAB_SCRIPT: &str = r#"(function(){var p=navigator.platform||"",u=navigator.userAgent||"",t=/Win/i.test(p)||/Windows/i.test(u)?"windows":/Mac/i.test(p)||/Mac OS X/i.test(u)?"macos":"linux",e=document.getElementById("tab-"+t);if(e){e.className="tab tab-current"}})();"#;

/// One row on the landing page.
pub struct Row {
    pub label: &'static str,
    pub arch: &'static str,
    pub name: String,
    pub href: String,
    pub size: String,
    pub sha256: String,
    pub signature_href: Option<String>,
    pub certificate_href: Option<String>,
}

/// One `<section>`: a platform and the artefacts for it.
pub struct Section {
    pub slug: &'static str,
    pub label: &'static str,
    pub rows: Vec<Row>,
}

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate<'a> {
    version: &'a str,
    released: &'a str,
    server_image: Option<&'a str>,
    sections: &'a [Section],
    /// The first artefact on the page, used in the copy-pasteable verify
    /// example so the operator's users see a command that actually works
    /// against this site rather than a `<placeholder>`.
    example: Option<&'a Row>,
    style: &'a str,
    script: &'a str,
    logo: &'a str,
}

/// The rendered page plus the Content-Security-Policy that pins its inline
/// `<style>` and `<script>` by hash.
#[derive(Debug)]
pub struct RenderedIndex {
    pub html: String,
    pub csp: String,
}

#[derive(Debug)]
pub enum RenderError {
    Asset { path: PathBuf, source: std::io::Error },
    Template(askama::Error),
}

impl fmt::Display for RenderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Asset { path, source } => write!(
                f,
                "cannot read brand asset {}: {source} \
                 (pass --static-dir, or mount one over the image's)",
                path.display()
            ),
            Self::Template(e) => write!(f, "cannot render the index page: {e}"),
        }
    }
}

impl std::error::Error for RenderError {}

/// Render the page. `static_dir` overrides the compiled-in brand assets.
pub fn render(
    validated: &ValidatedManifest,
    static_dir: Option<&Path>,
) -> Result<RenderedIndex, RenderError> {
    let (style, logo) = match static_dir {
        Some(dir) => (read_asset(dir, "style.css")?, read_asset(dir, "logo.svg")?),
        None => (DEFAULT_STYLE.to_string(), DEFAULT_LOGO.to_string()),
    };

    let sections = sections(validated);
    let example = sections.iter().flat_map(|s| s.rows.first()).next();

    let html = IndexTemplate {
        version: &validated.manifest.version,
        released: &validated.manifest.released,
        server_image: validated.manifest.server_image.as_deref(),
        sections: &sections,
        example,
        style: &style,
        script: TAB_SCRIPT,
        logo: &logo,
    }
    .render()
    .map_err(RenderError::Template)?;

    let csp = format!(
        "default-src 'none'; style-src '{}'; script-src '{}'; \
         base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        csp_hash(&style),
        csp_hash(TAB_SCRIPT),
    );

    Ok(RenderedIndex { html, csp })
}

fn read_asset(dir: &Path, name: &str) -> Result<String, RenderError> {
    let path = dir.join(name);
    std::fs::read_to_string(&path).map_err(|source| RenderError::Asset { path, source })
}

/// `sha256-<base64>`, the CSP source expression body for an inline block.
fn csp_hash(body: &str) -> String {
    let digest = Sha256::digest(body.as_bytes());
    format!(
        "sha256-{}",
        base64::engine::general_purpose::STANDARD.encode(digest)
    )
}

/// Group the manifest's files into the page's three sections, preserving the
/// manifest's order within each one so the operator controls the listing.
pub fn sections(validated: &ValidatedManifest) -> Vec<Section> {
    let m = &validated.manifest;
    let version_dir = m.version_dir();
    Platform::ALL
        .iter()
        .map(|&platform| Section {
            slug: platform.slug(),
            label: platform.label(),
            rows: m
                .files
                .iter()
                .filter(|f| f.platform == platform)
                .map(|f| row(&version_dir, f))
                .collect(),
        })
        .filter(|s| !s.rows.is_empty())
        .collect()
}

fn row(version_dir: &str, f: &FileEntry) -> Row {
    Row {
        label: f.kind.label(),
        arch: f.arch.label(),
        name: f.name.clone(),
        href: format!("/{version_dir}/{}", f.name),
        size: human_size(f.size),
        sha256: f.sha256.clone(),
        signature_href: f.cosign_signature.as_deref().map(|p| format!("/{p}")),
        certificate_href: f.cosign_certificate.as_deref().map(|p| format!("/{p}")),
    }
}

/// Binary units, one decimal place. Installers are tens to hundreds of MiB;
/// showing the raw byte count is accurate and useless.
fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{load_and_validate, Arch, Kind};
    use std::fs;

    /// Every (platform, kind, arch) combination the page has to cope with.
    fn every_kind() -> Vec<(Platform, Kind, Arch)> {
        vec![
            (Platform::Linux, Kind::GuiDeb, Arch::Amd64),
            (Platform::Linux, Kind::CliDeb, Arch::Arm64),
            (Platform::Linux, Kind::GuiRpm, Arch::X86_64),
            (Platform::Linux, Kind::CliRpm, Arch::Aarch64),
            (Platform::Macos, Kind::GuiPkg, Arch::Arm64),
            (Platform::Macos, Kind::CliPkg, Arch::Amd64),
            (Platform::Windows, Kind::GuiMsi, Arch::Amd64),
            (Platform::Windows, Kind::CliMsi, Arch::Arm64),
        ]
    }

    fn kind_slug(k: Kind) -> &'static str {
        match k {
            Kind::GuiDeb => "gui-deb",
            Kind::GuiRpm => "gui-rpm",
            Kind::GuiPkg => "gui-pkg",
            Kind::GuiMsi => "gui-msi",
            Kind::CliDeb => "cli-deb",
            Kind::CliRpm => "cli-rpm",
            Kind::CliPkg => "cli-pkg",
            Kind::CliMsi => "cli-msi",
        }
    }

    fn arch_slug(a: Arch) -> &'static str {
        match a {
            Arch::Amd64 => "amd64",
            Arch::Arm64 => "arm64",
            Arch::X86_64 => "x86_64",
            Arch::Aarch64 => "aarch64",
        }
    }

    fn ext(k: Kind) -> &'static str {
        match k {
            Kind::GuiDeb | Kind::CliDeb => "deb",
            Kind::GuiRpm | Kind::CliRpm => "rpm",
            Kind::GuiPkg | Kind::CliPkg => "pkg",
            Kind::GuiMsi | Kind::CliMsi => "msi",
        }
    }

    fn artefact_name(k: Kind, a: Arch) -> String {
        format!("{}-{}-0.4.0.{}", kind_slug(k), arch_slug(a), ext(k))
    }

    /// A root holding one artefact (plus signature) for every combination in
    /// [`every_kind`].
    fn full_matrix_root() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("v0.4.0")).expect("mkdir");
        let mut entries = Vec::new();
        for (p, k, a) in every_kind() {
            let name = artefact_name(k, a);
            let body = name.as_bytes().to_vec();
            fs::write(dir.path().join("v0.4.0").join(&name), &body).expect("write");
            fs::write(
                dir.path().join("v0.4.0").join(format!("{name}.sig")),
                b"signature",
            )
            .expect("write sig");
            entries.push(format!(
                r#"{{"platform":"{}","arch":"{}","kind":"{}","name":"{name}","size":{},
                    "sha256":"{}","cosign_signature":"v0.4.0/{name}.sig"}}"#,
                p.slug(),
                arch_slug(a),
                kind_slug(k),
                body.len(),
                crate::manifest::hex_lower(&Sha256::digest(&body)),
            ));
        }
        fs::write(
            dir.path().join("manifest.json"),
            format!(
                r#"{{"version":"0.4.0","released":"2026-06-01",
                    "server_image":"ghcr.io/ffquintella/bastionvault:v0.4.0",
                    "files":[{}]}}"#,
                entries.join(",")
            ),
        )
        .expect("write manifest");
        dir
    }

    #[test]
    fn renders_every_platform_kind_and_arch() {
        let dir = full_matrix_root();
        let validated = load_and_validate(dir.path(), false).expect("valid");
        let page = render(&validated, None).expect("render");

        for (p, k, a) in every_kind() {
            let name = artefact_name(k, a);
            assert!(page.html.contains(&name), "missing {name}");
            assert!(
                page.html.contains(&format!("href=\"/v0.4.0/{name}\"")),
                "missing download link for {name}"
            );
            assert!(
                page.html.contains(&format!("href=\"/v0.4.0/{name}.sig\"")),
                "missing signature link for {name}"
            );
            assert!(page.html.contains(k.label()), "missing label for {k:?}");
            assert!(page.html.contains(a.label()), "missing arch for {a:?}");
            assert!(
                page.html.contains(&format!("id=\"{}\"", p.slug())),
                "missing section for {p:?}"
            );
        }
    }

    #[test]
    fn renders_the_hash_from_the_manifest_verbatim() {
        let dir = full_matrix_root();
        let validated = load_and_validate(dir.path(), false).expect("valid");
        let page = render(&validated, None).expect("render");
        for f in &validated.manifest.files {
            assert!(
                page.html.contains(&f.sha256),
                "sha256 for {} not on the page",
                f.name
            );
        }
    }

    #[test]
    fn omits_a_platform_with_no_artefacts() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("v0.4.0")).expect("mkdir");
        fs::write(dir.path().join("v0.4.0/only.deb"), b"only").expect("write");
        fs::write(
            dir.path().join("manifest.json"),
            format!(
                r#"{{"version":"0.4.0","released":"d","files":[
                    {{"platform":"linux","arch":"amd64","kind":"cli-deb","name":"only.deb",
                      "size":4,"sha256":"{}"}}]}}"#,
                crate::manifest::hex_lower(&Sha256::digest(b"only"))
            ),
        )
        .expect("write");
        let validated = load_and_validate(dir.path(), false).expect("valid");
        let page = render(&validated, None).expect("render");
        assert!(page.html.contains("id=\"linux\""));
        assert!(!page.html.contains("id=\"macos\""));
        assert!(!page.html.contains("id=\"windows\""));
    }

    #[test]
    fn csp_pins_the_inline_blocks_by_hash_not_unsafe_inline() {
        let dir = full_matrix_root();
        let validated = load_and_validate(dir.path(), false).expect("valid");
        let page = render(&validated, None).expect("render");
        assert!(page.csp.contains("default-src 'none'"), "{}", page.csp);
        assert!(page.csp.contains("'sha256-"), "{}", page.csp);
        assert!(!page.csp.contains("unsafe-inline"), "{}", page.csp);
        assert!(page.csp.contains("frame-ancestors 'none'"), "{}", page.csp);
        // The script hash must be the hash of what actually shipped.
        assert!(page.csp.contains(&csp_hash(TAB_SCRIPT)), "{}", page.csp);
        assert!(page.html.contains(TAB_SCRIPT));
    }

    #[test]
    fn missing_brand_assets_are_a_named_error() {
        let dir = full_matrix_root();
        let validated = load_and_validate(dir.path(), false).expect("valid");
        let err = render(&validated, Some(Path::new("/nonexistent-static"))).expect_err("no assets");
        assert!(err.to_string().contains("style.css"), "{err}");
    }

    #[test]
    fn human_sizes() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(1024), "1.0 KiB");
        assert_eq!(human_size(41_234_567), "39.3 MiB");
    }
}
