# Feature: Native Client Installers (deb / rpm / pkg / msi)

## Summary

Build and ship **platform-native installers** for the two client-side
artefacts that end users actually install on their workstations:

- **`bastionvault-gui`** — the Tauri desktop application (existing GUI
  crate at [gui/src-tauri/](../gui/src-tauri)).
- **`bvault`** — the existing combined CLI / server binary
  ([bin/bastion_vault.rs](../bin/bastion_vault.rs)). Users install it for
  its `bvault login`, `bvault read`, `bvault write`, `bvault operator`,
  and the rest of the client subcommands; the server subcommand is
  irrelevant in a workstation install but the binary is the same.

Per-platform deliverables, per release:

| Platform | Format | GUI artefact | CLI artefact |
|---|---|---|---|
| Debian / Ubuntu (amd64, arm64) | `.deb` | `bastionvault-gui_X.Y.Z_<arch>.deb` | `bvault_X.Y.Z_<arch>.deb` |
| RHEL / Fedora / openSUSE (x86_64, aarch64) | `.rpm` | `bastionvault-gui-X.Y.Z-1.<arch>.rpm` | `bvault-X.Y.Z-1.<arch>.rpm` |
| macOS (x86_64, arm64, universal2) | `.pkg` | `BastionVault-X.Y.Z-<arch>.pkg` | `bvault-X.Y.Z-darwin-<arch>.pkg` |
| Windows (x64, arm64) | `.msi` | `BastionVault-X.Y.Z-<arch>.msi` | `bvault-X.Y.Z-windows-<arch>.msi` |

Distribution of these artefacts to end users is the job of two sibling
features:

- The **Client Distribution Website**
  ([features/packaging-distribution-website.md](packaging-distribution-website.md))
  surfaces them inside the operator's network.
- **GitHub Releases** publishes the same set publicly.

Container distribution of the **server** is in
[features/packaging-podman-server.md](packaging-podman-server.md) and is
deliberately separate.

## Motivation

- **Desktop users will not run `cargo install`.** A secrets-manager
  client that requires a Rust toolchain to install is a non-starter in
  every operations team that is not already a Rust shop.
- **IT departments need a managed install path.** Group Policy (Windows),
  MDM profiles (macOS), and apt / dnf / zypper (Linux) all expect a
  native package they can deploy. We meet them where they are.
- **Tauri's bundler already produces three of the four formats** (`.deb`,
  `.rpm`, `.dmg`/`.app`, `.msi`). The marginal work is wiring it into CI
  for our exact target matrix and adding the macOS `.pkg` and the CLI
  side, which Tauri's bundler does not own.
- **Signed installers are non-negotiable** for a security product. Each
  installer carries its platform-native signature (Authenticode for MSI,
  notarised pkg, signed deb / rpm) and ships alongside a Cosign signature
  + SHA-256 hash for cross-verification.

## Current State

- **No native installers exist.** No `cargo deb`, no `cargo
  generate-rpm`, no productbuild script, no WiX project, no GitHub
  Actions matrix that produces these on tag.
- The Tauri GUI crate's `bundle.targets` is `"all"` in
  [gui/src-tauri/tauri.conf.json](../gui/src-tauri/tauri.conf.json), but
  no CI runs `tauri build` against the cross-platform matrix and no
  signing identity is configured.
- The `bvault` binary builds cleanly on all four platforms, but is not
  packaged anywhere — operators copy it out of `target/release/`.
- The Packaging & Distribution row in [roadmap.md](../roadmap.md) currently
  reads `Todo`.

## Design

### Build matrix

| OS image (CI) | Targets produced |
|---|---|
| `ubuntu-22.04` | `x86_64-unknown-linux-gnu` → GUI .deb, CLI .deb, GUI .rpm, CLI .rpm |
| `ubuntu-22.04` (cross) | `aarch64-unknown-linux-gnu` → GUI .deb, CLI .deb, GUI .rpm, CLI .rpm |
| `macos-13` | `x86_64-apple-darwin` → GUI .pkg, CLI .pkg |
| `macos-14` | `aarch64-apple-darwin` → GUI .pkg, CLI .pkg |
| `windows-2022` | `x86_64-pc-windows-msvc` → GUI .msi, CLI .msi |
| `windows-2022` (cross) | `aarch64-pc-windows-msvc` → GUI .msi, CLI .msi |

A second pass on macOS produces a **universal2** GUI .pkg by lipo-ing the
two arch-specific `.app`s before wrapping them in a `productbuild`
package. The CLI ships one `.pkg` per arch, no universal — splitting CLI
binaries by arch keeps the install size small.

### GUI installers — Tauri's bundler

The GUI crate is a Tauri app; Tauri's bundler is the right tool. Each
platform-specific config lives next to
[gui/src-tauri/tauri.conf.json](../gui/src-tauri/tauri.conf.json):

- **Linux .deb / .rpm** — Tauri 2's bundler delegates to `cargo-deb` and
  `cargo-generate-rpm`. We pin the Tauri version that has the post-install
  scriptlet hooks we need (desktop-file-utils integration, MIME
  registration for `bv://` URLs).
- **macOS .pkg** — Tauri produces the `.app`; we wrap it in a `.pkg`
  with `productbuild --component … --identifier com.bastionvault.gui
  --version X.Y.Z --sign "Developer ID Installer: <team>"` so it can be
  delivered through Munki / Jamf / MDM. The notarised, stapled `.pkg` is
  the published artefact; the raw `.app` and `.dmg` are not shipped.
- **Windows .msi** — Tauri's WiX 3.x integration. We extend the default
  `wix.template.wxs` with our service-registration block (only used by
  the optional CLI install), Start Menu shortcuts, and a custom action
  that registers the `bv://` URL handler.

WiX 4 is **not** used. Tauri's MSI path is on WiX 3.x; switching is a
separate maintenance decision and not in scope here.

### CLI installers — direct packaging

The CLI is a single binary plus a shell-completion file and a manpage.
Tauri does not own this; we pack it ourselves:

- **`.deb`**: `cargo-deb` against the root crate, `[package.metadata.deb]`
  in `Cargo.toml` carrying the package name, dependencies (only
  `ca-certificates`), priority, and the post-install scriptlet that
  registers shell completions.
- **`.rpm`**: `cargo-generate-rpm` against the root crate,
  `[package.metadata.generate-rpm]` carrying the same metadata in RPM
  shape.
- **`.pkg`**: a small `pkgbuild` + `productbuild` pair. The `pkgbuild`
  step lays out `/usr/local/bin/bvault`, `/usr/local/share/man/man1/…`,
  and the bash / zsh / fish completions. `productbuild` signs and wraps.
- **`.msi`**: a small WiX 3.x project (separate from the GUI's) that
  installs `bvault.exe` to `C:\Program Files\BastionVault CLI\` and adds
  the directory to the system `PATH` via the standard WiX `Environment`
  element.

The CLI installer **does not** install or enable a server systemd unit /
launchd plist / Windows service. Server installs are a separate operator
decision and run through the container image, not the workstation
package.

### Signing identities

| Platform | Signing approach |
|---|---|
| `.deb` | `dpkg-sig` with the project's GPG release key. Operators add the project's apt repo signing key once. |
| `.rpm` | `rpm --addsign` with the same GPG release key. |
| `.pkg` | Apple Developer ID Installer cert, then `xcrun notarytool submit --wait` and `xcrun stapler staple`. |
| `.msi` | EV Authenticode certificate (cloud HSM). |

Each artefact is *additionally* signed with **Cosign keyless** for
cross-platform integrity verification. The Cosign signature lives next
to the installer (`<file>.sig` + `<file>.pem`) and is what the Client
Distribution Website surfaces alongside each download.

### apt / dnf repositories

Beyond the per-file `.deb` / `.rpm` artefacts on the website, we publish
two long-lived repositories operators can subscribe to:

- `apt.bastionvault.io` — `deb https://apt.bastionvault.io stable main`
- `rpm.bastionvault.io` — standard `dnf` baseurl + GPG key

These are static-site repositories generated by `aptly` / `createrepo_c`
from the same artefacts the release publishes; the apt / dnf indexes are
re-signed on every release. The repos themselves are hosted in the same
way as the downloads container — a static volume served behind a reverse
proxy. This is a stretch deliverable (Phase 5) and may be deferred to a
later release if EV cert procurement slips.

### File layout the installers produce

**Linux (GUI):**

```
/usr/bin/bastionvault-gui                       # the Tauri binary
/usr/share/applications/bastionvault.desktop    # XDG desktop entry
/usr/share/icons/hicolor/256x256/apps/bastionvault.png
/usr/share/mime/packages/bastionvault.xml       # bv:// URL handler
```

**Linux (CLI):**

```
/usr/bin/bvault
/usr/share/man/man1/bvault.1.gz
/usr/share/bash-completion/completions/bvault
/usr/share/zsh/site-functions/_bvault
/usr/share/fish/vendor_completions.d/bvault.fish
```

**macOS (GUI):**

```
/Applications/BastionVault.app/...
```

**macOS (CLI):**

```
/usr/local/bin/bvault
/usr/local/share/man/man1/bvault.1.gz
/usr/local/etc/bash_completion.d/bvault
```

**Windows (GUI):**

```
C:\Program Files\BastionVault\bastionvault-gui.exe
Start Menu shortcut, bv:// URL handler
```

**Windows (CLI):**

```
C:\Program Files\BastionVault CLI\bvault.exe
PATH entry for the install dir
```

### Release flow

```
[git tag vX.Y.Z]
       │
       ▼
.github/workflows/client-installers.yml
   │
   ├─ matrix: 6 jobs (3 OS × per-arch where needed)
   │     each builds GUI + CLI installers for its platform
   │
   ├─ macOS jobs notarise + staple
   ├─ Windows jobs Authenticode-sign
   ├─ Linux jobs GPG-sign deb + rpm
   │
   ├─ all jobs upload artefacts to a single GitHub release
   ├─ a final "publish" job:
   │     - cosign-signs each artefact (keyless)
   │     - generates manifest.json (the shape the downloads
   │       container expects, see packaging-distribution-website.md)
   │     - uploads manifest.json to the release
   │     - syncs the release into apt.bastionvault.io /
   │       rpm.bastionvault.io (Phase 5)
   │
   └─ a final "downloads-image" job (cross-feature):
         rebuilds the downloads container image with the new
         release directory baked into its sample-data layer
```

### Module Architecture

```
gui/src-tauri/
├── tauri.conf.json                   # already exists; extend bundler config
├── tauri.linux.conf.json             # per-platform overrides (deb/rpm)
├── tauri.macos.conf.json             # per-platform overrides (pkg signing)
├── tauri.windows.conf.json           # per-platform overrides (msi/WiX)
└── installers/
    ├── linux/
    │   ├── postinst                  # desktop-file-utils + MIME
    │   └── prerm
    ├── macos/
    │   ├── distribution.xml          # productbuild distribution definition
    │   └── scripts/                  # preinstall / postinstall
    └── windows/
        └── main.wxs                  # WiX 3.x project (extends Tauri default)

installers/cli/
├── README.md
├── deb/
│   └── (cargo-deb metadata in root Cargo.toml)
├── rpm/
│   └── (cargo-generate-rpm metadata in root Cargo.toml)
├── pkg/
│   ├── pkgbuild.sh
│   ├── productbuild.sh
│   └── distribution.xml
└── msi/
    ├── bvault.wxs                    # WiX 3.x project (CLI-only)
    └── License.rtf

.github/workflows/
└── client-installers.yml             # The 6-job matrix described above
```

## Implementation Scope

### Phase 1 — Linux Packages (deb + rpm), GUI + CLI, amd64

| File | Purpose |
|---|---|
| `gui/src-tauri/tauri.linux.conf.json` | Tauri bundler config: deb + rpm, post-install scripts, .desktop entry, icon paths. |
| `gui/src-tauri/installers/linux/postinst`, `prerm` | XDG / MIME registration. |
| Root `Cargo.toml` `[package.metadata.deb]` + `[package.metadata.generate-rpm]` | CLI .deb / .rpm. Manpage + completions emitted at build time by a `build.rs` extension. |
| `installers/cli/README.md` | How to build locally. |
| `.github/workflows/client-installers.yml` | Matrix entry: `ubuntu-22.04` / amd64. **Not yet GPG-signed.** |

Acceptance: `apt install ./bastionvault-gui_X.Y.Z_amd64.deb` and `dnf
install ./bastionvault-gui-X.Y.Z-1.x86_64.rpm` both put a working GUI on
the target distro; the CLI counterparts install a working `bvault`
binary with completions.

### Phase 2 — macOS .pkg (GUI + CLI, x86_64 + arm64 + universal2)

| File | Purpose |
|---|---|
| `gui/src-tauri/tauri.macos.conf.json` | Tauri bundler config: .app target, signing identity (env-var driven). |
| `gui/src-tauri/installers/macos/distribution.xml` + scripts | productbuild wrap. |
| `installers/cli/pkg/{pkgbuild,productbuild}.sh` + `distribution.xml` | CLI .pkg builder. |
| `.github/workflows/client-installers.yml` (extension) | `macos-13` + `macos-14` matrix entries; `notarytool submit --wait`; `stapler staple`. |

Acceptance: a notarised, stapled `.pkg` for both GUI and CLI installs
cleanly via `installer -pkg … -target /` and via Munki; Gatekeeper
accepts the install on a fresh macOS account.

### Phase 3 — Windows .msi (GUI + CLI, x64 + arm64)

| File | Purpose |
|---|---|
| `gui/src-tauri/tauri.windows.conf.json` | Tauri bundler config: WiX 3.x template path, signing identity (env-var driven). |
| `gui/src-tauri/installers/windows/main.wxs` | WiX project that extends Tauri's default with Start Menu shortcuts and the `bv://` URL handler. |
| `installers/cli/msi/{bvault.wxs,License.rtf}` | CLI WiX project; PATH entry; per-machine install. |
| `.github/workflows/client-installers.yml` (extension) | `windows-2022` + arm64 matrix entries; Authenticode signing via the EV cert configured as a CI secret. |

Acceptance: both MSIs pass Windows SmartScreen on a fresh install of
Windows 11; uninstall removes every file and registry entry.

### Phase 4 — Cosign + manifest.json + GitHub Release publish

| File | Purpose |
|---|---|
| `.github/workflows/client-installers.yml` (extension) | Final job: cosign-sign every artefact; generate `manifest.json` matching the shape in [features/packaging-distribution-website.md](packaging-distribution-website.md); upload everything to the GitHub release. |
| `tools/build-manifest/` | Small Rust helper that takes a directory of artefacts and emits a valid `manifest.json`. |
| `docs/docs/operations/installing-clients.md` | End-user docs: per-platform install + verify steps. |

Acceptance: a freshly tagged release on GitHub has all 24 expected
artefacts (4 platforms × 2 arches × 2 components, with universal2 GUI
.pkg adding one more) plus their `.sig` / `.pem` and a single
`manifest.json` that the downloads container starts cleanly against.

### Phase 5 — apt / dnf Repositories (Stretch)

| File | Purpose |
|---|---|
| `deploy/apt-repo/` | `aptly` config + sync job. |
| `deploy/rpm-repo/` | `createrepo_c` config + sync job. |
| `.github/workflows/repos.yml` | Re-index + re-sign repos on every release; sync to the static-site host. |

Acceptance: `apt-get install bvault` and `dnf install bvault` work after
adding the project's repo + signing key.

### Not In Scope

- **Windows MSIX / Microsoft Store distribution.** MSI is the
  enterprise-deployable format; MSIX has Store-specific signing
  requirements that we are not committing to.
- **macOS App Store distribution.** The GUI uses APIs (system keychain
  integration, in-process server mode) the App Store sandbox forbids.
- **Snap, Flatpak, AppImage.** Distro-native packaging is the supported
  path on Linux; alternative formats can be community-maintained from
  the same source.
- **Auto-update of installed clients.** The downloads container's GUI
  hookup ([features/packaging-distribution-website.md](packaging-distribution-website.md)
  Phase 4) surfaces a "new version available" banner that **links out**
  to the download page. The user re-runs the installer manually.
- **An installer that installs the server.** The server ships as a
  container image
  ([features/packaging-podman-server.md](packaging-podman-server.md)),
  not as a workstation MSI. The `bvault` binary in the CLI installer
  *can* run the server subcommand, but the installer does not register
  it as a service or open firewall rules.
- **Cross-distro Linux RPM matrix** (per-distro builds for Fedora /
  RHEL / openSUSE / Mageia variants). One `.rpm` per arch is
  sufficient; we test against current Fedora and RHEL 9 only.

## Testing Requirements

### Unit / Lint

- `cargo deb --no-build --output …` produces a `.deb` whose
  `dpkg-deb -I` metadata matches the expected name, version, and
  dependencies.
- `cargo generate-rpm` produces an `.rpm` whose `rpm -qpi` metadata
  matches.
- `lintian` on the produced `.deb` returns clean (no E:, no W: above the
  documented allowlist).
- `rpmlint` on the produced `.rpm` returns clean.
- WiX projects compile under WiX 3.x without warnings.
- `pkgutil --check-signature` confirms the `.pkg` is signed and notarised.
- `signtool verify /pa /v` confirms each `.msi` is Authenticode-signed.

### Integration Tests

- **Linux (Phase 1)**: in CI, `apt install ./*.deb` on a clean
  `debian:12` container; launch GUI under Xvfb, exercise the GUI's
  smoke-test route. Repeat with `dnf install ./*.rpm` on `fedora:40`.
  Run `bvault status` from the CLI install.
- **macOS (Phase 2)**: `installer -pkg … -target /` on a clean GitHub
  Actions macOS runner; launch GUI; run `bvault status`.
- **Windows (Phase 3)**: `msiexec /i …` on a clean GitHub Actions
  Windows runner; launch GUI via `start`; run `bvault.exe status`.
- **Cross-verify (Phase 4)**: `cosign verify-blob` against every
  artefact in the published release; `sha256sum -c` against the hashes
  in `manifest.json`.

### Cucumber BDD Scenarios

- IT admin downloads the `.msi` from the operator's downloads container,
  pushes it via Group Policy, end-user logs in to a workstation, GUI is
  present and CLI is on `PATH`.
- macOS user downloads the `.pkg`, double-clicks, Gatekeeper accepts the
  notarised installer, GUI appears in `/Applications/`.
- Linux ops adds the apt repo and key, runs `apt install bvault`,
  receives a working CLI without ever visiting GitHub.
- A user downloads an installer over an untrusted network, runs
  `cosign verify-blob`, the verification fails (because the
  attacker-modified file's signature does not match), the user does not
  proceed.

### Negative Tests

- Tampered `.deb` (one byte flipped in the binary): `dpkg-sig --verify`
  fails; `cosign verify-blob` fails. The user-facing docs explicitly
  warn that either failing is grounds to discard the file.
- Tampered `.msi`: `signtool verify /pa` fails; SmartScreen blocks.
- Tampered `.pkg`: `pkgutil --check-signature` fails; Gatekeeper blocks.
- An installer without a Cosign signature beside it: the operator's
  downloads page shows the file but flags the missing signature; the
  end-user docs flag this as "do not install."

## Security Considerations

- **Every shipped artefact carries two independent signatures**:
  platform-native (Authenticode / notarised pkg / GPG-signed deb /
  rpm) and Cosign keyless. Either one failing is grounds to refuse the
  file. The operator docs and end-user docs both spell this out.
- **No unsigned release artefact ever leaves CI.** The publish job
  refuses to push if any artefact lacks a signature.
- **Signing keys live in CI secrets, not in the repo**: Apple Developer
  ID + notarisation API key, EV Authenticode HSM credentials, and the
  GPG release key (subkey, not the master key). The master GPG key lives
  on a hardware token held by a release manager; subkey rotation is
  documented in `docs/docs/operations/release-key-rotation.md`.
- **Reproducible builds where possible**: the CLI .deb and .rpm targets
  are fully reproducible (same input, same output bit-for-bit). The
  Tauri bundles are not yet reproducible (WebView2 / WebKitGTK
  embedding adds non-deterministic bytes); we document this rather than
  pretending otherwise.
- **No telemetry, no auto-update, no phone-home** baked into any
  installer. The GUI's "check for updates" hookup is opt-in, polls a
  manifest the operator hosts, and links out instead of auto-installing.
- **Per-machine installs only on Windows.** Per-user MSIs hide a
  secrets-manager binary inside `%LOCALAPPDATA%`, where a malicious
  process with the same UID can swap it. Per-machine + Authenticode +
  PATH means a privileged install we can verify.
- **macOS: no kernel extensions, no privileged helper**. The CLI .pkg
  installs to `/usr/local/bin/`, nothing more. The GUI .pkg installs to
  `/Applications/`, nothing more.
- **Linux: no setuid, no setgid, no capabilities** on any installed
  binary. `bvault` does its own privilege-handling for the optional
  server subcommand; the installer does not bestow privileges.
- **The `bv://` URL handler is registered conservatively**: only a
  documented allow-list of action verbs is honoured; the rest are
  ignored. Specifically, no verb may invoke a vault write operation
  without an explicit user confirmation in the GUI.
- **Auto-update is explicitly out of scope**: silently updating a
  desktop secrets-manager client is too easy to weaponise. The
  downloads container surfaces a banner; the user re-runs the
  installer.
- **apt / dnf repos use the project's GPG release key only**, not a
  per-package ad-hoc signature. Operators add one key once and trust
  the chain from there.

## Tracking

When phases land, update [CHANGELOG.md](../CHANGELOG.md),
[roadmap.md](../roadmap.md) (Packaging & Distribution → Native Client
Installers row: `Todo` → `In Progress` (Phase 1) → `Done` (Phase 4 or
Phase 5)), and this file's "Current State" / phase markers.
