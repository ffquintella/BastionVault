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

**All four CLI installer formats build locally from a single host**
(`make cli-packages-all`). The Linux and Windows amd64 binaries are
cross-compiled in Docker via [`cross`](https://github.com/cross-rs/cross),
so a Mac or Linux workstation produces the whole set; the macOS `.pkg`
still needs a Mac for Apple's `pkgbuild`. Platform-native signing and the
CI matrix (Phase 4) remain open, as do the GUI installers.

- **Linux CLI packages (Phase 1, CLI side done).**
  `make linux-cli-packages` builds the `bastionvault` .deb (`cargo-deb`)
  and .rpm (`cargo-generate-rpm`) with the binary, manpage, and
  bash/zsh/fish completions from [installers/cli/](../installers/cli/).
  On a non-x86_64-Linux host the ELF is cross-built via `cross`. No CI
  matrix and no GPG signing yet.
- **macOS CLI .pkg (Phase 2, CLI side done 2026-07-10).**
  `make macos-cli-pkg` runs [`installers/cli/pkg/build-macos-pkg.sh`](../installers/cli/pkg/build-macos-pkg.sh):
  `pkgbuild` lays out `/usr/local/bin/bvault`, the gzipped manpage, and
  the bash + zsh completions, then `productbuild` wraps it as a
  distribution `.pkg` (arch-guarded via
  [`distribution.xml`](../installers/cli/pkg/distribution.xml)). Builds
  for the host arch by default; `CLI_MAC_TARGET=` selects the other arch
  (a Mac cross-builds both natively). Unsigned unless `INSTALLER_IDENTITY`
  is set; notarisation is a CI step. macOS only.
- **Windows CLI packages (Phase 3, CLI side).** Two build paths,
  auto-selected by host OS:
  - **On Windows** — WiX 3.x `candle`/`light` build the .msi (with the
    `WixUI_Minimal` license dialog) from
    [installers/cli/msi/bvault.wxs](../installers/cli/msi/bvault.wxs), and
    `choco pack` builds the .nupkg from
    [installers/cli/nupkg/](../installers/cli/nupkg/).
  - **On macOS / Linux (Docker, wired 2026-07-10)** — `cross` compiles
    `bvault.exe` for `x86_64-pc-windows-gnu` in a container, then
    [`wixl` (msitools)](https://gitlab.gnome.org/GNOME/msitools) links the
    .msi (silent-install; the WixUI dialog is gated behind `WithUI=1` and
    omitted here) and
    [`build-nupkg.py`](../installers/cli/nupkg/build-nupkg.py) assembles
    the .nupkg — no Windows runner, no Chocolatey. The same `bvault.wxs`
    serves both toolchains.

  `make windows-cli-packages` builds both; `make cli-packages` dispatches
  per host OS. x64 only; no Authenticode signing yet. The .nupkg is an
  addition to the original plan (which listed only the .msi for Windows).
- **GUI installers are wired to Tauri's bundler** in
  [gui/src-tauri/tauri.conf.json](../gui/src-tauri/tauri.conf.json)
  (package metadata, icons, Linux `depends` + maintainer scripts, macOS
  `minimumSystemVersion`), with per-host `make` targets:
  `gui-linux-packages` (`.deb`+`.rpm`), `gui-windows-msi` (`.msi`), and
  `gui-macos-pkg` (Tauri `.app` wrapped into a `/Applications` `.pkg` by
  [build-gui-pkg.sh](../gui/src-tauri/installers/macos/build-gui-pkg.sh)).
  A Tauri GUI cannot be *cross-compiled* (the WebView runtime is
  platform-native: WebView2 / WebKitGTK / WebKit). The macOS GUI `.pkg` is
  exercised on a Mac. The **Linux `.deb`/`.rpm` build off-Linux inside an
  emulated `linux/amd64` Docker container**
  ([installers/linux/Dockerfile](../gui/src-tauri/installers/linux/Dockerfile))
  — slower than a native build, but no Linux host required. The Windows
  `.msi` still needs a Windows host (no equivalent emulated WebView2
  path); that is a CI concern.
- Platform-native signing (GPG deb/rpm, Authenticode msi, notarised pkg),
  Cosign, the `manifest.json` publish, and the CI matrix (Phase 4) remain
  open, as does the `bv://` deep-link handler (needs app-side support).

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
├── tauri.conf.json                   # bundle.{linux,macOS} bundler config
│                                     # (per-platform overrides inline, not
│                                     #  separate tauri.<os>.conf.json files)
└── installers/
    ├── linux/
    │   ├── postinst                  # desktop-db / MIME / icon-cache refresh
    │   ├── prerm
    │   └── README.md
    └── macos/
        ├── build-gui-pkg.sh          # wrap Tauri .app → /Applications .pkg
        ├── distribution.xml          # productbuild distribution definition
        └── README.md
    # windows/: GUI .msi uses Tauri's default WiX bundler; a custom
    # main.wxs (bv:// handler) is deferred with the deep-link feature.

installers/cli/
├── README.md
├── manpage/bvault.1                 # roff manpage (deb/rpm/pkg)
├── completions/                     # bash / zsh / fish (deb/rpm/pkg)
│   ├── bvault.bash
│   ├── _bvault
│   └── bvault.fish
│   # .deb / .rpm carry no dir of their own: cargo-deb +
│   # cargo-generate-rpm metadata lives in the root Cargo.toml.
├── pkg/                             # macOS .pkg
│   ├── build-macos-pkg.sh           # pkgbuild + productbuild wrapper
│   └── distribution.xml             # productbuild distribution (templated)
├── msi/                             # Windows .msi
│   ├── bvault.wxs                   # WiX 3.x project (CLI-only; wixl-compatible)
│   └── License.rtf
└── nupkg/                           # Windows Chocolatey .nupkg
    ├── bastionvault-cli.nuspec
    ├── build-nupkg.py               # host-independent OPC assembler
    └── tools/{LICENSE,VERIFICATION}.txt

.github/workflows/
└── client-installers.yml             # The 6-job matrix described above
```

## Implementation Scope

### Phase 1 — Linux Packages (deb + rpm), GUI + CLI, amd64 — **CLI done; GUI skeleton**

| File | Purpose |
|---|---|
| [`gui/src-tauri/installers/linux/postinst`](../gui/src-tauri/installers/linux/postinst) + [`prerm`](../gui/src-tauri/installers/linux/prerm) | XDG / MIME / icon-cache registration on install / removal. **Done.** |
| `gui/src-tauri/tauri.conf.json` `bundle.linux.{deb,rpm}` + `installers/linux/Dockerfile` | Wiring of the postinst/prerm + runtime `depends` into the Tauri bundler (documented Tauri 2.x `postInstallScript` / `preRemoveScript` keys), plus an **emulated-amd64 Docker builder** so the GUI `.deb`/`.rpm` build off-Linux. **Done 2026-07-10.** Tauri cannot cross-compile the GUI (WebKitGTK is a native build+runtime dep), so `make gui-linux-packages` builds natively on Linux and inside an emulated `linux/amd64` container ([`build-in-docker.sh`](../gui/src-tauri/installers/linux/build-in-docker.sh)) elsewhere. See `gui/src-tauri/installers/linux/README.md`. |
| Root [`Cargo.toml`](../Cargo.toml) `[package.metadata.deb]` + `[package.metadata.generate-rpm]` | CLI .deb / .rpm. **Done.** |
| [`installers/cli/manpage/bvault.1`](../installers/cli/manpage/bvault.1) + [`installers/cli/completions/`](../installers/cli/completions/) | Static manpage + bash/zsh/fish completion stubs. Phase-1 hand-written; a follow-up will plug `clap_mangen` / `clap_complete` for derived output. **Done.** |
| [`installers/cli/README.md`](../installers/cli/README.md) | How to build locally. **Done.** |
| `Makefile` `linux-cli-deb` / `linux-cli-rpm` / `linux-cli-packages` | Local builds via cargo-deb / cargo-generate-rpm. **Done.** |
| `.github/workflows/client-installers.yml` | Matrix entry: `ubuntu-22.04` / amd64. **Not yet GPG-signed.** **Deferred** until the GUI bundling lands so a single workflow covers both deliverables. |

Acceptance (CLI, met today): `cargo install cargo-deb cargo-generate-rpm`
followed by `make linux-cli-packages` produces a `target/debian/*.deb`
and a `target/generate-rpm/*.rpm` containing the `bvault` binary, the
manpage at `/usr/share/man/man1/bvault.1`, and the three completion
files. Acceptance (GUI): pending the first Linux-host `tauri build` pass.

### Phase 2 — macOS .pkg (GUI + CLI, x86_64 + arm64 + universal2)

| File | Purpose |
|---|---|
| `gui/src-tauri/tauri.conf.json` `bundle.macOS` | Tauri bundler config: `.app` target + `minimumSystemVersion` (signing identity is env-var driven at build time). **Done.** |
| [`gui/src-tauri/installers/macos/build-gui-pkg.sh`](../gui/src-tauri/installers/macos/build-gui-pkg.sh) + [`distribution.xml`](../gui/src-tauri/installers/macos/distribution.xml) | Wrap the Tauri `.app` into a `/Applications` `.pkg` (pkgbuild + productbuild). **Done — `make gui-macos-pkg`; unsigned unless `INSTALLER_IDENTITY` set.** |
| [`installers/cli/pkg/build-macos-pkg.sh`](../installers/cli/pkg/build-macos-pkg.sh) + [`distribution.xml`](../installers/cli/pkg/distribution.xml) | CLI .pkg builder (pkgbuild + productbuild). **Done (local build via `make macos-cli-pkg`; unsigned unless `INSTALLER_IDENTITY` set; host arch or `CLI_MAC_TARGET=`).** |
| `.github/workflows/client-installers.yml` (extension) | `macos-13` + `macos-14` matrix entries; `notarytool submit --wait`; `stapler staple`. |

Acceptance (CLI, met today): `make macos-cli-pkg` produces a
distribution `.pkg`; `pkgutil --expand` / `--payload-files` confirm the
payload lays down `/usr/local/bin/bvault`, the gzipped manpage, and the
bash/zsh completions, with the distribution's `hostArchitectures` guard
matching the built arch. Acceptance (GUI + signing): a notarised,
stapled `.pkg` for both GUI and CLI installs cleanly via `installer -pkg
… -target /` and via Munki; Gatekeeper accepts the install on a fresh
macOS account — pending CI signing identity.

### Phase 3 — Windows .msi (GUI + CLI, x64 + arm64)

| File | Purpose |
|---|---|
| `gui/src-tauri/tauri.conf.json` `bundle.windows` | GUI `.msi` via Tauri's default WiX bundler (Start Menu shortcut auto-created). **Wired — `make gui-windows-msi` on a Windows host; verify + Authenticode-sign in CI.** |
| `gui/src-tauri/installers/windows/main.wxs` (`bv://` URL handler) | **Deferred** — a custom WiX fragment for the `bv://` scheme is only useful once the GUI handles deep-link URLs (Tauri deep-link plugin + app-side handling), a separate feature. Left off the default build to avoid shipping an unverified, non-functional registry entry. |
| [`installers/cli/msi/{bvault.wxs,License.rtf}`](../installers/cli/msi/bvault.wxs) | CLI WiX 3.x project; PATH entry; per-machine install. The WixUI license dialog is gated behind `WithUI=1` so the same .wxs builds under native WiX (`candle`/`light`) and under `wixl` (msitools). **Done (unsigned, x64 only).** |
| [`installers/cli/nupkg/`](../installers/cli/nupkg/) | Chocolatey .nupkg. `build-nupkg.py` assembles the OPC package on any host (no Chocolatey); native Windows still uses `choco pack`. Addition to the original plan. **Done.** |
| `Makefile` `windows-cli-msi` / `windows-cli-nupkg` / `windows-cli-packages` / `cli-packages` / `cli-packages-all` | Host-aware: native WiX/choco on Windows, else Docker cross (`x86_64-pc-windows-gnu`) + `wixl` + `build-nupkg.py`. **Done.** |
| `.github/workflows/client-installers.yml` (extension) | `windows-2022` + arm64 matrix entries; Authenticode signing via the EV cert configured as a CI secret. |

Acceptance (build, met today): `make windows-cli-packages` produces
`bvault-<version>-windows-x64.msi` and
`bastionvault-cli.<version>.nupkg` — on Windows via WiX/choco, and on
macOS/Linux via the Docker cross + `wixl` + `build-nupkg.py` path.
Acceptance (install + signing): both MSIs pass Windows SmartScreen on a
fresh install of Windows 11 and uninstall removes every file and registry
entry — pending Authenticode signing in CI.

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
