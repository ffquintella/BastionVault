# BastionVault CLI — native packaging (deb / rpm / pkg / msi / nupkg)

`installers/cli/` carries the static assets and build scripts that the
CLI packages bundle alongside the `bvault` binary:

```
installers/cli/
├── README.md             (this file)
├── manpage/
│   └── bvault.1          # roff manpage shipped to */man/man1/
├── completions/
│   ├── bvault.bash       # bash completion
│   ├── _bvault           # zsh completion
│   └── bvault.fish       # fish completion
├── pkg/                  # macOS .pkg
│   ├── build-macos-pkg.sh    # pkgbuild + productbuild wrapper
│   └── distribution.xml      # productbuild distribution (templated)
├── msi/                  # Windows .msi
│   ├── bvault.wxs        # WiX 3.x project (CLI-only): Program Files + system PATH
│   └── License.rtf       # shown by the WixUI_Minimal license dialog (native WiX only)
└── nupkg/                # Windows Chocolatey .nupkg
    ├── bastionvault-cli.nuspec   # package metadata (version injected at pack time)
    ├── build-nupkg.py            # host-independent .nupkg assembler (no Chocolatey)
    └── tools/
        ├── LICENSE.txt
        └── VERIFICATION.txt      # bvault.exe is staged here at build time
```

The Cargo.toml `[package.metadata.deb]` and
`[package.metadata.generate-rpm]` blocks reference the manpage /
completion paths verbatim; cargo-deb / cargo-generate-rpm copy them into
the package without any pre-build step.

## Building locally

`make cli-packages` builds the right formats for the current host
(Linux → deb+rpm, macOS → pkg, Windows → msi+nupkg). `make
cli-packages-all` builds every format from one host — the Linux and
Windows amd64 binaries are cross-compiled in Docker via
[`cross`](https://github.com/cross-rs/cross), so a Mac or Linux box can
produce the whole set (macOS `.pkg` still needs a Mac for Apple's
`pkgbuild`).

### Linux (.deb / .rpm)

```sh
cargo install cargo-deb cargo-generate-rpm
# On a non-x86_64-Linux host, also: cargo install cross  (+ Docker running)
make linux-cli-packages
ls target/x86_64-unknown-linux-gnu/debian/       # *.deb
ls target/x86_64-unknown-linux-gnu/generate-rpm/ # *.rpm
```

### macOS (.pkg)

Runs on macOS only (Apple's `pkgbuild`/`productbuild`). Builds for the
host arch by default; pass `CLI_MAC_TARGET=` for the other arch.

```sh
make macos-cli-pkg                                     # host arch
make macos-cli-pkg CLI_MAC_TARGET=x86_64-apple-darwin  # Intel
ls target/pkg/            # bvault-<version>-darwin-<arch>.pkg
```

Set `INSTALLER_IDENTITY="Developer ID Installer: <team>"` to sign the
pkg locally; notarisation (`xcrun notarytool` + `stapler`) is a CI step.

### Windows (.msi / .nupkg)

Two build paths, auto-selected by host OS:

- **On Windows** — the classic path: WiX 3.x `candle`/`light` build the
  `.msi` (with the `WixUI_Minimal` license dialog) and `choco pack`
  builds the `.nupkg`. Needs the WiX 3.x toolset on PATH and Chocolatey.
- **On macOS / Linux (Docker)** — `cross` compiles `bvault.exe` for
  `x86_64-pc-windows-gnu` in a container, then [`wixl`
  (msitools)](https://gitlab.gnome.org/GNOME/msitools) links the `.msi`
  and `build-nupkg.py` assembles the `.nupkg`. No Windows runner, no
  Chocolatey. Needs `cross` + Docker + `wixl` (`brew install msitools`
  or `apt-get install msitools`) + Python 3.

```sh
make windows-cli-packages
ls target/msi/            # bvault-<version>-windows-x64.msi
ls target/nupkg/          # bastionvault-cli.<version>.nupkg
```

The `.msi` installs `bvault.exe` to `C:\Program Files\BastionVault CLI\`
and appends that directory to the system PATH (removed on uninstall).
The `wixl` path produces a silent-install MSI (no UI extension); the
license dialog is present only on the native-WiX build. The Chocolatey
package relies on choco's automatic exe shimming, so `bvault` is on PATH
with no install script.

## Current limitations

- The manpage and completions are hand-written stubs covering only the
  top-level subcommands. A follow-up will plug `clap_mangen` /
  `clap_complete` in so they're derived from the real CLI definition.
- No platform-native signing yet (GPG deb/rpm, Authenticode msi,
  notarised pkg) and no Cosign — that is Phase 4 of the client-installers
  spec, wired in CI where the signing secrets live.
- amd64 (x86_64) is the default. arm64 packages build by overriding the
  target triple (`CLI_LINUX_TARGET=`, `CLI_MAC_TARGET=`), but are not yet
  part of the default `make` targets.
