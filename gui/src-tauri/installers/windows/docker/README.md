# BastionVault GUI — Windows x64 installer from Docker (no Windows host)

`make gui-windows-nsis` cross-compiles the GUI to `x86_64-pc-windows-msvc`
inside a Linux container and wraps it into a Windows installer, without a
Windows machine or a Windows VM anywhere in the loop.

```sh
XWIN_ACCEPT_LICENSE=1 make gui-windows-nsis
ls target/windows-docker/     # BastionVault_<version>_x64-setup.exe
```

## This produces an .exe, not an .msi

Tauri v2 compiles its **WiX/MSI bundler in only on Windows hosts** — it
drives WiX's `candle.exe` / `light.exe`, which are Windows binaries. Its
**NSIS bundler has no such gate**: it resolves `makensis` from `PATH`, and
`makensis` builds Windows installers fine on Linux. That asymmetry is the
whole reason this path exists.

So there are two off-Windows options, and they are not interchangeable:

| | `make gui-windows-nsis` (here) | `make gui-windows-msi` (../README.md) |
|---|---|---|
| Artifact | `…_x64-setup.exe` (NSIS) | `…_x64_en-US.msi` (WiX) |
| Needs | Docker | macOS + Tart + a Win11 ARM64 ISO |
| Windows involved | none | a real Windows 11 ARM64 VM |
| Speed | native, no emulation | native virtualization |

Both install to the same place with Start-menu and Add/Remove Programs
entries; MSI matters when a deployment tool (Intune, GPO software install,
`msiexec /qn` fleet rollout) requires that format specifically.

## How it works

- **`cargo-xwin`** downloads Microsoft's Visual C++ CRT and Windows SDK
  headers/libs, then builds with `clang-cl` + `lld-link` + `llvm-lib`
  against them. This is what makes an MSVC-ABI Windows binary buildable
  from Linux.
- **`makensis`** (Debian's `nsis`) compiles the installer script Tauri
  generates. Tauri fetches its own NSIS plugin (`nsis_tauri_utils.dll`)
  and language files at build time, so the container needs network access.
- **The container runs at the host's native arch.** Nothing is emulated —
  the cross-compile targets x64 Windows whether the container is
  `linux/arm64` or `linux/amd64`. On Apple Silicon that makes this
  *much* faster than the Linux `.deb`/`.rpm` path, which does run under
  emulation (`../../linux/build-in-docker.sh`).

Native deps that have to survive the cross-build, and what handles them:
`aws-lc-sys` (rustls' provider) needs `cmake` + `nasm` for its x86_64
Windows assembly; `wasmtime`/cranelift, `russh`, `hiqlite` and the IronRDP
fork are pure Rust; `yubikey`'s `pcsc-sys` links `WinSCard.lib` from the
SDK that xwin supplies.

## The Microsoft licence gate

The script **refuses to run** unless you set `XWIN_ACCEPT_LICENSE=1`
yourself. cargo-xwin downloads the MSVC CRT and Windows SDK from
Microsoft, which is permitted only under the Visual Studio licence terms
(<https://www.visualstudio.com/license-terms/>). Accepting those terms is
the operator's decision, so it is deliberately not baked into the
Dockerfile or the script.

## Env knobs

| Var | Default | Purpose |
|---|---|---|
| `XWIN_ACCEPT_LICENSE` | *(unset — required)* | accept the MSVC CRT/SDK licence terms |
| `GUI_WIN_BUILDER_IMAGE` | `bastionvault-gui-win-builder` | image tag |
| `GUI_WIN_PLATFORM` | host native | force e.g. `linux/amd64` |
| `GUI_BUNDLE_FEATURES` | `storage_hiqlite,ssh_pqc` | cargo features (mirrors `gui-build`) |
| `REBUILD_IMAGE=1` | — | rebuild the builder image |

## Caching

Four named Docker volumes keep the compile off the host tree and make
re-runs cheap: `…-cargo` (registry), `…-target` (`CARGO_TARGET_DIR`),
`…-node_modules` (shadows the host's darwin/arm64 install so `npm ci`
cannot clobber it), and `…-xwin` (the ~1 GB CRT/SDK download, so only the
first run pays for it). Only the finished installer is copied back, to
`target/windows-docker/`.

## Status

**Build-verified 2026-08-26** on an Apple Silicon Mac (`linux/arm64`
container, cross-compiling to x64): app binary is `PE32+ ... x86-64`,
installer is `BastionVault_0.41.17_x64-setup.exe` at 24 MB. A warm-cache run
links in ~2m20s; the first run additionally pays the ~1 GB CRT/SDK download
and a full cold compile of the graph.

**Not install-tested on real Windows yet** — nobody has run the `.exe` on a
Windows box and confirmed the install, the Start-menu entry, the WebView2
bootstrap and the uninstall. That is the remaining acceptance step, same as
it is for the Tart `.msi` path.

Two build notes worth knowing:

- `lld-link` emits `LNK4099` warnings ("cannot use debug info for
  libcmt.lib") because Microsoft's redistributable CRT ships without its
  PDBs. Cosmetic — the link succeeds.
- Tauri prints `Cross-platform compilation is experimental and does not
  support all features`. In practice that means **no Authenticode signing**
  (it needs a Windows host, or a custom `bundler > windows > sign_command`).
- The container bind-mounts the live working tree, so a build races with
  concurrent edits — an in-flight change elsewhere in the workspace will
  fail this build with an ordinary compile error.

## Deploying it (Chocolatey + Puppet)

The `.exe` this produces is not meant to be handed to operators directly — it
is the payload for a Chocolatey package:

```sh
XWIN_ACCEPT_LICENSE=1 make gui-windows-nsis   # -> target/windows-docker/*.exe
make windows-gui-nupkg                        # -> target/nupkg/bastionvault-gui.<ver>.nupkg
```

`make windows-gui-nupkg` packs whichever installer is newest (or
`GUI_INSTALLER=<path>`), and the package's install script passes the right
silent flag for the format it finds. Puppet then installs it unattended with
the `chocolatey` provider. See
[../../../../../installers/puppet/README.md](../../../../../installers/puppet/README.md)
for the full chain and the two caveats that decide whether a silent install
actually succeeds (WebView2 on isolated networks; Authenticode).

The GUI bundle is configured `bundle.windows.nsis.installMode = perMachine`
precisely for this path — Tauri's NSIS default of `currentUser` would install
into the SYSTEM profile when Chocolatey runs under Puppet.

## Signing

Not done here — Authenticode signing is a release/CI concern. `make
sign-packages` handles artifacts on disk if you supply keys; see
`installers/sign/README.md`.
