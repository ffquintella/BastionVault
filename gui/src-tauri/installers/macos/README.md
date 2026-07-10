# BastionVault GUI — macOS installer (.pkg)

Tauri's macOS bundler produces `BastionVault.app` (and a `.dmg`); Munki /
Jamf / MDM want a `.pkg`. `make gui-macos-pkg` builds the `.app`
(`tauri build --bundles app`) and then wraps it with `build-gui-pkg.sh`
into a distribution `.pkg` that installs into `/Applications`.

```
gui/src-tauri/installers/macos/
├── README.md          (this file)
├── build-gui-pkg.sh   # pkgbuild --component App + productbuild wrapper
└── distribution.xml   # productbuild distribution (@VERSION@/@HOSTARCH@ templated)
```

## Building

```sh
make gui-macos-pkg
ls target/pkg/          # BastionVault-<version>-<arch>.pkg
```

Runs on macOS only. Builds for the host arch by default; the produced
`.pkg` is arch-guarded via the distribution's `hostArchitectures`.

## Signing + notarisation

A local build is **unsigned**. Set `INSTALLER_IDENTITY="Developer ID
Installer: <team>"` to sign the pkg. Notarisation (`xcrun notarytool
submit --wait` + `xcrun stapler staple`) is a CI step — Gatekeeper
accepts a notarised, stapled `.pkg` on a fresh account; an unsigned one
is fine for local testing.

## Universal2

For a single fat `.pkg`, build the `.app` for both arches, `lipo` the
binaries, then run `build-gui-pkg.sh` with
`PKG_ARCH="arm64,x86_64"` (the file is named `-universal2`). The default
`make gui-macos-pkg` ships one arch (the host's).
