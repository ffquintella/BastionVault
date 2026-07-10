# BastionVault GUI — Linux installers (Tauri bundler)

The GUI's Linux `.deb` + `.rpm` bundles are produced by Tauri's bundler
(`make gui-linux-packages` → `tauri build --bundles deb,rpm`). This
directory holds the maintainer scriptlets the bundler injects and the
emulated-amd64 Docker builder used to build off-Linux.

## Building

`make gui-linux-packages` picks the path automatically:

- **On Linux** — builds natively; bundles land under
  `gui/src-tauri/target/release/bundle/{deb,rpm}/`. Needs the system
  `webkit2gtk-4.1` + `libsoup3` dev packages installed.
- **Off Linux (macOS / anything else)** — Tauri cannot cross-compile the
  GUI (WebKitGTK is a native build- *and* run-time dependency), so the
  build runs inside an **emulated amd64 Linux container**
  ([`Dockerfile`](Dockerfile), driven by
  [`build-in-docker.sh`](build-in-docker.sh)). On an Apple-Silicon Mac
  this runs under Docker Desktop's amd64 emulation (QEMU/Rosetta), so a
  Mac produces the Linux GUI installers with no native Linux host. The
  finished bundles are copied to `target/linux-docker/{deb,rpm}/`.
  **Emulated compilation is slow** (the first full backend build can take
  the better part of an hour); the cargo registry, `node_modules`, and
  `CARGO_TARGET_DIR` are cached in named Docker volumes so later runs are
  faster.

The bundler config is wired in
[`gui/src-tauri/tauri.conf.json`](../../tauri.conf.json) under
`bundle.linux.deb` / `bundle.linux.rpm`:

- `depends` — the WebKitGTK + GTK runtime libraries the app needs.
- `postInstallScript` → `installers/linux/postinst`
- `preRemoveScript`  → `installers/linux/prerm`

### Verify before publishing

1. `apt install ./bastionvault-gui_X.Y.Z_amd64.deb` (and the `.rpm` on a
   Fedora/RHEL box); confirm the desktop entry appears and the postinst
   ran (`update-desktop-database` / icon cache refreshed).
2. Confirm uninstall runs `prerm` and leaves no stale desktop/MIME state.

## Contents

```
gui/src-tauri/installers/linux/
├── README.md          (this file)
├── Dockerfile         # emulated amd64 GUI builder (webkit + rust + node)
├── build-in-docker.sh # build the .deb/.rpm in the container, copy them out
├── postinst           # desktop-db / MIME / icon-cache refresh on install
└── prerm              # same refresh on removal
```

## Not yet wired: the `bv://` URL handler

Registering the `bv://` scheme (desktop `MimeType`, MIME package XML) is
only useful once the GUI actually handles deep-link URLs, which needs the
Tauri deep-link plugin + app-side handling — a separate feature. The
postinst already calls `update-mime-database` (a no-op until a MIME
package ships), so enabling it later is additive.
