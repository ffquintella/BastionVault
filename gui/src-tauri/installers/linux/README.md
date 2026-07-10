# BastionVault GUI — Linux installers (Tauri bundler)

The GUI's Linux `.deb` + `.rpm` bundles are produced by Tauri's bundler
(`make gui-linux-packages` → `tauri build --bundles deb,rpm`). This
directory holds the maintainer scriptlets the bundler injects.

## Status: wired — verify on a Linux build host

The bundler config is wired in
[`gui/src-tauri/tauri.conf.json`](../../tauri.conf.json) under
`bundle.linux.deb` / `bundle.linux.rpm`:

- `depends` — the WebKitGTK + GTK runtime libraries the app needs.
- `postInstallScript` → `installers/linux/postinst`
- `preRemoveScript`  → `installers/linux/prerm`

Building the GUI needs a Linux host with the system `webkit2gtk-4.1` +
`libsoup3` dev packages (Tauri cannot cross-build the GUI — the WebView
runtime is platform-native). `make gui-linux-packages` is host-gated to
Linux for that reason. Everything here is authored against Tauri 2.x's
documented bundler config, but the produced `.deb` / `.rpm` have not been
exercised on a Linux runner yet — do that pass before publishing:

1. `make gui-linux-packages` on a Linux/amd64 host. Confirm Tauri writes
   a `.deb` and `.rpm` under `gui/src-tauri/target/release/bundle/`.
2. `apt install ./bastionvault-gui_X.Y.Z_amd64.deb` (and the `.rpm` on a
   Fedora/RHEL box); confirm the desktop entry appears and the postinst
   ran (`update-desktop-database` / icon cache refreshed).
3. Confirm uninstall runs `prerm` and leaves no stale desktop/MIME state.

## Contents

```
gui/src-tauri/installers/linux/
├── README.md  (this file)
├── postinst   # desktop-db / MIME / icon-cache refresh on install
└── prerm      # same refresh on removal
```

## Not yet wired: the `bv://` URL handler

Registering the `bv://` scheme (desktop `MimeType`, MIME package XML) is
only useful once the GUI actually handles deep-link URLs, which needs the
Tauri deep-link plugin + app-side handling — a separate feature. The
postinst already calls `update-mime-database` (a no-op until a MIME
package ships), so enabling it later is additive.
