# BastionVault GUI — Linux installers (Wave 2 / Phase 1, skeleton)

Placeholder / skeleton for the GUI's Linux .deb + .rpm bundles produced
by Tauri's bundler (`npx tauri build --bundles deb,rpm`).

## Status: skeleton only — NOT verified

This directory ships the post-install / pre-removal scriptlets and the
inputs they need so the bundler can pick them up via the Tauri config.
Phase 1 lands the CLI .deb / .rpm; the GUI side needs a real Tauri
build host (Linux/amd64 with the system webkit2gtk + libsoup3 deps) to
exercise. Until that pass happens:

- The Tauri config block referencing these scripts (under
  `gui/src-tauri/tauri.conf.json` `bundle.linux.deb.files` and
  `bundle.linux.rpm.files`) is added when we run the first real
  build, not now. Wiring it in cold without running `tauri build`
  invites silent format drift.
- These scripts are written against the Tauri 2.x bundler conventions
  (postinst / prerm executed during package install / removal,
  `set -e`, no `bash`-isms beyond what Debian / RPM scriptlets allow).

## Contents

```
gui/src-tauri/installers/linux/
├── README.md  (this file)
├── postinst   # XDG MIME registration for bv:// URLs, desktop DB update
└── prerm      # Reverse of postinst on uninstall
```

## Phase 1 follow-up

When a Linux build host is available:

1. Run `make gui-build` on a Linux host. Confirm Tauri produces a
   `.deb` and `.rpm` under `gui/src-tauri/target/release/bundle/`.
2. Add the missing fields to `tauri.conf.json` →
   `bundle.linux.deb.files` / `bundle.linux.rpm.files` to inject
   `postinst` and `prerm`.
3. Verify `apt install ./bastionvault-gui_X.Y.Z_amd64.deb` registers
   the `bv://` URL handler (`xdg-mime query default x-scheme-handler/bv`)
   and that uninstall reverses it.
