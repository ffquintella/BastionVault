# GUI installers — Tauri installers, Windows nupkg, signing.
# Included by the top-level Makefile; do not run standalone.

##@ GUI installers

.PHONY: gui-linux-packages gui-windows-msi gui-windows-nsis windows-gui-nupkg gui-macos-pkg sign-packages gui-packages

# ── GUI installers (Tauri bundler) ─────────────────────────────────────
#
# The GUI is a Tauri app; its installers are produced by Tauri's bundler
# (`tauri build --bundles ...`). Unlike the CLI, a Tauri GUI CANNOT be
# cross-built in Docker — the WebView runtime is platform-native
# (WebView2 on Windows, WebKitGTK on Linux, WebKit on macOS), so each
# format must be built on its own OS. That is why these targets are
# host-gated (and why the cross-platform matrix lives in CI, not here).
#
# The feature list mirrors `gui-build` (storage_hiqlite + ssh_pqc) so the
# packaged GUI ships the same capabilities as a normal production build.
#
#   Linux  : make gui-linux-packages   → .deb + .rpm (bundle/deb, bundle/rpm)
#   macOS  : make gui-macos-pkg         → .app wrapped into a .pkg (target/pkg)
#   Windows: make gui-windows-msi       → .msi (bundle/msi)
#   Windows: make gui-windows-nsis      → x64 .exe (cross-built in Docker)

GUI_BUNDLE_FEATURES ?= storage_hiqlite,ssh_pqc

gui-linux-packages: ## Build the GUI .deb + .rpm (native on Linux; emulated amd64 Docker container elsewhere)
ifeq ($(shell uname -s),Linux)
	@$(MAKE) gui-deps prune-stale
	cd gui && $(GUI_TAURI) build --bundles deb,rpm -- --features $(GUI_BUNDLE_FEATURES)
	@echo ""
	@echo "==> GUI bundles under target/release/bundle/:"
	@ls -lh target/release/bundle/deb/*.deb target/release/bundle/rpm/*.rpm \n	        gui/src-tauri/target/release/bundle/deb/*.deb \n	        gui/src-tauri/target/release/bundle/rpm/*.rpm 2>/dev/null || true
else
	@echo "==> not on Linux — building the GUI .deb/.rpm in an emulated amd64 Docker container"
	@GUI_BUNDLE_FEATURES=$(GUI_BUNDLE_FEATURES) bash gui/src-tauri/installers/linux/build-in-docker.sh
endif

gui-windows-msi: ## Build the GUI .msi (native on Windows; disposable Tart Win11 ARM64 VM elsewhere)
ifeq ($(OS),Windows_NT)
	@$(MAKE) gui-deps prune-stale
	cd gui && $(GUI_TAURI) build --bundles msi -- --features $(GUI_BUNDLE_FEATURES)
	@echo ""
	@echo "==> GUI .msi under target/release/bundle/msi/:"
	@ls -lh target/release/bundle/msi/*.msi \n	        gui/src-tauri/target/release/bundle/msi/*.msi 2>/dev/null || true
else ifeq ($(shell uname -s),Darwin)
	@echo "==> not on Windows — building the GUI .msi (x64) in a disposable Tart Win11 ARM64 VM"
	@GUI_BUNDLE_FEATURES=$(GUI_BUNDLE_FEATURES) bash gui/src-tauri/installers/windows/build-in-vm.sh
else
	@echo "ERROR: off-Windows GUI .msi builds use Tart (Apple Virtualization), which is macOS-only."; \
	 echo "       Build on a Windows host, or use the macOS Tart path."; exit 1
endif

# ── Windows GUI installer without Windows (Docker) ─────────────────────
#
# The .msi above needs a Windows host: Tauri v2 compiles its WiX/MSI
# bundler in only on Windows (it drives candle.exe/light.exe), which is why
# the off-Windows path is a Tart Win11 VM. Tauri's NSIS bundler has no such
# gate — it resolves `makensis` from PATH — so a Linux container CAN produce
# a Windows x64 installer, as an .exe rather than an .msi.
#
# cargo-xwin cross-compiles the graph to x86_64-pc-windows-msvc (clang-cl +
# lld-link against Microsoft's CRT/SDK headers) and makensis wraps it. The
# container runs at the HOST's native arch — nothing is emulated, unlike
# gui-linux-packages — so this is fast on Apple Silicon.
#
# Requires XWIN_ACCEPT_LICENSE=1: cargo-xwin downloads Microsoft's CRT and
# Windows SDK, which is only permitted under the Visual Studio licence
# terms. That acceptance is the operator's to give, so it is not baked into
# the script. See gui/src-tauri/installers/windows/docker/README.md.
gui-windows-nsis: ## Build the GUI Windows x64 .exe installer in Docker (no Windows host; needs XWIN_ACCEPT_LICENSE=1)
	@GUI_BUNDLE_FEATURES=$(GUI_BUNDLE_FEATURES) \
	 bash gui/src-tauri/installers/windows/docker/build-in-docker.sh

# ── Windows GUI Chocolatey package ─────────────────────────────────────
#
# Wraps the Tauri .msi in a Chocolatey/NuGet .nupkg so the desktop app can
# be deployed from a private feed the same way `bastionvault-cli` is. The
# CLI package needs no install script (Chocolatey auto-shims tools\*.exe);
# the GUI is a windowed app with Start-menu and uninstall entries, so its
# package hands the bundled .msi to msiexec — see
# gui/src-tauri/installers/windows/nupkg/tools/chocolateyInstall.ps1.
#
# The .nupkg itself is assembled by installers/cli/nupkg/build-nupkg.py
# (host-independent, no Chocolatey required), the same packer the CLI uses.
#
# The package takes EITHER bundle format, because the two off-Windows build
# paths produce different ones and Chocolatey abstracts the difference away
# from callers (`choco install bastionvault-gui` behaves identically, which is
# what lets a Puppet manifest stay format-agnostic):
#
#   .msi  from `make gui-windows-msi`   (Windows host, or the Tart Win11 VM)
#   .exe  from `make gui-windows-nsis`  (Docker cross-build, no Windows host)
#
# With neither variable set, the newest installer found under any of the four
# known output directories is packed. Otherwise name one explicitly:
#
#   make windows-gui-nupkg GUI_INSTALLER=target/windows-docker/BastionVault_0.41.17_x64-setup.exe
#   make windows-gui-nupkg GUI_MSI=out/BastionVault_0.38.3_x64_en-US.msi
GUI_NUPKG_DIR := gui/src-tauri/installers/windows/nupkg
GUI_MSI       ?=
# GUI_MSI is the older name and still works; GUI_INSTALLER is the format-neutral one.
GUI_INSTALLER ?= $(GUI_MSI)
PYTHON        ?= $(if $(filter Windows_NT,$(OS)),python,python3)

windows-gui-nupkg: ## Build the GUI Chocolatey .nupkg wrapping the .msi or NSIS .exe (GUI_INSTALLER=... to pack an existing one)
ifeq ($(OS),Windows_NT)
	@if [ -z "$(GUI_INSTALLER)" ]; then $(MAKE) gui-windows-msi; fi
endif
	@command -v $(PYTHON) >/dev/null 2>&1 || { \
		echo "ERROR: $(PYTHON) not found — needed to assemble the .nupkg."; \
		echo "       Override the interpreter with PYTHON=<path> if it is named differently."; \
		exit 1; \
	}
	@mkdir -p target/nupkg
	@INSTALLER="$(GUI_INSTALLER)"; \
	 if [ -z "$$INSTALLER" ]; then \
		INSTALLER=$$(ls -1t target/windows-docker/*.exe \
		               gui/src-tauri/target/x86_64-pc-windows-msvc/release/bundle/nsis/*.exe \
		               gui/src-tauri/target/release/bundle/nsis/*.exe \
		               gui/src-tauri/target/release/bundle/msi/*.msi \
		               target/release/bundle/msi/*.msi 2>/dev/null | head -1); \
	 fi; \
	 if [ -z "$$INSTALLER" ]; then \
		echo "ERROR: no GUI installer (.msi or .exe) found."; \
		echo "       Build one first — 'make gui-windows-nsis' (Docker, no Windows host)"; \
		echo "       or 'make gui-windows-msi' — or pass GUI_INSTALLER=<path>."; \
		exit 1; \
	 fi; \
	 echo "==> packing $$INSTALLER"; \
	 $(PYTHON) installers/cli/nupkg/build-nupkg.py \
		--nuspec $(GUI_NUPKG_DIR)/bastionvault-gui.nuspec \
		--version $(VERSION) \
		--tools "$$INSTALLER" \
		--tools $(GUI_NUPKG_DIR)/tools/chocolateyInstall.ps1 \
		--tools $(GUI_NUPKG_DIR)/tools/chocolateyUninstall.ps1 \
		--tools $(GUI_NUPKG_DIR)/tools/LICENSE.txt \
		--tools $(GUI_NUPKG_DIR)/tools/VERIFICATION.txt \
		--out target/nupkg
	@echo ""
	@echo "==> .nupkg under target/nupkg/:"
	@ls -lh target/nupkg/*.nupkg 2>/dev/null || true

gui-macos-pkg: gui-deps prune-stale ## Build the GUI .pkg (macOS only; Tauri .app wrapped by productbuild)
ifneq ($(shell uname -s),Darwin)
	@echo "ERROR: gui-macos-pkg must run on macOS (Tauri needs macOS to build the .app; pkgbuild is Apple's)."; exit 1
else
	cd gui && $(GUI_TAURI) build --bundles app -- --features $(GUI_BUNDLE_FEATURES)
	@APP=$$(find gui/src-tauri/target target -type d -name 'BastionVault.app' -path '*/bundle/macos/*' 2>/dev/null | head -1); \
	 if [ -z "$$APP" ]; then echo "ERROR: BastionVault.app not found under */bundle/macos/ after tauri build"; exit 1; fi; \
	 echo "==> wrapping $$APP into a .pkg"; \
	 VERSION=$(VERSION) APP_PATH=$$APP OUTPUT_DIR=target/pkg \
		bash gui/src-tauri/installers/macos/build-gui-pkg.sh
	@ls -lh target/pkg/BastionVault-*.pkg 2>/dev/null || true
endif

# ── Signing (Phase 4) ──────────────────────────────────────────────────
#
# Sign whatever installers are on disk with WHATEVER keys you supply via the
# environment (any GPG key, any code-signing .pfx/PEM, any Developer ID, any
# cosign key). Each mechanism is independent + optional — provide a key and
# that type is signed; omit it and it is skipped. Cosign + SHA256SUMS cover
# every artifact. See installers/sign/README.md for the full env-var list.
#
#   BV_GPG_KEY=… BV_WIN_PFX=… BV_COSIGN_KEY=… make sign-packages
#
# SIGN_DIRS overrides the scan roots (default: target/).
SIGN_DIRS ?=

sign-packages: ## Sign built installers with any keys you provide (env-driven; see installers/sign/README.md)
	@bash installers/sign/sign-artifacts.sh $(SIGN_DIRS)

gui-packages: ## Build the GUI installer(s) for this host (Linux: deb+rpm; macOS: pkg; Windows: msi)
ifeq ($(OS),Windows_NT)
	@$(MAKE) gui-windows-msi
else ifeq ($(shell uname -s),Linux)
	@$(MAKE) gui-linux-packages
else ifeq ($(shell uname -s),Darwin)
	@$(MAKE) gui-macos-pkg
else
	@echo "ERROR: unknown host — no GUI installer format wired"; exit 1
endif
