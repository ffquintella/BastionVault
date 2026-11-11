# CLI packages — bvault CLI .deb/.rpm/.msi/.nupkg/.pkg.
# Included by the top-level Makefile; do not run standalone.

##@ CLI packages

.PHONY: linux-cli-deb linux-cli-rpm linux-cli-packages windows-cli-msi windows-cli-nupkg windows-cli-packages macos-cli-pkg cli-packages cli-packages-all

# ── Linux CLI packages (Wave 2 / Phase 1) ──────────────────────────────
#
# Builds .deb (cargo-deb) and .rpm (cargo-generate-rpm) for the bvault
# CLI. The packaged binary is always a Linux amd64 (x86_64) ELF. Static
# assets (manpage, completions) live under installers/cli/ and are
# referenced by `[package.metadata.deb]` + `[package.metadata.generate-rpm]`
# in Cargo.toml.
#
# Host handling: on a native x86_64 Linux host we build directly with
# `cargo`. On any other host — notably an Apple-Silicon (arm64) Mac —
# we cross-build the Linux binary inside a Docker container via `cross`,
# so the package ships a real Linux amd64 ELF and not the host's native
# (e.g. macOS/arm64 Mach-O) binary. Building always targets the explicit
# CLI_LINUX_TARGET triple so the artifact layout is identical on both
# paths (target/$(CLI_LINUX_TARGET)/{release,generate-rpm,debian}/).
#
# Pre-reqs (one-time):
#   native Linux : `cargo install cargo-deb cargo-generate-rpm`
#   other hosts  : + `cargo install cross` and a running Docker/Podman
# These targets do NOT auto-install the helpers — installing build-time
# tooling automatically inside `make` would surprise CI.
#
# Override CLI_LINUX_TARGET (and the *_ARCH labels) to package a
# different Linux triple.
CLI_LINUX_TARGET    ?= x86_64-unknown-linux-gnu
CLI_LINUX_RPM_ARCH  ?= x86_64
CLI_LINUX_DEB_ARCH  ?= amd64

_CLI_UNAME_S := $(shell uname -s)
_CLI_UNAME_M := $(shell uname -m)
ifeq ($(_CLI_UNAME_S),Linux)
ifneq ($(filter x86_64 amd64,$(_CLI_UNAME_M)),)
CLI_LINUX_NATIVE := 1
endif
endif

ifeq ($(CLI_LINUX_NATIVE),1)
# Native x86_64 Linux: plain cargo, and let cargo-generate-rpm run its
# ldd-based dependency discovery (it works on the real target).
CLI_LINUX_CARGO   := cargo
CLI_LINUX_AUTOREQ := auto
else
# Cross-building from a non-Linux/non-amd64 host: compile inside Docker
# via `cross`, and disable rpm auto-req (the host has no usable `ldd`
# and could not read a foreign-arch ELF anyway).
CLI_LINUX_CARGO   := cross
CLI_LINUX_AUTOREQ := disabled
endif

# Preflight for the cross path: fail early with an actionable message if
# `cross` or a container engine is missing.
define _cli_require_cross
	@if [ "$(CLI_LINUX_CARGO)" = "cross" ]; then \
		command -v cross >/dev/null 2>&1 || { \
			echo "ERROR: this host is not native x86_64 Linux, so the Linux amd64"; \
			echo "       binary is cross-built via 'cross', which is not installed."; \
			echo "       Run: cargo install cross"; exit 1; }; \
		{ docker info >/dev/null 2>&1 || podman info >/dev/null 2>&1; } || { \
			echo "ERROR: 'cross' needs a running Docker or Podman engine."; \
			echo "       Start Docker Desktop (or your Podman machine) and retry."; \
			exit 1; }; \
	fi
endef

linux-cli-deb: ## Build the bvault CLI .deb (Linux amd64; cross-built via Docker on non-Linux hosts)
	@command -v cargo-deb >/dev/null 2>&1 || { \
		echo "ERROR: cargo-deb not installed. Run: cargo install cargo-deb"; \
		exit 1; \
	}
	$(_cli_require_cross)
	$(CLI_LINUX_CARGO) build -p bvault-cli --release --bin bvault --target $(CLI_LINUX_TARGET)
	cargo deb -p bvault-cli --no-build --no-strip --target $(CLI_LINUX_TARGET)
	@echo ""
	@echo "==> .deb under target/$(CLI_LINUX_TARGET)/debian/:"
	@ls -lh target/$(CLI_LINUX_TARGET)/debian/*.deb 2>/dev/null || true

linux-cli-rpm: ## Build the bvault CLI .rpm (Linux amd64; cross-built via Docker on non-Linux hosts)
	@command -v cargo-generate-rpm >/dev/null 2>&1 || { \
		echo "ERROR: cargo-generate-rpm not installed. Run: cargo install cargo-generate-rpm"; \
		exit 1; \
	}
	$(_cli_require_cross)
	$(CLI_LINUX_CARGO) build -p bvault-cli --release --bin bvault --target $(CLI_LINUX_TARGET)
	cargo generate-rpm -p bvault-cli --target $(CLI_LINUX_TARGET) --arch $(CLI_LINUX_RPM_ARCH) --auto-req $(CLI_LINUX_AUTOREQ)
	@echo ""
	@echo "==> .rpm under target/$(CLI_LINUX_TARGET)/generate-rpm/:"
	@ls -lh target/$(CLI_LINUX_TARGET)/generate-rpm/*.rpm 2>/dev/null || true

linux-cli-packages: linux-cli-deb linux-cli-rpm ## Build both .deb and .rpm for the bvault CLI

# ── Windows CLI packages (packaging Phase 3, CLI side) ─────────────────
#
# Builds the bvault CLI .msi (WiX project at installers/cli/msi/bvault.wxs
# — Program Files install + system PATH entry) and a Chocolatey .nupkg
# (installers/cli/nupkg/ — choco auto-shims the exe). Two build paths,
# auto-selected by host OS:
#
#   Windows host — the classic path: `cargo build` for the native exe,
#                  WiX 3.x candle/light for the .msi (with the
#                  WixUI_Minimal license dialog), `choco pack` for the
#                  .nupkg.
#
#   Non-Windows  — the Docker/cross path (this is what "build amd64
#   (Docker)       Windows packages on a Mac/Linux box" means): `cross`
#                  compiles bvault.exe for x86_64-pc-windows-gnu inside a
#                  container, `wixl` (msitools) links the .msi
#                  (silent-install; no UI extension), and build-nupkg.py
#                  assembles the .nupkg — no Windows runner, no
#                  Chocolatey required.
#
# Both paths share installers/cli/msi/bvault.wxs; the WixUI license
# dialog is gated behind `WithUI=1`, set only on the candle path.
#
# Pre-reqs (one-time):
#   Windows host : WiX 3.x toolset on PATH (candle/light) + Chocolatey.
#   Docker path  : `cargo install cross`, a running Docker/Podman, and
#                  `wixl` (msitools: `brew install msitools` or
#                  `apt-get install msitools`). Python 3 for the .nupkg.

CANDLE ?= candle
LIGHT  ?= light
CHOCO  ?= choco
WIXL   ?= wixl

# The Windows target triple for the cross (non-Windows) path. gnu, not
# msvc: `cross`'s container ships mingw-w64, so the GNU ABI cross-compiles
# without a Windows SDK. The produced bvault.exe is a native amd64 PE
# either way.
CLI_WIN_TARGET ?= x86_64-pc-windows-gnu

ifeq ($(OS),Windows_NT)
CLI_WIN_NATIVE := 1
CLI_WIN_EXE    := target/release/bvault.exe
else
CLI_WIN_EXE    := target/$(CLI_WIN_TARGET)/release/bvault.exe
endif

# Preflight for the Windows cross path: cross + a running container engine.
define _cli_win_require_cross
	@command -v cross >/dev/null 2>&1 || { \
		echo "ERROR: building Windows packages off-Windows cross-compiles the"; \
		echo "       exe via 'cross', which is not installed. Run: cargo install cross"; \
		exit 1; }
	@{ docker info >/dev/null 2>&1 || podman info >/dev/null 2>&1; } || { \
		echo "ERROR: 'cross' needs a running Docker or Podman engine."; \
		echo "       Start Docker Desktop (or your Podman machine) and retry."; \
		exit 1; }
endef

windows-cli-msi: ## Build the bvault CLI .msi (native WiX on Windows; Docker cross + wixl elsewhere)
ifeq ($(CLI_WIN_NATIVE),1)
	@command -v $(CANDLE) >/dev/null 2>&1 || { \
		echo "ERROR: WiX 'candle' not found. Install the WiX 3.x toolset and put its bin/ on PATH,"; \
		echo "       or pass CANDLE=/LIGHT= with full paths."; \
		exit 1; \
	}
	cargo build -p bvault-cli --release --bin bvault
	@mkdir -p target/msi
	$(CANDLE) -nologo -arch x64 \
		-dVersion=$(VERSION) \
		-dWithUI=1 \
		-dBvaultExe=$(CLI_WIN_EXE) \
		-dLicenseRtf=installers/cli/msi/License.rtf \
		-out target/msi/bvault.wixobj \
		installers/cli/msi/bvault.wxs
	$(LIGHT) -nologo -ext WixUIExtension \
		-out target/msi/bvault-$(VERSION)-windows-x64.msi \
		target/msi/bvault.wixobj
else
	@command -v $(WIXL) >/dev/null 2>&1 || { \
		echo "ERROR: 'wixl' (msitools) not found — needed to build the .msi off-Windows."; \
		echo "       Install it: 'brew install msitools' or 'apt-get install msitools'."; \
		exit 1; \
	}
	$(_cli_win_require_cross)
	cross build -p bvault-cli --release --bin bvault --target $(CLI_WIN_TARGET)
	@mkdir -p target/msi
	$(WIXL) --arch x64 \
		-D Version=$(VERSION) \
		-D WithUI=0 \
		-D BvaultExe=$(CLI_WIN_EXE) \
		-o target/msi/bvault-$(VERSION)-windows-x64.msi \
		installers/cli/msi/bvault.wxs
endif
	@echo ""
	@echo "==> .msi under target/msi/:"
	@ls -lh target/msi/*.msi 2>/dev/null || true

windows-cli-nupkg: ## Build the bvault CLI Chocolatey .nupkg (choco on Windows; Docker cross + build-nupkg.py elsewhere)
ifeq ($(CLI_WIN_NATIVE),1)
	@command -v $(CHOCO) >/dev/null 2>&1 || { \
		echo "ERROR: choco not found. Install Chocolatey: https://chocolatey.org/install"; \
		exit 1; \
	}
	cargo build -p bvault-cli --release --bin bvault
	@rm -rf target/nupkg/staging
	@mkdir -p target/nupkg/staging/tools
	cp installers/cli/nupkg/bastionvault-cli.nuspec target/nupkg/staging/
	cp installers/cli/nupkg/tools/LICENSE.txt \
	   installers/cli/nupkg/tools/VERIFICATION.txt \
	   target/nupkg/staging/tools/
	cp $(CLI_WIN_EXE) target/nupkg/staging/tools/
	cd target/nupkg/staging && $(CHOCO) pack bastionvault-cli.nuspec \
		--version $(VERSION) --outputdirectory ..
else
	@command -v python3 >/dev/null 2>&1 || { \
		echo "ERROR: python3 not found — needed to assemble the .nupkg off-Windows."; \
		exit 1; \
	}
	$(_cli_win_require_cross)
	cross build -p bvault-cli --release --bin bvault --target $(CLI_WIN_TARGET)
	@mkdir -p target/nupkg
	python3 installers/cli/nupkg/build-nupkg.py \
		--nuspec installers/cli/nupkg/bastionvault-cli.nuspec \
		--version $(VERSION) \
		--exe $(CLI_WIN_EXE) \
		--tools installers/cli/nupkg/tools/LICENSE.txt \
		--tools installers/cli/nupkg/tools/VERIFICATION.txt \
		--out target/nupkg
endif
	@echo ""
	@echo "==> .nupkg under target/nupkg/:"
	@ls -lh target/nupkg/*.nupkg 2>/dev/null || true

windows-cli-packages: windows-cli-msi windows-cli-nupkg ## Build both .msi and .nupkg for the bvault CLI

# ── macOS CLI package (.pkg) (packaging Phase 2, CLI side) ─────────────
#
# Builds a distribution-style .pkg that drops bvault + manpage +
# bash/zsh completions under /usr/local. macOS only (pkgbuild/productbuild
# are Apple tools). Builds for the host arch by default; set
# CLI_MAC_TARGET to build the other arch (a Mac cross-builds both arches
# natively — no Docker needed for macOS). Set INSTALLER_IDENTITY to sign
# with a Developer ID Installer cert; notarisation is a CI step.
#
#   make macos-cli-pkg                                     # host arch
#   make macos-cli-pkg CLI_MAC_TARGET=x86_64-apple-darwin  # Intel
#   make macos-cli-pkg CLI_MAC_TARGET=aarch64-apple-darwin # Apple Silicon

CLI_MAC_TARGET ?=

ifeq ($(CLI_MAC_TARGET),)
CLI_MAC_EXE  := target/release/bvault
CLI_MAC_ARCH := $(shell uname -m)
else
CLI_MAC_EXE  := target/$(CLI_MAC_TARGET)/release/bvault
CLI_MAC_ARCH := $(if $(findstring x86_64,$(CLI_MAC_TARGET)),x86_64,arm64)
endif

macos-cli-pkg: ## Build the bvault CLI .pkg (macOS only; host arch, or CLI_MAC_TARGET=<triple>)
ifneq ($(shell uname -s),Darwin)
	@echo "ERROR: macos-cli-pkg must run on macOS (pkgbuild/productbuild are Apple tools)."; exit 1
else
	@if [ -n "$(CLI_MAC_TARGET)" ]; then \
		rustup target list --installed | grep -q '^$(CLI_MAC_TARGET)$$' || rustup target add $(CLI_MAC_TARGET); \
		cargo build -p bvault-cli --release --bin bvault --target $(CLI_MAC_TARGET); \
	else \
		cargo build -p bvault-cli --release --bin bvault; \
	fi
	VERSION=$(VERSION) BVAULT_BIN=$(CLI_MAC_EXE) PKG_ARCH=$(CLI_MAC_ARCH) OUTPUT_DIR=target/pkg \
		bash installers/cli/pkg/build-macos-pkg.sh
endif

cli-packages: ## Build the bvault CLI packages for this host (Linux: deb+rpm; macOS: pkg; Windows: msi+nupkg)
ifeq ($(OS),Windows_NT)
	@$(MAKE) windows-cli-packages
else ifeq ($(shell uname -s),Linux)
	@$(MAKE) linux-cli-packages
else ifeq ($(shell uname -s),Darwin)
	@$(MAKE) macos-cli-pkg
else
	@echo "ERROR: unknown host — no CLI package format wired"; exit 1
endif

cli-packages-all: ## Build ALL CLI packages: Linux deb/rpm + Windows msi/nupkg via Docker (+ macOS pkg on a Mac)
	@$(MAKE) linux-cli-packages
	@$(MAKE) windows-cli-packages
ifeq ($(shell uname -s),Darwin)
	@$(MAKE) macos-cli-pkg
else
	@echo "==> skipping macOS .pkg (not on a Mac; .pkg needs Apple's pkgbuild)"
endif
