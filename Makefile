.DEFAULT_GOAL := help

ifeq ($(OS),Windows_NT)
VERSION := $(shell powershell -NoProfile -ExecutionPolicy Bypass -Command "((Select-String -Path Cargo.toml -Pattern '^version\s*=' -List).Line -replace '[^0-9.]','')")
else
VERSION := $(shell grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')
endif

# ── Windows: force `openssl-sys`'s vendored build to use Strawberry
# Perl instead of the MSYS perl that ships with Git for Windows.
#
# Problem: when `make` is invoked from Git-Bash (MSYS), `cargo`'s
# `Command::new("perl")` in the openssl-sys build script resolves
# to `C:\Program Files\Git\usr\bin\perl.exe` — a minimal MSYS perl
# that lacks `Locale::Maketext::Simple`. `perl ./Configure VC-WIN64A`
# then dies with "Can't locate Locale/Maketext/Simple.pm in @INC".
#
# Fix: `openssl-src` honours `OPENSSL_SRC_PERL`. Point it at
# Strawberry Perl (the standard Windows native install) so
# Configure runs with the full CPAN module set.
#
# Override on the command line if your Strawberry Perl lives
# elsewhere: `make OPENSSL_SRC_PERL=D:/perl/bin/perl.exe run-dev-gui`.
ifeq ($(OS),Windows_NT)
OPENSSL_SRC_PERL ?= C:/Strawberry/perl/bin/perl.exe
export OPENSSL_SRC_PERL

# Belt-and-braces: older `openssl-src` releases ignore
# `OPENSSL_SRC_PERL` and just call `Command::new("perl")`, which under
# Git-Bash resolves to the MSYS perl that lacks
# `Locale::Maketext::Simple`. Prepend Strawberry to PATH so the
# bare `perl` lookup hits the right interpreter regardless of which
# `openssl-src` version cargo picks. Override the locations on the
# command line if your Strawberry install is elsewhere:
#   `make STRAWBERRY_PERL_BIN=D:/perl/bin run-dev-gui`
STRAWBERRY_PERL_BIN ?= /c/Strawberry/perl/bin
STRAWBERRY_C_BIN    ?= /c/Strawberry/c/bin
export PATH := $(STRAWBERRY_PERL_BIN):$(STRAWBERRY_C_BIN):$(PATH)
endif

# ── Ensure rustup's toolchain wins over any system Rust (e.g.
# Homebrew's `rust` on macOS, distro packages on Linux, or a stray
# MSI on Windows). System Rust packages typically ship only the host
# std, so `cargo build --target wasm32-wasip1` fails with
# "can't find crate for `core`" even after `rustup target add` —
# because the active rustc isn't the rustup one. Prepending rustup's
# shim dir fixes both `cargo` and `rustc` lookups in one shot.
#
# `$(HOME)/.cargo/bin` is the standard rustup location on Unix and on
# Windows under MSYS/Git-Bash. For native cmd.exe make we fall back to
# `$(USERPROFILE)/.cargo/bin`. Override with `RUSTUP_CARGO_BIN=...` if
# yours lives elsewhere.
ifeq ($(OS),Windows_NT)
RUSTUP_CARGO_BIN ?= $(if $(HOME),$(HOME)/.cargo/bin,$(USERPROFILE)/.cargo/bin)
else
RUSTUP_CARGO_BIN ?= $(HOME)/.cargo/bin
endif
export PATH := $(RUSTUP_CARGO_BIN):$(PATH)

.PHONY: help build run-dev run-dev-gui gui-deps gui-build gui-test gui-check docs bump-minor bump-major bump-patch _bump-write bootstrap win-bootstrap clean gui-clean docs-clean deep-clean prune prune-stale target-size plugins-init plugins-target plugins-process-target plugins-wasm plugins-process plugins plugins-clean plugins-pack plugins-pack-build plugins-keygen plugins-sign plugins-test plugin-bump container-image container-image-run container-image-test container-repo-setup container-repo-show container-image-push linux-cli-deb linux-cli-rpm linux-cli-packages windows-cli-msi windows-cli-nupkg windows-cli-packages cli-packages

# Number of rustc incremental sessions to keep per crate. Anything
# older than the Nth most recent is reaped by `prune-stale`. Override
# from the command line — e.g. `make build KEEP=5` — when debugging
# an incremental-compilation bug where older generations need to
# stick around.
KEEP ?= 3

# WSL projects checked out under /mnt/c can reject npm's chmod while
# creating node_modules/.bin links. Avoid bin links there and call the
# package entrypoints directly; keep normal npx behavior elsewhere.
ifeq ($(OS),Windows_NT)
IS_WSL := 0
else
IS_WSL := $(shell uname -r 2>/dev/null | tr '[:upper:]' '[:lower:]' | grep -q microsoft && echo 1)
endif
ifeq ($(IS_WSL),1)
GUI_NPM_INSTALL := npm install --no-bin-links --no-save --package-lock=false
GUI_TAURI := node node_modules/@tauri-apps/cli/tauri.js
GUI_TSC := node node_modules/typescript/bin/tsc
GUI_VITE := node node_modules/vite/bin/vite.js
GUI_VITEST := node node_modules/vitest/vitest.mjs
else
GUI_NPM_INSTALL := npm install
GUI_TAURI := npx tauri
GUI_TSC := npx tsc
GUI_VITE := npx vite
GUI_VITEST := npx vitest
endif

help: ## List available commands
	@echo "BastionVault v$(VERSION)"
	@echo ""
	@echo "Usage: make <target>"
	@echo ""
ifeq ($(OS),Windows_NT)
	@powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-Content '$(firstword $(MAKEFILE_LIST))' | ForEach-Object { if (\$$_ -match '^([a-zA-Z_-]+):.*##\s*(.*)') { '  {0,-15} {1}' -f \$$matches[1], \$$matches[2] } }"
else
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*##"}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'
endif

prune-stale: ## Trim rustc incremental caches to the last KEEP sessions (default 3). Auto-runs before every compiling target.
	@KEEP=$(KEEP) bash scripts/prune-incremental.sh

build: prune-stale ## Build the project in release mode
	cargo build --release

run-dev: prune-stale ## Run the development server
	CARGO_BUILD_JOBS=6 cargo run -- server --config config/dev.hcl

gui-deps: ## Install GUI frontend dependencies
	cd gui && $(GUI_NPM_INSTALL)

# `--features` lists are explicit (not relying solely on the Tauri
# crate's `default = [...]`) so an operator skimming the Makefile
# can see exactly what the dev / prod GUI binaries ship with.
# `ssh_pqc` enables ML-DSA-65 SSH CA generation in the /ssh page.
run-dev-gui: gui-deps prune-stale ## Run the desktop GUI in dev mode with local MCP bridge enabled
	cd gui && CARGO_BUILD_JOBS=6 BASTION_EMBEDDED_STORAGE=file BASTION_TAURI_MCP=1 $(GUI_TAURI) dev -- --features storage_hiqlite,mcp_local_dev,ssh_pqc

run-dev-gui-hiqlite: gui-deps prune-stale ## Run the desktop GUI in dev mode, embedded vault on hiqlite (ports 8210/8220)
	cd gui && CARGO_BUILD_JOBS=6 BASTION_EMBEDDED_STORAGE=hiqlite $(GUI_TAURI) dev -- --features storage_hiqlite,ssh_pqc

# Lightest dev build: Tauri host + vite, with `bastion_vault` pulled
# in at default-features=false. That means no hiqlite (no Raft/SQLite
# compile), no cloud storage targets, no PQC SSH — just the bare
# minimum needed for the GUI to talk to an external bvault server via
# the Connect page. Local Vault profiles that depend on those
# features won't work in this build; that's the trade-off for the
# faster compile.
run-dev-gui-only: gui-deps prune-stale ## Run the desktop GUI in dev mode with no backend storage features (lightest compile) + MCP bridge
	cd gui && CARGO_BUILD_JOBS=6 BASTION_TAURI_MCP=1 $(GUI_TAURI) dev -- --no-default-features --features mcp_local_dev

gui-build: gui-deps prune-stale ## Build the desktop GUI for production
	cd gui && $(GUI_TAURI) build -- --features storage_hiqlite,ssh_pqc

gui-test: gui-deps ## Run GUI frontend tests (Vitest)
	cd gui && $(GUI_VITEST) run

gui-check: gui-deps ## Type-check and lint the GUI frontend
	cd gui && $(GUI_TSC) --noEmit && $(GUI_VITE) build

docs: ## Serve the Docsify-powered documentation site locally on http://localhost:3000
	@command -v docsify >/dev/null 2>&1 || npm i -g docsify-cli
	docsify serve docs

# `bump-*` targets bump the workspace version everywhere it lives:
# - `Cargo.toml` (root crate)
# - `gui/src-tauri/Cargo.toml` (Tauri host crate)
# - `gui/package.json` (npm package — drives `npm publish` / vite build IDs)
# - `gui/src-tauri/tauri.conf.json` (Tauri runtime version, baked into
#   the desktop app's About page)
#
# Each sed pattern is anchored so it only touches the *top-level*
# version field — `^version =` for the toml files, the indented
# `^  "version":` for the JSON files (matches the 2-space indentation
# `npm` and Tauri write).
#
# The GUI files don't carry the root crate's old version (they were
# at 0.1.0 while root was at 0.3.1 before this change), so we match
# any current value (`[^\"]*`) and overwrite to `$$NEW`. After the
# first sync run, every subsequent bump keeps all four files in
# lockstep.

# Cross-platform `sed -i` invocation. BSD sed (macOS, FreeBSD) needs an
# explicit empty backup-suffix argument (`-i ''`); GNU sed (Linux) errors
# on that and wants either `-i` alone or `-i ''` written without a space.
# Detect with --version, which BSD sed lacks.
ifeq ($(OS),Windows_NT)
# Git-Bash / MSYS2 ship GNU sed, which supports `-i` without a backup
# suffix. Native cmd.exe has no sed at all, so this Makefile already
# assumes a POSIX-ish shell on Windows.
SED_INPLACE := sed -i
else
SED_INPLACE := $(shell sed --version >/dev/null 2>&1 && echo "sed -i" || echo "sed -i ''")
endif

# `bump-*` keeps the four version sites in lockstep:
#   * root `Cargo.toml`               (workspace crate version)
#   * `gui/src-tauri/Cargo.toml`      (Tauri Rust crate)
#   * `gui/package.json`              (npm — bastion-vault-gui)
#   * `gui/src-tauri/tauri.conf.json` (Tauri runtime version pin)
#
# Workspace crates under `crates/` (`bv_crypto`, `bastion-plugin-sdk`,
# `bv-plugin-pack`) have independent versioning lifecycles and are NOT
# touched here — bump them by hand or via dedicated scripts as
# semver-relevant changes land.
#
# Each sed uses `[^\"]*` for the existing-version match so a manually
# patched root (or a previously-drifted gui) still bumps cleanly.

bump-patch: ## Bump patch version (0.0.x) across root + gui
	@NEW=$$(echo $(VERSION) | awk -F. '{printf "%d.%d.%d", $$1, $$2, $$3+1}'); \
	$(MAKE) --no-print-directory _bump-write NEW=$$NEW

bump-minor: ## Bump minor version (0.x.0) across root + gui
	@NEW=$$(echo $(VERSION) | awk -F. '{printf "%d.%d.0", $$1, $$2+1}'); \
	$(MAKE) --no-print-directory _bump-write NEW=$$NEW

bump-major: ## Bump major version (x.0.0) across root + gui
	@NEW=$$(echo $(VERSION) | awk -F. '{printf "%d.0.0", $$1+1}'); \
	$(MAKE) --no-print-directory _bump-write NEW=$$NEW

# Internal target — does the actual rewrite. Kept separate so the three
# user-facing targets stay one-liners and the sed list lives in one place.
_bump-write:
	@if [ -z "$(NEW)" ]; then echo "_bump-write: NEW must be set" >&2; exit 1; fi
	@# `1,/^version = /` constrains the substitution to the lines from
	@# 1 to the FIRST match — i.e. the `[package]` version. Without
	@# this, a workspace `Cargo.toml` carrying `[dependencies.libc] /
	@# version = "0.2"` would also get rewritten, which broke the
	@# previous bump pass.
	@$(SED_INPLACE) '1,/^version = /s/^version = "[^"]*"/version = "$(NEW)"/' Cargo.toml
	@$(SED_INPLACE) '1,/^version = /s/^version = "[^"]*"/version = "$(NEW)"/' gui/src-tauri/Cargo.toml
	@$(SED_INPLACE) '1,/^  "version":/s/^  "version": "[^"]*"/  "version": "$(NEW)"/' gui/package.json
	@$(SED_INPLACE) '1,/^  "version":/s/^  "version": "[^"]*"/  "version": "$(NEW)"/' gui/src-tauri/tauri.conf.json
	@echo "Bumped version: $(VERSION) -> $(NEW)"
	@echo "  Cargo.toml:                    $$(grep '^version' Cargo.toml | head -1)"
	@echo "  gui/src-tauri/Cargo.toml:      $$(grep '^version' gui/src-tauri/Cargo.toml | head -1)"
	@echo "  gui/package.json:              $$(grep '\"version\"' gui/package.json | head -1 | sed 's/^[ \t]*//')"
	@echo "  gui/src-tauri/tauri.conf.json: $$(grep '\"version\"' gui/src-tauri/tauri.conf.json | head -1 | sed 's/^[ \t]*//')"

# ── Server container image (Wave 1, Phase 1 of Packaging & Distribution) ──
#
# Builds the OCI image defined by `deploy/container/Containerfile`. The
# build context is the repo root so the cargo workspace can be copied in.
#
# Tooling: prefers `podman`, falls back to `docker`. Both are first-class
# on Linux and macOS (Docker Desktop / podman machine) so the same
# invocation works on either OS.
#
# Override knobs (chain on the command line):
#   make container-image CONTAINER_TOOL=docker
#   make container-image IMAGE_NAME=ghcr.io/ffquintella/bastionvault
#   make container-image IMAGE_TAG=v0.4.0-rc1
#   make container-image PLATFORM=linux/arm64    # default is linux/amd64
#   make container-image INCLUDE_SHELL=0         # opt-out of /bin/sh
#
# `BUILDX` toggles `docker buildx build` (multi-arch capable) when
# CONTAINER_TOOL=docker. Podman handles --platform natively so the toggle
# has no effect there.
#
# `INCLUDE_SHELL` (0|1, default 1) controls whether the production
# image carries a shell. On by default so `podman exec` works out of
# the box and the bundled `rustion-master-bootstrap.sh` can be invoked
# directly inside the container. Setting to 0 stages no shell, restoring
# the classic shell-less distroless property (smallest attack surface,
# no /bin/sh available inside the container at all). When on, a Debian
# builder layer stages `busybox-static` and copies it into the runtime
# as /bin/busybox with /bin/sh -> busybox (single static binary, no
# library deps, ~1 MB). The :debug variant always has a shell and is
# unaffected by this flag.

CONTAINER_TOOL ?= $(shell command -v podman >/dev/null 2>&1 && echo podman || echo docker)
IMAGE_NAME     ?= bastionvault
IMAGE_TAG      ?= $(VERSION)
BUILDX         ?= 0
INCLUDE_SHELL  ?= 1

# Default `PLATFORM` to linux/amd64 so the image we build by default
# matches what we publish from CI (Linux/amd64 runners) and what most
# deployment targets expect. On Apple Silicon this goes through QEMU,
# which historically segfaults rustc inside the builder image — if you
# hit that, build natively for arm64 with `make container-image-run`
# (which overrides PLATFORM=linux/arm64) or pass PLATFORM= explicitly.
#
# Override on the command line for cross-arch builds:
#   make container-image PLATFORM=linux/arm64    # default is linux/amd64
PLATFORM ?= linux/amd64

# Docker's BuildKit/buildx `docker-container` driver (Docker Desktop's default
# builder) leaves the build result in the cache and does NOT place it in the
# local image store unless `--load` is passed — so a subsequent `docker image
# inspect` / `tag` (e.g. from container-image-push) can't see it. The classic
# `docker` driver auto-loads, where `--load` is harmless. podman writes to local
# storage natively and doesn't take the flag. `--load` requires a single
# platform, so omit it for a comma-separated multi-arch PLATFORM.
comma := ,
ifeq ($(CONTAINER_TOOL),docker)
ifeq ($(findstring $(comma),$(PLATFORM)),)
_LOAD_FLAG := --load
endif
endif

# Resolve the docker subcommand once: `buildx build` if BUILDX=1 (and
# we're on docker), plain `build` otherwise.
ifeq ($(CONTAINER_TOOL),docker)
ifeq ($(BUILDX),1)
_BUILD_CMD := docker buildx build --platform $(PLATFORM) $(_LOAD_FLAG)
else
_BUILD_CMD := docker build --platform $(PLATFORM) $(_LOAD_FLAG)
endif
else
_BUILD_CMD := $(CONTAINER_TOOL) build --platform $(PLATFORM)
endif

container-image: ## Build the server OCI image (auto-detects podman/docker, override with CONTAINER_TOOL=)
	@command -v $(CONTAINER_TOOL) >/dev/null 2>&1 || { \
		echo "ERROR: '$(CONTAINER_TOOL)' not found. Install podman or docker, or override with CONTAINER_TOOL=."; \
		exit 1; \
	}
	@if [ "$(CONTAINER_TOOL)" = "podman" ]; then \
		if ! podman info >/dev/null 2>&1; then \
			if podman machine list --format '{{.Name}}' 2>/dev/null | grep -q .; then \
				echo "==> Podman daemon unreachable, attempting machine start..."; \
				start_out=$$(podman machine start 2>&1 || true); \
				if [ -n "$$start_out" ] && ! echo "$$start_out" | grep -qiE 'already running|machine .* is running'; then \
					echo "$$start_out"; \
				fi; \
				for i in 1 2 3 4 5 6 7 8 9 10; do \
					podman info >/dev/null 2>&1 && break; \
					sleep 1; \
				done; \
				podman info >/dev/null 2>&1 || { \
					echo "ERROR: podman daemon still unreachable after machine start."; \
					echo "       Output of last 'podman machine start':"; \
					echo "$$start_out" | sed 's/^/         /'; \
					echo "       Try: 'podman machine stop && podman machine start' manually."; \
					exit 1; \
				}; \
			else \
				echo "ERROR: podman is not running and no podman machine is configured."; \
				echo "       Run 'podman machine init' first, then retry."; \
				exit 1; \
			fi; \
		fi; \
	fi
	@echo "==> Building $(IMAGE_NAME):$(IMAGE_TAG) ($(PLATFORM), INCLUDE_SHELL=$(INCLUDE_SHELL)) with $(CONTAINER_TOOL)"
	$(_BUILD_CMD) \
		--build-arg INCLUDE_SHELL=$(INCLUDE_SHELL) \
		-f deploy/container/Containerfile \
		-t $(IMAGE_NAME):$(IMAGE_TAG) \
		-t $(IMAGE_NAME):latest \
		.
	@echo ""
	@echo "==> Built $(IMAGE_NAME):$(IMAGE_TAG) and $(IMAGE_NAME):latest"
	@echo "    Inspect: $(CONTAINER_TOOL) images $(IMAGE_NAME)"
	@echo "    Run:     make container-image-run"

container-image-test: ## Test the Wolfi runtime images (static checks; set SMOKE=1 to also build + run-smoke the image)
	@if [ "$(SMOKE)" = "1" ]; then \
		echo "==> Wolfi runtime tests (static + smoke build with $(CONTAINER_TOOL))"; \
		BV_CONTAINER_SMOKE=1 CONTAINER_TOOL=$(CONTAINER_TOOL) \
			bash deploy/container/test/wolfi-runtime.test.sh; \
	else \
		echo "==> Wolfi runtime tests (static only; pass SMOKE=1 to build + smoke-test)"; \
		bash deploy/container/test/wolfi-runtime.test.sh; \
	fi

container-image-run: ## Build (linux/arm64) and run the server image locally (config from deploy/container/config/)
	@$(MAKE) container-image PLATFORM=linux/arm64
	@echo "==> Running $(IMAGE_NAME):$(IMAGE_TAG) (linux/arm64)"
	$(CONTAINER_TOOL) run --rm -it \
		--platform linux/arm64 \
		-p 8200:8200 \
		-v $(PWD)/deploy/container/config:/etc/bvault/config:ro \
		$(IMAGE_NAME):$(IMAGE_TAG)

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
	$(CLI_LINUX_CARGO) build --release --bin bvault --target $(CLI_LINUX_TARGET)
	cargo deb --no-build --no-strip --target $(CLI_LINUX_TARGET)
	@echo ""
	@echo "==> .deb under target/$(CLI_LINUX_TARGET)/debian/:"
	@ls -lh target/$(CLI_LINUX_TARGET)/debian/*.deb 2>/dev/null || true

linux-cli-rpm: ## Build the bvault CLI .rpm (Linux amd64; cross-built via Docker on non-Linux hosts)
	@command -v cargo-generate-rpm >/dev/null 2>&1 || { \
		echo "ERROR: cargo-generate-rpm not installed. Run: cargo install cargo-generate-rpm"; \
		exit 1; \
	}
	$(_cli_require_cross)
	$(CLI_LINUX_CARGO) build --release --bin bvault --target $(CLI_LINUX_TARGET)
	cargo generate-rpm --target $(CLI_LINUX_TARGET) --arch $(CLI_LINUX_RPM_ARCH) --auto-req $(CLI_LINUX_AUTOREQ)
	@echo ""
	@echo "==> .rpm under target/$(CLI_LINUX_TARGET)/generate-rpm/:"
	@ls -lh target/$(CLI_LINUX_TARGET)/generate-rpm/*.rpm 2>/dev/null || true

linux-cli-packages: linux-cli-deb linux-cli-rpm ## Build both .deb and .rpm for the bvault CLI

# ── Windows CLI packages (packaging Phase 3, CLI side) ─────────────────
#
# Builds the bvault CLI .msi (WiX 3.x project at installers/cli/msi/
# bvault.wxs — Program Files install + system PATH entry) and a
# Chocolatey .nupkg (installers/cli/nupkg/ — choco auto-shims the exe).
# Both must run ON Windows: candle/light and choco are Windows tools.
#
# Pre-reqs (one-time):
#   .msi   — WiX Toolset 3.x with its bin/ on PATH (or pass
#            CANDLE=/LIGHT= with full paths).
#   .nupkg — Chocolatey (https://chocolatey.org/install).

CANDLE ?= candle
LIGHT  ?= light
CHOCO  ?= choco

windows-cli-msi: ## Build the bvault CLI .msi (WiX 3.x; output under target/msi/)
ifneq ($(OS),Windows_NT)
	@echo "ERROR: windows-cli-msi must run on Windows (WiX candle/light are Windows tools)."; exit 1
else
	@command -v $(CANDLE) >/dev/null 2>&1 || { \
		echo "ERROR: WiX 'candle' not found. Install the WiX 3.x toolset and put its bin/ on PATH,"; \
		echo "       or pass CANDLE=/LIGHT= with full paths."; \
		exit 1; \
	}
	cargo build --release --bin bvault
	@mkdir -p target/msi
	$(CANDLE) -nologo -arch x64 \
		-dVersion=$(VERSION) \
		-dBvaultExe=target/release/bvault.exe \
		-dLicenseRtf=installers/cli/msi/License.rtf \
		-out target/msi/bvault.wixobj \
		installers/cli/msi/bvault.wxs
	$(LIGHT) -nologo -ext WixUIExtension \
		-out target/msi/bvault-$(VERSION)-windows-x64.msi \
		target/msi/bvault.wixobj
	@echo ""
	@echo "==> .msi under target/msi/:"
	@ls -lh target/msi/*.msi 2>/dev/null || true
endif

windows-cli-nupkg: ## Build the bvault CLI Chocolatey .nupkg (output under target/nupkg/)
ifneq ($(OS),Windows_NT)
	@echo "ERROR: windows-cli-nupkg must run on Windows (choco is a Windows tool)."; exit 1
else
	@command -v $(CHOCO) >/dev/null 2>&1 || { \
		echo "ERROR: choco not found. Install Chocolatey: https://chocolatey.org/install"; \
		exit 1; \
	}
	cargo build --release --bin bvault
	@rm -rf target/nupkg/staging
	@mkdir -p target/nupkg/staging/tools
	cp installers/cli/nupkg/bastionvault-cli.nuspec target/nupkg/staging/
	cp installers/cli/nupkg/tools/LICENSE.txt \
	   installers/cli/nupkg/tools/VERIFICATION.txt \
	   target/nupkg/staging/tools/
	cp target/release/bvault.exe target/nupkg/staging/tools/
	cd target/nupkg/staging && $(CHOCO) pack bastionvault-cli.nuspec \
		--version $(VERSION) --outputdirectory ..
	@echo ""
	@echo "==> .nupkg under target/nupkg/:"
	@ls -lh target/nupkg/*.nupkg 2>/dev/null || true
endif

windows-cli-packages: windows-cli-msi windows-cli-nupkg ## Build both .msi and .nupkg for the bvault CLI

cli-packages: ## Build the bvault CLI packages for this host (Linux: deb+rpm, Windows: msi+nupkg)
ifeq ($(OS),Windows_NT)
	@$(MAKE) windows-cli-packages
else ifeq ($(shell uname -s),Linux)
	@$(MAKE) linux-cli-packages
else
	@echo "ERROR: no CLI package format for this host: .deb/.rpm build on Linux, .msi/.nupkg on Windows"; \
	echo "       (macOS .pkg is packaging Phase 2 — not wired yet)"; exit 1
endif

# ── Container image push (Sonatype Nexus, Docker Hub, GHCR, …) ─────────
#
# Two-step UX:
#   1. `make container-repo-setup` — interactive prompts; writes the
#      target registry config to `.container-repo.env` (gitignored).
#   2. `make container-image-push` — re-tags the local image and pushes
#      to whatever was saved. Builds the image first (via `make
#      container-image`) when no local `$(IMAGE_NAME):$(IMAGE_TAG)` exists.
#
# `.container-repo.env` is plain shell `KEY=value` lines so it can be
# sourced from the recipe and inspected with `cat`. We never write
# passwords; operators run `podman login` / `docker login` separately
# and the credential helpers handle the rest.

CONTAINER_REPO_ENV := .container-repo.env

container-repo-setup: ## Interactive setup: pick the target registry to push to (writes $(CONTAINER_REPO_ENV))
	@echo "==> Container image registry setup"
	@echo "    Saves to: $(CONTAINER_REPO_ENV) (gitignored)"
	@echo ""
	@echo "    Examples:"
	@echo "      Sonatype Nexus (port-based connector, e.g. 5000):"
	@echo "        REGISTRY=repo.example.com:5000   NAMESPACE=           IMAGE_NAME=bastionvault"
	@echo "      Sonatype Nexus (path-based routing):"
	@echo "        REGISTRY=repo.example.com        NAMESPACE=<repo>     IMAGE_NAME=bastionvault"
	@echo "      Docker Hub:"
	@echo "        REGISTRY=docker.io               NAMESPACE=<user|org> IMAGE_NAME=bastionvault"
	@echo "      GitHub Container Registry:"
	@echo "        REGISTRY=ghcr.io                 NAMESPACE=<user|org> IMAGE_NAME=bastionvault"
	@echo ""
	@printf "Registry hostname[:port]    [docker.io]: " ; read REG ; \
	 printf "Scheme (http|https)         [https]    : " ; read SCH ; \
	 printf "Namespace / repo path       [empty]    : " ; read NS  ; \
	 printf "Image name                  [bastionvault]: " ; read IMG ; \
	 printf "Default tag                 [$(VERSION)]: " ; read TAG ; \
	 REG=$${REG:-docker.io} ; \
	 SCH=$${SCH:-https} ; \
	 case "$$SCH" in http|https) ;; *) echo "ERROR: scheme must be http or https (got '$$SCH')"; exit 1 ;; esac ; \
	 IMG=$${IMG:-bastionvault} ; \
	 TAG=$${TAG:-$(VERSION)} ; \
	 { \
	   echo "# Generated by 'make container-repo-setup'."; \
	   echo "# Read by 'make container-image-push'. Do not commit."; \
	   echo "REGISTRY=$$REG"; \
	   echo "SCHEME=$$SCH"; \
	   echo "NAMESPACE=$$NS"; \
	   echo "IMAGE_NAME=$$IMG"; \
	   echo "DEFAULT_TAG=$$TAG"; \
	 } > $(CONTAINER_REPO_ENV)
	@echo ""
	@echo "==> Wrote $(CONTAINER_REPO_ENV):"
	@sed 's/^/    /' $(CONTAINER_REPO_ENV)
	@echo ""
	@echo "Next: log in to the registry with your container tool, then push."
	@echo "  $(CONTAINER_TOOL) login $$(grep '^REGISTRY=' $(CONTAINER_REPO_ENV) | cut -d= -f2)"
	@echo "  make container-image-push"

container-repo-show: ## Print the saved registry config from $(CONTAINER_REPO_ENV)
	@if [ ! -f $(CONTAINER_REPO_ENV) ]; then \
		echo "No registry configured yet. Run 'make container-repo-setup' first."; \
		exit 1; \
	fi
	@echo "==> $(CONTAINER_REPO_ENV)"
	@sed 's/^/    /' $(CONTAINER_REPO_ENV)

container-image-push: ## Build (if missing) + tag + push $(IMAGE_NAME):$(IMAGE_TAG) AND :latest to the saved registry. Override version with PUSH_TAG=
	@if [ ! -f $(CONTAINER_REPO_ENV) ]; then \
		echo "ERROR: no registry configured. Run 'make container-repo-setup' first."; \
		exit 1; \
	fi
	@command -v $(CONTAINER_TOOL) >/dev/null 2>&1 || { \
		echo "ERROR: '$(CONTAINER_TOOL)' not found."; exit 1; \
	}
	@if $(CONTAINER_TOOL) image inspect "$(IMAGE_NAME):$(IMAGE_TAG)" >/dev/null 2>&1 ; then \
		echo "==> using existing local image $(IMAGE_NAME):$(IMAGE_TAG)" ; \
	else \
		echo "==> local image $(IMAGE_NAME):$(IMAGE_TAG) not found — building it first" ; \
		$(MAKE) container-image ; \
	fi
	@. ./$(CONTAINER_REPO_ENV) ; \
	 SCHEME=$${SCHEME:-https} ; \
	 LOCAL_TAG="$(IMAGE_NAME):$(IMAGE_TAG)" ; \
	 VERSION_TAG="$${PUSH_TAG:-$(IMAGE_TAG)}" ; \
	 if [ -n "$$NAMESPACE" ]; then \
	   REMOTE_PFX="$$REGISTRY/$$NAMESPACE/$$IMAGE_NAME" ; \
	 else \
	   REMOTE_PFX="$$REGISTRY/$$IMAGE_NAME" ; \
	 fi ; \
	 REMOTE_VERSION="$$REMOTE_PFX:$$VERSION_TAG" ; \
	 REMOTE_LATEST="$$REMOTE_PFX:latest" ; \
	 if ! $(CONTAINER_TOOL) image inspect "$$LOCAL_TAG" >/dev/null 2>&1 ; then \
	   echo "ERROR: local image '$$LOCAL_TAG' still not found after build — check 'make container-image' output." ; \
	   exit 1 ; \
	 fi ; \
	 PUSH_FLAGS="" ; \
	 if [ "$$SCHEME" = "http" ]; then \
	   case "$(CONTAINER_TOOL)" in \
	     podman) PUSH_FLAGS="--tls-verify=false" ;; \
	     docker) \
	       echo "WARNING: SCHEME=http selected. Docker has no per-push insecure flag —" ; \
	       echo "         add \"$$REGISTRY\" to /etc/docker/daemon.json's" ; \
	       echo "         \"insecure-registries\" array and restart the daemon if the" ; \
	       echo "         push fails with a TLS error." ;; \
	   esac ; \
	 fi ; \
	 LOGIN_FLAGS="" ; \
	 if [ "$$SCHEME" = "http" ] && [ "$(CONTAINER_TOOL)" = "podman" ]; then \
	   LOGIN_FLAGS="--tls-verify=false" ; \
	 fi ; \
	 if $(CONTAINER_TOOL) login $$LOGIN_FLAGS --get-login "$$REGISTRY" >/dev/null 2>&1 ; then \
	   echo "==> already logged in to $$REGISTRY as $$($(CONTAINER_TOOL) login $$LOGIN_FLAGS --get-login $$REGISTRY 2>/dev/null)" ; \
	 else \
	   echo "==> not logged in to $$REGISTRY — running '$(CONTAINER_TOOL) login'" ; \
	   $(CONTAINER_TOOL) login $$LOGIN_FLAGS "$$REGISTRY" || { echo "ERROR: login to $$REGISTRY failed"; exit 1; } ; \
	 fi ; \
	 echo "==> tagging $$LOCAL_TAG as $$REMOTE_VERSION" ; \
	 $(CONTAINER_TOOL) tag "$$LOCAL_TAG" "$$REMOTE_VERSION" ; \
	 echo "==> tagging $$LOCAL_TAG as $$REMOTE_LATEST" ; \
	 $(CONTAINER_TOOL) tag "$$LOCAL_TAG" "$$REMOTE_LATEST" ; \
	 echo "==> pushing $$REMOTE_VERSION (scheme=$$SCHEME)" ; \
	 $(CONTAINER_TOOL) push $$PUSH_FLAGS "$$REMOTE_VERSION" ; \
	 echo "==> pushing $$REMOTE_LATEST (scheme=$$SCHEME)" ; \
	 $(CONTAINER_TOOL) push $$PUSH_FLAGS "$$REMOTE_LATEST"
	@echo ""
	@echo "==> Push complete."
	@echo "    If push failed with auth errors, run:"
	@. ./$(CONTAINER_REPO_ENV) ; \
	 if [ "$${SCHEME:-https}" = "http" ] && [ "$(CONTAINER_TOOL)" = "podman" ]; then \
	   echo "      $(CONTAINER_TOOL) login --tls-verify=false $$REGISTRY" ; \
	 else \
	   echo "      $(CONTAINER_TOOL) login $$REGISTRY" ; \
	 fi

clean: ## Remove Cargo build artefacts (target/) across the workspace
	cargo clean
	@echo "clean complete."

gui-clean: ## Remove GUI frontend build artefacts (node_modules, dist, vite cache)
	rm -rf gui/node_modules
	rm -rf gui/dist
	rm -rf gui/.vite
	rm -rf gui/src-tauri/target
	rm -rf gui/src-tauri/gen
	@echo "gui-clean complete."

docs-clean: ## Docsify has no build step — this target is a no-op kept for compatibility.
	@echo "docs-clean: Docsify is build-step-free; nothing to remove."

deep-clean: clean gui-clean docs-clean ## Run every clean target + drop cargo lockfiles so the next build resolves from scratch
	rm -f Cargo.lock
	rm -f gui/package-lock.json
	@echo "deep-clean complete."

target-size: ## Show which target/ subdirectories are eating disk
	@test -d target || { echo "target/ does not exist — nothing to measure"; exit 0; }
	@echo "==> target/ top-level"
	@du -sh target 2>/dev/null || true
	@echo "==> incremental caches (safe to delete; first rebuild will be slower)"
	@du -sh target/*/incremental 2>/dev/null || echo "  (none)"
	@echo "==> dep artefacts"
	@du -sh target/*/deps 2>/dev/null || echo "  (none)"
	@echo "==> full binaries"
	@du -sh target/*/bastion_vault* target/*/bvault* target/*/bastion-vault-gui* 2>/dev/null || echo "  (none)"

prune: ## Drop rustc incremental caches (saves GBs; next rebuild is slower but correct)
	@echo "==> Removing target/debug/incremental + target/release/incremental"
	@rm -rf target/debug/incremental 2>/dev/null || true
	@rm -rf target/release/incremental 2>/dev/null || true
	@rm -rf gui/src-tauri/target/debug/incremental 2>/dev/null || true
	@rm -rf gui/src-tauri/target/release/incremental 2>/dev/null || true
	@echo "==> If you want finer-grained cleanup, install cargo-sweep:"
	@echo "      cargo install cargo-sweep"
	@echo "    then: cargo sweep --time 7 --recursive"
	@echo "prune complete."

bootstrap: ## Install dependencies and set up the development environment
	rustup update stable
	cargo fetch
	cargo check
	@echo "Bootstrap complete."

win-bootstrap: ## Install Windows build deps (Perl, NASM, Node) via winget and adjust PATH
	@command -v winget >/dev/null 2>&1 || { echo "Error: winget not found. Install 'App Installer' from the Microsoft Store."; exit 1; }
	@echo "==> Installing Strawberry Perl (required for vendored OpenSSL)"
	@winget list --id StrawberryPerl.StrawberryPerl -e >/dev/null 2>&1 || \
		winget install --id StrawberryPerl.StrawberryPerl -e --accept-source-agreements --accept-package-agreements
	@echo "==> Installing NASM (required for OpenSSL asm optimizations)"
	@winget list --id NASM.NASM -e >/dev/null 2>&1 || \
		winget install --id NASM.NASM -e --accept-source-agreements --accept-package-agreements
	@echo "==> Installing Node.js LTS (required for GUI frontend)"
	@winget list --id OpenJS.NodeJS.LTS -e >/dev/null 2>&1 || \
		winget install --id OpenJS.NodeJS.LTS -e --accept-source-agreements --accept-package-agreements
	@echo "==> Updating Rust toolchain"
	@rustup update stable
	@echo ""
	@echo "==> scripts/win-env.sh exists (source it to set PATH and OPENSSL_SRC_PERL)"
	@test -f scripts/win-env.sh || { echo "ERROR: scripts/win-env.sh missing -- reinstall/clone repo"; exit 1; }
	@chmod +x scripts/win-env.sh 2>/dev/null || true
	@echo ""
	@echo "==> Detected install locations:"
	@test -d "/c/Strawberry/perl/bin"  && echo "  [OK]  Perl @ C:\\Strawberry\\perl\\bin"  || echo "  [MISS] Perl"
	@test -d "/c/Program Files/NASM"   && echo "  [OK]  NASM @ C:\\Program Files\\NASM"    || echo "  [MISS] NASM"
	@test -d "/c/Program Files/nodejs" && echo "  [OK]  Node @ C:\\Program Files\\nodejs"  || echo "  [MISS] Node"
	@echo ""
	@echo "win-bootstrap complete."
	@echo ""
	@echo "To use these tools in the current shell, run:"
	@echo "    source scripts/win-env.sh"
	@echo "Or open a new Git Bash shell so winget's PATH updates take effect."

# ── Reference plugins (plugins-ext/ submodule) ──────────────────────────
# Build the BastionVault-Plugins reference plugins. WASM plugins compile
# to wasm32-wasip1; process plugins compile native. Operators upload the
# resulting artefacts via the GUI's Plugins → Register flow.

PLUGINS_DIR := plugins-ext
PLUGINS_WASM_TARGET := wasm32-wasip1
PLUGINS_OUT := $(PLUGINS_DIR)/dist
# Where the dev signing key lives. The seed file is the secret half;
# the .pub file is what you register on the host as the publisher's
# allowlist entry. Override on the command line for CI / production
# (e.g. `make plugins-pack PLUGINS_SIGNING_KEY=keys/release`).
PLUGINS_SIGNING_KEY ?= $(PLUGINS_OUT)/dev-signing-key
PLUGINS_SIGNING_KEY_NAME ?= bastionvault-dev

# Target triple for the process-runtime plugins. Defaults to
# x86_64-unknown-linux-gnu (amd64 Linux) because that is what the
# BastionVault servers run — a .bvplugin packed with a host-native
# macOS/arm64 binary is rejected at invoke time with `Exec format
# error (os error 8)` (ENOEXEC: the Linux kernel can't execve a
# Mach-O). Defaulting to amd64 means `make plugins-pack` /
# `make plugins-sign` produce deployable bundles out of the box.
#
# Override for other deploy targets, or to build a host-native binary
# for local testing (empty = cargo's native target):
#
#   make plugins PLUGINS_PROCESS_TARGET=aarch64-unknown-linux-gnu  # arm64 Linux
#   make plugins PLUGINS_PROCESS_TARGET=                           # host native
#
# The rustup target is auto-installed via `plugins-process-target`.
# Cross-linkers / sysroots are NOT installed by this Makefile.
#
# When the target differs from the host (typical: macOS workstation
# cross-compiling to Linux), bare `cargo` will fail at the link step
# because clang on macOS doesn't speak GCC-style ELF linker flags.
# The auto-detect below routes the build through `cross`
# (https://github.com/cross-rs/cross) when:
#
#   - PLUGINS_PROCESS_TARGET is set
#   - PLUGINS_CARGO wasn't explicitly overridden
#   - `cross` is on PATH and Docker/Podman is running
#
# Force a specific runner with `PLUGINS_CARGO=cargo` (bare) or
# `PLUGINS_CARGO=cross` (always container). Install cross with
# `cargo install cross --git https://github.com/cross-rs/cross`.
PLUGINS_PROCESS_TARGET ?= x86_64-unknown-linux-gnu

# Host triple is detected once via rustc so we can compare against
# PLUGINS_PROCESS_TARGET. Older make doesn't shell well; fall back
# to empty if rustc isn't on PATH (and the comparison will treat the
# target as "not a cross-build", which is correct in that case).
ifeq ($(OS),Windows_NT)
PLUGINS_HOST_TARGET := $(shell powershell -NoProfile -ExecutionPolicy Bypass -Command "rustc -vV 2>\$$null | ForEach-Object { if (\$$_ -match '^host: (.*)') { \$$matches[1] } }")
else
PLUGINS_HOST_TARGET := $(shell rustc -vV 2>/dev/null | sed -n 's/^host: //p')
endif
PLUGINS_IS_CROSS := $(if $(PLUGINS_PROCESS_TARGET),$(if $(filter $(PLUGINS_PROCESS_TARGET),$(PLUGINS_HOST_TARGET)),,1),)
PLUGINS_HAS_CROSS := $(shell command -v cross >/dev/null 2>&1 && echo 1)

# Default runner: `cross` for cross-builds when available, else `cargo`.
# Override explicitly to opt out (`PLUGINS_CARGO=cargo`) or force
# (`PLUGINS_CARGO=cross`).
PLUGINS_CARGO ?= $(if $(and $(PLUGINS_IS_CROSS),$(PLUGINS_HAS_CROSS)),cross,cargo)

# Derived helpers so the recipes below stay readable.
#
# `_target_arg`   — empty when building for host, `--target <triple>`
#                   when cross-compiling. Spliced into the cargo line.
# `_target_dir`   — `target/release` for host builds, or
#                   `target/<triple>/release` for cross builds. This
#                   is where cargo drops the compiled binaries.
# `_exe`          — `.exe` for Windows targets (host OR cross), empty
#                   otherwise. Replaces the old `$(filter Windows_NT,$(OS))`
#                   check, which would mis-suffix when cross-compiling
#                   from a Windows host to Linux.
_target_arg := $(if $(PLUGINS_PROCESS_TARGET),--target $(PLUGINS_PROCESS_TARGET),)
_target_dir := $(if $(PLUGINS_PROCESS_TARGET),target/$(PLUGINS_PROCESS_TARGET)/release,target/release)
_is_windows_target := $(if $(PLUGINS_PROCESS_TARGET),$(findstring pc-windows,$(PLUGINS_PROCESS_TARGET)),$(filter Windows_NT,$(OS)))
_exe := $(if $(_is_windows_target),.exe,)

plugins-init: ## Initialise the BastionVault-Plugins submodule (first-time setup)
	@if [ ! -f "$(PLUGINS_DIR)/Cargo.toml" ]; then \
		echo "==> initialising plugins-ext submodule"; \
		git submodule update --init --recursive $(PLUGINS_DIR); \
	else \
		echo "==> plugins-ext already initialised"; \
	fi

plugins-target: ## Install the wasm32-wasip1 Rust target if missing
	@rustup target list --installed | grep -q '^$(PLUGINS_WASM_TARGET)$$' || { \
		echo "==> installing rustup target $(PLUGINS_WASM_TARGET)"; \
		rustup target add $(PLUGINS_WASM_TARGET); \
	}

plugins-process-target: ## Install the cross-compile target for process plugins if PLUGINS_PROCESS_TARGET is set
	@if [ -n "$(PLUGINS_PROCESS_TARGET)" ]; then \
		rustup target list --installed | grep -q '^$(PLUGINS_PROCESS_TARGET)$$' || { \
			echo "==> installing rustup target $(PLUGINS_PROCESS_TARGET)"; \
			rustup target add $(PLUGINS_PROCESS_TARGET); \
		}; \
	fi

plugins-pack-build: ## Build the bv-plugin-pack helper that produces .bvplugin bundles
	cargo build --release -p bv-plugin-pack

plugins-wasm: plugins-init plugins-target ## Compile the WASM reference plugins (release)
	@echo "==> building bastion-plugin-totp ($(PLUGINS_WASM_TARGET))"
	cd $(PLUGINS_DIR) && cargo build --release --target $(PLUGINS_WASM_TARGET) -p bastion-plugin-totp
	@mkdir -p $(PLUGINS_OUT)
	@cp $(PLUGINS_DIR)/target/$(PLUGINS_WASM_TARGET)/release/bastion_plugin_totp.wasm $(PLUGINS_OUT)/ 2>/dev/null \
		|| cp $(PLUGINS_DIR)/target/$(PLUGINS_WASM_TARGET)/release/bastion-plugin-totp.wasm $(PLUGINS_OUT)/
	@echo ""
	@echo "==> WASM plugins ready in $(PLUGINS_OUT)/"
	@ls -lh $(PLUGINS_OUT)/*.wasm 2>/dev/null || true

plugins-pack: plugins-wasm plugins-process plugins-pack-build ## Pack each plugin (WASM or process) + its plugin.toml into a .bvplugin bundle
	@# bv-plugin-pack always runs on the host, so its `.exe` suffix
	@# follows the host OS, not PLUGINS_PROCESS_TARGET. The packed
	@# binaries do follow the target — that's the whole point of
	@# `_exe` (see top of this section).
	$(eval _host_exe := $(if $(filter Windows_NT,$(OS)),.exe,))
	@echo "==> packing bastion-plugin-totp (wasm) into .bvplugin"
	./target/release/bv-plugin-pack$(_host_exe) \
		--manifest $(PLUGINS_DIR)/bastion-plugin-totp/plugin.toml \
		--binary   $(PLUGINS_OUT)/bastion_plugin_totp.wasm \
		--out      $(PLUGINS_OUT)/bastion-plugin-totp.bvplugin
	@echo "==> packing bastion-plugin-postgres (process) into .bvplugin"
	./target/release/bv-plugin-pack$(_host_exe) \
		--manifest $(PLUGINS_DIR)/bastion-plugin-postgres/plugin.toml \
		--binary   $(PLUGINS_OUT)/bastion-plugin-postgres$(_exe) \
		--out      $(PLUGINS_OUT)/bastion-plugin-postgres.bvplugin
	@echo "==> packing bastion-plugin-xca (process) into .bvplugin"
	./target/release/bv-plugin-pack$(_host_exe) \
		--manifest $(PLUGINS_DIR)/bastion-plugin-xca/plugin.toml \
		--binary   $(PLUGINS_OUT)/bastion-plugin-xca$(_exe) \
		--out      $(PLUGINS_OUT)/bastion-plugin-xca.bvplugin
	@echo "==> packing bastion-plugin-pmp (process) into .bvplugin"
	./target/release/bv-plugin-pack$(_host_exe) \
		--manifest $(PLUGINS_DIR)/bastion-plugin-pmp/plugin.toml \
		--binary   $(PLUGINS_OUT)/bastion-plugin-pmp$(_exe) \
		--out      $(PLUGINS_OUT)/bastion-plugin-pmp.bvplugin
	@echo ""
	@echo "==> Bundles ready in $(PLUGINS_OUT)/"
	@ls -lh $(PLUGINS_OUT)/*.bvplugin 2>/dev/null || true

plugins-keygen: plugins-pack-build ## Mint a fresh ML-DSA-65 dev signing keypair under $(PLUGINS_SIGNING_KEY)
	@mkdir -p $(dir $(PLUGINS_SIGNING_KEY))
	@if [ -f $(PLUGINS_SIGNING_KEY).seed ]; then \
		echo "==> $(PLUGINS_SIGNING_KEY).seed already exists; refusing to overwrite"; \
		echo "    Delete it first if you really want a new key."; \
		exit 1; \
	fi
	./target/release/bv-plugin-pack$(if $(filter Windows_NT,$(OS)),.exe,) \
		keygen --out $(PLUGINS_SIGNING_KEY)
	@echo ""
	@echo "==> register $(PLUGINS_SIGNING_KEY).pub on the host as publisher"
	@echo "    name=$(PLUGINS_SIGNING_KEY_NAME) so signed bundles validate."

plugins-sign: plugins-wasm plugins-process plugins-pack-build ## Repack each plugin with an ML-DSA-65 signature using $(PLUGINS_SIGNING_KEY).seed
	@if [ ! -f $(PLUGINS_SIGNING_KEY).seed ]; then \
		echo "==> $(PLUGINS_SIGNING_KEY).seed missing — run \`make plugins-keygen\` first"; \
		exit 1; \
	fi
	$(eval _host_exe := $(if $(filter Windows_NT,$(OS)),.exe,))
	@echo "==> signing bastion-plugin-totp (wasm)"
	./target/release/bv-plugin-pack$(_host_exe) \
		--manifest          $(PLUGINS_DIR)/bastion-plugin-totp/plugin.toml \
		--binary            $(PLUGINS_OUT)/bastion_plugin_totp.wasm \
		--out               $(PLUGINS_OUT)/bastion-plugin-totp.bvplugin \
		--signing-seed-file $(PLUGINS_SIGNING_KEY).seed \
		--signing-key-name  $(PLUGINS_SIGNING_KEY_NAME)
	@echo "==> signing bastion-plugin-postgres (process)"
	./target/release/bv-plugin-pack$(_host_exe) \
		--manifest          $(PLUGINS_DIR)/bastion-plugin-postgres/plugin.toml \
		--binary            $(PLUGINS_OUT)/bastion-plugin-postgres$(_exe) \
		--out               $(PLUGINS_OUT)/bastion-plugin-postgres.bvplugin \
		--signing-seed-file $(PLUGINS_SIGNING_KEY).seed \
		--signing-key-name  $(PLUGINS_SIGNING_KEY_NAME)
	@echo "==> signing bastion-plugin-xca (process)"
	./target/release/bv-plugin-pack$(_host_exe) \
		--manifest          $(PLUGINS_DIR)/bastion-plugin-xca/plugin.toml \
		--binary            $(PLUGINS_OUT)/bastion-plugin-xca$(_exe) \
		--out               $(PLUGINS_OUT)/bastion-plugin-xca.bvplugin \
		--signing-seed-file $(PLUGINS_SIGNING_KEY).seed \
		--signing-key-name  $(PLUGINS_SIGNING_KEY_NAME)
	@echo "==> signing bastion-plugin-pmp (process)"
	./target/release/bv-plugin-pack$(_host_exe) \
		--manifest          $(PLUGINS_DIR)/bastion-plugin-pmp/plugin.toml \
		--binary            $(PLUGINS_OUT)/bastion-plugin-pmp$(_exe) \
		--out               $(PLUGINS_OUT)/bastion-plugin-pmp.bvplugin \
		--signing-seed-file $(PLUGINS_SIGNING_KEY).seed \
		--signing-key-name  $(PLUGINS_SIGNING_KEY_NAME)
	@echo ""
	@echo "==> Signed bundles ready in $(PLUGINS_OUT)/"
	@echo "    Publisher pubkey to register on the host: $(PLUGINS_SIGNING_KEY).pub"
	@ls -lh $(PLUGINS_OUT)/*.bvplugin 2>/dev/null || true

plugins-process: plugins-init plugins-process-target ## Compile the process-runtime reference plugins (release, host or PLUGINS_PROCESS_TARGET)
	@# Guard against the common "bare cargo can't cross-link" trap.
	@# If we're cross-compiling and the operator hasn't routed
	@# through `cross` (and isn't using a known cross-toolchain
	@# linker), the link step will explode deep inside cargo with an
	@# inscrutable rust-lld error. Surface it now with a real fix.
	@if [ -n "$(PLUGINS_IS_CROSS)" ] && [ "$(PLUGINS_CARGO)" = "cargo" ]; then \
		echo "==> WARNING: cross-compiling $(PLUGINS_HOST_TARGET) → $(PLUGINS_PROCESS_TARGET) with bare cargo."; \
		echo "    This usually fails at link time (rust-lld can't accept GCC-style flags)."; \
		echo ""; \
		echo "    Fix: install \`cross\` and re-run — it'll be auto-detected:"; \
		echo "      cargo install cross --git https://github.com/cross-rs/cross"; \
		echo "      make plugins PLUGINS_PROCESS_TARGET=$(PLUGINS_PROCESS_TARGET)"; \
		echo ""; \
		echo "    \`cross\` needs Docker or Podman running. Override with"; \
		echo "    PLUGINS_CARGO=cargo to force bare cargo (you'll need a"; \
		echo "    matching cross-linker on PATH and CARGO_TARGET_*_LINKER set)."; \
		echo ""; \
	fi
	@echo "==> building bastion-plugin-postgres ($(if $(PLUGINS_PROCESS_TARGET),$(PLUGINS_PROCESS_TARGET),native)) via $(PLUGINS_CARGO)"
	cd $(PLUGINS_DIR) && $(PLUGINS_CARGO) build --release $(_target_arg) -p bastion-plugin-postgres
	@echo "==> building bastion-plugin-xca ($(if $(PLUGINS_PROCESS_TARGET),$(PLUGINS_PROCESS_TARGET),native)) via $(PLUGINS_CARGO)"
	cd $(PLUGINS_DIR) && $(PLUGINS_CARGO) build --release $(_target_arg) -p bastion-plugin-xca
	@echo "==> building bastion-plugin-pmp ($(if $(PLUGINS_PROCESS_TARGET),$(PLUGINS_PROCESS_TARGET),native)) via $(PLUGINS_CARGO)"
	cd $(PLUGINS_DIR) && $(PLUGINS_CARGO) build --release $(_target_arg) -p bastion-plugin-pmp
	@mkdir -p $(PLUGINS_OUT)
	@cp $(PLUGINS_DIR)/$(_target_dir)/bastion-plugin-postgres$(_exe) $(PLUGINS_OUT)/
	@cp $(PLUGINS_DIR)/$(_target_dir)/bastion-plugin-xca$(_exe)      $(PLUGINS_OUT)/
	@cp $(PLUGINS_DIR)/$(_target_dir)/bastion-plugin-pmp$(_exe)      $(PLUGINS_OUT)/
	@echo ""
	@echo "==> Process plugins ready in $(PLUGINS_OUT)/"
	@ls -lh $(PLUGINS_OUT)/bastion-plugin-postgres* $(PLUGINS_OUT)/bastion-plugin-xca* $(PLUGINS_OUT)/bastion-plugin-pmp* 2>/dev/null || true

plugins: plugins-pack plugins-process ## Build every reference plugin (WASM + .bvplugin bundle + process). Cross-compile with PLUGINS_PROCESS_TARGET=<triple>
	@echo ""
	@echo "==> All reference plugins built$(if $(PLUGINS_PROCESS_TARGET), for $(PLUGINS_PROCESS_TARGET),). Upload the artefacts via the GUI"
	@echo "   Plugins page (Admin → Plugins → Register plugin → Select file…),"
	@echo "   alongside the matching plugin.toml from $(PLUGINS_DIR)/<plugin>/."
	@if [ -z "$(PLUGINS_PROCESS_TARGET)" ]; then \
		echo ""; \
		echo "   WARNING: built host-native (PLUGINS_PROCESS_TARGET= override)."; \
		echo "   Process plugins will NOT run on an amd64 Linux server — the"; \
		echo "   invoke fails with 'Exec format error (os error 8)'. For a"; \
		echo "   deployable bundle, drop the override (defaults to amd64) or set:"; \
		echo "     make plugins PLUGINS_PROCESS_TARGET=x86_64-unknown-linux-gnu"; \
		echo "     make plugins PLUGINS_PROCESS_TARGET=aarch64-unknown-linux-gnu"; \
	fi

# `plugin-bump` bumps each reference plugin's version in lockstep across
# both `plugins-ext/<plugin>/Cargo.toml` and `plugins-ext/<plugin>/plugin.toml`.
# Override the bump kind on the command line: `make plugin-bump type=minor`
# (defaults to patch). Each plugin's current version is read from its own
# Cargo.toml so plugins that have drifted out of lockstep stay independent.
PLUGIN_NAMES := bastion-plugin-totp bastion-plugin-postgres bastion-plugin-xca bastion-plugin-pmp
type ?= patch

plugin-bump: ## Bump plugin versions across plugins-ext (type=major|minor|patch, default patch)
	@case "$(type)" in major|minor|patch) ;; *) echo "Invalid type=$(type) (use major|minor|patch)"; exit 1;; esac; \
	for p in $(PLUGIN_NAMES); do \
		CUR=$$(grep '^version' $(PLUGINS_DIR)/$$p/Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/'); \
		case "$(type)" in \
			major) NEW=$$(echo $$CUR | awk -F. '{printf "%d.0.0", $$1+1}');; \
			minor) NEW=$$(echo $$CUR | awk -F. '{printf "%d.%d.0", $$1, $$2+1}');; \
			patch) NEW=$$(echo $$CUR | awk -F. '{printf "%d.%d.%d", $$1, $$2, $$3+1}');; \
		esac; \
		sed -i.bak "s/^version = \"$$CUR\"/version = \"$$NEW\"/" $(PLUGINS_DIR)/$$p/Cargo.toml && rm -f $(PLUGINS_DIR)/$$p/Cargo.toml.bak; \
		sed -i.bak "s/^version     = \"$$CUR\"/version     = \"$$NEW\"/" $(PLUGINS_DIR)/$$p/plugin.toml && rm -f $(PLUGINS_DIR)/$$p/plugin.toml.bak; \
		echo "Bumped $$p: $$CUR -> $$NEW"; \
	done

plugins-clean: ## Remove plugins-ext build artefacts
	@rm -rf $(PLUGINS_DIR)/target $(PLUGINS_OUT)
	@echo "plugins-clean complete."

# Plugin unit-test infrastructure (features/plugin-testing.md).
# Three layers, cheapest first:
#   1. testkit self-tests   — the mock host + form-hook runner
#   2. ABI parity           — testkit's conformance module through the
#                             REAL WasmRuntime, so the mock can't drift
#                             from src/plugins/runtime.rs
#   3. host substrate tests — the in-crate `plugins::` module tests
#                             (runtime, catalog, manifest, verifier…)
plugins-test: ## Run plugin unit tests: testkit, host ABI parity, plugin substrate
	@echo "==> bastion-plugin-testkit unit tests"
	cargo test -p bastion-plugin-testkit
	@echo "==> ABI parity: testkit vs src/plugins/runtime.rs"
	cargo test --test test_plugin_testkit_parity
	@echo "==> host plugin substrate unit tests (src/plugins/*)"
	cargo test --lib plugins::
	@echo ""
	@echo "==> plugins-test complete."
