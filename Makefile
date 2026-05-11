.DEFAULT_GOAL := help

VERSION := $(shell grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')

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

.PHONY: help build run-dev run-dev-gui gui-deps gui-build gui-test gui-check docs bump-minor bump-major bump-patch _bump-write bootstrap win-bootstrap clean gui-clean docs-clean deep-clean prune prune-stale target-size plugins-init plugins-target plugins-process-target plugins-wasm plugins-process plugins plugins-clean plugins-pack plugins-pack-build plugins-keygen plugins-sign plugin-bump container-image container-image-run container-repo-setup container-repo-show container-image-push linux-cli-deb linux-cli-rpm linux-cli-packages

# Number of rustc incremental sessions to keep per crate. Anything
# older than the Nth most recent is reaped by `prune-stale`. Override
# from the command line — e.g. `make build KEEP=5` — when debugging
# an incremental-compilation bug where older generations need to
# stick around.
KEEP ?= 3

help: ## List available commands
	@echo "BastionVault v$(VERSION)"
	@echo ""
	@echo "Usage: make <target>"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*##"}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

prune-stale: ## Trim rustc incremental caches to the last KEEP sessions (default 3). Auto-runs before every compiling target.
	@KEEP=$(KEEP) bash scripts/prune-incremental.sh

build: prune-stale ## Build the project in release mode
	cargo build --release

run-dev: prune-stale ## Run the development server
	CARGO_BUILD_JOBS=6 cargo run -- server --config config/dev.hcl

gui-deps: ## Install GUI frontend dependencies
	cd gui && npm install

# `--features` lists are explicit (not relying solely on the Tauri
# crate's `default = [...]`) so an operator skimming the Makefile
# can see exactly what the dev / prod GUI binaries ship with.
# `ssh_pqc` enables ML-DSA-65 SSH CA generation in the /ssh page.
run-dev-gui: gui-deps prune-stale ## Run the desktop GUI in dev mode with local MCP bridge enabled
	cd gui && CARGO_BUILD_JOBS=6 BASTION_EMBEDDED_STORAGE=file BASTION_TAURI_MCP=1 npx tauri dev -- --features storage_hiqlite,mcp_local_dev,ssh_pqc

run-dev-gui-hiqlite: gui-deps prune-stale ## Run the desktop GUI in dev mode, embedded vault on hiqlite (ports 8210/8220)
	cd gui && CARGO_BUILD_JOBS=6 BASTION_EMBEDDED_STORAGE=hiqlite npx tauri dev -- --features storage_hiqlite,ssh_pqc

# Lightest dev build: Tauri host + vite, with `bastion_vault` pulled
# in at default-features=false. That means no hiqlite (no Raft/SQLite
# compile), no cloud storage targets, no PQC SSH — just the bare
# minimum needed for the GUI to talk to an external bvault server via
# the Connect page. Local Vault profiles that depend on those
# features won't work in this build; that's the trade-off for the
# faster compile.
run-dev-gui-only: gui-deps prune-stale ## Run the desktop GUI in dev mode with no backend storage features (lightest compile)
	cd gui && CARGO_BUILD_JOBS=6 npx tauri dev -- --no-default-features

gui-build: gui-deps prune-stale ## Build the desktop GUI for production
	cd gui && npx tauri build -- --features storage_hiqlite,ssh_pqc

gui-test: gui-deps ## Run GUI frontend tests (Vitest)
	cd gui && npx vitest run

gui-check: gui-deps ## Type-check and lint the GUI frontend
	cd gui && npx tsc --noEmit && npx vite build

docs: ## Start the documentation site locally
	cd docs && npm install && npx docusaurus clear && npx docusaurus start

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
SED_INPLACE := $(shell sed --version >/dev/null 2>&1 && echo "sed -i" || echo "sed -i ''")

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
#   make container-image INCLUDE_SHELL=1         # bake busybox /bin/sh in
#
# `BUILDX` toggles `docker buildx build` (multi-arch capable) when
# CONTAINER_TOOL=docker. Podman handles --platform natively so the toggle
# has no effect there.
#
# `INCLUDE_SHELL` (0|1, default 0) controls whether the production image
# carries a shell. Off by default to preserve the classic shell-less
# distroless property (smallest attack surface, no /bin/sh available
# inside the container at all). Set to 1 to stage `busybox-static` from
# a Debian builder layer and copy it into the runtime as /bin/busybox
# with /bin/sh -> busybox. The :debug variant always has a shell and is
# unaffected by this flag.

CONTAINER_TOOL ?= $(shell command -v podman >/dev/null 2>&1 && echo podman || echo docker)
IMAGE_NAME     ?= bastionvault
IMAGE_TAG      ?= $(VERSION)
BUILDX         ?= 0
INCLUDE_SHELL  ?= 0

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

# Resolve the docker subcommand once: `buildx build` if BUILDX=1 (and
# we're on docker), plain `build` otherwise.
ifeq ($(CONTAINER_TOOL),docker)
ifeq ($(BUILDX),1)
_BUILD_CMD := docker buildx build --platform $(PLATFORM)
else
_BUILD_CMD := docker build --platform $(PLATFORM)
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
				running=$$(podman machine list --format '{{.Running}}' 2>/dev/null | grep -c true || true); \
				if [ "$$running" -eq 0 ]; then \
					echo "==> Podman machine not running, starting it..."; \
					podman machine start || { echo "ERROR: failed to start podman machine"; exit 1; }; \
				fi; \
				for i in 1 2 3 4 5 6 7 8 9 10; do \
					podman info >/dev/null 2>&1 && break; \
					sleep 1; \
				done; \
				podman info >/dev/null 2>&1 || { echo "ERROR: podman machine started but daemon not responding"; exit 1; }; \
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
# CLI on the host's native arch. Static assets (manpage, completions)
# live under installers/cli/ and are referenced by `[package.metadata.deb]`
# + `[package.metadata.generate-rpm]` in Cargo.toml.
#
# Pre-reqs (one-time): `cargo install cargo-deb cargo-generate-rpm`.
# These targets do NOT auto-install the helpers — installing build-time
# tooling automatically inside `make` would surprise CI.

linux-cli-deb: ## Build the bvault CLI .deb (cargo-deb; output under target/debian/)
	@command -v cargo-deb >/dev/null 2>&1 || { \
		echo "ERROR: cargo-deb not installed. Run: cargo install cargo-deb"; \
		exit 1; \
	}
	cargo deb --no-strip
	@echo ""
	@echo "==> .deb under target/debian/:"
	@ls -lh target/debian/*.deb 2>/dev/null || true

linux-cli-rpm: ## Build the bvault CLI .rpm (cargo-generate-rpm; output under target/generate-rpm/)
	@command -v cargo-generate-rpm >/dev/null 2>&1 || { \
		echo "ERROR: cargo-generate-rpm not installed. Run: cargo install cargo-generate-rpm"; \
		exit 1; \
	}
	cargo build --release --bin bvault
	cargo generate-rpm
	@echo ""
	@echo "==> .rpm under target/generate-rpm/:"
	@ls -lh target/generate-rpm/*.rpm 2>/dev/null || true

linux-cli-packages: linux-cli-deb linux-cli-rpm ## Build both .deb and .rpm for the bvault CLI

# ── Container image push (Sonatype Nexus, Docker Hub, GHCR, …) ─────────
#
# Two-step UX:
#   1. `make container-repo-setup` — interactive prompts; writes the
#      target registry config to `.container-repo.env` (gitignored).
#   2. `make container-image-push` — re-tags the local image and pushes
#      to whatever was saved.
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

container-image-push: ## Tag + push $(IMAGE_NAME):$(IMAGE_TAG) AND :latest to the saved registry. Override version with PUSH_TAG=
	@if [ ! -f $(CONTAINER_REPO_ENV) ]; then \
		echo "ERROR: no registry configured. Run 'make container-repo-setup' first."; \
		exit 1; \
	fi
	@command -v $(CONTAINER_TOOL) >/dev/null 2>&1 || { \
		echo "ERROR: '$(CONTAINER_TOOL)' not found."; exit 1; \
	}
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
	   echo "ERROR: local image '$$LOCAL_TAG' not found. Build it first:" ; \
	   echo "  make container-image" ; \
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

docs-clean: ## Remove docs-site build artefacts (node_modules, .docusaurus, build)
	rm -rf docs/node_modules
	rm -rf docs/.docusaurus
	rm -rf docs/build
	@echo "docs-clean complete."

deep-clean: clean gui-clean docs-clean ## Run every clean target + drop cargo lockfiles so the next build resolves from scratch
	rm -f Cargo.lock
	rm -f gui/package-lock.json
	rm -f docs/package-lock.json
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

# Target triple for the process-runtime plugins. Empty (the default)
# means "build for the current host" — cargo's native target. Set
# this to cross-compile for a different OS/arch, e.g. when packaging
# Linux binaries from a macOS workstation for a Linux container:
#
#   make plugins PLUGINS_PROCESS_TARGET=x86_64-unknown-linux-gnu
#   make plugins PLUGINS_PROCESS_TARGET=aarch64-unknown-linux-gnu
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
PLUGINS_PROCESS_TARGET ?=

# Host triple is detected once via rustc so we can compare against
# PLUGINS_PROCESS_TARGET. Older make doesn't shell well; fall back
# to empty if rustc isn't on PATH (and the comparison will treat the
# target as "not a cross-build", which is correct in that case).
PLUGINS_HOST_TARGET := $(shell rustc -vV 2>/dev/null | sed -n 's/^host: //p')
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
		echo "   Built for the host. To target a Linux server from this workstation:"; \
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
