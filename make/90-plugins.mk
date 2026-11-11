# Plugins — Reference plugins, signing, dynamic-engine plugin tests.
# Included by the top-level Makefile; do not run standalone.

##@ Plugins

.PHONY: plugins-init plugins-target plugins-process-target plugins-pack-build plugins-wasm plugins-pack plugins-keygen plugins-sign plugins-process plugins plugin-bump plugins-clean plugins-test test-dbms dynamic-plugins-test dynamic-plugins-live

# ── Reference plugins (plugins-ext/ submodule) ──────────────────────────
# Build the BastionVault-Plugins reference plugins. WASM plugins compile
# to wasm32-unknown-unknown; process plugins compile native. Operators upload the
# resulting artefacts via the GUI's Plugins → Register flow.

PLUGINS_DIR := plugins-ext
# Every plugin the WASM host loads builds for wasm32-unknown-unknown, NOT
# wasm32-wasip1: the host links only the `bv` import module (no WASI), so a
# module importing `wasi_snapshot_preview1` cannot be instantiated and the
# catalog now refuses to register one. Do not switch this back to wasip1.
PLUGINS_WASM_TARGET := wasm32-unknown-unknown
PLUGINS_OUT := $(PLUGINS_DIR)/dist

# Dedicated target directory for the `bv-plugin-pack` signer/packer.
#
# `bv-plugin-pack` is a *root-workspace* member (crates/bv-plugin-pack),
# so a plain `cargo build -p bv-plugin-pack` drops it into the shared
# `./target` alongside the Tauri GUI (`gui/src-tauri`, also a root
# member). The two builds resolve the workspace with different feature
# unification and profiles, so alternating between `make plugins*` and
# `tauri dev` makes cargo re-fingerprint shared dependencies and forces
# a spurious GUI recompile. Building the packer into its own target dir
# breaks that ping-pong: packing/signing/rebuilding plugins never
# invalidates the GUI's cache. The reference plugins themselves already
# build into the isolated `plugins-ext/target`, so this closes the last
# path that leaked plugin work into the app's `./target`.
#
# Kept out of git (.gitignore) and the Tauri file watcher
# (gui/src-tauri/.taurignore).
PLUGINS_PACK_TARGET_DIR ?= target-plugin-pack
_host_exe := $(if $(filter Windows_NT,$(OS)),.exe,)
BV_PLUGIN_PACK := ./$(PLUGINS_PACK_TARGET_DIR)/release/bv-plugin-pack$(_host_exe)
# Where the signing key lives. The seed file is the secret half; the
# .pub file is what you register on the host as the publisher's
# allowlist entry. The default key + publisher name MUST agree: the
# host verifies a bundle's signature against the allowlist entry named
# by `PLUGINS_SIGNING_KEY_NAME`, so signing with a seed whose public
# half is registered under a *different* name fails verification with
# "signature verification failed against publisher <name>". Override
# both together on the command line for CI / production
# (e.g. `make plugins-sign PLUGINS_SIGNING_KEY=keys/release PLUGINS_SIGNING_KEY_NAME=acme-release`).
PLUGINS_SIGNING_KEY ?= $(PLUGINS_OUT)/hml-signing-key
PLUGINS_SIGNING_KEY_NAME ?= bastionvault-hml

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

# `cross` runs cargo from an x86_64 Linux container and therefore mirrors the
# active host toolchain as `<channel>-x86_64-unknown-linux-gnu`.  On non-Linux
# hosts, rustup 1.29+ refuses to install that executable toolchain unless the
# caller explicitly acknowledges it with `--force-non-host`.  cross 0.2.5 does
# not pass the flag itself (cross-rs/cross#1649), so install the exact sysroot
# name cross will request before invoking it.  This is separate from adding the
# process plugin's compilation target to the native host toolchain below.
PLUGINS_CROSS_HOST_TARGET := x86_64-unknown-linux-gnu
PLUGINS_CROSS_TOOLCHAIN := $(subst $(PLUGINS_HOST_TARGET),$(PLUGINS_CROSS_HOST_TARGET),$(notdir $(shell rustc --print sysroot 2>/dev/null)))
PLUGINS_NEEDS_CROSS_TOOLCHAIN := $(if $(and $(PLUGINS_IS_CROSS),$(filter cross,$(notdir $(PLUGINS_CARGO))),$(filter-out $(PLUGINS_CROSS_HOST_TARGET),$(PLUGINS_HOST_TARGET))),1,)

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

# Environment for container builds of the process plugins.
#
# `cd plugins-ext && cross build` runs cargo inside a container whose
# project root is the plugins-ext workspace, so neither this repo's
# `Cross.toml` nor its `.cargo/config.toml` is on the config-discovery
# path any more. Three things break:
#
#   - the SDK manifest (`crates/bastion-plugin-sdk`) declares its deps
#     with `registry = "uox-bastionvault"`, and the container has no
#     such registry, so the build dies before compiling anything with
#     `registry index was not found in any configuration`;
#   - `Cross.toml`'s glibc 2.17 image pin is ignored, so plugins would
#     silently link against the default image's glibc 2.39 and refuse
#     to start on RHEL 8/9 — the exact trap that pin exists to avoid.
#   - the manylinux image is multi-arch, but cross 0.2.5 mounts an x86_64
#     Linux Rust toolchain regardless of the host architecture. Docker Desktop
#     otherwise selects the native arm64 image on Apple Silicon, where that
#     toolchain cannot start because its x86_64 ELF loader is absent.
#
# `CROSS_CONFIG` points cross back at the repo-root `Cross.toml`, whose
# `[build.env] passthrough` forwards the two registry indexes into the
# container. `DOCKER_DEFAULT_PLATFORM` selects the matching x86_64 image
# variant for cross without changing the operator's global Docker settings.
# The indexes are read out of `.cargo/config.toml` so this stays a single
# source of truth. Harmless when the runner is bare `cargo`: the values match
# what it reads from the file anyway, and cargo ignores the Docker variable.
_registry_index = $(shell sed -n 's/^$(1) = { index = "\(.*\)" }.*/\1/p' .cargo/config.toml)
_plugins_cross_env := \
	CROSS_CONFIG='$(CURDIR)/Cross.toml' \
	DOCKER_DEFAULT_PLATFORM=linux/amd64 \
	CARGO_REGISTRIES_UOX_BASTIONVAULT_INDEX=$(call _registry_index,uox-bastionvault) \
	CARGO_REGISTRIES_UOX_FERROGATE_INDEX=$(call _registry_index,uox-ferrogate)

plugins-init: ## Initialise the BastionVault-Plugins submodule (first-time setup)
	@if [ ! -f "$(PLUGINS_DIR)/Cargo.toml" ]; then \
		echo "==> initialising plugins-ext submodule"; \
		git submodule update --init --recursive $(PLUGINS_DIR); \
	else \
		echo "==> plugins-ext already initialised"; \
	fi

plugins-target: ## Install the wasm32-unknown-unknown Rust target if missing
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
	@if [ -n "$(PLUGINS_NEEDS_CROSS_TOOLCHAIN)" ]; then \
		if [ -z "$(PLUGINS_CROSS_TOOLCHAIN)" ]; then \
			echo "ERROR: could not determine the Linux toolchain required by cross."; \
			exit 1; \
		fi; \
		rustup toolchain list | sed 's/ (.*)$$//' | grep -q '^$(PLUGINS_CROSS_TOOLCHAIN)$$' || { \
			echo "==> installing cross container toolchain $(PLUGINS_CROSS_TOOLCHAIN)"; \
			rustup toolchain add $(PLUGINS_CROSS_TOOLCHAIN) --profile minimal --force-non-host; \
		}; \
	fi

plugins-pack-build: ## Build the bv-plugin-pack helper that produces .bvplugin bundles
	CARGO_TARGET_DIR=$(PLUGINS_PACK_TARGET_DIR) cargo build --release -p bv-plugin-pack

plugins-wasm: plugins-init plugins-target ## Compile the WASM reference plugins (release)
	@echo "==> building bastion-plugin-totp ($(PLUGINS_WASM_TARGET))"
	cd $(PLUGINS_DIR) && cargo build --release --target $(PLUGINS_WASM_TARGET) -p bastion-plugin-totp
	@echo "==> building bastion-plugin-webhook-notify ($(PLUGINS_WASM_TARGET))"
	cd $(PLUGINS_DIR) && cargo build --release --target $(PLUGINS_WASM_TARGET) -p bastion-plugin-webhook-notify
	@echo "==> building bastion-plugin-self-accounts ($(PLUGINS_WASM_TARGET))"
	cd $(PLUGINS_DIR) && cargo build --release --target $(PLUGINS_WASM_TARGET) -p bastion-plugin-self-accounts
	@mkdir -p $(PLUGINS_OUT)
	@cp $(PLUGINS_DIR)/target/$(PLUGINS_WASM_TARGET)/release/bastion_plugin_self_accounts.wasm $(PLUGINS_OUT)/
	@cp $(PLUGINS_DIR)/target/$(PLUGINS_WASM_TARGET)/release/bastion_plugin_totp.wasm $(PLUGINS_OUT)/ 2>/dev/null \
		|| cp $(PLUGINS_DIR)/target/$(PLUGINS_WASM_TARGET)/release/bastion-plugin-totp.wasm $(PLUGINS_OUT)/
	@cp $(PLUGINS_DIR)/target/$(PLUGINS_WASM_TARGET)/release/bastion_plugin_webhook_notify.wasm $(PLUGINS_OUT)/ 2>/dev/null \
		|| cp $(PLUGINS_DIR)/target/$(PLUGINS_WASM_TARGET)/release/bastion-plugin-webhook-notify.wasm $(PLUGINS_OUT)/
	@echo ""
	@echo "==> WASM plugins ready in $(PLUGINS_OUT)/"
	@ls -lh $(PLUGINS_OUT)/*.wasm 2>/dev/null || true

plugins-pack: plugins-wasm plugins-process plugins-pack-build ## Pack each plugin (WASM or process) + its plugin.toml into a .bvplugin bundle
	@# bv-plugin-pack always runs on the host, so its `.exe` suffix
	@# (baked into $(BV_PLUGIN_PACK) via the global `_host_exe`) follows
	@# the host OS, not PLUGINS_PROCESS_TARGET. The packed binaries do
	@# follow the target — that's the whole point of `_exe` (see top of
	@# this section).
	@echo "==> packing bastion-plugin-totp (wasm) into .bvplugin"
	$(BV_PLUGIN_PACK) \
		--manifest $(PLUGINS_DIR)/bastion-plugin-totp/plugin.toml \
		--binary   $(PLUGINS_OUT)/bastion_plugin_totp.wasm \
		--out      $(PLUGINS_OUT)/bastion-plugin-totp.bvplugin
	@echo "==> packing bastion-plugin-postgres (process) into .bvplugin"
	$(BV_PLUGIN_PACK) \
		--manifest $(DYNAMIC_PLUGINS_DIR)/bastion-plugin-postgres/plugin.toml \
		--binary   $(PLUGINS_OUT)/bastion-plugin-postgres$(_exe) \
		--out      $(PLUGINS_OUT)/bastion-plugin-postgres.bvplugin
	@echo "==> packing bastion-plugin-xca (process) into .bvplugin"
	$(BV_PLUGIN_PACK) \
		--manifest $(PLUGINS_DIR)/bastion-plugin-xca/plugin.toml \
		--binary   $(PLUGINS_OUT)/bastion-plugin-xca$(_exe) \
		--out      $(PLUGINS_OUT)/bastion-plugin-xca.bvplugin
	@echo "==> packing bastion-plugin-pmp (process) into .bvplugin"
	$(BV_PLUGIN_PACK) \
		--manifest $(PLUGINS_DIR)/bastion-plugin-pmp/plugin.toml \
		--binary   $(PLUGINS_OUT)/bastion-plugin-pmp$(_exe) \
		--out      $(PLUGINS_OUT)/bastion-plugin-pmp.bvplugin
	@echo "==> packing bastion-plugin-email (process) into .bvplugin"
	$(BV_PLUGIN_PACK) \
		--manifest $(PLUGINS_DIR)/bastion-plugin-email/plugin.toml \
		--binary   $(PLUGINS_OUT)/bastion-plugin-email$(_exe) \
		--out      $(PLUGINS_OUT)/bastion-plugin-email.bvplugin
	@echo "==> packing bastion-plugin-dbms-management (process) into .bvplugin"
	$(BV_PLUGIN_PACK) \
		--manifest $(PLUGINS_DIR)/bastion-plugin-dbms-management/plugin.toml \
		--binary   $(PLUGINS_OUT)/bastion-plugin-dbms-management$(_exe) \
		--out      $(PLUGINS_OUT)/bastion-plugin-dbms-management.bvplugin
	@echo "==> packing bastion-plugin-webhook-notify (wasm app-module) into .bvplugin"
	$(BV_PLUGIN_PACK) \
		--manifest $(PLUGINS_DIR)/bastion-plugin-webhook-notify/plugin.toml \
		--binary   $(PLUGINS_OUT)/bastion_plugin_webhook_notify.wasm \
		--out      $(PLUGINS_OUT)/bastion-plugin-webhook-notify.bvplugin
	@echo "==> packing bastion-plugin-self-accounts (wasm credential provider) into .bvplugin"
	@echo "    embeds the validated sibling surface.json in the v2 bundle"
	$(BV_PLUGIN_PACK) \
		--manifest $(PLUGINS_DIR)/bastion-plugin-self-accounts/plugin.toml \
		--binary   $(PLUGINS_OUT)/bastion_plugin_self_accounts.wasm \
		--out      $(PLUGINS_OUT)/bastion-plugin-self-accounts.bvplugin
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
	$(BV_PLUGIN_PACK) \
		keygen --out $(PLUGINS_SIGNING_KEY)
	@echo ""
	@echo "==> register $(PLUGINS_SIGNING_KEY).pub on the host as publisher"
	@echo "    name=$(PLUGINS_SIGNING_KEY_NAME) so signed bundles validate."

plugins-sign: plugins-wasm plugins-process plugins-pack-build ## Repack each plugin with an ML-DSA-65 signature using $(PLUGINS_SIGNING_KEY).seed
	@if [ ! -f $(PLUGINS_SIGNING_KEY).seed ]; then \
		echo "==> $(PLUGINS_SIGNING_KEY).seed missing — run \`make plugins-keygen\` first"; \
		exit 1; \
	fi
	@echo "==> signing bastion-plugin-totp (wasm)"
	$(BV_PLUGIN_PACK) \
		--manifest          $(PLUGINS_DIR)/bastion-plugin-totp/plugin.toml \
		--binary            $(PLUGINS_OUT)/bastion_plugin_totp.wasm \
		--out               $(PLUGINS_OUT)/bastion-plugin-totp.bvplugin \
		--signing-seed-file $(PLUGINS_SIGNING_KEY).seed \
		--signing-key-name  $(PLUGINS_SIGNING_KEY_NAME)
	@echo "==> signing bastion-plugin-postgres (process)"
	$(BV_PLUGIN_PACK) \
		--manifest          $(DYNAMIC_PLUGINS_DIR)/bastion-plugin-postgres/plugin.toml \
		--binary            $(PLUGINS_OUT)/bastion-plugin-postgres$(_exe) \
		--out               $(PLUGINS_OUT)/bastion-plugin-postgres.bvplugin \
		--signing-seed-file $(PLUGINS_SIGNING_KEY).seed \
		--signing-key-name  $(PLUGINS_SIGNING_KEY_NAME)
	@echo "==> signing bastion-plugin-xca (process)"
	$(BV_PLUGIN_PACK) \
		--manifest          $(PLUGINS_DIR)/bastion-plugin-xca/plugin.toml \
		--binary            $(PLUGINS_OUT)/bastion-plugin-xca$(_exe) \
		--out               $(PLUGINS_OUT)/bastion-plugin-xca.bvplugin \
		--signing-seed-file $(PLUGINS_SIGNING_KEY).seed \
		--signing-key-name  $(PLUGINS_SIGNING_KEY_NAME)
	@echo "==> signing bastion-plugin-pmp (process)"
	$(BV_PLUGIN_PACK) \
		--manifest          $(PLUGINS_DIR)/bastion-plugin-pmp/plugin.toml \
		--binary            $(PLUGINS_OUT)/bastion-plugin-pmp$(_exe) \
		--out               $(PLUGINS_OUT)/bastion-plugin-pmp.bvplugin \
		--signing-seed-file $(PLUGINS_SIGNING_KEY).seed \
		--signing-key-name  $(PLUGINS_SIGNING_KEY_NAME)
	@echo "==> signing bastion-plugin-email (process)"
	$(BV_PLUGIN_PACK) \
		--manifest          $(PLUGINS_DIR)/bastion-plugin-email/plugin.toml \
		--binary            $(PLUGINS_OUT)/bastion-plugin-email$(_exe) \
		--out               $(PLUGINS_OUT)/bastion-plugin-email.bvplugin \
		--signing-seed-file $(PLUGINS_SIGNING_KEY).seed \
		--signing-key-name  $(PLUGINS_SIGNING_KEY_NAME)
	@echo "==> signing bastion-plugin-dbms-management (process)"
	$(BV_PLUGIN_PACK) \
		--manifest          $(PLUGINS_DIR)/bastion-plugin-dbms-management/plugin.toml \
		--binary            $(PLUGINS_OUT)/bastion-plugin-dbms-management$(_exe) \
		--out               $(PLUGINS_OUT)/bastion-plugin-dbms-management.bvplugin \
		--signing-seed-file $(PLUGINS_SIGNING_KEY).seed \
		--signing-key-name  $(PLUGINS_SIGNING_KEY_NAME)
	@echo "==> signing bastion-plugin-webhook-notify (wasm app-module)"
	$(BV_PLUGIN_PACK) \
		--manifest          $(PLUGINS_DIR)/bastion-plugin-webhook-notify/plugin.toml \
		--binary            $(PLUGINS_OUT)/bastion_plugin_webhook_notify.wasm \
		--out               $(PLUGINS_OUT)/bastion-plugin-webhook-notify.bvplugin \
		--signing-seed-file $(PLUGINS_SIGNING_KEY).seed \
		--signing-key-name  $(PLUGINS_SIGNING_KEY_NAME)
	@echo "==> signing bastion-plugin-self-accounts (wasm credential provider)"
	$(BV_PLUGIN_PACK) \
		--manifest          $(PLUGINS_DIR)/bastion-plugin-self-accounts/plugin.toml \
		--binary            $(PLUGINS_OUT)/bastion_plugin_self_accounts.wasm \
		--out               $(PLUGINS_OUT)/bastion-plugin-self-accounts.bvplugin \
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
	cd $(DYNAMIC_PLUGINS_DIR) && $(_plugins_cross_env) $(PLUGINS_CARGO) build --release $(_target_arg) -p bastion-plugin-postgres
	@echo "==> building bastion-plugin-xca ($(if $(PLUGINS_PROCESS_TARGET),$(PLUGINS_PROCESS_TARGET),native)) via $(PLUGINS_CARGO)"
	cd $(PLUGINS_DIR) && $(_plugins_cross_env) $(PLUGINS_CARGO) build --release $(_target_arg) -p bastion-plugin-xca
	@echo "==> building bastion-plugin-pmp ($(if $(PLUGINS_PROCESS_TARGET),$(PLUGINS_PROCESS_TARGET),native)) via $(PLUGINS_CARGO)"
	cd $(PLUGINS_DIR) && $(_plugins_cross_env) $(PLUGINS_CARGO) build --release $(_target_arg) -p bastion-plugin-pmp
	@echo "==> building bastion-plugin-email ($(if $(PLUGINS_PROCESS_TARGET),$(PLUGINS_PROCESS_TARGET),native)) via $(PLUGINS_CARGO)"
	cd $(PLUGINS_DIR) && $(_plugins_cross_env) $(PLUGINS_CARGO) build --release $(_target_arg) -p bastion-plugin-email
	@echo "==> building bastion-plugin-dbms-management ($(if $(PLUGINS_PROCESS_TARGET),$(PLUGINS_PROCESS_TARGET),native)) via $(PLUGINS_CARGO)"
	cd $(PLUGINS_DIR) && $(_plugins_cross_env) $(PLUGINS_CARGO) build --release $(_target_arg) -p bastion-plugin-dbms-management
	@mkdir -p $(PLUGINS_OUT)
	@cp $(DYNAMIC_PLUGINS_DIR)/$(_target_dir)/bastion-plugin-postgres$(_exe) $(PLUGINS_OUT)/
	@cp $(PLUGINS_DIR)/$(_target_dir)/bastion-plugin-xca$(_exe)      $(PLUGINS_OUT)/
	@cp $(PLUGINS_DIR)/$(_target_dir)/bastion-plugin-pmp$(_exe)      $(PLUGINS_OUT)/
	@cp $(PLUGINS_DIR)/$(_target_dir)/bastion-plugin-email$(_exe)    $(PLUGINS_OUT)/
	@cp $(PLUGINS_DIR)/$(_target_dir)/bastion-plugin-dbms-management$(_exe) $(PLUGINS_OUT)/
	@echo ""
	@echo "==> Process plugins ready in $(PLUGINS_OUT)/"
	@ls -lh $(PLUGINS_OUT)/bastion-plugin-postgres* $(PLUGINS_OUT)/bastion-plugin-xca* $(PLUGINS_OUT)/bastion-plugin-pmp* $(PLUGINS_OUT)/bastion-plugin-email* $(PLUGINS_OUT)/bastion-plugin-dbms-management* 2>/dev/null || true

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
PLUGIN_NAMES := bastion-plugin-totp bastion-plugin-postgres bastion-plugin-xca bastion-plugin-pmp bastion-plugin-email bastion-plugin-dbms-management bastion-plugin-webhook-notify bastion-plugin-self-accounts
type ?= patch

plugin-bump: ## Bump plugin versions across plugins-ext (type=major|minor|patch, default patch)
	@case "$(type)" in major|minor|patch) ;; *) echo "Invalid type=$(type) (use major|minor|patch)"; exit 1;; esac; \
	for p in $(PLUGIN_NAMES); do \
		D=$(PLUGINS_DIR); [ "$$p" = bastion-plugin-postgres ] && D=$(DYNAMIC_PLUGINS_DIR); \
		CUR=$$(grep '^version' $$D/$$p/Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/'); \
		case "$(type)" in \
			major) NEW=$$(echo $$CUR | awk -F. '{printf "%d.0.0", $$1+1}');; \
			minor) NEW=$$(echo $$CUR | awk -F. '{printf "%d.%d.0", $$1, $$2+1}');; \
			patch) NEW=$$(echo $$CUR | awk -F. '{printf "%d.%d.%d", $$1, $$2, $$3+1}');; \
		esac; \
		sed -i.bak "s/^version = \"$$CUR\"/version = \"$$NEW\"/" $$D/$$p/Cargo.toml && rm -f $$D/$$p/Cargo.toml.bak; \
		sed -i.bak "s/^version     = \"$$CUR\"/version     = \"$$NEW\"/" $$D/$$p/plugin.toml && rm -f $$D/$$p/plugin.toml.bak; \
		echo "Bumped $$p: $$CUR -> $$NEW"; \
	done

plugins-clean: ## Remove plugins-ext build artefacts
	@rm -rf $(PLUGINS_DIR)/target $(PLUGINS_OUT) $(PLUGINS_PACK_TARGET_DIR)
	@echo "plugins-clean complete."

# Plugin unit-test infrastructure (features/plugin-testing.md).
# Three layers, cheapest first:
#   1. testkit self-tests   — the mock host + form-hook runner
#   2. ABI parity           — testkit's conformance module through the
#                             REAL WasmRuntime, so the mock can't drift
#                             from src/plugins/runtime.rs
#   3. host substrate tests — the in-crate `plugins::` module tests
#                             (runtime, catalog, manifest, verifier…)
plugins-test: require-nextest ## Run plugin unit tests: testkit, host ABI parity, plugin substrate
	@echo "==> bastion-plugin-testkit unit tests"
	cargo nextest run -p bastion-plugin-testkit
	@echo "==> bv-plugin-pack unit tests (bundle verification)"
	cargo nextest run -p bv-plugin-pack
	@echo "==> ABI parity: testkit vs src/plugins/runtime.rs"
	cargo nextest run --test test_plugin_testkit_parity
	@echo "==> host plugin substrate unit tests (src/plugins/*)"
	cargo nextest run --lib -E 'test(/^plugins::/)'
	@echo "==> bastion-plugin-sdk process runner (ABI 1.4 protocols)"
	cargo nextest run -p bastion-plugin-sdk --lib --features process
	@echo "==> bastion-plugin-self-accounts: handlers (host stubs), manifest + surface, wasm end to end"
	cd $(PLUGINS_DIR) && cargo build --release --target $(PLUGINS_WASM_TARGET) -p bastion-plugin-self-accounts
	cd $(PLUGINS_DIR) && cargo test --release -p bastion-plugin-self-accounts --features host_test
	@echo "==> bastion-plugin-self-accounts on the REAL host, and Connect through it (needs the wasm built above)"
	cargo nextest run -p bastion_vault --lib --run-ignored only -E 'test(/self_accounts_(host|connect)/)'
	@echo "==> bastion-plugin-dbms-management: unit tests, the binary through the testkit, type-level invariants"
	cd $(PLUGINS_DIR) && cargo nextest run -p bastion-plugin-dbms-management
	cd $(PLUGINS_DIR) && cargo test -p bastion-plugin-dbms-management --doc
	@echo ""
	@echo "==> plugins-test complete."

# Not part of plugins-test or `make test`: starts throwaway postgres:16,
# mysql:8.4, mariadb:11.4, mssql/server:2022 (linux/amd64) and
# gvenzl/oracle-free:23-full (the full image: it has orapki for the TCPS
# wallet) containers through docker (features/sql-browser.md, Testing Plan).
# Without docker the tests skip; BV_TEST_REQUIRE_CONTAINER=1 makes that a
# failure.
test-dbms: require-nextest ## SQL browser plugin against live PostgreSQL, MySQL, MariaDB, SQL Server and Oracle Free containers (docker) + dependency ban
	cd $(PLUGINS_DIR) && cargo nextest run -p bastion-plugin-dbms-management --lib --run-ignored only
	@echo "==> no openssl-sys / aws-lc-sys / native-tls in the dbms-management plugin graph"
	@cd $(PLUGINS_DIR) && for c in openssl-sys aws-lc-sys native-tls; do \
		if cargo tree -p bastion-plugin-dbms-management --target all -i $$c >/dev/null 2>&1; then echo "$$c is in the plugin graph"; exit 1; fi; \
	done
	@echo "==> test-dbms complete."

# ── Dynamic-secret engine plugins (dynamic-engine-plugins/, T62) ────────
# A separate Cargo workspace with its own target/, like plugins-ext. The SDK
# runs through the testkit as a real process and as WASM; the live-Postgres
# test stays ignored (see dynamic-engine-plugins/README.md).
DYNAMIC_PLUGINS_DIR := dynamic-engine-plugins

dynamic-plugins-test: require-nextest ## Dynamic SDK + engine plugins: unit tests, testkit process and WASM runs, dependency ban
	@echo "==> wasm32 build of the SDK fixture (for the WASM-runtime tests)"
	cd $(DYNAMIC_PLUGINS_DIR) && cargo build --release --target $(PLUGINS_WASM_TARGET) -p bastion-plugin-dynamic-fixture --lib
	@echo "==> SDK, fixture and Postgres plugin tests"
	cd $(DYNAMIC_PLUGINS_DIR) && cargo nextest run -p bastion-plugin-dynamic-sdk -p bastion-plugin-dynamic-fixture -p bastion-plugin-postgres
	@echo "==> the fixture over the WASM imports (needs the wasm built above)"
	cd $(DYNAMIC_PLUGINS_DIR) && cargo nextest run -p bastion-plugin-dynamic-fixture --run-ignored only
	@echo "==> no openssl-sys / aws-lc-sys anywhere in the plugin graph"
	@cd $(DYNAMIC_PLUGINS_DIR) && for c in openssl-sys aws-lc-sys; do \
		if cargo tree --workspace --target all -i $$c >/dev/null 2>&1; then echo "$$c is in the dynamic-engine-plugins graph"; exit 1; fi; \
	done
	@echo "==> dynamic-plugins-test complete."

# Not part of dynamic-plugins-test: it starts a postgres:16 container through
# docker or podman (BV_TEST_CONTAINER_ENGINE forces one) and removes it afterwards.
# No engine: skipped with a message; BV_TEST_REQUIRE_CONTAINER=1 makes that a failure.
dynamic-plugins-live: require-nextest ## Live Postgres plugin test against a throwaway container (docker/podman)
	cd $(DYNAMIC_PLUGINS_DIR) && cargo nextest run -p bastion-plugin-postgres --test live --run-ignored only --no-capture
