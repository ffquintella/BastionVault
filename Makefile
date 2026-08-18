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

# ── Dev build speed: parallel rustc front-end ─────────────────────
#
# rustc's parallel front-end (`-Z threads=N`) splits a crate's
# analysis (parsing, macro expansion, type-checking) across threads.
# On this workspace — 1200+ crates, and a handful of huge serial
# bottleneck crates (the main lib, the Tauri GUI, hiqlite) — it
# meaningfully shortens the tail of every build on a multi-core host.
#
# The flag is nightly-gated, but the parallel front-end is compiled
# into the *stable* compiler too; `RUSTC_BOOTSTRAP=1` unlocks it
# without installing a separate nightly toolchain. This is a
# semver-exempt escape hatch — scoped here to make-driven local dev
# builds only, and trivially reversible.
#
# Applied as a *per-target* variable (not a global export) to the
# host-native main-workspace dev targets listed in FAST_BUILD_TARGETS.
# It deliberately does NOT leak into the plugin builds, because:
#   * `cross` (used for the Linux plugin targets) forwards RUSTFLAGS
#     into the container but NOT RUSTC_BOOTSTRAP, so `-Z threads`
#     would hit a plain stable rustc there and fail hard; and
#   * the signed/distributable plugin artefacts must not carry an
#     ad-hoc host RUSTFLAGS that changes their output.
#
# Tune or disable from the command line:
#   make build RUSTC_THREADS=6   # use 6 threads instead of 8
#   make build RUSTC_THREADS=0   # off — plain stable behaviour
#
# Windows is intentionally excluded: setting RUSTFLAGS here would
# override (not merge with) the `/PDBPAGESIZE:8192` linker flag that
# .cargo/config.toml sets for the *-pc-windows-msvc targets, bringing
# back the GUI link failure `LNK1318` that flag exists to prevent.
FAST_BUILD_TARGETS := build run-dev run-dev-gui run-dev-gui-hiqlite run-dev-gui-only bootstrap
ifneq ($(OS),Windows_NT)
RUSTC_THREADS ?= 8
ifneq ($(RUSTC_THREADS),0)
$(FAST_BUILD_TARGETS): export RUSTC_BOOTSTRAP := 1
$(FAST_BUILD_TARGETS): export RUSTFLAGS := $(strip $(RUSTFLAGS) -Z threads=$(RUSTC_THREADS))
endif
endif

# ── Never run two recipes at once ─────────────────────────────────
#
# Almost every target here is a cargo invocation, and cargo already saturates
# the machine. Two of them do NOT run in parallel — the second blocks on the
# shared target/ build lock for as long as the first takes. Measured on this
# tree: a `cargo check -p bv-errors` that should cost <1s took 9m14s wall with
# 0.4s of CPU because a concurrent test + clippy held the lock (AGENTS.md §5).
#
# Aggregate targets (`test-all`, `test-release`, `cli-packages-all`) list
# several such invocations, so a stray `make -j` turns a slow run into a
# pathological one. This makes -j a no-op for recipe scheduling; it does not
# affect cargo's own internal parallelism, which is where the cores actually go.
.NOTPARALLEL:

.PHONY: help build run-dev run-dev-gui gui-deps gui-build gui-test gui-check require-nextest test-bin test test-changed test-plan ci-plan check-isolated check-hsm test-integration test-doc test-cucumber test-hiqlite test-all test-release docs bump-minor bump-major bump-patch _bump-write bootstrap win-bootstrap clean gui-clean docs-clean deep-clean prune prune-stale target-size plugins-init plugins-target plugins-process-target plugins-wasm plugins-process plugins plugins-clean plugins-pack plugins-pack-build plugins-keygen plugins-sign plugins-test plugin-bump container-image container-image-run container-image-test container-repo-setup container-repo-show container-image-push linux-cli-deb linux-cli-rpm linux-cli-packages windows-cli-msi windows-cli-nupkg windows-cli-packages macos-cli-pkg cli-packages cli-packages-all gui-linux-packages gui-windows-msi windows-gui-nupkg gui-macos-pkg gui-packages macos-client-install sign-packages crates-login crates-publish-dry crates-publish crates-verify crates-plan crates-bump crates-publish-changed crates-publish-changed-dry crates-tag-push bench-build bench-build-quick deps-unused deps-unused-warn build-timings

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

# ── Test runner: cargo-nextest ────────────────────────────────────
#
# The test suite runs under `cargo nextest` rather than `cargo test`.
# It is a separate binary (`cargo install --locked cargo-nextest`), so
# every test target depends on `require-nextest`, which fails with
# install instructions rather than a bare "no such subcommand".
#
# Minimum version 0.9.84 — `.config/nextest.toml` uses `default-filter`,
# which landed in that release. An older nextest rejects the key with a
# config error rather than silently ignoring it.
#
# Two suites deliberately stay on plain `cargo test`; see the comments
# in `.config/nextest.toml` for why (a `harness = false` binary nextest
# cannot enumerate, and port allocators that depend on all tests sharing
# one process). `test-cucumber` and `test-hiqlite` cover them.
NEXTEST_MIN_VERSION := 0.9.84

# Deliberately NOT added to FAST_BUILD_TARGETS: the `-Z threads` RUSTFLAGS
# those targets export key a *separate* set of build artefacts. `make test`
# is meant to reuse whatever a bare `cargo check`/`cargo clippy` in the
# same tree already built, and target/ is large enough without a second
# flag-variant of the dependency graph. Run `make test RUSTFLAGS=...` if
# you want the parallel front-end for a one-off test compile.

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

# ── Tests ─────────────────────────────────────────────────────────

require-nextest: ## Check cargo-nextest is installed; print install instructions if not
	@command -v cargo-nextest >/dev/null 2>&1 || { \
		echo ""; \
		echo "  error: cargo-nextest is not installed."; \
		echo ""; \
		echo "  This project's test targets run under nextest (process-per-test,"; \
		echo "  real cross-binary parallelism, per-test isolation). Install it with:"; \
		echo ""; \
		echo "      cargo install --locked cargo-nextest"; \
		echo "      brew install cargo-nextest              # macOS / Linuxbrew"; \
		echo ""; \
		echo "  Requires >= $(NEXTEST_MIN_VERSION). Prebuilt binaries (much faster than"; \
		echo "  building from source) are at https://nexte.st/docs/installation/pre-built-binaries/"; \
		echo ""; \
		echo "  To run a suite without nextest, fall back to plain cargo:"; \
		echo "      cargo test --lib"; \
		echo ""; \
		exit 1; \
	}
	@cargo nextest --version

# The `cli::command::*` unit tests do not call the CLI in-process — they
# spawn the real `bvault` executable, resolved by
# `test_utils::get_project_binary_path()` as `target/<profile>/bvault`.
# Building the lib/bin *test harnesses* does not produce that file, so on a
# tree that has never run `cargo build`, 19 tests fail with
# "Failed to execute command: No such file or directory (os error 2)".
# It is easy to miss locally, where a stale binary from an earlier build is
# usually lying around; CI has no such luck. Declare the dependency.
test-bin: prune-stale ## Build the bvault executable that the cli::command::* tests spawn
	cargo build -p bvault-cli --bin bvault

# ── Test scope ────────────────────────────────────────────────────────
#
# This workspace has a ROOT package, so a bare `cargo nextest run` runs
# only that package — not `crates/*`. That was invisible while all the code
# lived in the root crate, and it became a coverage hole the moment
# roadmaps/workspace-decomposition.md started moving code out: extracting
# `src/shamir.rs` into `crates/bv-shamir` silently dropped its 21 tests
# from `make test`, and every later extraction would do the same, quietly.
#
# A separate `test-crates` target was tried first, on the theory that mixing
# the crates in destabilised the suite. That theory was wrong, and the
# measurement is kept here so nobody re-derives it: three consecutive runs at
# each scope failed 1/0/2 tests wide and 0/0/3 tests root-only. The suite has
# a pre-existing family of flaky timing-dependent tests (`modules::auth::
# expiration::*`, the 20s window in `metrics::system_metrics::test_sys_metrics`,
# the AppRole tidy race) that fail at either scope, so there is nothing to
# isolate — widening is simply the simpler correct thing. Those tests are
# tracked separately; do NOT add nextest `retries` to paper over them
# (.config/nextest.toml explains why).
#
# Excluded, and why:
#   bastion-vault-gui  desktop app; drags in the whole Tauri toolchain.
#                      Has its own checks (see `cd gui && npx vitest run`).
#
# The FerroGate `ferro-*` verifier crates used to need an exclusion here:
# they were vendored under third_party/ and a path dependency of a member
# is a workspace member regardless of `exclude`. They now come from the
# `uox-ferrogate` registry, so cargo never builds their test targets and
# there is nothing to exclude.
#
# Stated as exclusions, not an inclusion list, so a crate created by a
# future phase is covered the day it exists with no Makefile edit to forget.
TEST_SCOPE := --workspace \
	--exclude bastion-vault-gui

test: require-nextest test-bin ## Run the unit test suite (lib + bins) with nextest
	cargo nextest run $(TEST_SCOPE) --lib --bins

# ── Inner loop: only what the change can have broken ──────────────
#
# `make test` links ~40 test harnesses, five of them 200 MB+. Paying that on
# every edit is the largest single sink of wall-clock time in development, and
# nearly all of it goes on tests the edit cannot reach.
#
# `test-changed` derives the affected set from git + the cargo dependency graph
# (reverse deps, dev-deps included) and runs only those packages. See
# scripts/test-changed.sh for how the set is derived and what forces a full run.
#
#   make test-changed                 # uncommitted work
#   make test-changed BASE=main       # ...plus everything since merge-base(main)
#   make test-changed DIRECT=1        # changed packages only, no dependents
#   make test-changed PKG=bv-engine-pki
#   make test-changed FILTER=issue_cert
#   make test-plan                    # print the plan, build nothing
#
# It does NOT replace `make test-release`. It narrows the loop; the gate stays
# where it is.
TC_FLAGS := $(foreach p,$(PKG),--pkg $(p))
ifdef BASE
TC_FLAGS += --base $(BASE)
endif
ifdef DIRECT
TC_FLAGS += --direct
endif

test-changed: require-nextest prune-stale ## Run only the tests affected by your changes (PKG=/BASE=/DIRECT=1/FILTER=)
	scripts/test-changed.sh $(TC_FLAGS) $(if $(FILTER),-- $(FILTER))

test-plan: ## Show which packages `make test-changed` would test, without building
	@scripts/test-changed.sh --list $(TC_FLAGS)

# ── The CI plan, runnable locally ─────────────────────────────────
#
# What .github/workflows/tests.yml will do with a change, without pushing to
# find out. Same graph as `test-plan`, different consumer.
#
#   make ci-plan                    # the working tree, as a PR would see it
#   make ci-plan BASE=main          # ...plus everything since merge-base(main)
#   make ci-plan FULL=1             # the everything plan, which is what main runs
#   make ci-plan PKG=bv-engine-pki  # "what would CI do if I touched this crate?"
ci-plan: ## Show the CI job plan for your change (scripts/ci-plan.sh), building nothing
	@scripts/ci-plan.sh $(if $(BASE),--base $(BASE)) $(if $(FULL),--full) $(foreach p,$(PKG),--pkg $(p))

# ── Each crate builds on its own ──────────────────────────────────
#
# `cargo check --workspace` is NOT a proxy for "each crate builds". Cargo
# unifies features across everything in one build, so a crate can be missing a
# feature it needs and stay green because some sibling turns it on. That is not
# hypothetical here: Phase 4 of roadmaps/workspace-decomposition.md left
# `bv-server` unable to build alone (`log::set_boxed_logger` — `env_logger` had
# been what pulled in `log/std`) while the workspace check passed, and Phase 4.5
# found it by hand. Anything downstream of `bv-server` would have hit it first.
#
# One target dir and one cargo invocation per member, sequentially: each check
# reuses what the previous one built, so the only real cost is the crates whose
# feature set genuinely differs — which is exactly the set this is looking for.
# Serial on purpose (AGENTS.md §5): parallel cargo invocations queue on the
# shared target/ lock rather than overlapping.
#
# The GUI is excluded for the same reason it is everywhere else: it drags in the
# whole Tauri toolchain and has its own checks.
#
# No `--all-targets`: the `check` gate already front-end-compiles every test
# target across the workspace, and repeating that here would roughly double this
# target's cost to re-check code that cannot be affected by the thing it is
# looking for. Feature unification bites the production graph — a lib that
# cannot build without a sibling's feature — which is what `cargo check -p X`
# alone measures.
check-isolated: prune-stale ## cargo check every workspace member on its own (catches feature-unification bugs)
	@set -e; \
	pkgs=$$(cargo metadata --format-version 1 --no-deps \
	        | python3 -c 'import json,sys; print(" ".join(sorted(p["name"] for p in json.load(sys.stdin)["packages"] if p["name"] != "bastion-vault-gui")))'); \
	n=$$(echo $$pkgs | wc -w | tr -d " "); i=0; \
	for p in $$pkgs; do \
	  i=$$((i+1)); \
	  echo "==> [$$i/$$n] cargo check -p $$p"; \
	  cargo check -p $$p; \
	done; \
	echo ""; \
	echo "==> check-isolated: all $$n members build on their own."

# ── The HSM seal backends ─────────────────────────────────────────
#
# The one part of the workspace that NO other target compiles. `hsm_mock` and
# `hsm_yubihsm2` are off by default everywhere, `--all-features` is banned
# (AGENTS.md §5), and `check-isolated` above checks each member with default
# features — so the whole seal-backend surface was unbuilt until the official
# container image built it, twice, minutes into a cross-compile.
#
# Two halves, both in scripts/check-hsm.sh: a cargo-metadata walk of the
# feature chain (bvault-cli -> bastion_vault -> bv-core; compiles nothing) and
# `cargo check -p bv-core --features <both>`. bv-core is the whole compile-error
# surface because every `#[cfg(feature = "hsm_*")]` site in the workspace lives
# there; the script's header shows how to re-derive that.
#
# DEEP=1 also checks `-p bvault-cli`, which is the image's own build graph.
# Measured at 53 s wall / 213 s CPU on a warm local tree, against ~6 s for the
# cheap form. It is kept out of the per-change path on grounds of what it adds
# rather than what it costs: bv-core is already the entire compile-error
# surface, so DEEP re-checks the same ten cfg blocks through 70k more lines of
# root crate, bv-server and CLI. It runs in `make test-release`, where the
# question is "would the release image build?" rather than "did I break it?".
#
# Note this pulls `yubihsm` + `rusb`, and rusb's `vendored` feature compiles
# libusb from C source via its build script — which `cargo check` runs. That is
# the bulk of a cold run here (~35 s on a warm target dir); it is also the
# reason this is its own target and not folded into `check-isolated`.
check-hsm: prune-stale ## cargo check the HSM seal backends (nothing else compiles them; DEEP=1 for the image's graph)
	@scripts/check-hsm.sh $(if $(DEEP),--deep)

test-integration: require-nextest prune-stale ## Run the tests/ integration suite with nextest (links ~30 binaries; slow)
	cargo nextest run $(TEST_SCOPE) --tests

# nextest cannot run doctests — it drives libtest binaries, and rustdoc's
# test runner is a separate thing entirely. This stays on `cargo test`.
# See https://nexte.st/docs/design/custom-test-harnesses/
test-doc: prune-stale ## Run doctests (cargo test --doc; nextest cannot run these)
	cargo test $(TEST_SCOPE) --doc

# `harness = false`, so nextest cannot enumerate its cases. Binds fixed
# ports 28100/28200 and shares one backend across all scenarios, so it
# also cannot overlap with another run of itself.
test-cucumber: prune-stale ## Run the cucumber feature suite (harness = false, so plain cargo test)
	cargo test --test cucumber_hiqlite

# These MUST share one process: both suites hand themselves disjoint TCP
# ports from a process-global atomic counter, and a dropped hiqlite
# backend releases its listeners asynchronously. One process per test
# would restart the counter at zero every time and collide on ports.
# `--test-threads=1` on top of the in-crate `#[serial]` markers.
test-hiqlite: prune-stale ## Run the hiqlite storage + HA fault-injection suites (plain cargo test, single process)
	CARGO_TEST_HIQLITE=1 cargo test -p bv-storage --lib --features storage_hiqlite hiqlite::test:: -- --test-threads=1
	CARGO_TEST_HIQLITE=1 cargo test --test hiqlite_ha_fault_injection -- --test-threads=1

test-all: test test-integration test-doc ## Run unit + integration + doctests (excludes the port-bound hiqlite suites; see test-hiqlite)
	@echo ""
	@echo "==> test-all complete. Port-bound suites are not included here:"
	@echo "    make test-hiqlite   # hiqlite storage + HA fault injection"
	@echo "    make test-cucumber  # cucumber feature files"

# ── The release gate ──────────────────────────────────────────────
#
# EVERY suite this repo has, in one target, so "did we run everything?" has an
# answer that is not a checklist someone reads from memory. Run it before
# cutting a release, and before merging anything that touches a persisted
# format, a storage barrier, authn/authz, or the plugin ABI.
#
# `test-all` is the subset that excludes the port-bound and non-libtest suites;
# this is the superset that does not. Expect tens of minutes: it links the ~30
# integration binaries, runs rustdoc over every crate, and stands hiqlite
# clusters up and down on real TCP ports.
#
# Ordered cheapest-and-broadest first, so the run that is going to fail usually
# fails early. Each line is a separate sub-make, and `.NOTPARALLEL` above keeps
# them from overlapping — two cargo invocations do not run in parallel, they
# queue on the shared target/ lock (AGENTS.md §5).
#
# Deliberately NOT here: `make build` (a release *build* is its own step) and
# `tests/e2e/rustion-ssh` (needs real remote hosts, cannot be hermetic).
test-release: require-nextest ## Every suite, for a release or a high-risk merge (slow: tens of minutes)
	@echo "==> [1/8] unit tests (lib + bins)"      && $(MAKE) --no-print-directory test
	@echo "==> [2/8] integration tests (tests/)"   && $(MAKE) --no-print-directory test-integration
	@echo "==> [3/8] doctests"                     && $(MAKE) --no-print-directory test-doc
	@echo "==> [4/8] hiqlite storage + HA"         && $(MAKE) --no-print-directory test-hiqlite
	@echo "==> [5/8] cucumber features"            && $(MAKE) --no-print-directory test-cucumber
	@echo "==> [6/8] plugin ABI + substrate"       && $(MAKE) --no-print-directory plugins-test
	@echo "==> [7/8] GUI typecheck + vitest"       && $(MAKE) --no-print-directory gui-check gui-test
	@# DEEP=1, not the cheap per-change variant: a release cuts the container
	@# image, and the image builds `-p bvault-cli` with both HSM backends. This
	@# is the one place that is worth paying for the image's real graph.
	@echo "==> [8/8] HSM seal backends (image graph)" && $(MAKE) --no-print-directory check-hsm DEEP=1
	@echo ""
	@echo "==> test-release complete: every suite in this repo passed."
	@echo "    Not covered (needs real hosts, run by hand): tests/e2e/rustion-ssh"

docs: ## Serve the Docsify-powered documentation site locally on http://localhost:3000
	@command -v docsify >/dev/null 2>&1 || npm i -g docsify-cli
	docsify serve docs

# ── Decomposition instrumentation (Phase 0) ───────────────────────
#
# See roadmaps/workspace-decomposition.md. `bench-build` is the instrument every
# later phase reports its delta against; `deps-unused` keeps the dependency
# graph from re-growing the slack Phase 0 removed.

bench-build: require-nextest ## Measure incremental build cost (median of 3) and append a row to docs/build-timings/baseline.md
	scripts/bench-build.sh

bench-build-quick: require-nextest ## Same, single sample, nothing written to the log
	scripts/bench-build.sh --repeat 1 --no-log

deps-unused: ## Report unused direct dependencies in our crates (needs cargo-machete)
	scripts/deps-unused.sh

deps-unused-warn: ## Same, but never fails -- the shape CI uses
	scripts/deps-unused.sh --warn

build-timings: ## Write a cargo --timings HTML for a full lib rebuild (target/cargo-timings/)
	@# Touching core.rs forces the monolith to rebuild as one unit, which is the
	@# number the decomposition divides. Deps stay cached, so this shows the
	@# crate's own cost rather than a cold graph -- the cold picture comes from
	@# CI, where a cold build happens anyway.
	touch src/core.rs
	cargo build --lib --timings
	@echo
	@echo "==> open target/cargo-timings/cargo-timing.html"
	@echo "    archive it as docs/build-timings/lib-selftime-<commit>.html when it"
	@echo "    is a phase boundary worth keeping."

# ── FerroGate SDK ─────────────────────────────────────────────────
#
# The `ferro-*` verifier crates come from the `uox-ferrogate` Cloudsmith
# registry (declared in .cargo/config.toml), pinned to an exact version in
# Cargo.toml. There is no re-vendoring step any more — bump the three `=`
# requirements and commit that. See docs/ferrogate-machine-auth.md
# § SDK dependency.

# ── Cargo registry: Cloudsmith uox/bastionvault ───────────────────
#
# The registry itself is declared in `.cargo/config.toml`. The token is
# never stored in the repo — see docs/publishing-crates.md.

CARGO_REGISTRY ?= uox-bastionvault

crates-login: ## Store a Cloudsmith Cargo API token in $CARGO_HOME (prompts; never touches the repo)
	@echo "Get an API key: https://cloudsmith.io/user/settings/api/"
	@echo "It is written to \$$CARGO_HOME/credentials.toml, outside this repo."
	@echo "(The repo's .gitignore also blocks .cargo/credentials* as a backstop.)"
	@echo
	cargo login --registry $(CARGO_REGISTRY)

crates-verify: ## Package the dependency-free crates from a staged tarball (no upload, no token)
	@# Only the crates with no *workspace* dependencies can be packaged
	@# before anything is on the registry: cargo resolves each dependency
	@# in its published (registry) form before it will stage a tarball, so
	@# a crate like bv_plugin_manifest cannot be verified until
	@# bv_plugin_surface is actually live. `make crates-publish-dry`
	@# reports those as "deferred".
	cargo package -p bv_plugin_surface -p bv_crypto -p bastion-plugin-testkit --allow-dirty

crates-publish-dry: ## Dry-run publish of all library crates in dependency order (uploads nothing)
	scripts/publish-crates.sh --registry $(CARGO_REGISTRY)

crates-publish: ## Publish all library crates to the Cloudsmith registry FOR REAL (irreversible; needs a clean tree)
	@echo "This uploads crates to '$(CARGO_REGISTRY)'. A published version can"
	@echo "never be replaced -- only yanked and superseded. Ctrl-C to abort."
	@echo
	@printf "Type the registry name to confirm: "; \
	read -r confirm; \
	if [ "$$confirm" != "$(CARGO_REGISTRY)" ]; then echo "aborted."; exit 1; fi
	scripts/publish-crates.sh --registry $(CARGO_REGISTRY) --execute

# ── Per-crate releases: build and push only what changed ──────────
#
# Phase 6 of roadmaps/workspace-decomposition.md. Every library crate carries
# its own version and is released on its own schedule, so a normal release
# ships a handful of crates rather than all 38. The three targets below are
# the whole loop:
#
#   make crates-plan               # what changed, and what would ship
#   make crates-bump               # patch-bump exactly those crates
#   make crates-publish-changed    # build + upload exactly those crates
#
# "Changed" means the crate's directory differs from its last
# `<name>-v<version>` release tag — scripts/crates-plan.sh explains how, and
# `make crates-plan` prints the reason per crate. Nothing here consults the
# product version: `bv-shamir` has not changed since it was extracted and must
# not be republished 40 times because the GUI shipped.
#
# WHY A PATCH BUMP DOES NOT DRAG THE WORKSPACE WITH IT: internal dependencies
# are declared `version = "0.1.0"`, a caret requirement matching every 0.1.x.
# Bumping `bv-errors` to 0.1.1 leaves all 32 dependents' manifests untouched,
# so their tarballs are unchanged and they are not republished — a consumer
# picks up 0.1.1 on its own. Do NOT pin internal deps with `=`, and do NOT
# move them into `[workspace.dependencies]`; either turns every release into a
# whole-workspace release. See AGENTS.md § Per-crate versioning.

crates-plan: ## Show which crates changed since their last published version (no build, no upload)
	@scripts/crates-plan.sh --registry $(CARGO_REGISTRY) $(if $(OFFLINE),--offline)

# MINOR=<crate> for a breaking change — that is the one call this cannot make
# for you, because it is a judgement about the crate's public API. Patch is the
# default because it is the safe default.
#
#   make crates-bump                        # patch-bump every changed crate
#   make crates-bump MINOR=bv-errors        # ...and treat bv-errors as breaking
#   make crates-bump CRATE=bv-engine-pki    # bump one, changed or not
#   make crates-bump DRY=1                  # show the edits, write nothing
crates-bump: ## Bump the version of each changed crate (MINOR=<crate> for breaking, CRATE=<name>, DRY=1)
	@scripts/crates-bump.sh $(if $(DRY),--dry-run) \
		$(foreach c,$(MINOR),--minor $(c)) $(foreach c,$(CRATE),--crate $(c))

crates-publish-changed-dry: ## Dry-run publish of ONLY the changed crates (uploads nothing)
	scripts/publish-crates.sh --registry $(CARGO_REGISTRY) --changed

crates-publish-changed: ## Publish ONLY the changed crates FOR REAL (irreversible; needs a clean tree)
	@# The plan is computed ONCE here and handed to the publish run, so the
	@# set you are asked to confirm is exactly the set that ships. Recomputing
	@# it after the prompt would leave a window where a `git commit` in another
	@# terminal changes what gets uploaded.
	@scripts/crates-plan.sh --registry $(CARGO_REGISTRY) --json > .crates-plan.json
	@scripts/crates-plan.sh --registry $(CARGO_REGISTRY)
	@echo
	@echo "This uploads the crates marked 'publish' above to '$(CARGO_REGISTRY)'."
	@echo "A published version can never be replaced -- only yanked and"
	@echo "superseded. Ctrl-C to abort."
	@echo
	@printf "Type the registry name to confirm: "; \
	read -r confirm; \
	if [ "$$confirm" != "$(CARGO_REGISTRY)" ]; then echo "aborted."; rm -f .crates-plan.json; exit 1; fi
	scripts/publish-crates.sh --registry $(CARGO_REGISTRY) --changed --execute \
		--plan-file .crates-plan.json
	@rm -f .crates-plan.json

# Separate from the publish step on purpose. The upload is irreversible and
# has already happened; pushing the tags is what makes the release visible to
# everyone else, and that stays a deliberate second action.
crates-tag-push: ## Push the local <crate>-v<version> tags written by the last publish
	@tags=$$(git tag --points-at HEAD | grep -E -- '-v[0-9]+\.[0-9]+\.[0-9]+$$' || true); \
	if [ -z "$$tags" ]; then \
		echo "No per-crate release tags at HEAD. Nothing to push."; exit 0; \
	fi; \
	echo "Pushing to origin:"; echo "$$tags" | sed 's/^/  /'; echo; \
	printf "Push these tags? [y/N] "; read -r ans; \
	if [ "$$ans" != "y" ] && [ "$$ans" != "Y" ]; then echo "aborted."; exit 1; fi; \
	git push origin $$tags

# ── The PRODUCT version, which is not the library versions ────────
#
# Two version schemes live in this repo since Phase 6 of
# roadmaps/workspace-decomposition.md, and conflating them is the mistake to
# avoid:
#
#   PRODUCT  — one number, what `bvault --version` prints and what the
#              installers are named after. The root crate, `bvault-cli` and
#              the GUI move together, and `bump-*` below is what moves them.
#              None of them is published to the registry.
#
#   LIBRARY  — 38 independent numbers, one per publishable crate, moved by
#              content rather than by release: `make crates-bump` bumps only
#              the crates that actually changed. See `make crates-plan`.
#
# `bv-server` is the odd one: it is Tier 4 like `bvault-cli`, but it carries
# its own 0.1.0 rather than the product version, because nothing prints it —
# it is a library the CLI and the GUI link, not a thing an operator names. It
# is unpublishable either way (it reaches `bastion_vault`), so the number is
# inert. Left as it is rather than "tidied" into the lockstep list.
#
# So `bump-*` deliberately does NOT touch the `crates/bv-*` libraries. A
# release that ships the GUI must not republish `bv-shamir`, which has not
# changed since it was extracted. If you find yourself adding a
# `crates/bv-<library>` line to `_bump-write`, you are re-coupling the two
# schemes — use `crates-bump` instead.
#
# `bump-*` targets bump the product version everywhere it lives:
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

# `bump-*` keeps the shipped-product version sites in lockstep:
#   * root `Cargo.toml`               (workspace crate version)
#   * `gui/src-tauri/Cargo.toml`      (Tauri Rust crate)
#   * `gui/package.json`              (npm — bastion-vault-gui)
#   * `gui/src-tauri/tauri.conf.json` (Tauri runtime version pin)
#   * `crates/bvault-cli/Cargo.toml`  (the `bvault` CLI — Phase 4 moved the
#                                      binary out of the root package, and
#                                      `bvault --version` is operator-facing)
#   * the `bastion_vault` version pins in `crates/bvault-cli/Cargo.toml` and
#     `crates/bv-server/Cargo.toml` — Tier 4 depends on the root crate by
#     version as well as by path, so a stale pin breaks resolution outright.
#
# The library crates under `crates/` (`bv_crypto`, `bastion-plugin-sdk`,
# `bv-plugin-pack`, and the Tier 0–3 crates Phases 1–3 created) have
# independent versioning lifecycles and are NOT touched here — bump them by
# hand or via dedicated scripts as semver-relevant changes land.
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
	@# `bvault-cli` carries the shipped product version, not an independent
	@# one: `bvault --version` is what operators read. Phase 4.
	@$(SED_INPLACE) '1,/^version = /s/^version = "[^"]*"/version = "$(NEW)"/' crates/bvault-cli/Cargo.toml
	@# Both Tier 4 crates pin `bastion_vault` by version as well as by path
	@# (the `publish = ["uox-bastionvault"]` setup requires it). Leaving these
	@# behind makes the workspace unresolvable on the very next bump, because
	@# a `version = "0.39.7"` requirement cannot match a 0.40.0 package.
	@$(SED_INPLACE) 's/^bastion_vault = { path = "\.\.\/\.\.", version = "[^"]*"/bastion_vault = { path = "..\/..", version = "$(NEW)"/' crates/bvault-cli/Cargo.toml
	@$(SED_INPLACE) 's/^bastion_vault = { path = "\.\.\/\.\.", version = "[^"]*"/bastion_vault = { path = "..\/..", version = "$(NEW)"/' crates/bv-server/Cargo.toml
	@echo "Bumped version: $(VERSION) -> $(NEW)"
	@echo "  Cargo.toml:                    $$(grep '^version' Cargo.toml | head -1)"
	@echo "  gui/src-tauri/Cargo.toml:      $$(grep '^version' gui/src-tauri/Cargo.toml | head -1)"
	@echo "  gui/package.json:              $$(grep '\"version\"' gui/package.json | head -1 | sed 's/^[ \t]*//')"
	@echo "  gui/src-tauri/tauri.conf.json: $$(grep '\"version\"' gui/src-tauri/tauri.conf.json | head -1 | sed 's/^[ \t]*//')"
	@echo "  crates/bvault-cli/Cargo.toml:  $$(grep '^version' crates/bvault-cli/Cargo.toml | head -1)"
	@echo "  bastion_vault pins:            $$(grep -h '^bastion_vault = ' crates/bvault-cli/Cargo.toml crates/bv-server/Cargo.toml | grep -o 'version = \"[^\"]*\"' | tr '\n' ' ')"

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

GUI_BUNDLE_FEATURES ?= storage_hiqlite,ssh_pqc

gui-linux-packages: ## Build the GUI .deb + .rpm (native on Linux; emulated amd64 Docker container elsewhere)
ifeq ($(shell uname -s),Linux)
	@$(MAKE) gui-deps prune-stale
	cd gui && $(GUI_TAURI) build --bundles deb,rpm -- --features $(GUI_BUNDLE_FEATURES)
	@echo ""
	@echo "==> GUI bundles under gui/src-tauri/target/release/bundle/:"
	@ls -lh gui/src-tauri/target/release/bundle/deb/*.deb gui/src-tauri/target/release/bundle/rpm/*.rpm 2>/dev/null || true
else
	@echo "==> not on Linux — building the GUI .deb/.rpm in an emulated amd64 Docker container"
	@GUI_BUNDLE_FEATURES=$(GUI_BUNDLE_FEATURES) bash gui/src-tauri/installers/linux/build-in-docker.sh
endif

gui-windows-msi: ## Build the GUI .msi (native on Windows; disposable Tart Win11 ARM64 VM elsewhere)
ifeq ($(OS),Windows_NT)
	@$(MAKE) gui-deps prune-stale
	cd gui && $(GUI_TAURI) build --bundles msi -- --features $(GUI_BUNDLE_FEATURES)
	@echo ""
	@echo "==> GUI .msi under gui/src-tauri/target/release/bundle/msi/:"
	@ls -lh gui/src-tauri/target/release/bundle/msi/*.msi 2>/dev/null || true
else ifeq ($(shell uname -s),Darwin)
	@echo "==> not on Windows — building the GUI .msi (x64) in a disposable Tart Win11 ARM64 VM"
	@GUI_BUNDLE_FEATURES=$(GUI_BUNDLE_FEATURES) bash gui/src-tauri/installers/windows/build-in-vm.sh
else
	@echo "ERROR: off-Windows GUI .msi builds use Tart (Apple Virtualization), which is macOS-only."; \
	 echo "       Build on a Windows host, or use the macOS Tart path."; exit 1
endif

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
# On a Windows host this builds the .msi first. Off Windows, point it at an
# .msi produced by the Tart VM path:
#
#   make windows-gui-nupkg GUI_MSI=out/BastionVault_0.38.3_x64_en-US.msi
GUI_NUPKG_DIR := gui/src-tauri/installers/windows/nupkg
GUI_MSI       ?=
PYTHON        ?= $(if $(filter Windows_NT,$(OS)),python,python3)

windows-gui-nupkg: ## Build the GUI Chocolatey .nupkg wrapping the Tauri .msi (GUI_MSI=... to pack an existing one)
ifeq ($(OS),Windows_NT)
	@if [ -z "$(GUI_MSI)" ]; then $(MAKE) gui-windows-msi; fi
endif
	@command -v $(PYTHON) >/dev/null 2>&1 || { \
		echo "ERROR: $(PYTHON) not found — needed to assemble the .nupkg."; \
		echo "       Override the interpreter with PYTHON=<path> if it is named differently."; \
		exit 1; \
	}
	@mkdir -p target/nupkg
	@MSI="$(GUI_MSI)"; \
	 if [ -z "$$MSI" ]; then \
		MSI=$$(ls -1t gui/src-tauri/target/release/bundle/msi/*.msi \
		               target/release/bundle/msi/*.msi 2>/dev/null | head -1); \
	 fi; \
	 if [ -z "$$MSI" ]; then \
		echo "ERROR: no GUI .msi found under */release/bundle/msi/."; \
		echo "       Build it first ('make gui-windows-msi'), or pass GUI_MSI=<path>."; \
		exit 1; \
	 fi; \
	 echo "==> packing $$MSI"; \
	 $(PYTHON) installers/cli/nupkg/build-nupkg.py \
		--nuspec $(GUI_NUPKG_DIR)/bastionvault-gui.nuspec \
		--version $(VERSION) \
		--tools "$$MSI" \
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

# ── Install the macOS client on this Mac ───────────────────────────────
#
# Build both halves of the macOS client — the Tauri GUI (.app wrapped into
# a .pkg) and the bvault CLI (.pkg) — for the host arch, then hand them to
# Apple's installer(8) so they land where macOS expects:
#
#   /Applications/BastionVault.app
#   /usr/local/bin/bvault (+ manpage + bash/zsh completions)
#
# The install step needs administrator rights and will prompt for your
# password once. macOS only (Tauri needs macOS for the .app, and
# pkgbuild/installer are Apple tools).
#
#   make macos-client-install                       # build + install both
#   make macos-client-install BV_QUIT_RUNNING=1     # also quit a running GUI
#   make macos-client-install MACOS_CLIENT_PARTS=cli # CLI only (or gui)
#
# The GUI half refuses to install over a running BastionVault.app — it may
# be holding an unsealed embedded vault — unless BV_QUIT_RUNNING=1 asks it
# to quit gracefully first.
#
# Set INSTALLER_IDENTITY to sign the packages before installing; a local
# unsigned .pkg installs fine via installer(8).

# Which halves to build + install: gui, cli, or both.
MACOS_CLIENT_PARTS ?= both
MACOS_CLIENT_ARCH  := $(shell uname -m)
MACOS_CLIENT_GUI_PKG := target/pkg/BastionVault-$(VERSION)-$(MACOS_CLIENT_ARCH).pkg
MACOS_CLIENT_CLI_PKG := target/pkg/bvault-$(VERSION)-darwin-$(MACOS_CLIENT_ARCH).pkg

macos-client-install: ## Build the macOS client (GUI .app + bvault CLI) and install it on this Mac
ifneq ($(shell uname -s),Darwin)
	@echo "ERROR: macos-client-install must run on macOS (Tauri needs macOS for the .app;"; \
	 echo "       pkgbuild/installer are Apple tools)."; exit 1
else
	@case "$(MACOS_CLIENT_PARTS)" in \
	   both|gui|cli) ;; \
	   *) echo "ERROR: MACOS_CLIENT_PARTS must be both, gui, or cli (got '$(MACOS_CLIENT_PARTS)')"; exit 1 ;; \
	 esac
ifneq ($(MACOS_CLIENT_PARTS),cli)
	@$(MAKE) gui-macos-pkg
endif
ifneq ($(MACOS_CLIENT_PARTS),gui)
	@$(MAKE) macos-cli-pkg
endif
	@GUI_PKG=$(if $(filter-out cli,$(MACOS_CLIENT_PARTS)),$(MACOS_CLIENT_GUI_PKG),) \
	 CLI_PKG=$(if $(filter-out gui,$(MACOS_CLIENT_PARTS)),$(MACOS_CLIENT_CLI_PKG),) \
	 BV_QUIT_RUNNING=$(BV_QUIT_RUNNING) \
		bash installers/macos/install-client.sh
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

# The cargo-nextest step is the test runner every `make test*` target needs.
# Guarded on presence because `cargo install` would otherwise rebuild it from
# source on every bootstrap.
bootstrap: ## Install dependencies and set up the development environment
	rustup update stable
	cargo fetch
	@command -v cargo-nextest >/dev/null 2>&1 \
		&& echo "==> cargo-nextest already installed: $$(cargo nextest --version)" \
		|| cargo install --locked cargo-nextest
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
	CARGO_TARGET_DIR=$(PLUGINS_PACK_TARGET_DIR) cargo build --release -p bv-plugin-pack

plugins-wasm: plugins-init plugins-target ## Compile the WASM reference plugins (release)
	@echo "==> building bastion-plugin-totp ($(PLUGINS_WASM_TARGET))"
	cd $(PLUGINS_DIR) && cargo build --release --target $(PLUGINS_WASM_TARGET) -p bastion-plugin-totp
	@echo "==> building bastion-plugin-webhook-notify ($(PLUGINS_WASM_TARGET))"
	cd $(PLUGINS_DIR) && cargo build --release --target $(PLUGINS_WASM_TARGET) -p bastion-plugin-webhook-notify
	@mkdir -p $(PLUGINS_OUT)
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
		--manifest $(PLUGINS_DIR)/bastion-plugin-postgres/plugin.toml \
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
	@echo "==> packing bastion-plugin-webhook-notify (wasm app-module) into .bvplugin"
	$(BV_PLUGIN_PACK) \
		--manifest $(PLUGINS_DIR)/bastion-plugin-webhook-notify/plugin.toml \
		--binary   $(PLUGINS_OUT)/bastion_plugin_webhook_notify.wasm \
		--out      $(PLUGINS_OUT)/bastion-plugin-webhook-notify.bvplugin
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
		--manifest          $(PLUGINS_DIR)/bastion-plugin-postgres/plugin.toml \
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
	@echo "==> signing bastion-plugin-webhook-notify (wasm app-module)"
	$(BV_PLUGIN_PACK) \
		--manifest          $(PLUGINS_DIR)/bastion-plugin-webhook-notify/plugin.toml \
		--binary            $(PLUGINS_OUT)/bastion_plugin_webhook_notify.wasm \
		--out               $(PLUGINS_OUT)/bastion-plugin-webhook-notify.bvplugin \
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
	@echo "==> building bastion-plugin-email ($(if $(PLUGINS_PROCESS_TARGET),$(PLUGINS_PROCESS_TARGET),native)) via $(PLUGINS_CARGO)"
	cd $(PLUGINS_DIR) && $(PLUGINS_CARGO) build --release $(_target_arg) -p bastion-plugin-email
	@mkdir -p $(PLUGINS_OUT)
	@cp $(PLUGINS_DIR)/$(_target_dir)/bastion-plugin-postgres$(_exe) $(PLUGINS_OUT)/
	@cp $(PLUGINS_DIR)/$(_target_dir)/bastion-plugin-xca$(_exe)      $(PLUGINS_OUT)/
	@cp $(PLUGINS_DIR)/$(_target_dir)/bastion-plugin-pmp$(_exe)      $(PLUGINS_OUT)/
	@cp $(PLUGINS_DIR)/$(_target_dir)/bastion-plugin-email$(_exe)    $(PLUGINS_OUT)/
	@echo ""
	@echo "==> Process plugins ready in $(PLUGINS_OUT)/"
	@ls -lh $(PLUGINS_OUT)/bastion-plugin-postgres* $(PLUGINS_OUT)/bastion-plugin-xca* $(PLUGINS_OUT)/bastion-plugin-pmp* $(PLUGINS_OUT)/bastion-plugin-email* 2>/dev/null || true

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
PLUGIN_NAMES := bastion-plugin-totp bastion-plugin-postgres bastion-plugin-xca bastion-plugin-pmp bastion-plugin-email bastion-plugin-webhook-notify
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
	@echo "==> ABI parity: testkit vs src/plugins/runtime.rs"
	cargo nextest run --test test_plugin_testkit_parity
	@echo "==> host plugin substrate unit tests (src/plugins/*)"
	cargo nextest run --lib -E 'test(/^plugins::/)'
	@echo ""
	@echo "==> plugins-test complete."
