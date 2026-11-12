# Tests — nextest, affected-only runs, CI plan, isolation and release gates.
# Included by the top-level Makefile; do not run standalone.

##@ Tests

.PHONY: require-nextest test-bin test test-changed test-plan ci-plan check-isolated check-hsm test-pki-composite test-pki-composite-lib test-pki-composite-integration test-integration test-doc test-cucumber test-hiqlite test-all test-release

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
# `make test` links ~44 test harnesses, five of them 200 MB+. Paying that on
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

# ── Composite PKI issuance (feature-gated) ────────────────────────
#
# `pki_pqc_composite` is off by default and `--all-features` is banned
# (AGENTS.md §5), so bv-engine-pki's composite arms — and the composite
# regression tests for the issuance hardening (T147, T148, T150) — compile in
# no other target. NEXTEST_PROFILE=ci selects the profile CI writes JUnit with;
# CI calls the two halves as separate steps because both write the same file.
#
# -lib: scoped to the one crate on purpose. The feature adds code only there
# and changes nothing beneath it, so a warm tree rebuilds just bv-engine-pki.
#
# -integration: tests/test_pki_composite.rs, gated on the same feature through
# the root crate (`bastion_vault/pki_pqc_composite`), so every integration
# shard compiles it to nothing. It is the one test that verifies both halves of
# a composite signature with fips204 + p256 instead of the engine's own code.
# Run at $(TEST_SCOPE), the integration suite's scope, so the third-party
# graph unifies as it does for `make test-integration` and only bv-engine-pki,
# bastion_vault, bv-server and the test binary build a second variant: ~17 s
# of critical path measured non-incrementally on a warm tree (T152).
test-pki-composite: test-pki-composite-lib test-pki-composite-integration ## Run the composite (pki_pqc_composite) PKI tests: engine unit tests + tests/test_pki_composite.rs

test-pki-composite-lib: require-nextest prune-stale ## Run bv-engine-pki unit tests with the composite (pki_pqc_composite) feature on
	cargo nextest run $(if $(NEXTEST_PROFILE),--profile $(NEXTEST_PROFILE)) -p bv-engine-pki --lib --features pki_pqc_composite

test-pki-composite-integration: require-nextest prune-stale ## Run tests/test_pki_composite.rs with the root crate's pki_pqc_composite feature on
	cargo nextest run $(if $(NEXTEST_PROFILE),--profile $(NEXTEST_PROFILE)) $(TEST_SCOPE) --features bastion_vault/pki_pqc_composite --test test_pki_composite

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
	cargo test --test cucumber_exchange

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
# `tests/test_pki_composite.rs` compiles to nothing in step 2; step 8 runs it.
test-release: require-nextest ## Every suite, for a release or a high-risk merge (slow: tens of minutes)
	@echo "==> [1/9] unit tests (lib + bins)"      && $(MAKE) --no-print-directory test
	@echo "==> [2/9] integration tests (tests/)"   && $(MAKE) --no-print-directory test-integration
	@echo "==> [3/9] doctests"                     && $(MAKE) --no-print-directory test-doc
	@echo "==> [4/9] hiqlite storage + HA"         && $(MAKE) --no-print-directory test-hiqlite
	@echo "==> [5/9] cucumber features"            && $(MAKE) --no-print-directory test-cucumber
	@echo "==> [6/9] plugin ABI + substrate"       && $(MAKE) --no-print-directory plugins-test
	@echo "==> [7/9] GUI typecheck + vitest"       && $(MAKE) --no-print-directory gui-check gui-test
	@echo "==> [8/9] composite PKI issuance"       && $(MAKE) --no-print-directory test-pki-composite
	@# DEEP=1, not the cheap per-change variant: a release cuts the container
	@# image, and the image builds `-p bvault-cli` with both HSM backends. This
	@# is the one place that is worth paying for the image's real graph.
	@echo "==> [9/9] HSM seal backends (image graph)" && $(MAKE) --no-print-directory check-hsm DEEP=1
	@echo ""
	@echo "==> test-release complete: every suite in this repo passed."
	@echo "    Not covered (needs real hosts, run by hand): tests/e2e/rustion-ssh"
