# Build & run (dev) — Release build, dev server, fast-build flags, dev parallelism.
# Included by the top-level Makefile; do not run standalone.

##@ Build & run (dev)

.PHONY: build run-dev

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
# The default is one thread per core on the build host, detected below,
# rather than a number pinned to whichever machine was in front of us
# when the flag was added. Returns flatten well before they stop on a
# very large host, so dial it down there if a build starts thrashing.
#
# Tune or disable from the command line:
#   make build RUSTC_THREADS=6   # cap the front-end at 6 threads
#   make build RUSTC_THREADS=0   # off — plain stable behaviour
#
# Windows is intentionally excluded: setting RUSTFLAGS here would
# override (not merge with) the `/PDBPAGESIZE:8192` linker flag that
# .cargo/config.toml sets for the *-pc-windows-msvc targets, bringing
# back the GUI link failure `LNK1318` that flag exists to prevent.
FAST_BUILD_TARGETS := build install run-dev run-dev-gui run-dev-gui-hiqlite run-dev-gui-only run-dev-gui-proxy bootstrap
ifneq ($(OS),Windows_NT)
# `getconf` is POSIX and present on macOS and every Linux distro we build on;
# `sysctl -n hw.ncpu` covers the BSDs, and 8 is the last-resort fallback so a
# detection failure degrades to the old fixed default instead of `-Z threads=`.
HOST_CORES := $(shell getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 8)
RUSTC_THREADS ?= $(if $(strip $(HOST_CORES)),$(strip $(HOST_CORES)),8)
ifneq ($(RUSTC_THREADS),0)
$(FAST_BUILD_TARGETS): export RUSTC_BOOTSTRAP := 1
$(FAST_BUILD_TARGETS): export RUSTFLAGS := $(strip $(RUSTFLAGS) -Z threads=$(RUSTC_THREADS))
endif
endif

# Number of rustc incremental sessions to keep per crate. Anything
# older than the Nth most recent is reaped by `prune-stale`. Override
# from the command line — e.g. `make build KEEP=5` — when debugging
# an incremental-compilation bug where older generations need to
# stick around.
KEEP ?= 3

# ── Dev rebuild parallelism ───────────────────────────────────────
#
# The `run-dev*` targets used to pin `CARGO_BUILD_JOBS=6`, which capped
# cargo at 6 concurrent rustc processes no matter how many cores the host
# had. Empty now means cargo's own default — one job per core — so a dev
# rebuild uses the whole machine, matching `make build` and the container
# build (whose `CARGO_BUILD_JOBS` is likewise empty by default).
#
# Set it to cap parallelism again when the machine is memory-bound rather
# than CPU-bound: the GUI dev build links `bastion_vault` + Tauri + wry,
# and N concurrent rustc processes each holding a large crate graph can
# push a 16 GB host into swap, which is slower than fewer jobs.
#
#   make run-dev-gui DEV_BUILD_JOBS=6   # back to the old fixed cap
DEV_BUILD_JOBS ?=
_DEV_JOBS_ENV := $(if $(strip $(DEV_BUILD_JOBS)),CARGO_BUILD_JOBS=$(strip $(DEV_BUILD_JOBS)) ,)

build: prune-stale ## Build the project in release mode
	cargo build --release

run-dev: prune-stale ## Run the development server
	$(_DEV_JOBS_ENV)cargo run -- server --config config/dev.hcl
