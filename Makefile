# BastionVault build system — thin entry point.
#
# The targets live in make/*.mk, one module per function, included in
# numeric order. `make help` lists them grouped by function; `make help-<word>`
# filters (e.g. `make help-plugins`). The host OS is detected automatically
# (make/10-platform.mk -> $(OS_FAMILY)); `make package` / `make release-local`
# pick the right installer for it.
#
#   make/00-help.mk       help
#   make/10-platform.mk   OS + toolchain detection
#   make/20-build.mk      build, run-dev
#   make/30-gui.mk        desktop GUI
#   make/40-test.mk       tests          make/45-verify.mk  verification tiers
#   make/50-quality.mk    docs, benches, unused deps
#   make/60-version.mk    product version
#   make/65-crates.mk     library crates / registry
#   make/70-container.mk  OCI images
#   make/74..76           packaging (host-aware / CLI / GUI)
#   make/80-install.mk    install      make/85-release.mk  standalone release
#   make/90-plugins.mk    plugins      make/95-clean.mk    clean / prune
#   make/96-setup.mk      bootstrap

.DEFAULT_GOAL := help

ifeq ($(OS),Windows_NT)
VERSION := $(shell powershell -NoProfile -ExecutionPolicy Bypass -Command "((Select-String -Path Cargo.toml -Pattern '^version\s*=' -List).Line -replace '[^0-9.]','')")
else
VERSION := $(shell grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')
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

# Modules, in dependency order (platform first; later ones read its variables).
include make/00-help.mk
include make/10-platform.mk
include make/20-build.mk
include make/30-gui.mk
include make/40-test.mk
include make/45-verify.mk
include make/50-quality.mk
include make/60-version.mk
include make/65-crates.mk
include make/70-container.mk
include make/74-package.mk
include make/75-pkg-cli.mk
include make/76-pkg-gui.mk
include make/80-install.mk
include make/85-release.mk
include make/90-plugins.mk
include make/95-clean.mk
include make/96-setup.mk
