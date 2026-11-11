# Product versioning — bump-patch/minor/major for the product version.
# Included by the top-level Makefile; do not run standalone.

##@ Product versioning

.PHONY: bump-patch bump-minor bump-major _bump-write

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
#   * `gui/package-lock.json`         (the same version, twice: the top-level
#                                      one and `packages[""].version`)
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
	@# The lockfile carries the same version twice and is otherwise full of
	@# dependency `"version"` keys, so neither substitution may run
	@# unanchored. The first is the top-level object's own key (2-space
	@# indent, first in the file). The second lives in `packages[""]`, the
	@# root-project entry — the range is opened by that entry's key so the
	@# substitution can only ever reach its version and not a
	@# `node_modules/...` entry's.
	@$(SED_INPLACE) '1,/^  "version":/s/^  "version": "[^"]*"/  "version": "$(NEW)"/' gui/package-lock.json
	@$(SED_INPLACE) '/^    "":/,/^      "version":/s/^      "version": "[^"]*"/      "version": "$(NEW)"/' gui/package-lock.json
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
	@# Cargo.lock records every workspace member's version. CI builds with
	@# `--locked`, so a bump committed without the matching lock fails the
	@# release job ("cannot update the lock file"). `--workspace` re-resolves
	@# the members only and leaves every third-party pin alone.
	@cargo update --workspace --offline >/dev/null 2>&1 || { echo "_bump-write: cargo update --workspace --offline failed; run it by hand and commit Cargo.lock" >&2; exit 1; }
	@echo "Bumped version: $(VERSION) -> $(NEW)"
	@echo "  Cargo.toml:                   $$(grep '^version' Cargo.toml | head -1)"
	@echo "  gui/src-tauri/Cargo.toml:      $$(grep '^version' gui/src-tauri/Cargo.toml | head -1)"
	@echo "  gui/package.json:              $$(grep '\"version\"' gui/package.json | head -1 | sed 's/^[ \t]*//')"
	@echo "  gui/src-tauri/tauri.conf.json: $$(grep '\"version\"' gui/src-tauri/tauri.conf.json | head -1 | sed 's/^[ \t]*//')"
	@echo "  gui/package-lock.json:         $$(grep -E '^  \"version\":|^      \"version\":' gui/package-lock.json | head -2 | grep -o '\"version\": \"[^\"]*\"' | tr '\n' ' ')"
	@echo "  crates/bvault-cli/Cargo.toml:  $$(grep '^version' crates/bvault-cli/Cargo.toml | head -1)"
	@echo "  bastion_vault pins:            $$(grep -h '^bastion_vault = ' crates/bvault-cli/Cargo.toml crates/bv-server/Cargo.toml | grep -o 'version = \"[^\"]*\"' | tr '\n' ' ')"
