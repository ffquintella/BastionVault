# Standalone release — Tag/dispatch release and per-platform standalone builds.
# Included by the top-level Makefile; do not run standalone.

##@ Standalone release

.PHONY: release-version-check release release-dispatch release-linux-appimage release-macos-pkg release-windows-msi release-local release-checksums

# ── Standalone desktop release (one tag -> three installers) ───────────
#
# `make release` cuts a release of the STANDALONE desktop client: the
# Tauri GUI with the embedded vault on the plain **file** storage
# backend. One `releases/<version>` tag drives one GitHub Actions run
# (`.github/workflows/standalone-release.yml`) which builds three
# installers on three runners and publishes them to the GitHub release:
#
#   Linux   .AppImage   ubuntu-24.04 (x86_64, so glibc 2.39+ on the target)
#   macOS   .pkg        macos-15 (Apple Silicon, arm64)
#   Windows .msi        windows-latest (x64)
#
# Why CI and not here: a Tauri app cannot be cross-compiled. The WebView
# is a native build-time dependency (WebKitGTK / WebKit / WebView2), so
# each format has to be produced on its own OS — the same reason
# `gui-linux-packages` / `gui-windows-msi` / `gui-macos-pkg` are
# host-gated. CI is where three hosts exist at once. The workflow calls
# the very same `release-*-*` targets below, so an artefact built on a
# developer's machine is comparable to the published one.
#
#   make release                  # tag releases/$(VERSION) + push -> CI builds and publishes
#   make release DRY_RUN=1        # print what it would tag/push, change nothing
#   make release ALLOW_DIRTY=1    # tag a dirty worktree (you almost never want this)
#   make release-dispatch         # re-run the workflow for an existing tag
#   make release-local            # build THIS host's standalone installer into dist/
#
# "Standalone" is a feature selection, not a separate crate:
#
#   --no-default-features --features embedded_vault,ssh_pqc
#
# which drops `storage_hiqlite` (no embedded Raft/SQLite cluster) and
# `cloud_targets` (no S3/OneDrive/GDrive/Dropbox vault profiles) from the
# GUI's defaults. The file backend needs no feature of its own — it is
# unconditional in `bv-storage` and is what `embedded::storage_kind()`
# selects when `BASTION_EMBEDDED_STORAGE` is unset. `embedded_vault`
# keeps the in-process `EmbeddedBackend`; `ssh_pqc` keeps ML-DSA-65 SSH
# CA generation, which is a signing-time code path and costs a
# standalone user nothing.
#
# CAVEAT worth knowing before you ship one: the Add Local Vault modal
# still offers "hiqlite" as a storage engine. In a standalone build that
# backend is not compiled in, so choosing it fails at vault-open time
# with a backend-not-found error rather than being greyed out.

STANDALONE_FEATURES ?= embedded_vault,ssh_pqc
STANDALONE_CARGO_ARGS := --no-default-features --features $(STANDALONE_FEATURES)

# Where the staged, release-named artefacts land. The GitHub job uploads
# whatever is in here, so the naming below is the published contract.
RELEASE_DIST ?= dist

# Asset names carry a `-standalone-` infix on purpose: `macos-release.yml`
# publishes `BastionVault-<version>-arm64.pkg` (the Homebrew-cask channel)
# to the *same* release tag, and an un-infixed name would clobber it.
RELEASE_HOST_ARCH := $(shell uname -m 2>/dev/null)
# The CI runners are x86_64 Linux and x64 Windows, but derive Linux from the
# host anyway so an aarch64 Linux build does not get labelled x86_64. Windows
# stays literal: Tauri's WiX bundler only produces x64 here.
RELEASE_APPIMAGE  = BastionVault-$(VERSION)-standalone-$(RELEASE_HOST_ARCH).AppImage
RELEASE_MSI      := BastionVault-$(VERSION)-standalone-x64.msi
RELEASE_MAC_ARCH := $(RELEASE_HOST_ARCH)
RELEASE_MAC_PKG   = BastionVault-$(VERSION)-standalone-$(RELEASE_MAC_ARCH).pkg

RELEASE_TAG   ?= releases/$(VERSION)
RELEASE_REPO  ?= $(shell git config --get remote.origin.url 2>/dev/null)

# The version has to agree in two places or the artefacts get labelled
# with a version nobody can reproduce. Same check the workflow runs, so a
# mismatch fails here in milliseconds instead of 40 minutes into a build.
release-version-check: ## Check Cargo.toml and tauri.conf.json agree on $(VERSION)
	@set -eu; \
	 gui_version=$$(grep -m1 '"version"' gui/src-tauri/tauri.conf.json \
	                | sed 's/.*"\([0-9][^"]*\)".*/\1/'); \
	 if [ "$$gui_version" != "$(VERSION)" ]; then \
		echo "ERROR: version mismatch."; \
		echo "  Cargo.toml          : $(VERSION)"; \
		echo "  tauri.conf.json     : $$gui_version"; \
		echo "Run 'make bump-patch' (or bump-minor/bump-major), commit, then retry."; \
		exit 1; \
	 fi; \
	 echo "==> versions agree on $(VERSION)"

release: release-version-check ## Cut the standalone desktop release: tag releases/$(VERSION) and push (CI builds + publishes)
	@set -eu; \
	 if [ "$${ALLOW_DIRTY:-0}" != "1" ] && [ -n "$$(git status --porcelain)" ]; then \
		echo "ERROR: the worktree is dirty. A release tag must name a committed tree,"; \
		echo "       or the published installers cannot be rebuilt from it."; \
		echo ""; \
		git status --short; \
		echo ""; \
		echo "Commit (or stash) first, or override with ALLOW_DIRTY=1 if you know why."; \
		exit 1; \
	 fi; \
	 if git rev-parse -q --verify "refs/tags/$(RELEASE_TAG)" >/dev/null; then \
		echo "ERROR: tag $(RELEASE_TAG) already exists locally."; \
		echo "       Bump the version ('make bump-patch') for a new release, or"; \
		echo "       re-run the build for the existing tag: make release-dispatch"; \
		exit 1; \
	 fi; \
	 echo "==> release $(VERSION)"; \
	 echo "    tag    : $(RELEASE_TAG)"; \
	 echo "    remote : $(RELEASE_REPO)"; \
	 echo "    builds : Linux .AppImage / macOS .pkg / Windows .msi (standalone, file backend)"; \
	 if [ "$${DRY_RUN:-0}" = "1" ]; then \
		echo ""; \
		echo "==> DRY_RUN=1 — would run:"; \
		echo "    git tag -a $(RELEASE_TAG) -m 'BastionVault $(VERSION)'"; \
		echo "    git push origin $(RELEASE_TAG)"; \
		exit 0; \
	 fi; \
	 git tag -a "$(RELEASE_TAG)" -m "BastionVault $(VERSION)"; \
	 git push origin "$(RELEASE_TAG)"; \
	 echo ""; \
	 echo "==> pushed $(RELEASE_TAG). The standalone-release workflow is now building."; \
	 echo "    Watch it:  gh run watch \$$(gh run list --workflow=standalone-release.yml -L1 --json databaseId -q '.[0].databaseId')"; \
	 echo "    Release:   gh release view $(RELEASE_TAG)"

release-dispatch: ## Re-run the standalone-release workflow for an existing tag (TAG=releases/x.y.z)
	@set -eu; \
	 command -v gh >/dev/null 2>&1 || { \
		echo "ERROR: the GitHub CLI ('gh') is required to dispatch a workflow run."; exit 1; }; \
	 tag="$${TAG:-$(RELEASE_TAG)}"; \
	 git rev-parse -q --verify "refs/tags/$$tag" >/dev/null \
		|| { echo "ERROR: no such tag: $$tag"; exit 1; }; \
	 echo "==> dispatching standalone-release.yml for $$tag"; \
	 gh workflow run standalone-release.yml -f "tag=$$tag"

# ── Per-platform standalone builds (host-gated; CI calls these) ────────
#
# Each one builds the bundle with Tauri and stages it into $(RELEASE_DIST)
# under the published name. They are separate targets rather than one
# `if`-ladder because CI runs exactly one per runner.

release-linux-appimage: gui-deps prune-stale ## Build the standalone Linux .AppImage into dist/ (Linux only)
ifneq ($(shell uname -s),Linux)
	@echo "ERROR: release-linux-appimage must run on Linux — Tauri links against the host's"; \
	 echo "       WebKitGTK and cannot cross-compile. Use the CI workflow, or"; \
	 echo "       'make gui-linux-packages' which has an emulated-Docker path for .deb/.rpm."; \
	 exit 1
else
	@# APPIMAGE_EXTRACT_AND_RUN lets linuxdeploy (itself an AppImage) run
	@# without FUSE, which containers and GitHub runners do not always have.
	cd gui && APPIMAGE_EXTRACT_AND_RUN=1 $(GUI_TAURI) build --bundles appimage -- $(STANDALONE_CARGO_ARGS)
	@set -eu; \
	 src=$$(ls -1t target/release/bundle/appimage/*.AppImage \
	              gui/src-tauri/target/release/bundle/appimage/*.AppImage 2>/dev/null | head -1); \
	 [ -n "$$src" ] || { echo "ERROR: no .AppImage found after the Tauri build"; exit 1; }; \
	 mkdir -p $(RELEASE_DIST); \
	 install -m 0755 "$$src" "$(RELEASE_DIST)/$(RELEASE_APPIMAGE)"; \
	 echo "==> $(RELEASE_DIST)/$(RELEASE_APPIMAGE)"; \
	 ls -lh "$(RELEASE_DIST)/$(RELEASE_APPIMAGE)"
endif

release-macos-pkg: gui-deps prune-stale ## Build the standalone macOS .pkg into dist/ (macOS only)
ifneq ($(shell uname -s),Darwin)
	@echo "ERROR: release-macos-pkg must run on macOS (Tauri needs macOS for the .app;"; \
	 echo "       pkgbuild/productbuild are Apple's)."; exit 1
else
	cd gui && $(GUI_TAURI) build --bundles app -- $(STANDALONE_CARGO_ARGS)
	@set -eu; \
	 app=$$(find gui/src-tauri/target target -type d -name 'BastionVault.app' \
	              -path '*/bundle/macos/*' 2>/dev/null | head -1 || true); \
	 [ -n "$$app" ] || { echo "ERROR: BastionVault.app not found under */bundle/macos/ after the Tauri build"; exit 1; }; \
	 echo "==> wrapping $$app into a .pkg"; \
	 VERSION=$(VERSION) APP_PATH="$$app" PKG_ARCH=$(RELEASE_MAC_ARCH) OUTPUT_DIR=target/pkg \
		bash gui/src-tauri/installers/macos/build-gui-pkg.sh; \
	 mkdir -p $(RELEASE_DIST); \
	 install -m 0644 "target/pkg/BastionVault-$(VERSION)-$(RELEASE_MAC_ARCH).pkg" \
	                 "$(RELEASE_DIST)/$(RELEASE_MAC_PKG)"; \
	 echo "==> $(RELEASE_DIST)/$(RELEASE_MAC_PKG)"; \
	 ls -lh "$(RELEASE_DIST)/$(RELEASE_MAC_PKG)"
endif

release-windows-msi: gui-deps prune-stale ## Build the standalone Windows .msi into dist/ (Windows only)
ifneq ($(OS),Windows_NT)
	@echo "ERROR: release-windows-msi must run on Windows — Tauri v2 compiles its WiX/MSI"; \
	 echo "       bundler in only on Windows. Off-Windows paths: 'make gui-windows-msi'"; \
	 echo "       (Tart Win11 VM on macOS) or 'make gui-windows-nsis' (Docker, .exe)."; \
	 exit 1
else
	cd gui && $(GUI_TAURI) build --bundles msi -- $(STANDALONE_CARGO_ARGS)
	@set -eu; \
	 src=$$(ls -1t gui/src-tauri/target/release/bundle/msi/*.msi \
	              target/release/bundle/msi/*.msi 2>/dev/null | head -1); \
	 [ -n "$$src" ] || { echo "ERROR: no .msi found after the Tauri build"; exit 1; }; \
	 mkdir -p $(RELEASE_DIST); \
	 cp "$$src" "$(RELEASE_DIST)/$(RELEASE_MSI)"; \
	 echo "==> $(RELEASE_DIST)/$(RELEASE_MSI)"; \
	 ls -lh "$(RELEASE_DIST)/$(RELEASE_MSI)"
endif

release-local: ## Build the standalone installer for THIS host into dist/ (AppImage / pkg / msi)
ifeq ($(OS),Windows_NT)
	@$(MAKE) release-windows-msi
else ifeq ($(shell uname -s),Linux)
	@$(MAKE) release-linux-appimage
else ifeq ($(shell uname -s),Darwin)
	@$(MAKE) release-macos-pkg
else
	@echo "ERROR: unknown host — no standalone installer format wired"; exit 1
endif

# Named SHA256SUMS-standalone.txt rather than SHA256SUMS so it cannot
# collide with the file `macos-release.yml` publishes to the same tag.
release-checksums: ## Checksum everything staged in dist/ into SHA256SUMS-standalone.txt
	@set -eu; \
	 cd $(RELEASE_DIST); \
	 files=$$(ls -1 | grep -v '^SHA256SUMS' || true); \
	 [ -n "$$files" ] || { echo "ERROR: nothing staged in $(RELEASE_DIST)/"; exit 1; }; \
	 if command -v sha256sum >/dev/null 2>&1; then \
		sha256sum $$files > SHA256SUMS-standalone.txt; \
	 else \
		shasum -a 256 $$files > SHA256SUMS-standalone.txt; \
	 fi; \
	 cat SHA256SUMS-standalone.txt
