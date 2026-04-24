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
endif

.PHONY: help build run-dev run-dev-gui gui-deps gui-build gui-test gui-check docs bump-minor bump-major bump-patch bootstrap win-bootstrap clean gui-clean docs-clean deep-clean prune target-size

help: ## List available commands
	@echo "BastionVault v$(VERSION)"
	@echo ""
	@echo "Usage: make <target>"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*##"}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

build: ## Build the project in release mode
	cargo build --release

run-dev: ## Run the development server
	cargo run -- server --config config/dev.hcl

gui-deps: ## Install GUI frontend dependencies
	cd gui && npm install

run-dev-gui: gui-deps ## Run the desktop GUI in dev mode (embedded = file storage)
	cd gui && BASTION_EMBEDDED_STORAGE=file npx tauri dev -- --features storage_hiqlite

run-dev-gui-hiqlite: gui-deps ## Run the desktop GUI in dev mode, embedded vault on hiqlite (ports 8210/8220)
	cd gui && BASTION_EMBEDDED_STORAGE=hiqlite npx tauri dev -- --features storage_hiqlite

gui-build: gui-deps ## Build the desktop GUI for production
	cd gui && npx tauri build -- --features storage_hiqlite

gui-test: gui-deps ## Run GUI frontend tests (Vitest)
	cd gui && npx vitest run

gui-check: gui-deps ## Type-check and lint the GUI frontend
	cd gui && npx tsc --noEmit && npx vite build

docs: ## Start the documentation site locally
	cd docs && npm install && npx docusaurus clear && npx docusaurus start

bump-patch: ## Bump patch version (0.0.x)
	@NEW=$$(echo $(VERSION) | awk -F. '{printf "%d.%d.%d", $$1, $$2, $$3+1}'); \
	sed -i '' "s/^version = \"$(VERSION)\"/version = \"$$NEW\"/" Cargo.toml; \
	echo "Bumped version: $(VERSION) -> $$NEW"

bump-minor: ## Bump minor version (0.x.0)
	@NEW=$$(echo $(VERSION) | awk -F. '{printf "%d.%d.0", $$1, $$2+1}'); \
	sed -i '' "s/^version = \"$(VERSION)\"/version = \"$$NEW\"/" Cargo.toml; \
	echo "Bumped version: $(VERSION) -> $$NEW"

bump-major: ## Bump major version (x.0.0)
	@NEW=$$(echo $(VERSION) | awk -F. '{printf "%d.0.0", $$1+1}'); \
	sed -i '' "s/^version = \"$(VERSION)\"/version = \"$$NEW\"/" Cargo.toml; \
	echo "Bumped version: $(VERSION) -> $$NEW"

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
