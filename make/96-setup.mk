# Setup — Bootstrap dev environment.
# Included by the top-level Makefile; do not run standalone.

##@ Setup

.PHONY: bootstrap win-bootstrap

bootstrap: ## Install dependencies and set up the development environment
	rustup update stable
	cargo fetch
	@command -v cargo-nextest >/dev/null 2>&1 \
		&& echo "==> cargo-nextest already installed: $$(cargo nextest --version)" \
		|| cargo install --locked cargo-nextest
	@# Kani model checker (T31 Phase 3). `cargo kani setup` downloads the
	@# CBMC bundle and the pinned nightly it needs; it is a no-op once done.
	@command -v cargo-kani >/dev/null 2>&1 \
		&& echo "==> cargo-kani already installed: $$(cargo kani --version)" \
		|| cargo install --locked kani-verifier
	cargo kani setup
	@# `cross` is required for cross-compiling process plugins (e.g.
	@# darwin → x86_64-unknown-linux-gnu). Bare cargo fails at link time
	@# because rust-lld rejects GCC-style flags. The Makefile auto-detects
	@# `cross` and switches to it when PLUGINS_PROCESS_TARGET differs from
	@# the host triple. Needs Docker or Podman running at build time.
	@command -v cross >/dev/null 2>&1 \
		&& echo "==> cross already installed: $$(cross --version | head -n1)" \
		|| cargo install cross --git https://github.com/cross-rs/cross
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
