# Install — Install from source, macOS client install.
# Included by the top-level Makefile; do not run standalone.

##@ Install

.PHONY: install uninstall macos-client-install

# ── Install from source onto this machine ─────────────────────────────
#
# `make install` builds the release `bvault` binary and drops it, plus
# the manpage and the shell completions, under $(PREFIX) — the same file
# set the .pkg/.deb/.rpm packages install, minus the package database
# entry. Use it when you build from source and want the server on PATH
# without producing an installer first.
#
# Like the CLI packages, this bestows NO privileges and registers NO
# service: it is a plain file drop (features/packaging-client-binaries.md).
# There is no systemd unit or launchd job in this repo; run the server
# with `bvault server --config <file>`.
#
#   make install                       # /usr/local, sudo only if needed
#   make install PREFIX=$$HOME/.local  # no sudo at all
#   make install DESTDIR=/tmp/stage    # stage into a fake root
#   make install NO_BUILD=1            # install whatever is in target/release
#   make uninstall                     # remove exactly what install wrote
#
# DESTDIR is prepended to every path and is for staging only — it is not
# baked into anything, so a staged tree is relocatable to /.

PREFIX  ?= /usr/local
DESTDIR ?=
NO_BUILD ?=

INSTALL_BIN_SRC ?= target/release/bvault
INSTALL_CLI_DIR := installers/cli

# Paths written, in the order the recipe writes them. `uninstall` removes
# this same list, so keep the two in step.
INSTALL_BIN_DST  := $(DESTDIR)$(PREFIX)/bin/bvault
INSTALL_MAN_DST  := $(DESTDIR)$(PREFIX)/share/man/man1/bvault.1.gz
INSTALL_BASH_DST := $(DESTDIR)$(PREFIX)/etc/bash_completion.d/bvault
INSTALL_ZSH_DST  := $(DESTDIR)$(PREFIX)/share/zsh/site-functions/_bvault
INSTALL_FISH_DST := $(DESTDIR)$(PREFIX)/share/fish/vendor_completions.d/bvault.fish

install: ## Build and install bvault + manpage + completions under $(PREFIX) (default /usr/local)
ifeq ($(OS),Windows_NT)
	@echo "ERROR: 'make install' is Unix-only (it writes a POSIX file layout)."; \
	 echo "       On Windows build an installer instead: make windows-cli-packages"; exit 1
else
ifneq ($(NO_BUILD),1)
	@$(MAKE) prune-stale
	cargo build -p bvault-cli --release --bin bvault
endif
	@[ -f "$(INSTALL_BIN_SRC)" ] || { \
	   echo "ERROR: $(INSTALL_BIN_SRC) not found — drop NO_BUILD=1, or point INSTALL_BIN_SRC at a binary."; exit 1; }
	@# Only escalate when the destination actually needs it. A PREFIX the
	@# user owns ($$HOME/.local, a DESTDIR staging root) installs with no
	@# sudo at all; /usr/local on a fresh machine needs it for the mkdir.
	@SUDO=; \
	 if [ "$$(id -u)" != 0 ]; then \
	   probe="$(DESTDIR)$(PREFIX)"; \
	   while [ -n "$$probe" ] && [ ! -d "$$probe" ]; do probe="$$(dirname "$$probe")"; done; \
	   if [ ! -w "$$probe" ]; then \
	     command -v sudo >/dev/null 2>&1 || { echo "ERROR: $(DESTDIR)$(PREFIX) is not writable and sudo is not available."; exit 1; }; \
	     echo "==> $(DESTDIR)$(PREFIX) is not writable — using sudo"; \
	     SUDO=sudo; \
	   fi; \
	 fi; \
	 set -e; \
	 $$SUDO install -d -m 0755 "$(dir $(INSTALL_BIN_DST))" "$(dir $(INSTALL_MAN_DST))" \
	                           "$(dir $(INSTALL_BASH_DST))" "$(dir $(INSTALL_ZSH_DST))" \
	                           "$(dir $(INSTALL_FISH_DST))"; \
	 $$SUDO install -m 0755 "$(INSTALL_BIN_SRC)" "$(INSTALL_BIN_DST)"; \
	 gzip -9 -c "$(INSTALL_CLI_DIR)/manpage/bvault.1" | $$SUDO tee "$(INSTALL_MAN_DST)" >/dev/null; \
	 $$SUDO chmod 0644 "$(INSTALL_MAN_DST)"; \
	 $$SUDO install -m 0644 "$(INSTALL_CLI_DIR)/completions/bvault.bash" "$(INSTALL_BASH_DST)"; \
	 $$SUDO install -m 0644 "$(INSTALL_CLI_DIR)/completions/_bvault"     "$(INSTALL_ZSH_DST)"; \
	 $$SUDO install -m 0644 "$(INSTALL_CLI_DIR)/completions/bvault.fish" "$(INSTALL_FISH_DST)"
	@echo ""
	@echo "==> Installed BastionVault $(VERSION):"
	@echo "    $(INSTALL_BIN_DST)"
	@echo "    $(INSTALL_MAN_DST)"
	@echo "    $(INSTALL_BASH_DST)"
	@echo "    $(INSTALL_ZSH_DST)"
	@echo "    $(INSTALL_FISH_DST)"
	@echo ""
	@echo "    No service was registered and no config was written."
	@echo "    Start a local server with:  bvault server --config config/dev.hcl"
	@echo "    Production config shapes:   config/single-node.hcl, config/ha-cluster.hcl"
	@command -v bvault >/dev/null 2>&1 || \
	   echo "    NOTE: $(PREFIX)/bin is not on your PATH — add it to use 'bvault' unqualified."
endif

uninstall: ## Remove the files `make install` wrote under $(PREFIX)
ifeq ($(OS),Windows_NT)
	@echo "ERROR: 'make uninstall' is Unix-only."; exit 1
else
	@SUDO=; \
	 if [ "$$(id -u)" != 0 ] && [ ! -w "$(dir $(INSTALL_BIN_DST))" ]; then SUDO=sudo; fi; \
	 for f in "$(INSTALL_BIN_DST)" "$(INSTALL_MAN_DST)" "$(INSTALL_BASH_DST)" \
	          "$(INSTALL_ZSH_DST)" "$(INSTALL_FISH_DST)"; do \
	   if [ -e "$$f" ]; then $$SUDO rm -f "$$f" && echo "    removed $$f"; fi; \
	 done
	@echo "==> Vault data and config were NOT touched (this target never created any)."
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
