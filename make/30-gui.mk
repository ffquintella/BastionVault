# Desktop GUI — GUI dev runs, debug proxy, frontend build/test/check.
# Included by the top-level Makefile; do not run standalone.

##@ Desktop GUI

.PHONY: gui-deps run-dev-gui run-dev-gui-proxy gui-build gui-test gui-check

gui-deps: ## Install GUI frontend dependencies
	cd gui && $(GUI_NPM_INSTALL)

# `--features` lists are explicit (not relying solely on the Tauri
# crate's `default = [...]`) so an operator skimming the Makefile
# can see exactly what the dev / prod GUI binaries ship with.
# `ssh_pqc` enables ML-DSA-65 SSH CA generation in the /ssh page.
run-dev-gui: gui-deps prune-stale ## Run the desktop GUI in dev mode with local MCP bridge enabled
	cd gui && $(_DEV_JOBS_ENV)BASTION_EMBEDDED_STORAGE=file BASTION_TAURI_MCP=1 $(GUI_TAURI) dev -- --features storage_hiqlite,mcp_local_dev,ssh_pqc

run-dev-gui-hiqlite: gui-deps prune-stale ## Run the desktop GUI in dev mode, embedded vault on hiqlite (ports 8210/8220)
	cd gui && $(_DEV_JOBS_ENV)BASTION_EMBEDDED_STORAGE=hiqlite $(GUI_TAURI) dev -- --features storage_hiqlite,ssh_pqc

# Lightest dev build: Tauri host + vite, with `bastion_vault` pulled
# in at default-features=false. That means no hiqlite (no Raft/SQLite
# compile), no cloud storage targets, no PQC SSH — just the bare
# minimum needed for the GUI to talk to an external bvault server via
# the Connect page. Local Vault profiles that depend on those
# features won't work in this build; that's the trade-off for the
# faster compile.
run-dev-gui-only: gui-deps prune-stale ## Run the desktop GUI in dev mode with no backend storage features (lightest compile) + MCP bridge
	cd gui && $(_DEV_JOBS_ENV)BASTION_TAURI_MCP=1 $(GUI_TAURI) dev -- --no-default-features --features mcp_local_dev

# ── Debug proxy (Charles / mitmproxy / Fiddler / Burp) ────────────
#
# Routes every outbound vault HTTP(S) request the GUI makes through an
# intercepting proxy so the API stream can be read while debugging.
# Covers all three client paths — the legacy `api::Client`, the
# bv-client `RemoteBackend`, and the cluster-discovery health probes.
#
# The proxy terminates TLS, so it sees the session token and every
# secret payload in cleartext. That is the whole point and also the
# reason this is a dev-only path: the code is behind the `debug_proxy`
# Cargo feature (compiled out of every default and packaged build) AND
# behind `BASTION_DEBUG_PROXY` being set. Point it at scratch vaults
# only. See docs/debug-proxy.md.
#
# Charles' certificate must be trusted for HTTPS targets. Export it
# with Help → SSL Proxying → Save Charles Root Certificate (choose the
# .pem format) and drop it at the path below, or pass your own:
#
#   make run-dev-gui-proxy PROXY_CA=/path/to/root.pem
#   make run-dev-gui-proxy PROXY=http://127.0.0.1:8080    # mitmproxy
#   make run-dev-gui-proxy PROXY_INSECURE=1               # skip verification
#
# Remember to enable SSL Proxying for the vault host:port in Charles
# (Proxy → SSL Proxying Settings), or it will only tunnel CONNECT.
PROXY ?= http://127.0.0.1:8888
PROXY_CA ?= $(HOME)/.charles/charles-ssl-proxying-certificate.pem
PROXY_INSECURE ?=

run-dev-gui-proxy: gui-deps prune-stale ## Run the desktop GUI in dev mode with all vault HTTP(S) routed through a debug proxy (Charles-compatible)
	@if [ -n "$(PROXY_INSECURE)" ]; then \
		echo "run-dev-gui-proxy: TLS verification DISABLED for this run (PROXY_INSECURE=$(PROXY_INSECURE))"; \
	elif [ -f "$(PROXY_CA)" ]; then \
		echo "run-dev-gui-proxy: trusting proxy CA $(PROXY_CA)"; \
	else \
		echo "run-dev-gui-proxy: no proxy CA at $(PROXY_CA)"; \
		echo "  HTTPS vaults will fail the handshake against the proxy certificate."; \
		echo "  Export the Charles root cert as PEM to that path, or re-run with"; \
		echo "    make run-dev-gui-proxy PROXY_CA=/path/to/root.pem"; \
		echo "    make run-dev-gui-proxy PROXY_INSECURE=1   # no verification at all"; \
		echo "  Continuing — plain-HTTP targets still work."; \
	fi
	@echo "run-dev-gui-proxy: proxying vault traffic through $(PROXY)"
	cd gui && $(_DEV_JOBS_ENV)BASTION_EMBEDDED_STORAGE=file BASTION_TAURI_MCP=1 \
		BASTION_DEBUG_PROXY="$(PROXY)" \
		$(if $(PROXY_INSECURE),BASTION_DEBUG_PROXY_INSECURE="$(PROXY_INSECURE)",$(if $(wildcard $(PROXY_CA)),BASTION_DEBUG_PROXY_CA="$(PROXY_CA)",)) \
		$(GUI_TAURI) dev -- --features storage_hiqlite,mcp_local_dev,ssh_pqc,debug_proxy

gui-build: gui-deps prune-stale ## Build the desktop GUI for production
	cd gui && $(GUI_TAURI) build -- --features storage_hiqlite,ssh_pqc

gui-test: gui-deps ## Run GUI frontend tests (Vitest)
	cd gui && $(GUI_VITEST) run

gui-check: gui-deps ## Type-check and lint the GUI frontend
	cd gui && $(GUI_TSC) --noEmit && $(GUI_VITE) build
