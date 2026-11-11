# Clean & maintenance — Clean, prune, target-size.
# Included by the top-level Makefile; do not run standalone.

##@ Clean & maintenance

.PHONY: prune-stale clean gui-clean docs-clean deep-clean target-size prune

prune-stale: ## Trim rustc incremental caches to the last KEEP sessions (default 3). Auto-runs before every compiling target.
	@KEEP=$(KEEP) bash scripts/prune-incremental.sh

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
