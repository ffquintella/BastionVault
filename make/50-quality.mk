# Docs, quality & benchmarks — Docs site, build benchmarks, unused-deps, timings.
# Included by the top-level Makefile; do not run standalone.

##@ Docs, quality & benchmarks

.PHONY: docs bench-build bench-build-quick deps-unused deps-unused-warn build-timings

docs: ## Serve the Docsify-powered documentation site locally on http://localhost:3000
	@command -v docsify >/dev/null 2>&1 || npm i -g docsify-cli
	docsify serve docs

# ── Decomposition instrumentation (Phase 0) ───────────────────────
#
# See roadmaps/workspace-decomposition.md. `bench-build` is the instrument every
# later phase reports its delta against; `deps-unused` keeps the dependency
# graph from re-growing the slack Phase 0 removed.

bench-build: require-nextest ## Measure incremental build cost (median of 3) and append a row to docs/build-timings/baseline.md
	scripts/bench-build.sh

bench-build-quick: require-nextest ## Same, single sample, nothing written to the log
	scripts/bench-build.sh --repeat 1 --no-log

deps-unused: ## Report unused direct dependencies in our crates (needs cargo-machete)
	scripts/deps-unused.sh

deps-unused-warn: ## Same, but never fails -- the shape CI uses
	scripts/deps-unused.sh --warn

build-timings: ## Write a cargo --timings HTML for a full lib rebuild (target/cargo-timings/)
	@# Touching core.rs forces the monolith to rebuild as one unit, which is the
	@# number the decomposition divides. Deps stay cached, so this shows the
	@# crate's own cost rather than a cold graph -- the cold picture comes from
	@# CI, where a cold build happens anyway.
	touch src/core.rs
	cargo build --lib --timings
	@echo
	@echo "==> open target/cargo-timings/cargo-timing.html"
	@echo "    archive it as docs/build-timings/lib-selftime-<commit>.html when it"
	@echo "    is a phase boundary worth keeping."
