# Verification tiers — Policy/ACL verification tiers 0-3 (gates, Kani, differential).
# Included by the top-level Makefile; do not run standalone.

##@ Verification tiers

.PHONY: verify-gates verify-routes verify-fast verify-kani verify-differential verify verify-full verification-report

# ── Verification tiers (T31 Phase 4) ──────────────────────────────
#
# The three guarantees of roadmaps/formal-verification-and-type-driven-security.md
# — structural (no privileged route without the authorization witness),
# mechanical (no SQL built from runtime strings) and mathematical (the ACL
# decision core, model-checked by Kani) — in tiers of rising cost.
# .github/workflows/verify.yml runs these same targets, so a tier means the
# same thing on a laptop and on a runner:
#
#   make verify-fast           tier 0  SQL gates, the two zero-dependency crates,
#                                      Kani inventory + gate self-test, route
#                                      inventory + witness doctests
#   make verify                tier 1  + Kani fast set + differential at 10k cases
#   make verify-full           tier 2  + every harness + differential at 1M cases
#   make verification-report   tier 3  verification-report.md from the evidence
#
# Each step leaves a JSON record in target/verify/ (scripts/verify.py), and the
# report states only what those records show for the exact tree it runs on. A
# Kani run is judged by scripts/verify.py, not by cargo-kani's exit status:
# cargo kani exits 0 on an UNSATISFIABLE cover, i.e. on a vacuous proof.
# `make -k verify-full` keeps going past a failed step so the report still has
# every result; its verdict is FAIL either way.
#
# Semgrep is not a cargo tool and may not be installed here. Without it the
# semgrep step fails and says how to install it; SEMGREP=0 records the step as
# SKIPPED instead — explicitly, never silently — and a SKIPPED step does not
# count towards any tier. tests.yml's sql-guard job always runs it.
#
# Measured on a warm tree (Apple M-series, Kani 0.68.0): verify-fast 33 s,
# verify 146 s (the Kani fast set 92 s of it), verify-full 35 min (the full
# Kani set 245 s, 1M differential cases 851 s, ~10 min rebuilding the bv-kernel
# test harness). The root build.rs reruns after an edit to any root-package
# file, docs and scripts included, so "warm" means no such edit since the last
# build. `make bootstrap` installs Kani.
VERIFY := python3 scripts/verify.py
SEMGREP ?= 1
KANI_SET ?= fast
# Recursive (`=`), so the python only runs for a target that uses them. The
# numbers live in scripts/verify.py, where the report's tier check reads them.
VERIFY_PR_CASES = $(shell $(VERIFY) cases 1)
VERIFY_FULL_CASES = $(shell $(VERIFY) cases 2)
CASES ?= $(VERIFY_PR_CASES)

verify-gates: prune-stale ## Tier 0 without a workspace build: SQL gates, clippy + tests of bv-policy-core/bv-sql-guard, Kani inventory, gate self-test (SEMGREP=0 to skip Semgrep)
	@$(VERIFY) step sql-gate -- scripts/check-sql-guard.sh
	@if [ "$(SEMGREP)" = "0" ]; then \
		$(VERIFY) step semgrep --skip "SEMGREP=0 was passed"; \
	else \
		$(VERIFY) step semgrep -- semgrep --config .semgrep/sql-guard.yml --error --metrics=off crates src; \
	fi
	@$(VERIFY) step core-lint -- cargo clippy -p bv-policy-core -p bv-sql-guard --all-targets -- -D warnings
	@$(VERIFY) step core-tests -- cargo test -p bv-policy-core -p bv-sql-guard
	@$(VERIFY) step kani-inventory -- $(VERIFY) inventory
	@$(VERIFY) step gate-selftest -- $(VERIFY) selftest

verify-routes: require-nextest prune-stale ## Tier 0 structural half: route inventory + golden files, registration gate, Authorized<R> compile_fail doctests
	@$(VERIFY) step routes -- cargo nextest run -p bv-server --lib routes:: authz::
	@$(VERIFY) step witness-doctests -- cargo test --doc -p bv-server authz

verify-fast: verify-gates verify-routes ## Tier 0 — every push: gates, zero-dependency crates, route inventory (<60 s warm)

verify-kani: ## Kani over KANI_SET=fast|full, judged by the gate (scripts/kani-harnesses.txt); prints counterexamples on failure
	@$(VERIFY) kani --set $(KANI_SET) --playback-on-failure

# The reject budget scales with CASES. The suite's rule-path generator filters
# out `+*` (the policy parser refuses it), about 6.7 % of draws (a trailing
# glob, p = 0.4, after a `+` segment, p = 1/6), and a policy-set case draws
# several paths. Proptest's fixed default of 65 536 local rejects therefore
# aborted the 1M run with "Too many local rejects" — measured: after 183 701
# accepted cases of production_agrees_with_the_frozen_evaluator (~0.36 rejects
# per case), and in segment_matcher_agrees_with_the_frozen_one. Not a
# disagreement. max(65536, CASES) leaves the accepted-case count alone and
# still aborts once rejects outnumber accepted cases. The cleaner fix — a
# generator that never draws `+*` — belongs to the Phase 3 suite.
verify-differential: require-nextest prune-stale ## The ACL differential suite (bv-kernel policy::differential) at CASES generated cases (default 10000)
	@rejects=$$(( $(CASES) > 65536 ? $(CASES) : 65536 )); \
	$(VERIFY) step differential --note cases=$(CASES) --note max_local_rejects=$$rejects -- \
		env PROPTEST_CASES=$(CASES) PROPTEST_MAX_LOCAL_REJECTS=$$rejects \
		cargo nextest run -p bv-kernel --lib differential

# Target-specific values reach the prerequisites, so `make verify` runs the
# fast harness set and 10k cases; `make verify CASES=100000` still overrides.
verify: KANI_SET = fast
verify: CASES = $(VERIFY_PR_CASES)
verify: verify-fast verify-kani verify-differential ## Tier 1 — every PR touching the ACL: tier 0 + Kani fast set + differential at 10k cases

verify-full: KANI_SET = full
verify-full: CASES = $(VERIFY_FULL_CASES)
verify-full: verify-fast verify-kani verify-differential ## Tier 2 — nightly and release: tier 0 + every Kani harness + differential at 1M cases

verification-report: ## Tier 3 — write target/verify/verification-report.md from the recorded evidence (TAG=, REQUIRE_TIER=0|1|2)
	@$(VERIFY) report $(if $(TAG),--tag $(TAG)) $(if $(REQUIRE_TIER),--require-tier $(REQUIRE_TIER))
