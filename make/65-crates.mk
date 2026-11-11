# Library crates & registry — Cloudsmith cargo registry, per-crate bump and publish.
# Included by the top-level Makefile; do not run standalone.

##@ Library crates & registry

.PHONY: crates-login crates-verify crates-publish-dry crates-publish crates-plan crates-bump crates-publish-changed-dry crates-publish-changed crates-tag-push

# ── FerroGate SDK ─────────────────────────────────────────────────
#
# The `ferro-*` verifier crates come from the `uox-ferrogate` Cloudsmith
# registry (declared in .cargo/config.toml), pinned to an exact version in
# Cargo.toml. There is no re-vendoring step any more — bump the three `=`
# requirements and commit that. See docs/ferrogate-machine-auth.md
# § SDK dependency.

# ── Cargo registry: Cloudsmith uox/bastionvault ───────────────────
#
# The registry itself is declared in `.cargo/config.toml`. The token is
# never stored in the repo — see docs/publishing-crates.md.

CARGO_REGISTRY ?= uox-bastionvault

crates-login: ## Store a Cloudsmith Cargo API token in $CARGO_HOME (prompts; never touches the repo)
	@echo "Get an API key: https://cloudsmith.io/user/settings/api/"
	@echo "It is written to \$$CARGO_HOME/credentials.toml, outside this repo."
	@echo "(The repo's .gitignore also blocks .cargo/credentials* as a backstop.)"
	@echo
	cargo login --registry $(CARGO_REGISTRY)

crates-verify: ## Package the dependency-free crates from a staged tarball (no upload, no token)
	@# Only the crates with no *workspace* dependencies can be packaged
	@# before anything is on the registry: cargo resolves each dependency
	@# in its published (registry) form before it will stage a tarball, so
	@# a crate like bv_plugin_manifest cannot be verified until
	@# bv_plugin_surface is actually live. `make crates-publish-dry`
	@# reports those as "deferred".
	cargo package -p bv_plugin_surface -p bv_crypto -p bastion-plugin-testkit --allow-dirty

crates-publish-dry: ## Dry-run publish of all library crates in dependency order (uploads nothing)
	scripts/publish-crates.sh --registry $(CARGO_REGISTRY)

crates-publish: ## Publish all library crates to the Cloudsmith registry FOR REAL (irreversible; needs a clean tree)
	@echo "This uploads crates to '$(CARGO_REGISTRY)'. A published version can"
	@echo "never be replaced -- only yanked and superseded. Ctrl-C to abort."
	@echo
	@printf "Type the registry name to confirm: "; \
	read -r confirm; \
	if [ "$$confirm" != "$(CARGO_REGISTRY)" ]; then echo "aborted."; exit 1; fi
	scripts/publish-crates.sh --registry $(CARGO_REGISTRY) --execute

# ── Per-crate releases: build and push only what changed ──────────
#
# Phase 6 of roadmaps/workspace-decomposition.md. Every library crate carries
# its own version and is released on its own schedule, so a normal release
# ships a handful of crates rather than all 38. The three targets below are
# the whole loop:
#
#   make crates-plan               # what changed, and what would ship
#   make crates-bump               # patch-bump exactly those crates
#   make crates-publish-changed    # build + upload exactly those crates
#
# "Changed" means the crate's directory differs from its last
# `<name>-v<version>` release tag — scripts/crates-plan.sh explains how, and
# `make crates-plan` prints the reason per crate. Nothing here consults the
# product version: `bv-shamir` has not changed since it was extracted and must
# not be republished 40 times because the GUI shipped.
#
# WHY A PATCH BUMP DOES NOT DRAG THE WORKSPACE WITH IT: internal dependencies
# are declared `version = "0.1.0"`, a caret requirement matching every 0.1.x.
# Bumping `bv-errors` to 0.1.1 leaves all 32 dependents' manifests untouched,
# so their tarballs are unchanged and they are not republished — a consumer
# picks up 0.1.1 on its own. Do NOT pin internal deps with `=`, and do NOT
# move them into `[workspace.dependencies]`; either turns every release into a
# whole-workspace release. See AGENTS.md § Per-crate versioning.

crates-plan: ## Show which crates changed since their last published version (no build, no upload)
	@scripts/crates-plan.sh --registry $(CARGO_REGISTRY) $(if $(OFFLINE),--offline)

# MINOR=<crate> for a breaking change — that is the one call this cannot make
# for you, because it is a judgement about the crate's public API. Patch is the
# default because it is the safe default.
#
#   make crates-bump                        # patch-bump every changed crate
#   make crates-bump MINOR=bv-errors        # ...and treat bv-errors as breaking
#   make crates-bump CRATE=bv-engine-pki    # bump one, changed or not
#   make crates-bump DRY=1                  # show the edits, write nothing
crates-bump: ## Bump the version of each changed crate (MINOR=<crate> for breaking, CRATE=<name>, DRY=1)
	@scripts/crates-bump.sh $(if $(DRY),--dry-run) \
		$(foreach c,$(MINOR),--minor $(c)) $(foreach c,$(CRATE),--crate $(c))

crates-publish-changed-dry: ## Dry-run publish of ONLY the changed crates (uploads nothing)
	scripts/publish-crates.sh --registry $(CARGO_REGISTRY) --changed

crates-publish-changed: ## Publish ONLY the changed crates FOR REAL (irreversible; needs a clean tree)
	@# The plan is computed ONCE here and handed to the publish run, so the
	@# set you are asked to confirm is exactly the set that ships. Recomputing
	@# it after the prompt would leave a window where a `git commit` in another
	@# terminal changes what gets uploaded.
	@scripts/crates-plan.sh --registry $(CARGO_REGISTRY) --json > .crates-plan.json
	@scripts/crates-plan.sh --registry $(CARGO_REGISTRY)
	@echo
	@echo "This uploads the crates marked 'publish' above to '$(CARGO_REGISTRY)'."
	@echo "A published version can never be replaced -- only yanked and"
	@echo "superseded. Ctrl-C to abort."
	@echo
	@printf "Type the registry name to confirm: "; \
	read -r confirm; \
	if [ "$$confirm" != "$(CARGO_REGISTRY)" ]; then echo "aborted."; rm -f .crates-plan.json; exit 1; fi
	scripts/publish-crates.sh --registry $(CARGO_REGISTRY) --changed --execute \
		--plan-file .crates-plan.json
	@rm -f .crates-plan.json

# Separate from the publish step on purpose. The upload is irreversible and
# has already happened; pushing the tags is what makes the release visible to
# everyone else, and that stays a deliberate second action.
crates-tag-push: ## Push the local <crate>-v<version> tags written by the last publish
	@tags=$$(git tag --points-at HEAD | grep -E -- '-v[0-9]+\.[0-9]+\.[0-9]+$$' || true); \
	if [ -z "$$tags" ]; then \
		echo "No per-crate release tags at HEAD. Nothing to push."; exit 0; \
	fi; \
	echo "Pushing to origin:"; echo "$$tags" | sed 's/^/  /'; echo; \
	printf "Push these tags? [y/N] "; read -r ans; \
	if [ "$$ans" != "y" ] && [ "$$ans" != "Y" ]; then echo "aborted."; exit 1; fi; \
	git push origin $$tags
