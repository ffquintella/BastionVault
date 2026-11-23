# Command taxonomy — `make <group> [<subcommand>...]`.
#
# The public surface of this Makefile is a short list of groups, each with
# subcommands:
#
#   make test                 default subcommand of the group
#   make test changed         one subcommand
#   make test unit doc        several, run in the order given
#   make help [<group>]       the groups, or one group's subcommands
#
# This file is the single source of truth for that map. Every subcommand points
# at an implementation target in a make/NN-*.mk module; those targets keep
# their historical names (`test-changed`, `gui-build`, `crates-bump`, ...), so
# CI, scripts/ and muscle memory keep working, but they are no longer listed by
# `make help`. To add a command: write the target in its module, then add a
# `<sub>:<target>` entry to its group below.
#
# How dispatch works (GNU make 3.81 compatible, no recursion): when the first
# goal is a group, the words after it are its subcommands. The group target is
# given the matching implementation targets as prerequisites, and the typed
# subcommand words are declared as empty targets so make does not try to build
# them as files. A group with no default (clean, release, bump, crates, check,
# gui) prints its help instead of acting — destructive or ambiguous verbs never
# run by omission.
#
# Rules for names: a subcommand must not equal an existing implementation
# target (its empty target would shadow it); `make taxonomy-check` enforces
# that and that every mapped target exists.

GROUPS := run build test check verify gui bump crates container package install release plugins clean setup

run.desc       := Start things locally
run.default    := server
run.subs       := server:run-dev docs:run-docs

build.desc     := Build binaries and measure the build
build.default  := release
build.subs     := release:build-release gui:gui-build timings:build-timings bench:bench-build bench-quick:bench-build-quick

test.desc      := Run tests
test.default   := unit
test.subs      := unit:test-unit bin:test-bin changed:test-changed plan:test-plan integration:test-integration doc:test-doc cucumber:test-cucumber hiqlite:test-hiqlite all:test-all release:test-release pki-composite:test-pki-composite pki-composite-lib:test-pki-composite-lib pki-composite-integration:test-pki-composite-integration oidc-legacy-tls:test-oidc-legacy-tls dbms:test-dbms gui:gui-test

check.desc     := Static checks and plans (nothing is built or changed)
check.default  :=
check.subs     := isolated:check-isolated hsm:check-hsm ci:ci-plan gui:gui-check deps:deps-unused deps-warn:deps-unused-warn

verify.desc    := Formal-verification tiers
verify.default := pr
verify.subs    := fast:verify-fast pr:verify-pr full:verify-full gates:verify-gates routes:verify-routes kani:verify-kani differential:verify-differential report:verification-report

gui.desc       := Desktop GUI (Tauri)
gui.default    :=
gui.subs       := deps:gui-deps dev:run-dev-gui dev-hiqlite:run-dev-gui-hiqlite dev-light:run-dev-gui-only dev-proxy:run-dev-gui-proxy build:gui-build test:gui-test check:gui-check clean:gui-clean

bump.desc      := Bump the product version (root crate + GUI)
bump.default   :=
bump.subs      := patch:bump-patch minor:bump-minor major:bump-major

crates.desc    := Library crates and the Cloudsmith registry
crates.default :=
crates.subs    := plan:crates-plan bump:crates-bump verify:crates-verify login:crates-login publish-dry:crates-publish-dry publish:crates-publish publish-changed-dry:crates-publish-changed-dry publish-changed:crates-publish-changed tag-push:crates-tag-push

container.desc    := OCI images (server, dependency layer, downloads)
container.default := image
container.subs    := image:container-image run:container-image-run test:container-image-test push:container-image-push deps-key:container-deps-key deps-ref:container-deps-ref deps-image:container-deps-image deps-push:container-deps-push cache-clean:container-cache-clean repo-setup:container-repo-setup repo-show:container-repo-show downloads:downloads-image downloads-run:downloads-image-run downloads-test:downloads-image-test

package.desc    := Installers (bare: CLI + GUI for this host)
package.default := host
package.subs    := host:package-host cli:cli-packages cli-all:cli-packages-all cli-linux:linux-cli-packages cli-deb:linux-cli-deb cli-rpm:linux-cli-rpm cli-windows:windows-cli-packages cli-msi:windows-cli-msi cli-nupkg:windows-cli-nupkg cli-pkg:macos-cli-pkg gui:gui-packages gui-linux:gui-linux-packages gui-msi:gui-windows-msi gui-nsis:gui-windows-nsis gui-nupkg:windows-gui-nupkg gui-pkg:gui-macos-pkg sign:sign-packages

install.desc    := Install bvault on this machine
install.default := bin
install.subs    := bin:install-bin remove:uninstall macos-client:macos-client-install

release.desc    := Standalone desktop release (never runs by omission)
release.default :=
release.subs    := check:release-version-check cut:release-cut dispatch:release-dispatch local:release-local appimage:release-linux-appimage pkg:release-macos-pkg msi:release-windows-msi checksums:release-checksums

plugins.desc    := Reference plugins, bundles, signing and plugin tests
plugins.default := all
plugins.subs    := all:plugins-all init:plugins-init target:plugins-target process-target:plugins-process-target pack-build:plugins-pack-build wasm:plugins-wasm process:plugins-process pack:plugins-pack keygen:plugins-keygen sign:plugins-sign bump:plugin-bump clean:plugins-clean test:plugins-test dynamic-test:dynamic-plugins-test dynamic-live:dynamic-plugins-live

clean.desc      := Remove artefacts (always explicit; see AGENTS.md section 5)
clean.default   :=
clean.subs      := cargo:clean-cargo gui:gui-clean deep:deep-clean incremental:prune stale:prune-stale size:target-size

setup.desc      := Bootstrap a development machine
setup.default   := host
setup.subs      := host:bootstrap windows:win-bootstrap

# ── dispatch ───────────────────────────────────────────────────────
.PHONY: $(GROUPS)

# sub-name / implementation lookups: $(call grp_impl,<group>,<sub>)
grp_names = $(foreach e,$($(1).subs),$(firstword $(subst :, ,$(e))))
grp_impl  = $(patsubst $(2):%,%,$(filter $(2):%,$($(1).subs)))

_GRP_FIRST := $(firstword $(MAKECMDGOALS))
_GRP_ARGS  := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))

ifneq ($(filter $(GROUPS),$(_GRP_FIRST)),)
# Groups other than the active one are empty targets: they may legitimately
# appear as a subcommand word elsewhere (`make gui test`).
$(filter-out $(_GRP_FIRST),$(GROUPS)): ; @:
_GRP_REQ := $(or $(_GRP_ARGS),$($(_GRP_FIRST).default))
_GRP_BAD := $(filter-out $(call grp_names,$(_GRP_FIRST)),$(_GRP_REQ))
ifneq ($(_GRP_BAD),)
$(error Unknown subcommand '$(firstword $(_GRP_BAD))' for 'make $(_GRP_FIRST)'. Try: make help $(_GRP_FIRST))
endif
ifeq ($(_GRP_REQ),)
$(_GRP_FIRST): ; @$(MAKE) --no-print-directory help $(_GRP_FIRST)
else
$(_GRP_FIRST): $(foreach s,$(_GRP_REQ),$(call grp_impl,$(_GRP_FIRST),$(s)))
_GRP_SWALLOW := $(filter-out $(GROUPS) help,$(_GRP_ARGS))
ifneq ($(strip $(_GRP_SWALLOW)),)
.PHONY: $(_GRP_SWALLOW)
$(_GRP_SWALLOW): ; @:
endif
endif
else
$(GROUPS): ; @:
endif

# ── taxonomy self-check ────────────────────────────────────────────
# Every mapped target must exist, and no subcommand word may shadow a target.
.PHONY: taxonomy-check
taxonomy-check:
	@targets=$$(grep -hoE '^[a-zA-Z0-9_.-]+:' $(MAKEFILE_LIST) | tr -d : | sort -u); \
	 bad=0; \
	 for ent in $(foreach g,$(GROUPS),$(foreach e,$($(g).subs),$(g):$(e))); do \
	   g=$${ent%%:*}; r=$${ent#*:}; s=$${r%%:*}; t=$${r#*:}; \
	   echo "$$targets" | grep -qx "$$t" || { echo "missing target: $$g $$s -> $$t"; bad=1; }; \
	   echo "$$targets" | grep -qx "$$s" && { echo "subcommand shadows a target: $$g $$s"; bad=1; }; \
	 done; \
	 [ $$bad = 0 ] && echo "taxonomy ok"
