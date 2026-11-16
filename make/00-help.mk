# Help — the command taxonomy, rendered from the map in make/02-groups.mk.
# Included by the top-level Makefile.
#
#   make help            the groups, one line each
#   make help <group>    that group's subcommands, with descriptions
#   make help-<word>     grep every documented target for <word> (legacy filter)

##@ Help

.PHONY: help
_HELP_ARG := $(if $(filter help,$(firstword $(MAKECMDGOALS))),$(word 2,$(MAKECMDGOALS)))

help: ## List the command groups; `make help <group>` lists a group's subcommands
ifeq ($(_HELP_ARG),)
	@echo "BastionVault v$(VERSION)  [host: $(OS_FAMILY)/$(HOST_ARCH)]"
	@echo ""
	@echo "Usage: make <group> [<subcommand>...]      make help <group> for subcommands"
	@echo ""
	@$(foreach g,$(GROUPS),printf '  \033[36m%-10s\033[0m %-62s %s\n' '$(g)' '$($(g).desc)' '$(if $($(g).default),[default: $($(g).default)],[explicit subcommand])';)
	@echo ""
	@echo "Examples: make test changed   |   make gui dev   |   make crates plan   |   make help test"
else
ifeq ($(filter $(_HELP_ARG),$(GROUPS)),)
	$(error Unknown group '$(_HELP_ARG)'. Groups: $(GROUPS))
endif
	@echo "make $(_HELP_ARG) <subcommand>   — $($(_HELP_ARG).desc)"
	@echo "$(if $($(_HELP_ARG).default),Default (bare 'make $(_HELP_ARG)'): $($(_HELP_ARG).default),Bare 'make $(_HELP_ARG)' shows this list; pick a subcommand.)"
	@echo ""
ifeq ($(OS),Windows_NT)
	@$(foreach e,$($(_HELP_ARG).subs),printf '  %-28s -> %s\n' '$(firstword $(subst :, ,$(e)))' '$(lastword $(subst :, ,$(e)))';)
else
	@$(foreach e,$($(_HELP_ARG).subs),printf '  \033[36m%-28s\033[0m %s\n' '$(firstword $(subst :, ,$(e)))' "$$(grep -h '^$(lastword $(subst :, ,$(e))):.*## ' $(MAKEFILE_LIST) | head -1 | sed 's/^[^#]*## //')";)
endif
endif

# `make help-<word>` lists only the documented targets whose name or description matches.
.PHONY: help-%
help-%:
	@grep -hE '^[a-zA-Z0-9_.-]+:.*## .*$*' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*## "} {printf "  \033[36m%-28s\033[0m %s\n", $$1, $$2}'
