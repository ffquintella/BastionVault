# Help — self-documenting target list, grouped by the `##@ Section` headers
# at the top of each make/*.mk module. Included by the top-level Makefile.

##@ Help

.PHONY: help
help: ## List available commands, grouped by function
	@echo "BastionVault v$(VERSION)  [host: $(OS_FAMILY)/$(HOST_ARCH)]"
	@echo ""
	@echo "Usage: make <target>      (make help-<word> to filter, e.g. make help-plugins)"
ifeq ($(OS),Windows_NT)
	@powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-Content '$(MAKEFILE_LIST)'.Split(' ') | ForEach-Object { if (\$$_ -match '^##@\s*(.*)') { '' ; \$$matches[1] } elseif (\$$_ -match '^([a-zA-Z0-9_.-]+):.*##\s*(.*)') { '  {0,-28} {1}' -f \$$matches[1], \$$matches[2] } }"
else
	@awk 'BEGIN {FS = ":.*## "} \
		/^##@/ {printf "\n\033[1m%s\033[0m\n", substr($$0, 5); next} \
		/^[a-zA-Z0-9_.-]+:.*## / {printf "  \033[36m%-28s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
endif

# `make help-<word>` lists only the targets whose name or description matches.
.PHONY: help-%
help-%:
	@grep -hE '^[a-zA-Z0-9_.-]+:.*## .*$*' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*## "} {printf "  \033[36m%-28s\033[0m %s\n", $$1, $$2}'
