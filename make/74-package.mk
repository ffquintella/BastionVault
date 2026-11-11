# Package — one-command installers for whatever host this runs on.
# Included by the top-level Makefile; do not run standalone.

##@ Packaging (auto-detects host OS)

.PHONY: package
package: ## Build CLI + GUI installers for THIS host (Linux: deb+rpm; macOS: pkg; Windows: msi+nupkg)
	@$(MAKE) cli-packages
	@$(MAKE) gui-packages
