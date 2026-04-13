.DEFAULT_GOAL := help

VERSION := $(shell grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')

.PHONY: help build run-dev docs bump-minor bump-major bump-patch bootstrap

help: ## List available commands
	@echo "BastionVault v$(VERSION)"
	@echo ""
	@echo "Usage: make <target>"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*##"}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

build: ## Build the project in release mode
	cargo build --release

run-dev: ## Run the development server
	cargo run -- server --config config/dev.hcl

docs: ## Start the documentation site locally
	cd docs && npm install && npx docusaurus clear && npx docusaurus start

bump-patch: ## Bump patch version (0.0.x)
	@NEW=$$(echo $(VERSION) | awk -F. '{printf "%d.%d.%d", $$1, $$2, $$3+1}'); \
	sed -i '' "s/^version = \"$(VERSION)\"/version = \"$$NEW\"/" Cargo.toml; \
	echo "Bumped version: $(VERSION) -> $$NEW"

bump-minor: ## Bump minor version (0.x.0)
	@NEW=$$(echo $(VERSION) | awk -F. '{printf "%d.%d.0", $$1, $$2+1}'); \
	sed -i '' "s/^version = \"$(VERSION)\"/version = \"$$NEW\"/" Cargo.toml; \
	echo "Bumped version: $(VERSION) -> $$NEW"

bump-major: ## Bump major version (x.0.0)
	@NEW=$$(echo $(VERSION) | awk -F. '{printf "%d.0.0", $$1+1}'); \
	sed -i '' "s/^version = \"$(VERSION)\"/version = \"$$NEW\"/" Cargo.toml; \
	echo "Bumped version: $(VERSION) -> $$NEW"

bootstrap: ## Install dependencies and set up the development environment
	rustup update stable
	cargo fetch
	cargo check
	@echo "Bootstrap complete."
