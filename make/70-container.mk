# Container images — Server/downloads OCI images, deps layer, registry push.
# Included by the top-level Makefile; do not run standalone.

##@ Container images

.PHONY: container-image container-deps-key container-deps-ref container-deps-image container-deps-push container-cache-clean container-image-test container-image-run downloads-image downloads-image-run downloads-image-test container-repo-setup container-repo-show container-image-push

# ── Server container image (Wave 1, Phase 1 of Packaging & Distribution) ──
#
# Builds the OCI image defined by `deploy/container/Containerfile`. The
# build context is the repo root so the cargo workspace can be copied in.
#
# Tooling: prefers `podman`, falls back to `docker`. Both are first-class
# on Linux and macOS (Docker Desktop / podman machine) so the same
# invocation works on either OS.
#
# Override knobs (chain on the command line):
#   make container-image CONTAINER_TOOL=docker
#   make container-image IMAGE_NAME=ghcr.io/ffquintella/bastionvault
#   make container-image IMAGE_TAG=v0.4.0-rc1
#   make container-image PLATFORM=linux/arm64    # default is linux/amd64
#   make container-image INCLUDE_SHELL=0         # opt-out of /bin/sh
#   make container-image CACHE=0                 # cold build, ignore the cache
#   make container-image CARGO_BUILD_JOBS=2      # cap compile parallelism
#   make container-image CACHE_REF=ghcr.io/ffquintella/bastionvault:buildcache
#
# Build cache: the Containerfile splits the compile into a cargo-chef
# dependency layer and a workspace layer, so an ordinary rebuild reuses the
# ~1200 third-party crates and recompiles only the workspace. That works off
# the local layer cache with no flags. `CACHE_REF` additionally imports and
# exports that layer from a registry, which is what makes a fresh machine (or
# a CI runner) skip the dependency build too — it needs docker with
# BUILDX=1 (the docker-container driver); podman ignores it.
#
# `CACHE=0` forces a cold build. Use it for the artefact you sign and publish
# if you want the release to owe nothing to mutable cache state; `make
# container-cache-clean` drops the local build cache outright.
#
# `BUILDX` toggles `docker buildx build` (multi-arch capable) when
# CONTAINER_TOOL=docker. Podman handles --platform natively so the toggle
# has no effect there.
#
# `INCLUDE_SHELL` (0|1, default 1) controls whether the production
# image carries a shell. On by default so `podman exec` works out of
# the box and the bundled `rustion-master-bootstrap.sh` can be invoked
# directly inside the container. Setting to 0 stages no shell, restoring
# the classic shell-less distroless property (smallest attack surface,
# no /bin/sh available inside the container at all). When on, a Debian
# builder layer stages `busybox-static` and copies it into the runtime
# as /bin/busybox with /bin/sh -> busybox (single static binary, no
# library deps, ~1 MB). The :debug variant always has a shell and is
# unaffected by this flag.

CONTAINER_TOOL ?= $(shell command -v podman >/dev/null 2>&1 && echo podman || echo docker)
IMAGE_NAME     ?= bastionvault
IMAGE_TAG      ?= $(VERSION)
BUILDX         ?= 0
INCLUDE_SHELL  ?= 1

# Default `PLATFORM` to linux/amd64 so the image we build by default
# matches what we publish from CI (Linux/amd64 runners) and what most
# deployment targets expect. On Apple Silicon this goes through QEMU,
# which historically segfaults rustc inside the builder image — if you
# hit that, build natively for arm64 with `make container-image-run`
# (which overrides PLATFORM=linux/arm64) or pass PLATFORM= explicitly.
#
# Override on the command line for cross-arch builds:
#   make container-image PLATFORM=linux/arm64    # default is linux/amd64
PLATFORM ?= linux/amd64

# Build-cache knobs. Empty CARGO_BUILD_JOBS means one job per core, which is
# the Containerfile's default too (it used to be pinned to 2).
CACHE            ?= 1
CACHE_REF        ?=
CARGO_BUILD_JOBS ?=

# ── Dependency-layer image (the cross-run build cache) ─────────────────
#
# The Containerfile's `deps` stage is the ~1200-crate cook. Published as an
# image and passed back via BUILDER_BASE, it turns a cold CI build into a pull:
# the `chef`, `planner` and `deps` stages are then not built at all.
#
#   make container-deps-image            # build the cook as an image
#   make container-deps-push             # publish it
#   make container-image BUILDER_BASE=$$(make -s container-deps-ref)
#
# DEPS_KEY is the cache key: the digest of every input the cook depends on and
# nothing else. Source edits do not change it; a Cargo.lock or toolchain change
# does, which is exactly when the dependencies have to be rebuilt. It lives here
# rather than in CI so a laptop and a runner compute the same key.
_SHA256          := $(shell command -v sha256sum >/dev/null 2>&1 && echo sha256sum || echo 'shasum -a 256')
_DEPS_KEY_FILES  := Cargo.lock rust-toolchain.toml deploy/container/Containerfile deploy/container/cross-env.sh
DEPS_KEY         ?= $(shell cat $(_DEPS_KEY_FILES) 2>/dev/null | $(_SHA256) | cut -c1-16)
DEPS_IMAGE       ?= $(IMAGE_NAME)-builder
# The cook is per-architecture (it compiles for the target triple), so the tag
# has to be too — otherwise an arm64 run would happily start from an amd64 cook.
PLATFORM_SLUG    := $(subst /,-,$(PLATFORM))
DEPS_TAG         ?= deps-$(PLATFORM_SLUG)-$(DEPS_KEY)
DEPS_REF         ?= $(DEPS_IMAGE):$(DEPS_TAG)

# Where the workspace build starts from. Empty = build the `deps` stage in this
# build (the Containerfile's default).
BUILDER_BASE     ?=
ifneq ($(BUILDER_BASE),)
_BUILDER_BASE_FLAG := --build-arg BUILDER_BASE=$(BUILDER_BASE)
endif

# Registry TLS for the dependency-image pull/push and for a `FROM` that resolves
# to a registry. Only podman takes the flag; docker configures insecure
# registries at the daemon instead, so the flag is dropped there rather than
# failing the command. Set TLS_VERIFY=false for a plaintext-http registry.
TLS_VERIFY       ?=
ifneq ($(TLS_VERIFY),)
ifneq ($(CONTAINER_TOOL),docker)
_TLS_FLAG := --tls-verify=$(TLS_VERIFY)
endif
endif

# HSM feature set. Threaded through BOTH the cook and the workspace build from
# one variable: cargo fingerprints the feature set, so a `deps` image cooked
# with a different set than the build asks for is silently ignored and every
# crate is rebuilt — a cache that looks like it hit and behaves like it missed.
# Empty (the default) leaves the Containerfile's own default in force for both.
BVAULT_FEATURES  ?=
ifneq ($(BVAULT_FEATURES),)
_FEATURES_FLAG := --build-arg BVAULT_FEATURES=$(BVAULT_FEATURES)
endif

ifeq ($(CACHE),0)
_CACHE_FLAGS := --no-cache
else
ifneq ($(CACHE_REF),)
ifeq ($(CONTAINER_TOOL),docker)
_CACHE_FLAGS := --cache-from type=registry,ref=$(CACHE_REF) \
                --cache-to type=registry,ref=$(CACHE_REF),mode=max
else
# podman/buildah take a bare image reference here, NOT buildx's
# `type=registry,ref=` descriptor — passing the descriptor makes podman treat
# the whole string as an image name and the cache silently never hits. This
# branch is why CACHE_REF was a no-op on every podman runner.
_CACHE_FLAGS := --cache-from $(CACHE_REF) --cache-to $(CACHE_REF)
endif
endif
endif

# Docker's BuildKit/buildx `docker-container` driver (Docker Desktop's default
# builder) leaves the build result in the cache and does NOT place it in the
# local image store unless `--load` is passed — so a subsequent `docker image
# inspect` / `tag` (e.g. from container-image-push) can't see it. The classic
# `docker` driver auto-loads, where `--load` is harmless. podman writes to local
# storage natively and doesn't take the flag. `--load` requires a single
# platform, so omit it for a comma-separated multi-arch PLATFORM.
comma := ,
ifeq ($(CONTAINER_TOOL),docker)
ifeq ($(findstring $(comma),$(PLATFORM)),)
_LOAD_FLAG := --load
endif
endif

# Resolve the docker subcommand once: `buildx build` if BUILDX=1 (and
# we're on docker), plain `build` otherwise.
ifeq ($(CONTAINER_TOOL),docker)
ifeq ($(BUILDX),1)
_BUILD_CMD := docker buildx build --platform $(PLATFORM) $(_LOAD_FLAG)
else
_BUILD_CMD := docker build --platform $(PLATFORM) $(_LOAD_FLAG)
endif
else
_BUILD_CMD := $(CONTAINER_TOOL) build --platform $(PLATFORM)
endif

container-image: ## Build the server OCI image (auto-detects podman/docker, override with CONTAINER_TOOL=)
	@command -v $(CONTAINER_TOOL) >/dev/null 2>&1 || { \
		echo "ERROR: '$(CONTAINER_TOOL)' not found. Install podman or docker, or override with CONTAINER_TOOL=."; \
		exit 1; \
	}
	@if [ "$(CONTAINER_TOOL)" = "podman" ]; then \
		if ! podman info >/dev/null 2>&1; then \
			if podman machine list --format '{{.Name}}' 2>/dev/null | grep -q .; then \
				echo "==> Podman daemon unreachable, attempting machine start..."; \
				start_out=$$(podman machine start 2>&1 || true); \
				if [ -n "$$start_out" ] && ! echo "$$start_out" | grep -qiE 'already running|machine .* is running'; then \
					echo "$$start_out"; \
				fi; \
				for i in 1 2 3 4 5 6 7 8 9 10; do \
					podman info >/dev/null 2>&1 && break; \
					sleep 1; \
				done; \
				podman info >/dev/null 2>&1 || { \
					echo "ERROR: podman daemon still unreachable after machine start."; \
					echo "       Output of last 'podman machine start':"; \
					echo "$$start_out" | sed 's/^/         /'; \
					echo "       Try: 'podman machine stop && podman machine start' manually."; \
					exit 1; \
				}; \
			else \
				echo "ERROR: podman is not running and no podman machine is configured."; \
				echo "       Run 'podman machine init' first, then retry."; \
				exit 1; \
			fi; \
		fi; \
	fi
	@echo "==> Building $(IMAGE_NAME):$(IMAGE_TAG) ($(PLATFORM), INCLUDE_SHELL=$(INCLUDE_SHELL), CACHE=$(CACHE)) with $(CONTAINER_TOOL)"
	$(_BUILD_CMD) $(_CACHE_FLAGS) $(_BUILDER_BASE_FLAG) $(_TLS_FLAG) $(_FEATURES_FLAG) \
		--build-arg INCLUDE_SHELL=$(INCLUDE_SHELL) \
		--build-arg CARGO_BUILD_JOBS=$(CARGO_BUILD_JOBS) \
		-f deploy/container/Containerfile \
		-t $(IMAGE_NAME):$(IMAGE_TAG) \
		-t $(IMAGE_NAME):latest \
		.
	@echo ""
	@echo "==> Built $(IMAGE_NAME):$(IMAGE_TAG) and $(IMAGE_NAME):latest"
	@echo "    Inspect: $(CONTAINER_TOOL) images $(IMAGE_NAME)"
	@echo "    Run:     make container-image-run"

container-deps-key: ## Print the dependency-layer cache key (digest of Cargo.lock + toolchain + Containerfile)
	@echo "$(DEPS_KEY)"

container-deps-ref: ## Print the dependency-layer image reference for this key + platform
	@echo "$(DEPS_REF)"

container-deps-image: ## Build the dependency (cargo-chef cook) stage as a publishable image
	@echo "==> Building $(DEPS_REF) ($(PLATFORM)) with $(CONTAINER_TOOL)"
	$(_BUILD_CMD) $(_TLS_FLAG) $(_FEATURES_FLAG) \
		--build-arg CARGO_BUILD_JOBS=$(CARGO_BUILD_JOBS) \
		--target deps \
		-f deploy/container/Containerfile \
		-t $(DEPS_REF) \
		.
	@echo "==> Built $(DEPS_REF)"
	@echo "    Use it: make container-image BUILDER_BASE=$(DEPS_REF)"

container-deps-push: ## Push the dependency-layer image (build it first)
	@echo "==> Pushing $(DEPS_REF)"
	$(CONTAINER_TOOL) push $(_TLS_FLAG) $(DEPS_REF)

container-cache-clean: ## Drop the local container build cache (forces a cold dependency build)
	@echo "==> Pruning $(CONTAINER_TOOL) build cache"
	@if [ "$(CONTAINER_TOOL)" = "docker" ]; then \
		docker builder prune --force ; \
	else \
		podman system prune --force ; \
	fi

container-image-test: ## Test the Wolfi runtime images (static checks; set SMOKE=1 to also build + run-smoke the image)
	@if [ "$(SMOKE)" = "1" ]; then \
		echo "==> Wolfi runtime tests (static + smoke build with $(CONTAINER_TOOL))"; \
		BV_CONTAINER_SMOKE=1 CONTAINER_TOOL=$(CONTAINER_TOOL) \
			bash deploy/container/test/wolfi-runtime.test.sh; \
	else \
		echo "==> Wolfi runtime tests (static only; pass SMOKE=1 to build + smoke-test)"; \
		bash deploy/container/test/wolfi-runtime.test.sh; \
	fi

container-image-run: ## Build (linux/arm64) and run the server image locally (config from deploy/container/config/)
	@$(MAKE) container-image PLATFORM=linux/arm64
	@echo "==> Running $(IMAGE_NAME):$(IMAGE_TAG) (linux/arm64)"
	$(CONTAINER_TOOL) run --rm -it \
		--platform linux/arm64 \
		-p 8200:8200 \
		-v $(PWD)/deploy/container/config:/etc/bvault/config:ro \
		$(IMAGE_NAME):$(IMAGE_TAG)

# ── Client downloads site image (Wave 3 / Phase 2) ─────────────────────
#
# A second, much smaller OCI image: the static download site that serves the
# signed client installers inside an operator's network. It shares this file's
# CONTAINER_TOOL / PLATFORM / CACHE plumbing and deploy/container/cross-env.sh
# with the server image, and nothing else — different Containerfile, different
# binary, different repository.
#
# Phase 2 is amd64 and unsigned. Cosign signing, the SBOM attestation, arm64
# and TLS are Phase 3. See deploy/downloads/README.md and
# features/packaging-distribution-website.md.
#
#   make downloads-image
#   make downloads-image PLATFORM=linux/arm64
#   make downloads-image-run      # serve the checked-in fixtures on :8080
#   make downloads-image-test     # build + run + curl every route + tear down
#
# INCLUDE_SHELL defaults to 0 here, the opposite of the server image: this
# container serves static files and has nothing to `exec` into. Pass
# DOWNLOADS_INCLUDE_SHELL=1 to keep busybox for debugging.
DOWNLOADS_IMAGE_NAME    ?= bastionvault-downloads
DOWNLOADS_IMAGE_TAG     ?= $(VERSION)
DOWNLOADS_INCLUDE_SHELL ?= 0
DOWNLOADS_PORT          ?= 8080
DOWNLOADS_FIXTURE       ?= $(PWD)/cmd/bv-downloads-server/fixtures/v0.4.0

downloads-image: ## Build the client-downloads OCI image (PLATFORM= defaults to linux/amd64)
	@command -v $(CONTAINER_TOOL) >/dev/null 2>&1 || { \
		echo "ERROR: '$(CONTAINER_TOOL)' not found. Install podman or docker, or override with CONTAINER_TOOL=."; \
		exit 1; \
	}
	@echo "==> Building $(DOWNLOADS_IMAGE_NAME):$(DOWNLOADS_IMAGE_TAG) ($(PLATFORM), INCLUDE_SHELL=$(DOWNLOADS_INCLUDE_SHELL)) with $(CONTAINER_TOOL)"
	$(_BUILD_CMD) \
		--build-arg INCLUDE_SHELL=$(DOWNLOADS_INCLUDE_SHELL) \
		--build-arg CARGO_BUILD_JOBS=$(CARGO_BUILD_JOBS) \
		-f deploy/downloads/Containerfile \
		-t $(DOWNLOADS_IMAGE_NAME):$(DOWNLOADS_IMAGE_TAG) \
		-t $(DOWNLOADS_IMAGE_NAME):latest \
		.
	@echo ""
	@echo "==> Built $(DOWNLOADS_IMAGE_NAME):$(DOWNLOADS_IMAGE_TAG) and :latest"
	@echo "    Run: make downloads-image-run"

downloads-image-run: ## Build + run the downloads image over the checked-in fixture release
	@$(MAKE) downloads-image
	@echo "==> Serving $(DOWNLOADS_FIXTURE) on http://localhost:$(DOWNLOADS_PORT)/"
	$(CONTAINER_TOOL) run --rm -it \
		--platform $(PLATFORM) \
		-p $(DOWNLOADS_PORT):8080 \
		-v $(DOWNLOADS_FIXTURE):/srv/bv-downloads:ro \
		$(DOWNLOADS_IMAGE_NAME):$(DOWNLOADS_IMAGE_TAG) --verify-hashes

downloads-image-test: ## Build the downloads image, smoke every documented route against the fixtures, tear down
	@$(MAKE) downloads-image
	@bash deploy/downloads/test/smoke.sh

# ── Container image push (Sonatype Nexus, Docker Hub, GHCR, …) ─────────
#
# Two-step UX:
#   1. `make container-repo-setup` — interactive prompts; writes the
#      target registry config to `.container-repo.env` (gitignored).
#   2. `make container-image-push` — re-tags the local image and pushes
#      to whatever was saved. Builds the image first (via `make
#      container-image`) when no local `$(IMAGE_NAME):$(IMAGE_TAG)` exists.
#
# `.container-repo.env` is plain shell `KEY=value` lines so it can be
# sourced from the recipe and inspected with `cat`. We never write
# passwords; operators run `podman login` / `docker login` separately
# and the credential helpers handle the rest.

CONTAINER_REPO_ENV := .container-repo.env

container-repo-setup: ## Interactive setup: pick the target registry to push to (writes $(CONTAINER_REPO_ENV))
	@echo "==> Container image registry setup"
	@echo "    Saves to: $(CONTAINER_REPO_ENV) (gitignored)"
	@echo ""
	@echo "    Examples:"
	@echo "      Sonatype Nexus (port-based connector, e.g. 5000):"
	@echo "        REGISTRY=repo.example.com:5000   NAMESPACE=           IMAGE_NAME=bastionvault"
	@echo "      Sonatype Nexus (path-based routing):"
	@echo "        REGISTRY=repo.example.com        NAMESPACE=<repo>     IMAGE_NAME=bastionvault"
	@echo "      Docker Hub:"
	@echo "        REGISTRY=docker.io               NAMESPACE=<user|org> IMAGE_NAME=bastionvault"
	@echo "      GitHub Container Registry:"
	@echo "        REGISTRY=ghcr.io                 NAMESPACE=<user|org> IMAGE_NAME=bastionvault"
	@echo ""
	@printf "Registry hostname[:port]    [docker.io]: " ; read REG ; \
	 printf "Scheme (http|https)         [https]    : " ; read SCH ; \
	 printf "Namespace / repo path       [empty]    : " ; read NS  ; \
	 printf "Image name                  [bastionvault]: " ; read IMG ; \
	 printf "Default tag                 [$(VERSION)]: " ; read TAG ; \
	 REG=$${REG:-docker.io} ; \
	 SCH=$${SCH:-https} ; \
	 case "$$SCH" in http|https) ;; *) echo "ERROR: scheme must be http or https (got '$$SCH')"; exit 1 ;; esac ; \
	 IMG=$${IMG:-bastionvault} ; \
	 TAG=$${TAG:-$(VERSION)} ; \
	 { \
	   echo "# Generated by 'make container-repo-setup'."; \
	   echo "# Read by 'make container-image-push'. Do not commit."; \
	   echo "REGISTRY=$$REG"; \
	   echo "SCHEME=$$SCH"; \
	   echo "NAMESPACE=$$NS"; \
	   echo "IMAGE_NAME=$$IMG"; \
	   echo "DEFAULT_TAG=$$TAG"; \
	 } > $(CONTAINER_REPO_ENV)
	@echo ""
	@echo "==> Wrote $(CONTAINER_REPO_ENV):"
	@sed 's/^/    /' $(CONTAINER_REPO_ENV)
	@echo ""
	@echo "Next: log in to the registry with your container tool, then push."
	@echo "  $(CONTAINER_TOOL) login $$(grep '^REGISTRY=' $(CONTAINER_REPO_ENV) | cut -d= -f2)"
	@echo "  make container-image-push"

container-repo-show: ## Print the saved registry config from $(CONTAINER_REPO_ENV)
	@if [ ! -f $(CONTAINER_REPO_ENV) ]; then \
		echo "No registry configured yet. Run 'make container-repo-setup' first."; \
		exit 1; \
	fi
	@echo "==> $(CONTAINER_REPO_ENV)"
	@sed 's/^/    /' $(CONTAINER_REPO_ENV)

container-image-push: ## Build (if missing) + tag + push $(IMAGE_NAME):$(IMAGE_TAG) AND :latest to the saved registry. Override version with PUSH_TAG=
	@if [ ! -f $(CONTAINER_REPO_ENV) ]; then \
		echo "ERROR: no registry configured. Run 'make container-repo-setup' first."; \
		exit 1; \
	fi
	@command -v $(CONTAINER_TOOL) >/dev/null 2>&1 || { \
		echo "ERROR: '$(CONTAINER_TOOL)' not found."; exit 1; \
	}
	@if $(CONTAINER_TOOL) image inspect "$(IMAGE_NAME):$(IMAGE_TAG)" >/dev/null 2>&1 ; then \
		echo "==> using existing local image $(IMAGE_NAME):$(IMAGE_TAG)" ; \
	else \
		echo "==> local image $(IMAGE_NAME):$(IMAGE_TAG) not found — building it first" ; \
		$(MAKE) container-image ; \
	fi
	@. ./$(CONTAINER_REPO_ENV) ; \
	 SCHEME=$${SCHEME:-https} ; \
	 LOCAL_TAG="$(IMAGE_NAME):$(IMAGE_TAG)" ; \
	 VERSION_TAG="$${PUSH_TAG:-$(IMAGE_TAG)}" ; \
	 if [ -n "$$NAMESPACE" ]; then \
	   REMOTE_PFX="$$REGISTRY/$$NAMESPACE/$$IMAGE_NAME" ; \
	 else \
	   REMOTE_PFX="$$REGISTRY/$$IMAGE_NAME" ; \
	 fi ; \
	 REMOTE_VERSION="$$REMOTE_PFX:$$VERSION_TAG" ; \
	 REMOTE_LATEST="$$REMOTE_PFX:latest" ; \
	 if ! $(CONTAINER_TOOL) image inspect "$$LOCAL_TAG" >/dev/null 2>&1 ; then \
	   echo "ERROR: local image '$$LOCAL_TAG' still not found after build — check 'make container-image' output." ; \
	   exit 1 ; \
	 fi ; \
	 PUSH_FLAGS="" ; \
	 if [ "$$SCHEME" = "http" ]; then \
	   case "$(CONTAINER_TOOL)" in \
	     podman) PUSH_FLAGS="--tls-verify=false" ;; \
	     docker) \
	       echo "WARNING: SCHEME=http selected. Docker has no per-push insecure flag —" ; \
	       echo "         add \"$$REGISTRY\" to /etc/docker/daemon.json's" ; \
	       echo "         \"insecure-registries\" array and restart the daemon if the" ; \
	       echo "         push fails with a TLS error." ;; \
	   esac ; \
	 fi ; \
	 LOGIN_FLAGS="" ; \
	 if [ "$$SCHEME" = "http" ] && [ "$(CONTAINER_TOOL)" = "podman" ]; then \
	   LOGIN_FLAGS="--tls-verify=false" ; \
	 fi ; \
	 if $(CONTAINER_TOOL) login $$LOGIN_FLAGS --get-login "$$REGISTRY" >/dev/null 2>&1 ; then \
	   echo "==> already logged in to $$REGISTRY as $$($(CONTAINER_TOOL) login $$LOGIN_FLAGS --get-login $$REGISTRY 2>/dev/null)" ; \
	 else \
	   echo "==> not logged in to $$REGISTRY — running '$(CONTAINER_TOOL) login'" ; \
	   $(CONTAINER_TOOL) login $$LOGIN_FLAGS "$$REGISTRY" || { echo "ERROR: login to $$REGISTRY failed"; exit 1; } ; \
	 fi ; \
	 echo "==> tagging $$LOCAL_TAG as $$REMOTE_VERSION" ; \
	 $(CONTAINER_TOOL) tag "$$LOCAL_TAG" "$$REMOTE_VERSION" ; \
	 echo "==> tagging $$LOCAL_TAG as $$REMOTE_LATEST" ; \
	 $(CONTAINER_TOOL) tag "$$LOCAL_TAG" "$$REMOTE_LATEST" ; \
	 echo "==> pushing $$REMOTE_VERSION (scheme=$$SCHEME)" ; \
	 $(CONTAINER_TOOL) push $$PUSH_FLAGS "$$REMOTE_VERSION" ; \
	 echo "==> pushing $$REMOTE_LATEST (scheme=$$SCHEME)" ; \
	 $(CONTAINER_TOOL) push $$PUSH_FLAGS "$$REMOTE_LATEST"
	@echo ""
	@echo "==> Push complete."
	@echo "    If push failed with auth errors, run:"
	@. ./$(CONTAINER_REPO_ENV) ; \
	 if [ "$${SCHEME:-https}" = "http" ] && [ "$(CONTAINER_TOOL)" = "podman" ]; then \
	   echo "      $(CONTAINER_TOOL) login --tls-verify=false $$REGISTRY" ; \
	 else \
	   echo "      $(CONTAINER_TOOL) login $$REGISTRY" ; \
	 fi
