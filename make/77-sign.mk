# Executable signing — signs the binaries that go INTO the installers.
# Included by the top-level Makefile; do not run standalone.
# The certificate is never in this tree: installers/sign/README-exe.md.

##@ Executable signing

.PHONY: sign-exe-setup sign-exe sign-exe-verify

SIGN_EXE_SH := bash installers/sign/sign-exe.sh
SIGN_BIN    ?= target/release/bvault
SIGN_OUT    ?= target/signed/bin

# $(call sign_stage,<file-or-.app>,<out-dir>): leaves the effective binary at
# <out-dir>/<name> (signed when a config exists, a plain copy otherwise).
# SIGN=0 skips; with no config and no terminal it skips rather than fails.
sign_stage = $(SIGN_EXE_SH) sign --auto --out $(2) $(1)

sign-exe-setup: ## Ask for the signing cert/key files and save them outside the repo (REDO=1 to change)
	@$(SIGN_EXE_SH) setup $(if $(REDO),--redo,)

sign-exe: ## Build bvault (unless NO_BUILD=1) and write a signed copy under target/signed/bin/
ifneq ($(NO_BUILD),1)
	cargo build -p bvault-cli --release --bin bvault
endif
	@$(call sign_stage,$(SIGN_BIN),$(SIGN_OUT))
	@ls -l $(SIGN_OUT)/$(notdir $(SIGN_BIN))*

sign-exe-verify: ## Verify the signed copy under target/signed/bin/ against the configured certificate
	@$(SIGN_EXE_SH) verify $(SIGN_OUT)/$(notdir $(SIGN_BIN))
