# Cross-compilation environment for the container builder stage.
#
# SOURCED (not executed) by every cargo-bearing RUN in
# deploy/container/Containerfile:
#
#   . /usr/local/bin/bv-cross-env
#
# It exists because the dependency-cook step and the real build have to
# agree on *every* one of these variables. Cargo's fingerprint covers the
# target triple, the linker and the cc-rs compiler vars, so a single
# difference between the two steps makes the cooked artefacts unusable and
# silently rebuilds ~1200 crates — the exact cost the cook step exists to
# avoid. One definition, sourced twice, cannot drift.
#
# Inputs (from BuildKit / --build-arg):
#   TARGETARCH        amd64 | arm64
#   CARGO_BUILD_JOBS  optional; empty means "one job per core"
#
# Exports:
#   RUST_TARGET                       the target triple
#   CARGO_TARGET_<TRIPLE>_LINKER      cross linker for the Rust link step
#   CC_/CXX_/AR_<triple>              cross toolchain for cc-rs build scripts
#   RUST_MIN_STACK                    see below

case "$TARGETARCH" in
    amd64)  RUST_TARGET=x86_64-unknown-linux-gnu;  CROSS_PFX=x86_64-linux-gnu ;;
    arm64)  RUST_TARGET=aarch64-unknown-linux-gnu; CROSS_PFX=aarch64-linux-gnu ;;
    *)      echo "unsupported TARGETARCH=${TARGETARCH:-<unset>}" >&2; exit 1 ;;
esac
export RUST_TARGET

# `CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER` for cargo; the lower-case
# `CC_x86_64_unknown_linux_gnu` family for cc-rs (ring, the PQ crates' build
# scripts, rusb's vendored libusb).
RUST_TARGET_ENV=$(echo "$RUST_TARGET" | tr '[:lower:]-' '[:upper:]_')
RUST_TARGET_VAR=$(echo "$RUST_TARGET" | tr '-' '_')
export CARGO_TARGET_${RUST_TARGET_ENV}_LINKER=${CROSS_PFX}-gcc
export CC_${RUST_TARGET_VAR}=${CROSS_PFX}-gcc
export CXX_${RUST_TARGET_VAR}=${CROSS_PFX}-g++
export AR_${RUST_TARGET_VAR}=${CROSS_PFX}-ar

# Job count. Empty — the default — leaves cargo on its own default of one
# job per available core.
#
# This was pinned to 2 while the image had no build cache at all, when every
# build was a cold build of the whole graph and the pin was a hedge against
# the builder VM's memory. It was the single largest contributor to the
# build's wall clock. Now that dependencies come out of a cached layer, a
# memory-constrained builder can put the cap back explicitly:
#
#   make container-image CARGO_BUILD_JOBS=2
#   podman build --build-arg CARGO_BUILD_JOBS=2 ...
if [ -n "${CARGO_BUILD_JOBS:-}" ]; then
    export CARGO_BUILD_JOBS
else
    unset CARGO_BUILD_JOBS
fi

# The ML-DSA / ML-KEM const-generic code monomorphises deeply enough to
# overflow rustc's default thread stack on some hosts.
export RUST_MIN_STACK=16777216
