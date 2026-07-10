# Emulated-amd64 Linux builder for the BastionVault GUI .deb / .rpm.
#
# Tauri cannot cross-compile the GUI: the WebView runtime (WebKitGTK) is a
# native build- AND run-time dependency, so the GUI must be built inside a
# real Linux/amd64 environment. This image is that environment; built and
# run with `--platform=linux/amd64`, it runs under Docker Desktop's amd64
# emulation (QEMU / Rosetta) on an Apple-Silicon Mac, so a Mac can produce
# the Linux GUI installers without a native Linux host.
#
# The repo is bind-mounted at run time (see build-in-docker.sh) — nothing
# is COPYed in — so the build context is just this directory and the image
# only carries the toolchain.
FROM --platform=linux/amd64 debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive

# System dependencies, grouped by purpose:
#   - Tauri GUI build : libwebkit2gtk-4.1-dev (pulls gtk3 + soup3),
#                       librsvg2-dev, libayatana-appindicator3-dev, libxdo-dev
#   - toolchain glue  : build-essential, pkg-config, file, curl, wget, git,
#                       ca-certificates, perl (vendored OpenSSL), libssl-dev
#   - crypto asm      : nasm + cmake (aws-lc-sys / ring)
#   - bundlers        : dpkg-dev (.deb), rpm + fakeroot (.rpm)
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential pkg-config file curl wget git ca-certificates \
        perl libssl-dev nasm cmake dpkg-dev rpm fakeroot \
        libwebkit2gtk-4.1-dev librsvg2-dev \
        libayatana-appindicator3-dev libxdo-dev \
    && rm -rf /var/lib/apt/lists/*

# Node.js LTS for the Vite frontend build (Tauri's beforeBuildCommand).
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

# Rust (stable) via rustup. CARGO_HOME/RUSTUP_HOME live under /opt so a
# named volume can be mounted at /opt/cargo/registry for dep caching
# without shadowing the toolchain binaries in /opt/cargo/bin.
ENV RUSTUP_HOME=/opt/rustup \
    CARGO_HOME=/opt/cargo \
    PATH=/opt/cargo/bin:$PATH
RUN curl -fsSL https://sh.rustup.rs | sh -s -- -y \
        --default-toolchain stable --profile minimal \
    && rustc --version && cargo --version

WORKDIR /work
