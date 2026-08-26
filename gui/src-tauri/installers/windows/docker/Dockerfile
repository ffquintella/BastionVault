# Builder image for the BastionVault GUI Windows x64 installer, produced
# WITHOUT a Windows host: `cargo-xwin` cross-compiles the whole graph to
# `x86_64-pc-windows-msvc` with clang-cl + lld-link against the Microsoft
# CRT/SDK headers, and Tauri's NSIS bundler runs Linux `makensis` to wrap
# the result into a Windows installer .exe.
#
# WHY NSIS AND NOT .MSI: Tauri v2's WiX/MSI bundler is compiled in only on
# Windows hosts (it drives WiX's candle.exe/light.exe). The NSIS bundler is
# not — it resolves a `makensis` from PATH, which is why this path can work
# in a container at all. An .msi still requires the Tart VM path (see
# ../README.md) or a real Windows host.
#
# The image is arch-agnostic on purpose: the cross-compile targets x64
# Windows regardless of whether this container runs on linux/arm64 or
# linux/amd64, so on Apple Silicon it runs NATIVELY (no QEMU emulation,
# unlike the Linux .deb/.rpm path in ../../linux/Dockerfile).
FROM debian:trixie-slim

ENV DEBIAN_FRONTEND=noninteractive

# clang/lld/llvm  → clang-cl, lld-link, llvm-lib, llvm-rc (the MSVC-alike
#                   toolchain cargo-xwin drives)
# cmake/ninja     → aws-lc-sys' build (rustls' crypto provider)
# nasm            → aws-lc-sys' x86_64 Windows assembly
# perl            → assorted -sys build scripts
# nsis            → makensis, the Windows installer compiler (Linux build)
# git             → cargo's git deps (the IronRDP fork)
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl git xz-utils file pkg-config \
        build-essential clang lld llvm cmake ninja-build nasm perl python3 \
        nsis nsis-common \
    && rm -rf /var/lib/apt/lists/*

# Debian's LLVM ships lld-link, llvm-lib and llvm-rc but no `clang-cl`
# binary at all — and clang-cl is the one cargo-xwin shells out to. It is
# not a separate program: clang picks its MSVC driver mode from argv[0], so
# a symlink named clang-cl IS clang-cl.
RUN ln -s "$(ls -d /usr/lib/llvm-*/bin/clang | tail -1)" /usr/bin/clang-cl \
    && clang-cl --version >/dev/null

# Node 22: the GUI frontend is Vite 7 (needs ^20.19 || >=22.12) and Debian
# trixie ships 20.19.x, which only just satisfies it. Pin 22 explicitly.
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

ENV CARGO_HOME=/opt/cargo \
    RUSTUP_HOME=/opt/rustup \
    PATH=/opt/cargo/bin:$PATH \
    XWIN_CACHE_DIR=/opt/xwin

# rust-toolchain.toml in the repo pins `stable`; install that plus the
# Windows target. cargo-xwin supplies the CRT/SDK, not rustup.
RUN curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal \
        --default-toolchain stable \
    && rustup target add x86_64-pc-windows-msvc \
    && cargo install --locked cargo-xwin \
    && rm -rf /opt/cargo/registry /opt/cargo/git

WORKDIR /work
