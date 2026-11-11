# Platform & toolchain — OS detection, host toolchain PATH fixes, WSL/GUI tool wrappers.
# Included by the top-level Makefile; do not run standalone.


.PHONY: 

# ── Windows: force `openssl-sys`'s vendored build to use Strawberry
# Perl instead of the MSYS perl that ships with Git for Windows.
#
# Problem: when `make` is invoked from Git-Bash (MSYS), `cargo`'s
# `Command::new("perl")` in the openssl-sys build script resolves
# to `C:\Program Files\Git\usr\bin\perl.exe` — a minimal MSYS perl
# that lacks `Locale::Maketext::Simple`. `perl ./Configure VC-WIN64A`
# then dies with "Can't locate Locale/Maketext/Simple.pm in @INC".
#
# Fix: `openssl-src` honours `OPENSSL_SRC_PERL`. Point it at
# Strawberry Perl (the standard Windows native install) so
# Configure runs with the full CPAN module set.
#
# Override on the command line if your Strawberry Perl lives
# elsewhere: `make OPENSSL_SRC_PERL=D:/perl/bin/perl.exe run-dev-gui`.
ifeq ($(OS),Windows_NT)
OPENSSL_SRC_PERL ?= C:/Strawberry/perl/bin/perl.exe
export OPENSSL_SRC_PERL

# Belt-and-braces: older `openssl-src` releases ignore
# `OPENSSL_SRC_PERL` and just call `Command::new("perl")`, which under
# Git-Bash resolves to the MSYS perl that lacks
# `Locale::Maketext::Simple`. Prepend Strawberry to PATH so the
# bare `perl` lookup hits the right interpreter regardless of which
# `openssl-src` version cargo picks. Override the locations on the
# command line if your Strawberry install is elsewhere:
#   `make STRAWBERRY_PERL_BIN=D:/perl/bin run-dev-gui`
STRAWBERRY_PERL_BIN ?= /c/Strawberry/perl/bin
STRAWBERRY_C_BIN    ?= /c/Strawberry/c/bin
export PATH := $(STRAWBERRY_PERL_BIN):$(STRAWBERRY_C_BIN):$(PATH)
endif

# ── Ensure rustup's toolchain wins over any system Rust (e.g.
# Homebrew's `rust` on macOS, distro packages on Linux, or a stray
# MSI on Windows). System Rust packages typically ship only the host
# std, so `cargo build --target wasm32-unknown-unknown` fails with
# "can't find crate for `core`" even after `rustup target add` —
# because the active rustc isn't the rustup one. Prepending rustup's
# shim dir fixes both `cargo` and `rustc` lookups in one shot.
#
# `$(HOME)/.cargo/bin` is the standard rustup location on Unix and on
# Windows under MSYS/Git-Bash. For native cmd.exe make we fall back to
# `$(USERPROFILE)/.cargo/bin`. Override with `RUSTUP_CARGO_BIN=...` if
# yours lives elsewhere.
ifeq ($(OS),Windows_NT)
RUSTUP_CARGO_BIN ?= $(if $(HOME),$(HOME)/.cargo/bin,$(USERPROFILE)/.cargo/bin)
else
RUSTUP_CARGO_BIN ?= $(HOME)/.cargo/bin
endif
export PATH := $(RUSTUP_CARGO_BIN):$(PATH)

# WSL projects checked out under /mnt/c can reject npm's chmod while
# creating node_modules/.bin links. Avoid bin links there and call the
# package entrypoints directly; keep normal npx behavior elsewhere.
ifeq ($(OS),Windows_NT)
IS_WSL := 0
else
IS_WSL := $(shell uname -r 2>/dev/null | tr '[:upper:]' '[:lower:]' | grep -q microsoft && echo 1)
endif
ifeq ($(IS_WSL),1)
GUI_NPM_INSTALL := npm install --no-bin-links --no-save --package-lock=false
GUI_TAURI := node node_modules/@tauri-apps/cli/tauri.js
GUI_TSC := node node_modules/typescript/bin/tsc
GUI_VITE := node node_modules/vite/bin/vite.js
GUI_VITEST := node node_modules/vitest/vitest.mjs
else
GUI_NPM_INSTALL := npm install
GUI_TAURI := npx tauri
GUI_TSC := npx tsc
GUI_VITE := npx vite
GUI_VITEST := npx vitest
endif

# ── Host detection ────────────────────────────────────────────────
#
# One place that says which OS this is, so targets and docs can branch on
# $(OS_FAMILY) (windows | macos | linux) instead of re-running `uname`.
# Override with `make OS_FAMILY=linux ...` only to test another branch.
# IS_WSL (above) is a Linux sub-case: OS_FAMILY stays `linux` there.
ifeq ($(OS),Windows_NT)
OS_FAMILY ?= windows
HOST_ARCH ?= $(or $(PROCESSOR_ARCHITEW6432),$(PROCESSOR_ARCHITECTURE))
else
_HOST_UNAME_S := $(shell uname -s 2>/dev/null)
OS_FAMILY ?= $(if $(filter Darwin,$(_HOST_UNAME_S)),macos,$(if $(filter Linux,$(_HOST_UNAME_S)),linux,unknown))
HOST_ARCH ?= $(shell uname -m 2>/dev/null)
endif
