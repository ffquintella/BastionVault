---
sidebar_position: 2
title: Install
---

# Install BastionVault

BastionVault can be used as a standalone application or as a Rust library:

1. Build from source to get the `bvault` binary, or
2. Add it as a dependency from [crates.io](https://crates.io/crates/bastion_vault) for other Rust projects.

This document covers building and installing BastionVault as an application. For library usage, see [docs.rs](https://docs.rs/bastion_vault/latest/bastion_vault).

## Operating System

BastionVault works on the following operating systems:

* Linux
* macOS
* Windows (experimental)

## Prerequisite

BastionVault is written in [Rust](https://rust-lang.org), so Rust must be installed before building. Read [this](https://www.rust-lang.org/tools/install) to install Rust.

## Build from Source

Clone the repository from GitHub:

~~~bash
git clone https://github.com/ffquintella/BastionVault.git
cd BastionVault
~~~

Build the binary using `make` or `cargo`:

~~~bash
make build
~~~

Or directly with Cargo:

~~~bash
cargo build --release
~~~

After a successful build, the `bvault` executable will be in `target/release/` (or `target/debug/` for debug builds).

## Verify BastionVault

Run the following command:

~~~bash
target/release/bvault --help
~~~

You should see output similar to:

~~~
A secure and high performance secret management software that is compatible with Hashicorp Vault.

Usage: bvault [COMMAND]

Commands:
  server    Start a BastionVault server
  status    Print seal and HA status
  operator  Perform operator-specific tasks
  read      Read data from BastionVault
  write     Write data to BastionVault
  delete    Delete secrets and configuration
  list      List data from BastionVault
  login     Authenticate to BastionVault
  auth      Manage auth methods
  policy    Manage policies
  secrets   Manage secrets engines

Options:
  -h, --help     Print help
  -V, --version  Print version
~~~

That means you now have a ready-to-use BastionVault binary.
