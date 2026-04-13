---
sidebar_position: 2
title: Install
---

# Install BastionVault

BastionVault must be installed properly in your environment before it actually works. Currently BastionVault is only available by source code. BastionVault can be used as an application or a library, thus:

1. BastionVault is available to compile from source code only, or
2. BastionVault is availabe on [crates.io](https://crates.io/crates/bastion_vault) for other Rust projects.

This document is about how to build and install BastionVault in the application form. For the library form, please go to [docs.rs](https://docs.rs/bastion_vault/latest/bastion_vault) for more information.

## Operating System

BastionVault is supposed to work on the following operating systems:

* Linux
* macOS
* Windows (experimental)

In this document, macOS is used as the demonstration operating system.

## Prerequisite

BastionVault is developed in [Rust](https://rust-lang.org) programming language, so Rust must be properly installed in your environment before building BastionVault.

Read [this](https://www.rust-lang.org/tools/install) to make Rust work for you.

## Build from Source

Clone the latest BastionVault source code from Github:

~~~bash
git clone https://github.com/ffquintella/BastionVault.git
~~~

Then you have a directory called BastionVault now. Change directory into it.

~~~bash
cd BastionVault
~~~

Simply build the binary by using the tool Cargo.

~~~bash
cargo build
~~~

Rust toolchain is responsible for taking care of almost everything during the build process. After BastionVault is successfully built, you get a bundle of files in the `BastionVault/target/debug` directory. There will be a executable file called `bvault`, which is the application of BastionVault.

## Verify BastionVault

Simply run the following command:

~~~bash
target/debug/bvault --help
~~~

And you will get a response similar to:

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