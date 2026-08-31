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

## Desktop App — Prebuilt Installers

Each release publishes prebuilt installers for the **standalone desktop
client**: the BastionVault GUI with an embedded vault on the local **file**
storage backend. No server to run, no cluster to join — the vault lives in
your home directory.

Download them from the
[Releases page](https://github.com/ffquintella/BastionVault/releases), under
the `releases/<version>` tag:

| Platform | Asset |
|---|---|
| Linux (x86_64) | `BastionVault-<version>-standalone-x86_64.AppImage` |
| macOS (Apple Silicon) | `BastionVault-<version>-standalone-arm64.pkg` |
| Windows (x64) | `BastionVault-<version>-standalone-x64.msi` |

Verify what you downloaded against `SHA256SUMS-standalone.txt` from the same
release before installing:

~~~bash
sha256sum -c SHA256SUMS-standalone.txt --ignore-missing
~~~

Then:

* **Linux** — `chmod +x BastionVault-*.AppImage && ./BastionVault-*.AppImage`.
  Tauri bundles WebKitGTK into the image, so there is nothing to install
  first; two host requirements remain. The AppImage self-mounts via **FUSE
  2** — if your distro ships only FUSE 3, either install `libfuse2` or run
  it as `./BastionVault-*.AppImage --appimage-extract-and-run`. And the
  image is built on Ubuntu 24.04, so it needs **glibc 2.39 or newer** —
  Ubuntu 24.04+, Debian 13+, Fedora 40+, RHEL 10+. On anything older it
  will refuse to start; build from source there instead.
  `.deb` and `.rpm` packages exist as `make gui-linux-packages` targets but
  are not published to the Releases page.
* **macOS** — open the `.pkg`; it installs to `/Applications/BastionVault.app`.
  Until the release is notarised, Gatekeeper will block the first launch —
  right-click the app and choose **Open**.
* **Windows** — run the `.msi`. Until the release is Authenticode-signed,
  SmartScreen will warn; choose **More info → Run anyway**.

These installers omit the hiqlite cluster backend and the cloud storage
targets. If you need a clustered vault, a cloud-backed vault profile, or the
`bvault` CLI, build from source below or use the server container image.

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
