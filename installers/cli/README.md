# BastionVault CLI — Linux packaging (Wave 2 / Phase 1)

`installers/cli/` carries the static assets that the `bastionvault`
.deb / .rpm packages bundle alongside the `bvault` binary:

```
installers/cli/
├── README.md             (this file)
├── manpage/
│   └── bvault.1          # roff manpage shipped to /usr/share/man/man1/
└── completions/
    ├── bvault.bash       # /usr/share/bash-completion/completions/bvault
    ├── _bvault           # /usr/share/zsh/site-functions/_bvault
    └── bvault.fish       # /usr/share/fish/vendor_completions.d/bvault.fish
```

The Cargo.toml `[package.metadata.deb]` and
`[package.metadata.generate-rpm]` blocks reference these paths
verbatim; cargo-deb / cargo-generate-rpm copy them into the package
without any pre-build step.

## Building locally

```sh
cargo install cargo-deb cargo-generate-rpm
make linux-cli-packages
ls target/debian/         # *.deb
ls target/generate-rpm/   # *.rpm
```

## Phase 1 limitations

- The manpage and completions are hand-written stubs covering only the
  top-level subcommands. A follow-up will plug `clap_mangen` /
  `clap_complete` in so they're derived from the real CLI definition.
- No GPG signing yet (Phase 4 of the client-installers spec).
- amd64 only. arm64 cross-builds are a Phase 2 item alongside the
  macOS arm64 installers.
