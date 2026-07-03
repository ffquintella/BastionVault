# BastionVault CLI — native packaging (Linux .deb/.rpm, Windows .msi/.nupkg)

`installers/cli/` carries the static assets that the CLI packages
bundle alongside the `bvault` binary:

```
installers/cli/
├── README.md             (this file)
├── manpage/
│   └── bvault.1          # roff manpage shipped to /usr/share/man/man1/
├── completions/
│   ├── bvault.bash       # /usr/share/bash-completion/completions/bvault
│   ├── _bvault           # /usr/share/zsh/site-functions/_bvault
│   └── bvault.fish       # /usr/share/fish/vendor_completions.d/bvault.fish
├── msi/
│   ├── bvault.wxs        # WiX 3.x project (CLI-only): Program Files + system PATH
│   └── License.rtf       # shown by the WixUI_Minimal license dialog
└── nupkg/
    ├── bastionvault-cli.nuspec   # Chocolatey package (version injected at pack time)
    └── tools/
        ├── LICENSE.txt
        └── VERIFICATION.txt      # bvault.exe is staged here at build time
```

The Cargo.toml `[package.metadata.deb]` and
`[package.metadata.generate-rpm]` blocks reference these paths
verbatim; cargo-deb / cargo-generate-rpm copy them into the package
without any pre-build step.

## Building locally

Linux (.deb / .rpm):

```sh
cargo install cargo-deb cargo-generate-rpm
make linux-cli-packages
ls target/debian/         # *.deb
ls target/generate-rpm/   # *.rpm
```

Windows (.msi / .nupkg — must run ON Windows; needs the WiX 3.x
toolset on PATH and Chocolatey):

```sh
make windows-cli-packages
ls target/msi/            # bvault-<version>-windows-x64.msi
ls target/nupkg/          # bastionvault-cli.<version>.nupkg
```

`make cli-packages` picks the right pair for the host OS. The .msi
installs to `C:\Program Files\BastionVault CLI\` and appends that
directory to the system PATH (removed on uninstall); the Chocolatey
package relies on choco's automatic exe shimming, so `bvault` is on
PATH with no install script.

## Phase 1 limitations

- The manpage and completions are hand-written stubs covering only the
  top-level subcommands. A follow-up will plug `clap_mangen` /
  `clap_complete` in so they're derived from the real CLI definition.
- No GPG signing yet (Phase 4 of the client-installers spec).
- amd64 only. arm64 cross-builds are a Phase 2 item alongside the
  macOS arm64 installers.
