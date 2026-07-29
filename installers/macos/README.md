# BastionVault — install the macOS client on this Mac

`make macos-client-install` is the one-command path from a source checkout
to a working desktop client on your own Mac. It builds both halves for the
host arch and then installs them:

| Half | Built by | Lands at |
|------|----------|----------|
| GUI  | `make gui-macos-pkg` (Tauri `.app` → `.pkg`) | `/Applications/BastionVault.app` |
| CLI  | `make macos-cli-pkg` (`pkgbuild` + `productbuild`) | `/usr/local/bin/bvault` + manpage + bash/zsh completions |

```
installers/macos/
├── README.md            (this file)
└── install-client.sh    # hands the built .pkg(s) to Apple's installer(8)
```

The `.pkg` builders live with their respective halves
([`installers/cli/pkg/`](../cli/pkg/) and
[`gui/src-tauri/installers/macos/`](../../gui/src-tauri/installers/macos/));
this directory only holds the *install* step, so the packaging targets stay
usable on their own (CI builds packages, it does not install them).

## Usage

```sh
make macos-client-install                        # build + install both halves
make macos-client-install MACOS_CLIENT_PARTS=cli # CLI only (or gui)
make macos-client-install BV_QUIT_RUNNING=1      # quit a running GUI first
```

Both installs write outside `$HOME`, so `installer(8)` runs under `sudo`.
The script takes the credential once up front rather than letting each
package prompt separately. Afterwards it checks that the app bundle and the
binary actually appeared, prints both versions, and warns if
`/usr/local/bin` is missing from your `PATH`.

macOS only: Tauri needs macOS to build the `.app`, and
`pkgbuild`/`installer` are Apple tools.

## Installing over a running GUI

The GUI half **refuses** to install while `BastionVault.app` is running.
Two reasons:

- The running app may hold an **unsealed embedded vault**. Replacing it
  underneath itself is not something to do silently.
- Overwriting a live bundle leaves it half-old/half-new — the mapped
  executable keeps running while its resources are swapped out.

Quit the app and re-run, or pass `BV_QUIT_RUNNING=1` to have the script ask
it to quit via AppleScript (a graceful quit, so the app can seal and flush
on its way out — not a kill). It waits up to 10s and fails loudly if the
app is still up.

## Signing

A locally built `.pkg` is unsigned, which `installer(8)` accepts fine —
Gatekeeper does not gate an explicit root install. Set
`INSTALLER_IDENTITY="Developer ID Installer: <team>"` to sign the packages
during the build; notarisation is a CI step (see
[`installers/sign/README.md`](../sign/README.md)).

## Uninstalling

```sh
sudo rm -rf /Applications/BastionVault.app
sudo rm -f /usr/local/bin/bvault \
           /usr/local/share/man/man1/bvault.1.gz \
           /usr/local/etc/bash_completion.d/bvault \
           /usr/local/share/zsh/site-functions/_bvault
sudo pkgutil --forget com.bastionvault.gui
sudo pkgutil --forget com.bastionvault.cli
```

User data (vault state, config under `~/Library/Application Support/`) is
untouched by both the install and the commands above.
