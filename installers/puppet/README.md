# Unattended Windows deployment — Puppet → Chocolatey → BastionVault GUI

The full chain, none of it needing a Windows machine to *build*:

```
make gui-windows-nsis      # Docker cross-build  -> x64 NSIS .exe
make windows-gui-nupkg     # wrap it             -> bastionvault-gui.<ver>.nupkg
  (publish the .nupkg to a NuGet feed or a file share)
puppet agent               # chocolatey provider -> choco install -y -> silent install
```

Everything after the publish step is unattended: the `chocolatey` provider
runs `choco install -y`, and the package's `chocolateyInstall.ps1` passes the
installer's silent flag. No dialog, no language selector, no reboot prompt.

See [examples/bastionvault_gui.pp](examples/bastionvault_gui.pp) for a
copy-pasteable profile class. The minimal form is just:

```puppet
package { 'bastionvault-gui':
  ensure   => '0.41.17',
  provider => chocolatey,
  source   => 'https://nuget.internal.example/chocolatey',
}
```

## Why the installer format stopped mattering

The `.nupkg` wraps **either** bundle format, and Chocolatey hides the
difference from callers — `choco install bastionvault-gui` behaves identically
whether the payload is an `.msi` or an NSIS `.exe`, so the Puppet manifest
never mentions it:

| Payload | Built by | Needs a Windows host? |
|---|---|---|
| NSIS `.exe` | `make gui-windows-nsis` | **no** — Docker cross-build |
| WiX `.msi` | `make gui-windows-msi` | yes (Tart Win11 VM or a real host) |

`make windows-gui-nupkg` packs whichever is newest on disk, or the one named
by `GUI_INSTALLER=<path>`.

## Three things that actually decide whether an unattended install works

These matter far more than the installer format, and two of them are settled
in the build rather than in Puppet.

### 1. Per-machine scope — settled, was previously wrong

`gui/src-tauri/tauri.conf.json` sets `bundle.windows.nsis.installMode` to
`perMachine`. **Tauri's NSIS default is `currentUser`**, and Chocolatey under
Puppet runs as SYSTEM — so with the default, an unattended install lands in
`C:\Windows\System32\config\systemprofile\AppData\Local` and no operator can
ever launch it. `perMachine` puts it in Program Files with an HKLM uninstall
entry, which is also what Chocolatey's auto-uninstaller and
`ensure => absent` need in order to find it.

### 2. WebView2 on the target — decide this for your network

The GUI is a Tauri app: it needs the WebView2 runtime **on the machine it
installs on**. Windows 11 ships it, and Windows 10 has had it pushed via Edge
updates, so it is usually already there. Where it is not, Tauri's default
`webviewInstallMode` is `downloadBootstrapper` — which **downloads from
Microsoft at install time**.

On a segregated network with no route to Microsoft's CDN, that turns into a
failed unattended install on exactly the hosts that lack the runtime. If that
describes your fleet, set an offline mode in `tauri.conf.json`:

```json
"windows": {
  "webviewInstallMode": { "type": "offlineInstaller" },
  "nsis": { "installMode": "perMachine" }
}
```

`offlineInstaller` embeds the full runtime — it adds roughly 127 MB to the
installer *and* to every `.nupkg` you ship, so it is deliberately not the
default here. Check whether your targets already have WebView2 before paying
that cost:

```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}' -Name pv
```

### 3. The package must be signed for a real fleet

Nothing in this chain does Authenticode signing — the cross-build cannot
(signing needs a Windows host or a custom `bundler > windows > sign_command`).
An unsigned installer will draw SmartScreen warnings on interactive use, and
some environments block unsigned executables outright, which fails the
install. `make sign-packages` signs artefacts on disk from env-supplied keys;
see [../sign/README.md](../sign/README.md).

## Publishing the .nupkg

Chocolatey needs a source it can reach. Two that fit this repo:

- **A NuGet feed.** Cloudsmith already hosts this project's Cargo registry
  (`uox/bastionvault`) and supports NuGet repositories, so the same account
  can carry the Chocolatey feed. Push with `choco push` or Cloudsmith's API.
- **A file share or local directory.** `source => '\\\\fileserver\\choco'` works
  and needs no service at all — often the shortest path on an isolated
  network.

## Verifying a deployment

```powershell
choco list --local-only bastionvault-gui
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' |
  Where-Object DisplayName -like 'BastionVault*' |
  Select-Object DisplayName, DisplayVersion, InstallLocation
```

Chocolatey's own log — `C:\ProgramData\chocolatey\logs\chocolatey.log` — is
the first place to look when a silent install fails; the MSI path
additionally writes `bastionvault-gui.msi.install.log` beside it.

## Status

The build and packaging chain is verified end to end on macOS (a 24 MB
`bastionvault-gui.0.41.17.nupkg` carrying the cross-built x64 `.exe`).
**The install itself has not been exercised on a Windows host**, so the
Puppet manifest, the silent flags and the uninstall path are authored to the
documented Chocolatey/Tauri/NSIS behaviour rather than observed. Validate on
one machine before rolling to a fleet.
