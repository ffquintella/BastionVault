$ErrorActionPreference = 'Stop'
$toolsDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

# The package carries ONE bundled installer, and which format it is depends on
# how it was built -- both are supported on purpose:
#
#   *.msi  Tauri's WiX bundle   (make gui-windows-msi, needs a Windows host
#                                or the Tart Win11 VM)
#   *.exe  Tauri's NSIS bundle  (make gui-windows-nsis, cross-built in Docker
#                                with no Windows host at all)
#
# Both file names carry the version (and the MSI a locale too), so glob rather
# than hard-code a name that changes every release. Chocolatey abstracts the
# difference away for callers: `choco install bastionvault-gui` behaves
# identically either way, which is what lets Puppet stay format-agnostic.
$installer = @(Get-ChildItem -LiteralPath $toolsDir -Filter '*.msi') +
             @(Get-ChildItem -LiteralPath $toolsDir -Filter '*.exe') |
             Select-Object -First 1
if (-not $installer) {
    throw "no .msi or .exe found in $toolsDir -- the package was built incorrectly."
}

$logDir = Join-Path $env:ProgramData 'chocolatey\logs'

if ($installer.Extension -eq '.msi') {
    # Keep a verbose msiexec log next to Chocolatey's own logs: when a
    # per-machine MSI fails mid-install, its log is the only record of which
    # action failed.
    $msiLog = Join-Path $logDir 'bastionvault-gui.msi.install.log'
    $packageArgs = @{
        packageName    = 'bastionvault-gui'
        fileType       = 'msi'
        file           = $installer.FullName
        silentArgs     = "/qn /norestart /l*v `"$msiLog`""
        # 3010 / 1641 are "success, reboot required" -- not failures.
        validExitCodes = @(0, 3010, 1641)
    }
} else {
    # Tauri's NSIS installer: /S is silent. The bundle is configured
    # installMode = perMachine (gui/src-tauri/tauri.conf.json), which is what
    # makes an unattended SYSTEM-context install land in Program Files with an
    # HKLM uninstall entry instead of in SYSTEM's own user profile.
    $packageArgs = @{
        packageName    = 'bastionvault-gui'
        fileType       = 'exe'
        file           = $installer.FullName
        silentArgs     = '/S'
        validExitCodes = @(0, 3010, 1641)
    }
}

Write-Host "Installing BastionVault from $($installer.Name) ($($packageArgs.fileType), silent)"
Install-ChocolateyInstallPackage @packageArgs
