$ErrorActionPreference = 'Stop'
$toolsDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

# The bundled installer is Tauri's WiX output, whose file name carries the
# version and locale (BastionVault_<ver>_x64_en-US.msi). Glob for it rather
# than hard-coding a name that changes with every release.
$msi = Get-ChildItem -LiteralPath $toolsDir -Filter '*.msi' | Select-Object -First 1
if (-not $msi) {
    throw "no .msi found in $toolsDir -- the package was built incorrectly."
}

# Keep a verbose msiexec log next to Chocolatey's own logs: when a per-machine
# MSI fails mid-install, its log is the only record of which action failed.
$msiLog = Join-Path $env:ProgramData 'chocolatey\logs\bastionvault-gui.msi.install.log'

$packageArgs = @{
    packageName    = 'bastionvault-gui'
    fileType       = 'msi'
    file           = $msi.FullName
    silentArgs     = "/qn /norestart /l*v `"$msiLog`""
    # 3010 / 1641 are "success, reboot required" -- not failures.
    validExitCodes = @(0, 3010, 1641)
}
Install-ChocolateyInstallPackage @packageArgs
