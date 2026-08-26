$ErrorActionPreference = 'Stop'

# Remove the product through its Add/Remove Programs entry, which is where
# both bundle formats register themselves:
#
#   MSI  -- UninstallString is an msiexec /X{ProductCode} invocation
#   NSIS -- UninstallString points at $INSTDIR\uninstall.exe
#
# Both are removed silently and non-interactively; a Puppet run with
# `ensure => absent` must never block on a dialog.
$keys = @(Get-UninstallRegistryKey -SoftwareName 'BastionVault*')

if ($keys.Count -eq 0) {
    Write-Warning 'BastionVault was not found in the registry; nothing to remove.'
    return
}
if ($keys.Count -gt 1) {
    Write-Warning "Found $($keys.Count) matching entries; not removing automatically. Uninstall BastionVault from 'Apps & features'."
    return
}

$key       = $keys[0]
$validExit = @(0, 3010, 1641)

if ($key.UninstallString -match 'msiexec') {
    # PSChildName is the ProductCode GUID for an MSI-registered product.
    $productCode = $key.PSChildName
    Write-Host "Uninstalling BastionVault MSI ($productCode)..."
    $exit = (Start-Process 'msiexec.exe' `
                -ArgumentList "/x `"$productCode`" /qn /norestart" `
                -Wait -PassThru -NoNewWindow).ExitCode
    if ($validExit -notcontains $exit) { throw "msiexec /x failed with exit code $exit" }
} else {
    # NSIS: the registry value can be quoted and can carry its own arguments,
    # so take the executable path only, then add /S ourselves.
    $uninstaller = $key.UninstallString.Trim('"')
    if ($uninstaller -match '^(?<exe>.+?\.exe)') { $uninstaller = $Matches['exe'] }
    if (-not (Test-Path -LiteralPath $uninstaller)) {
        throw "uninstaller not found at '$uninstaller' (registry UninstallString: $($key.UninstallString))"
    }
    Write-Host "Uninstalling BastionVault NSIS bundle ($uninstaller)..."
    $exit = (Start-Process $uninstaller -ArgumentList '/S' -Wait -PassThru -NoNewWindow).ExitCode
    if ($validExit -notcontains $exit) { throw "NSIS uninstaller failed with exit code $exit" }
}
