$ErrorActionPreference = 'Stop'

# Remove the product through msiexec /x, found by its Add/Remove Programs
# entry. Tauri registers the MSI under the app's productName.
$keys = @(Get-UninstallRegistryKey -SoftwareName 'BastionVault*')

if ($keys.Count -eq 0) {
    Write-Warning 'BastionVault was not found in the registry; skipping MSI removal.'
} elseif ($keys.Count -gt 1) {
    Write-Warning "Found $($keys.Count) matching entries; not removing automatically. Uninstall BastionVault from 'Apps & features'."
} else {
    $productCode = $keys[0].PSChildName
    Write-Host "Uninstalling BastionVault ($productCode)..."
    $exit = (Start-Process 'msiexec.exe' -ArgumentList "/x `"$productCode`" /qn /norestart" -Wait -PassThru -NoNewWindow).ExitCode
    if (@(0, 3010, 1641) -notcontains $exit) {
        throw "msiexec /x failed with exit code $exit"
    }
}
