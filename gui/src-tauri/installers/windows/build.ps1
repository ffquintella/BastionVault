# build.ps1 — cross-compile the BastionVault GUI to x64 and bundle the .msi,
# inside the Windows 11 ARM64 build VM. Invoked by build-in-vm.sh via
# `tart exec`. Staged into the base image at C:\bv\build.ps1 by provision.ps1.
#
# The repo is shared into the VM read-only ('bvsrc') and an output directory
# read-write ('bvout') by `tart run --dir=...`. We copy the source to a local
# disk first (a cargo target dir on a virtiofs share is slow and can misbehave
# with file locking), build there, then copy the finished .msi to 'bvout'.
param(
    [string]$Features = "storage_hiqlite,ssh_pqc",
    # Guest-side paths of the Tart --dir shares. Auto-detected when empty.
    [string]$SrcShare = "",
    [string]$OutShare = ""
)
$ErrorActionPreference = "Stop"
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"

function Find-Drive([scriptblock]$pred) {
    foreach ($d in (Get-PSDrive -PSProvider FileSystem)) {
        try { if (& $pred $d.Root) { return $d.Root } } catch {}
    }
    return $null
}

# Source share = the mounted drive that holds this repo (Cargo.toml + gui\src-tauri).
if (-not $SrcShare) {
    $SrcShare = Find-Drive { param($r) (Test-Path (Join-Path $r "Cargo.toml")) -and (Test-Path (Join-Path $r "gui\src-tauri")) }
}
if (-not $SrcShare) { throw "could not locate the 'bvsrc' source share in the guest" }

# Output share = a writable mounted drive that is neither C: nor the source.
if (-not $OutShare) {
    $OutShare = Find-Drive {
        param($r)
        ($r -ne "C:\") -and ($r -ne $SrcShare) -and (Test-Path $r) -and -not (Test-Path (Join-Path $r "Cargo.toml"))
    }
}
if (-not $OutShare) { throw "could not locate the 'bvout' output share in the guest" }

Write-Host "==> source share: $SrcShare"
Write-Host "==> output share: $OutShare"

# Copy the source to a local build dir, excluding heavy/host-arch dirs.
$build = "C:\build\BastionVault"
if (Test-Path $build) { Remove-Item -Recurse -Force $build }
New-Item -ItemType Directory -Force -Path $build | Out-Null
Write-Host "==> copying source to $build (excluding target, node_modules, .git)"
robocopy $SrcShare $build /MIR /XD target node_modules .git /NFL /NDL /NJH /NJS /NP | Out-Null
if ($LASTEXITCODE -ge 8) { throw "robocopy failed ($LASTEXITCODE)" }
$global:LASTEXITCODE = 0

Set-Location "$build\gui"

Write-Host "==> npm ci"
if (Test-Path "package-lock.json") { npm ci } else { npm install }
if ($LASTEXITCODE -ne 0) { throw "npm install failed" }

Write-Host "==> tauri build (cross-compile x86_64-pc-windows-msvc, .msi)"
# --target makes cargo cross-compile to x64; Tauri bundles an x64 .msi.
npx tauri build --target x86_64-pc-windows-msvc --bundles msi -- --features $Features
if ($LASTEXITCODE -ne 0) { throw "tauri build failed" }

$msiDir = "$build\gui\src-tauri\target\x86_64-pc-windows-msvc\release\bundle\msi"
$msi = Get-ChildItem -Path $msiDir -Filter *.msi -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $msi) {
    # Some workspace layouts put the target at the repo root.
    $msi = Get-ChildItem -Path "$build\target\x86_64-pc-windows-msvc\release\bundle\msi" -Filter *.msi -ErrorAction SilentlyContinue | Select-Object -First 1
}
if (-not $msi) { throw "no .msi produced under a bundle\msi directory" }

Copy-Item -Path $msi.FullName -Destination $OutShare -Force
Write-Host "==> copied $($msi.Name) to output share $OutShare"
