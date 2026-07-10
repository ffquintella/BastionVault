# provision.ps1 — bake the BastionVault GUI build toolchain into the Windows
# 11 ARM64 Tart base image. Run ONCE, by Packer, when building
# `bastionvault-win11-builder`. Idempotent enough to re-run by hand.
#
# Installs, for an ARM64 host cross-compiling to x64:
#   - Chocolatey (bootstrap package manager)
#   - VS 2022 Build Tools: C++ toolset + Windows SDK + the x86/x64 target
#     compilers (so an ARM64 host can link x86_64-pc-windows-msvc)
#   - Rust via rustup (host toolchain) + the x86_64-pc-windows-msvc target
#   - Node.js LTS (Vite frontend build), Git
#   - Tart Guest Agent (so `tart exec` works against this image)
#
# WiX is NOT installed here: Tauri v2 downloads its own WiX at build time.
# WebView2 ships with Windows 11.
$ErrorActionPreference = "Stop"
Set-ExecutionPolicy Bypass -Scope Process -Force

Write-Host "==> installing Chocolatey"
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
$env:Path += ";$env:ProgramData\chocolatey\bin"

Write-Host "==> installing VS 2022 Build Tools (C++ + Windows SDK + x64 target tools)"
# VCTools gives the ARM64-hosted compilers; VC.Tools.x86.x64 adds the x64
# cross target; the Win11 SDK provides the import libs the linker needs.
choco install -y visualstudio2022buildtools --package-parameters `
  "--add Microsoft.VisualStudio.Workload.VCTools --add Microsoft.VisualStudio.Component.VC.Tools.x86.x64 --add Microsoft.VisualStudio.Component.Windows11SDK.22621 --includeRecommended --quiet --wait --norestart"

Write-Host "==> installing Node.js LTS + Git"
choco install -y nodejs-lts git

Write-Host "==> installing Rust (rustup) + x86_64-pc-windows-msvc target"
$rustup = "$env:TEMP\rustup-init.exe"
# ARM64 rustup installer; host toolchain matches the VM (aarch64), then we
# add the x64 target for cross-compilation.
Invoke-WebRequest -Uri "https://static.rust-lang.org/rustup/dist/aarch64-pc-windows-msvc/rustup-init.exe" -OutFile $rustup
& $rustup -y --default-toolchain stable --profile minimal
$cargoBin = "$env:USERPROFILE\.cargo\bin"
$env:Path = "$cargoBin;$env:Path"
& "$cargoBin\rustup.exe" target add x86_64-pc-windows-msvc

Write-Host "==> installing the Tart Guest Agent (enables 'tart exec')"
# The guest agent is what `tart exec` talks to. Pinned via the latest
# release's Windows installer.
$agent = "$env:TEMP\tart-guest-agent.msi"
Invoke-WebRequest -Uri "https://github.com/cirruslabs/tart-guest-agent/releases/latest/download/tart-guest-agent-windows-installer.msi" -OutFile $agent
Start-Process msiexec.exe -ArgumentList "/i `"$agent`" /qn /norestart" -Wait

Write-Host "==> staging build.ps1 to C:\bv\"
New-Item -ItemType Directory -Force -Path "C:\bv" | Out-Null
Copy-Item -Path "$PSScriptRoot\build.ps1" -Destination "C:\bv\build.ps1" -Force

Write-Host "==> provision complete"
