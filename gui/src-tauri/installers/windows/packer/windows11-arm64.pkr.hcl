# Packer template — build the disposable Windows 11 ARM64 Tart base image
# `bastionvault-win11-builder` with the full GUI build toolchain baked in.
#
# This is the one-time, "completely built via the tool" image build. Once it
# exists, build-in-vm.sh clones it into an ephemeral VM per build and deletes
# that clone afterwards, so day-to-day builds never touch this template.
#
# Prerequisites (see README.md):
#   - Tart + Packer (`brew install cirruslabs/cli/tart packer`)
#   - A Windows 11 ARM64 ISO (free from Microsoft) at -var windows_iso=...
#   - An autounattend ISO built from autounattend.xml (README shows the
#     one-liner) at -var autounattend_iso=...
#
# Run:
#   packer init .
#   packer build \
#     -var windows_iso=$HOME/isos/Win11_ARM64.iso \
#     -var autounattend_iso=$HOME/isos/autounattend.iso \
#     windows11-arm64.pkr.hcl

packer {
  required_plugins {
    tart = {
      version = ">= 1.12.0"
      source  = "github.com/cirruslabs/tart"
    }
  }
}

variable "windows_iso" {
  type = string
}
variable "autounattend_iso" {
  type = string
}
variable "image_name" {
  type    = string
  default = "bastionvault-win11-builder"
}
variable "cpu_count" {
  type    = number
  default = 4
}
variable "memory_gb" {
  type    = number
  default = 8
}
variable "disk_size_gb" {
  type    = number
  default = 90
}

source "tart-cli" "win11" {
  vm_name = var.image_name
  # Boot the Windows installer ISO plus the autounattend ISO; autounattend.xml
  # drives a zero-touch install and enables WinRM for the provisioners below.
  from_iso           = [var.windows_iso, var.autounattend_iso]
  cpu_count          = var.cpu_count
  memory_gb          = var.memory_gb
  disk_size_gb       = var.disk_size_gb
  recovery_partition = "keep"

  # Communicate over WinRM once autounattend has installed Windows + enabled it.
  communicator   = "winrm"
  winrm_username = "admin"
  winrm_password = "admin"
  winrm_timeout  = "2h"
  winrm_use_ssl  = false
  winrm_insecure = true

  # Give Windows setup + first boot time before WinRM is expected.
  create_grace_time = "120s"
}

build {
  sources = ["source.tart-cli.win11"]

  # Copy the provisioning + build scripts into the guest.
  provisioner "file" {
    source      = "${path.root}/../provision.ps1"
    destination = "C:/bv-provision/provision.ps1"
  }
  provisioner "file" {
    source      = "${path.root}/../build.ps1"
    destination = "C:/bv-provision/build.ps1"
  }

  # Install the toolchain (Rust + x64 target, Node, VS Build Tools, guest agent).
  provisioner "powershell" {
    inline = [
      "Set-ExecutionPolicy Bypass -Scope Process -Force",
      "& C:/bv-provision/provision.ps1",
    ]
    # VS Build Tools + rustup can take a while under a fresh VM.
    timeout = "90m"
  }
}
