# BastionVault GUI — Windows installer (.msi) via a disposable Tart VM

Windows can't be built in a container (there is no Windows-container runtime
under macOS emulation), and x64 Windows only runs under painfully slow QEMU
emulation on Apple Silicon. So the off-Windows path builds the GUI `.msi`
inside a **native ARM64 Windows 11 VM** managed by
[Tart](https://tart.run) — the Multipass-equivalent for Apple Silicon, using
Apple's Virtualization.framework — and **cross-compiles to x64**
(`x86_64-pc-windows-msvc`). The ARM64 VM is fast (native virtualization); the
artifact is a normal x64 `.msi`.

On a Windows host, `make gui-windows-msi` just runs Tauri's WiX bundler
directly; this whole directory is only for the off-Windows (Mac) path.

```
gui/src-tauri/installers/windows/
├── README.md          (this file)
├── build-in-vm.sh     # orchestrator: clone → build → copy .msi out → destroy
├── provision.ps1      # bakes the toolchain into the base image (once)
├── build.ps1          # per-build: cross-compile x64 + bundle the .msi
└── packer/
    ├── windows11-arm64.pkr.hcl  # builds the base image from a Win11 ARM64 ISO
    └── autounattend.xml         # zero-touch Windows install answer file
```

## One-time setup

```sh
brew install cirruslabs/cli/tart hashicorp/tap/packer
```

You also need a **Windows 11 ARM64 ISO** (free from Microsoft — the "Windows
11 (arm64)" disk image; Microsoft does not offer a stable auto-download URL,
so download it once by hand).

### Build the base image (`bastionvault-win11-builder`)

Two ways — the automated one is what the "built entirely by the tool"
requirement asks for; the manual one is the reliable fallback if the
unattended install needs tweaking for your specific ISO.

**Automated (Packer).** Build an autounattend ISO from `autounattend.xml`,
then run Packer:

```sh
mkdir -p /tmp/ua && cp packer/autounattend.xml /tmp/ua/
hdiutil makehybrid -iso -joliet -default-volume-name UNATTEND \
  -o ~/isos/autounattend.iso /tmp/ua

cd packer
packer init .
packer build \
  -var windows_iso=$HOME/isos/Win11_ARM64.iso \
  -var autounattend_iso=$HOME/isos/autounattend.iso \
  windows11-arm64.pkr.hcl
```

`autounattend.xml` is the least-tested piece of this pipeline (Windows setup
is picky about the answer file and the ISO's image index). If Packer stalls
waiting for WinRM, use the manual path instead.

**Manual (reliable first time).**

```sh
tart create --disk-size 90 bastionvault-win11-builder
tart run bastionvault-win11-builder --disk ~/isos/Win11_ARM64.iso   # install Windows in the UI (user: admin / pass: admin)
# once Windows is up, install the guest agent + toolchain:
tart exec bastionvault-win11-builder powershell -ExecutionPolicy Bypass -File provision.ps1
tart stop bastionvault-win11-builder
```

Either way you end up with a reusable `bastionvault-win11-builder` image that
carries Rust (+ the `x86_64-pc-windows-msvc` target), Node, VS Build Tools,
and the Tart guest agent.

## Building the .msi

```sh
make gui-windows-msi        # on a Mac → uses the Tart VM automatically
# or directly:
bash gui/src-tauri/installers/windows/build-in-vm.sh
ls target/windows-vm/       # bvault GUI .msi (x64)
```

Each run **clones** the base image into an ephemeral VM, builds inside it, and
**deletes the clone on exit** — the build environment is disposable; only the
base image and the finished `.msi` persist.

## Status / caveats

- **Not exercised end-to-end in this repo's CI yet.** The scripts are authored
  to the documented Tart / Packer / Windows conventions and the Bash + HCL +
  XML are validated, but a full run needs a Windows 11 ARM64 ISO and an Apple
  Silicon host (a base-image build is ~1h; a cross-compiled build is fast
  afterwards). Validate on first run.
- **Signing** (Authenticode) is a CI concern, not done here.
- The base image uses throwaway `admin`/`admin` credentials — it is a
  disposable local build VM, never a shipped artifact.
