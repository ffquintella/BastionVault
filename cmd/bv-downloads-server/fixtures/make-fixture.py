#!/usr/bin/env python3
"""Regenerate the downloads-server fixture release root.

The manifest carries real SHA-256 digests over the placeholder bodies, so the
files and the manifest have to be written together or `--verify-hashes` fails.
Run from the repository root:

    python3 cmd/bv-downloads-server/fixtures/make-fixture.py
"""

import hashlib
import json
import pathlib

VERSION = "0.4.0"

# (platform, arch, kind, file name) — one artefact per `kind` in the closed
# enum, so the fixture exercises the whole matrix the page has to render.
SPECS = [
    ("linux", "amd64", "gui-deb", f"bastionvault-gui_{VERSION}_amd64.deb"),
    ("linux", "amd64", "cli-deb", f"bvault_{VERSION}_amd64.deb"),
    ("linux", "x86_64", "gui-rpm", f"bastionvault-gui-{VERSION}-1.x86_64.rpm"),
    ("linux", "x86_64", "cli-rpm", f"bvault-{VERSION}-1.x86_64.rpm"),
    ("macos", "arm64", "gui-pkg", f"BastionVault-{VERSION}-arm64.pkg"),
    ("macos", "arm64", "cli-pkg", f"bvault-{VERSION}-darwin-arm64.pkg"),
    ("windows", "amd64", "gui-msi", f"BastionVault-{VERSION}-x64.msi"),
    ("windows", "amd64", "cli-msi", f"bvault-{VERSION}-windows-x64.msi"),
]

root = pathlib.Path(__file__).resolve().parent / f"v{VERSION}"
vdir = root / f"v{VERSION}"
vdir.mkdir(parents=True, exist_ok=True)

files = []
for platform, arch, kind, name in SPECS:
    body = (
        f"PLACEHOLDER BastionVault {VERSION} artefact fixture\n"
        f"kind={kind} platform={platform} arch={arch}\n"
        f"name={name}\n"
        "Not a real package. Present so the downloads server has something to\n"
        "hash, list and serve in tests and in the container smoke check.\n"
    ).encode()
    (vdir / name).write_bytes(body)
    (vdir / f"{name}.sig").write_bytes(
        b"MEUCIQD-placeholder-cosign-signature-for-" + name.encode() + b"\n"
    )
    (vdir / f"{name}.pem").write_bytes(
        b"-----BEGIN CERTIFICATE-----\n"
        b"UExBQ0VIT0xERVIgLSBub3QgYSByZWFsIEZ1bGNpbyBjZXJ0aWZpY2F0ZQ==\n"
        b"-----END CERTIFICATE-----\n"
    )
    files.append(
        {
            "platform": platform,
            "arch": arch,
            "kind": kind,
            "name": name,
            "size": len(body),
            "sha256": hashlib.sha256(body).hexdigest(),
            "cosign_signature": f"v{VERSION}/{name}.sig",
            "cosign_certificate": f"v{VERSION}/{name}.pem",
        }
    )

(root / "manifest.json").write_text(
    json.dumps(
        {
            "version": VERSION,
            "released": "2026-06-01",
            "server_image": f"ghcr.io/ffquintella/bastionvault:v{VERSION}",
            "files": files,
        },
        indent=2,
    )
    + "\n"
)
print(f"wrote {len(files)} artefacts + manifest under {root}")
