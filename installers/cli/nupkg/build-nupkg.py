#!/usr/bin/env python3
"""Build a Chocolatey/NuGet .nupkg for the bvault CLI without Chocolatey.

A .nupkg is an OPC (Open Packaging Conventions) ZIP: the nuspec, the
payload under tools/, plus three OPC control parts ([Content_Types].xml,
_rels/.rels, and a core-properties .psmdcp). `choco pack` builds this on
Windows; this script builds the identical structure on any host with
Python 3, so the Docker/off-Windows packaging path does not need a
Windows runner or Chocolatey.

The output is byte-for-byte deterministic given the same inputs (fixed
zip timestamps, fixed psmdcp part name), which keeps the reproducible-build
promise in features/packaging-client-binaries.md for the CLI packages.

Usage:
    build-nupkg.py --nuspec <path> --version X.Y.Z --exe <bvault.exe> \
                   --tools <extra file> [...] --out <dir>

The nuspec's <version> placeholder is overwritten with --version. Every
--exe / --tools file is placed under tools/ in the package.
"""
import argparse
import re
import sys
import zipfile
from pathlib import Path
from xml.sax.saxutils import escape

# A fixed timestamp keeps the archive reproducible. NuGet/Chocolatey do
# not care about the stored mtime; a constant one means identical inputs
# yield an identical .nupkg.
FIXED_TIME = (1980, 1, 1, 0, 0, 0)

# OPC requires a content-type declaration for every file extension in the
# package. The two control extensions have specific media types; every
# other extension (nuspec + whatever ships under tools/) is application/octet,
# matching what `choco pack` emits.
CONTENT_TYPE_OVERRIDES = {
    "rels": "application/vnd.openxmlformats-package.relationships+xml",
    "psmdcp": "application/vnd.openxmlformats-package.core-properties+xml",
}


def build_content_types(extensions):
    lines = ['<?xml version="1.0" encoding="utf-8"?>',
             '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">']
    # "rels" and "psmdcp" are always present (the OPC control parts).
    for ext in sorted(set(extensions) | set(CONTENT_TYPE_OVERRIDES)):
        ctype = CONTENT_TYPE_OVERRIDES.get(ext, "application/octet")
        lines.append(f'  <Default Extension="{escape(ext)}" ContentType="{ctype}" />')
    lines.append("</Types>")
    lines.append("")
    return "\n".join(lines)

# Deterministic psmdcp part name (choco uses a random hex name; any stable
# name is valid as long as _rels/.rels points at it).
PSMDCP_PART = "package/services/metadata/core-properties/bastionvault.psmdcp"

RELS = f"""<?xml version="1.0" encoding="utf-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Type="http://schemas.microsoft.com/packaging/2010/07/manifest" Target="/{{nuspec}}" Id="Rmanifest" />
  <Relationship Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="/{PSMDCP_PART}" Id="Rcoreprops" />
</Relationships>
"""


def read_meta(nuspec_text, tag):
    m = re.search(rf"<{tag}>(.*?)</{tag}>", nuspec_text, re.DOTALL)
    return m.group(1).strip() if m else ""


def build_psmdcp(nuspec_text, version):
    creator = read_meta(nuspec_text, "authors")
    description = read_meta(nuspec_text, "description")
    pkg_id = read_meta(nuspec_text, "id")
    tags = read_meta(nuspec_text, "tags")
    return f"""<?xml version="1.0" encoding="utf-8"?>
<coreProperties xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns="http://schemas.openxmlformats.org/package/2006/metadata/core-properties">
  <dc:creator>{escape(creator)}</dc:creator>
  <dc:description>{escape(description)}</dc:description>
  <dc:identifier>{escape(pkg_id)}</dc:identifier>
  <version>{escape(version)}</version>
  <keywords>{escape(tags)}</keywords>
  <lastModifiedBy>build-nupkg.py</lastModifiedBy>
</coreProperties>
"""


def add_str(zf, name, text):
    zi = zipfile.ZipInfo(name, date_time=FIXED_TIME)
    zi.compress_type = zipfile.ZIP_DEFLATED
    zf.writestr(zi, text)


def add_file(zf, name, path):
    zi = zipfile.ZipInfo(name, date_time=FIXED_TIME)
    zi.compress_type = zipfile.ZIP_DEFLATED
    zf.writestr(zi, Path(path).read_bytes())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--nuspec", required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--exe", action="append", default=[],
                    help="binary to place under tools/ (repeatable)")
    ap.add_argument("--tools", action="append", default=[],
                    help="extra file to place under tools/ (repeatable)")
    ap.add_argument("--out", required=True, help="output directory")
    args = ap.parse_args()

    nuspec_path = Path(args.nuspec)
    nuspec_text = nuspec_path.read_text(encoding="utf-8")
    pkg_id = read_meta(nuspec_text, "id")
    if not pkg_id:
        print("ERROR: nuspec has no <id>", file=sys.stderr)
        return 1

    # Overwrite the nuspec's placeholder <version> with the real one.
    # [^<]* (no DOTALL) keeps the match from crossing into other tags, so an
    # illustrative "<version>" inside an XML comment can't be matched — the
    # real <version>N.N.N</version> is the first well-formed one.
    nuspec_text = re.sub(r"<version>[^<]*</version>",
                         f"<version>{escape(args.version)}</version>",
                         nuspec_text, count=1)

    nuspec_name = f"{pkg_id}.nuspec"
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{pkg_id}.{args.version}.nupkg"

    payload = args.exe + args.tools
    # Extensions across every part so [Content_Types].xml is complete.
    exts = {"nuspec"} | {Path(f).suffix.lstrip(".").lower()
                         for f in payload if Path(f).suffix}

    with zipfile.ZipFile(out_path, "w") as zf:
        add_str(zf, nuspec_name, nuspec_text)
        for f in payload:
            add_file(zf, f"tools/{Path(f).name}", f)
        add_str(zf, "[Content_Types].xml", build_content_types(exts))
        add_str(zf, "_rels/.rels", RELS.format(nuspec=nuspec_name))
        add_str(zf, PSMDCP_PART, build_psmdcp(nuspec_text, args.version))

    print(f"==> Built {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
