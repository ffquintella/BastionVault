# Signing installer artifacts (Phase 4)

`sign-artifacts.sh` signs every installer on disk with the right mechanism
for each type, using **whatever keys you supply** via the environment.
Nothing is tied to a specific HSM, identity, or cert — bring any key.

```sh
make sign-packages                         # scans target/
BV_GPG_KEY=… BV_WIN_PFX=… make sign-packages
bash installers/sign/sign-artifacts.sh dir1 dir2   # explicit dirs
```

Every mechanism is **independent and optional**: supply a key and that type
is signed; omit it and that type is skipped (with a note). On top of the
platform-native signatures, every artifact also gets a cross-platform
**Cosign** signature and a line in `SHA256SUMS`. Native-signing failures are
collected and the run exits non-zero (a signing step must fail loud); Cosign
is best-effort (never blocks native signing).

## What signs what

| Artifact | Mechanism | Tool | Provide |
|---|---|---|---|
| `.deb` | GPG (embedded if `dpkg-sig` present, else detached `.asc`) | `gpg` / `dpkg-sig` | `BV_GPG_KEY` |
| `.rpm` | GPG (`rpm --addsign` if `rpmsign` present, else detached `.asc`) | `gpg` / `rpmsign` | `BV_GPG_KEY` |
| `.msi`, `.exe` | Authenticode | `osslsigncode` (runs on macOS/Linux) | `BV_WIN_PFX` or `BV_WIN_CERT`+`BV_WIN_KEY` |
| `.pkg` | Developer ID + optional notarization | `productsign` / `notarytool` | `BV_MACOS_INSTALLER_IDENTITY` |
| `.nupkg` | NuGet signature (optional) | `nuget sign` | `BV_NUGET_CERT_FP` |
| *(all)* | Cosign (`.cosign.bundle`, or `.sig`/`.pem` on cosign v2) | `cosign` | `BV_COSIGN_KEY` or `BV_COSIGN_KEYLESS=1` |

## Environment variables

```
# deb / rpm (GPG)
BV_GPG_KEY        key id / email / fingerprint
BV_GPG_HOMEDIR    GNUPGHOME override (optional)

# msi / exe (Authenticode via osslsigncode)
BV_WIN_PFX        PKCS#12 (.pfx/.p12) code-signing cert
BV_WIN_PFX_PASS   its password (optional)
BV_WIN_CERT       PEM cert   +  BV_WIN_KEY   PEM key   (alternative to PFX)
BV_WIN_TS_URL     RFC3161 timestamp URL [http://timestamp.digicert.com]
BV_WIN_NO_TS=1    disable timestamping (offline)

# pkg (macOS)
BV_MACOS_INSTALLER_IDENTITY   "Developer ID Installer: <team>"
BV_NOTARY_PROFILE             notarytool keychain profile (optional)

# nupkg (optional)
BV_NUGET_CERT_FP  code-signing cert SHA-1 fingerprint
BV_NUGET_TS_URL   timestamp URL

# Cosign (applied to every artifact)
BV_COSIGN_KEY     path to a cosign private key (+ COSIGN_PASSWORD)
BV_COSIGN_KEYLESS=1   keyless (OIDC + Rekor) instead of a key
BV_COSIGN_TLOG=1  (key mode) also upload to the Rekor transparency log

# output
BV_SUMS_FILE      SHA256SUMS path [./SHA256SUMS]
```

## Verifying

```sh
# GPG detached
gpg --verify foo.deb.asc foo.deb

# Authenticode (osslsigncode; a self-signed test cert needs -CAfile)
osslsigncode verify -in foo.msi

# Cosign (v3 bundle)
cosign verify-blob --key cosign.pub --new-bundle-format --bundle foo.cosign.bundle foo
# Cosign (v2 detached)
cosign verify-blob --key cosign.pub --signature foo.sig foo

# hashes
sha256sum -c SHA256SUMS
```

## Generating a key to try it (any key works)

```sh
# GPG
gpg --quick-generate-key "you@example.com" default default never
# a self-signed code-signing PFX (test only)
openssl req -x509 -newkey rsa:2048 -keyout k.pem -out c.pem -days 30 -nodes \
  -subj "/CN=Test" -addext "extendedKeyUsage=codeSigning"
openssl pkcs12 -export -out c.pfx -inkey k.pem -in c.pem -passout pass:pw
# cosign
COSIGN_PASSWORD="" cosign generate-key-pair
```

## Status

Verified end-to-end on macOS against real BastionVault artifacts with
throwaway keys: GPG (deb/rpm), Authenticode (msi via osslsigncode), and
Cosign (all five artifact types) all sign and verify. Production release
signing (real GPG release subkey, EV Authenticode cert, Apple Developer ID +
notarization) plugs into the same script by pointing the env vars at those
keys, and belongs in CI where the secrets live.
