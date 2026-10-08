#!/usr/bin/env bash
# Regression tests for .github/actions/setup-kani's install step. The action
# has to stay a composite action so it can use the Actions cache primitives;
# extract and run that step with a stub cargo instead of downloading Kani.
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

extract_install_step() {
  python3 - "$ROOT/.github/actions/setup-kani/action.yml" "$WORK/install-kani" <<'PY'
import pathlib
import sys

source = pathlib.Path(sys.argv[1]).read_text().splitlines()
out = pathlib.Path(sys.argv[2])
start = source.index("    - name: Install Kani")
run = start + source[start:].index("      run: |") + 1
lines = []
for line in source[run:]:
    if line.startswith("    - name:"):
        break
    if not line:
        lines.append(line)
        continue
    if not line.startswith("        "):
        raise SystemExit(f"unexpected install-step indentation: {line!r}")
    lines.append(line[8:])
out.write_text("\n".join(lines) + "\n")
out.chmod(0o755)
PY
}

write_cargo_stub() {
  mkdir -p "$WORK/bin"
  printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    'printf "%s\\n" "$*" >> "$CARGO_LOG"' \
    'case "$1" in' \
    '  kani)' \
    '    case "${2:-}" in' \
    '      --version)' \
    '        if [ -f "$CARGO_STATE/installed" ]; then' \
    '          printf "%s\\n" "${CARGO_POST_INSTALL_VERSION:-Kani Rust Verifier 0.68.0 (cargo plugin)}"' \
    '          exit "${CARGO_POST_INSTALL_EXIT:-0}"' \
    '        else' \
    '          printf "%s\\n" "${CARGO_KANI_VERSION}"' \
    '          exit "${CARGO_KANI_EXIT:-0}"' \
    '        fi' \
    '        ;;' \
    '      setup) touch "$CARGO_STATE/setup" ;;' \
    '    esac' \
    '    ;;' \
    '  install)' \
    '    case " $* " in' \
    '      *" --force "*) touch "$CARGO_STATE/installed" ;;' \
    '      *) echo "cargo install needs --force to replace cached binaries" >&2; exit 73 ;;' \
    '    esac' \
    '    ;;' \
    'esac' > "$WORK/bin/cargo"
  chmod +x "$WORK/bin/cargo"
}

run_install_step() {
  PATH="$WORK/bin:$PATH" \
  HOME="$WORK/home" \
  KANI_VERSION=0.68.0 \
  CARGO_LOG="$WORK/cargo.log" \
  CARGO_STATE="$WORK/state" \
  CARGO_KANI_VERSION="$1" \
  CARGO_POST_INSTALL_VERSION="${2:-Kani Rust Verifier 0.68.0 (cargo plugin)}" \
  CARGO_KANI_EXIT="${3:-0}" \
  CARGO_POST_INSTALL_EXIT="${4:-0}" \
  "$WORK/install-kani"
}

assert_contains() {
  grep -Fqx "$1" "$2" || {
    echo "expected '$1' in $2" >&2
    exit 1
  }
}

assert_not_contains() {
  ! grep -Fqx "$1" "$2" || {
    echo "did not expect '$1' in $2" >&2
    exit 1
  }
}

assert_output_contains() {
  grep -Fq "$1" "$2" || {
    echo "expected '$1' in $2" >&2
    exit 1
  }
}

prepare_case() {
  rm -rf "$WORK/home" "$WORK/state" "$WORK/cargo.log"
  mkdir -p "$WORK/home/.kani/kani-0.68.0/toolchain/bin" "$WORK/state"
  touch "$WORK/home/.kani/kani-0.68.0/toolchain/bin/rustc"
  chmod +x "$WORK/home/.kani/kani-0.68.0/toolchain/bin/rustc"
}

extract_install_step
write_cargo_stub

prepare_case
run_install_step 'Kani Rust Verifier 0.68.0 (cargo plugin)'
assert_not_contains 'install --locked --force kani-verifier --version 0.68.0' "$WORK/cargo.log"
assert_not_contains 'kani setup' "$WORK/cargo.log"

prepare_case
run_install_step 'Kani Rust Verifier 0.67.0 (cargo plugin)'
assert_contains 'install --locked --force kani-verifier --version 0.68.0' "$WORK/cargo.log"

prepare_case
run_install_step 'cached driver could not start' \
  'Kani Rust Verifier 0.68.0 (cargo plugin)' 42 >"$WORK/nonzero-probe.out" 2>&1
assert_contains 'install --locked --force kani-verifier --version 0.68.0' "$WORK/cargo.log"
assert_contains 'kani setup' "$WORK/cargo.log"
assert_output_contains 'Cached Kani driver is unavailable or has the wrong version' \
  "$WORK/nonzero-probe.out"
assert_output_contains 'cached driver could not start' "$WORK/nonzero-probe.out"

prepare_case
rm -f "$WORK/home/.kani/kani-0.68.0/toolchain/bin/rustc"
run_install_step 'Kani Rust Verifier 0.68.0 (cargo plugin)'
assert_contains 'kani setup' "$WORK/cargo.log"

prepare_case
if run_install_step 'Kani Rust Verifier 0.67.0 (cargo plugin)' \
  'Kani Rust Verifier 0.67.0 (cargo plugin)'; then
  echo 'expected an installed driver with the wrong version to fail' >&2
  exit 1
fi
assert_contains 'install --locked --force kani-verifier --version 0.68.0' "$WORK/cargo.log"

prepare_case
if run_install_step 'Kani Rust Verifier 0.67.0 (cargo plugin)' \
  'Kani Rust Verifier 0.68.0 (cargo plugin)' 0 43 >"$WORK/final-probe.out" 2>&1; then
  echo 'expected a nonzero final driver probe to fail' >&2
  exit 1
fi
assert_output_contains 'Kani driver failed after installation' "$WORK/final-probe.out"
