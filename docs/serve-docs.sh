#!/usr/bin/env bash
# Start the Docsify documentation site at http://localhost:3000 (PORT overrides).
# Uses a docsify on PATH if there is one; otherwise runs a pinned docsify-cli
# through npx, with no global install.
#
# Install scripts are disabled for the npx run: docsify's own postinstall runs
# `npx husky install`, a dev-only git-hook step that fails outside docsify's
# repo and aborts the whole install. Serving the site needs none of them.
set -euo pipefail

DOCSIFY_CLI_VERSION="4.4.4"
PORT="${PORT:-3000}"

cd "$(dirname "$0")/.."

if command -v docsify >/dev/null 2>&1; then
  exec docsify serve docs --port "$PORT"
fi

exec env npm_config_ignore_scripts=true \
  npx --yes "docsify-cli@${DOCSIFY_CLI_VERSION}" serve docs --port "$PORT"
