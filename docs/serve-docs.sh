#!/usr/bin/env bash
# Start the Docsify documentation site at http://localhost:3000.
# Installs docsify-cli globally on first run if it is not on PATH.
set -euo pipefail

if ! command -v docsify >/dev/null 2>&1; then
  echo "docsify-cli not found; installing globally..."
  npm i -g docsify-cli
fi

cd "$(dirname "$0")/.."
exec docsify serve docs --port 3000
