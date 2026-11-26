#!/usr/bin/env bash
# usage: select-plugin-key.sh <default-key> <default-name> <dir>...
# Prompts on stderr; stdout is "<key-path-without-.seed>|<publisher-name>".
# Only file names are read, never seed contents.
set -euo pipefail

default_key=$1
default_name=$2
shift 2

keys=()
seen=""
for d in "$@"; do
  [ -d "$d" ] || continue
  for f in "$d"/*.seed; do
    [ -f "$f" ] || continue
    dir=$(cd "$(dirname "$f")" && pwd)
    base=$(basename "$f" .seed)
    k="$dir/$base"
    case "$seen" in *"|$k|"*) continue ;; esac
    seen="$seen|$k|"
    keys+=("$k")
  done
done

# The default key keeps its registered publisher name; any other key is
# named after its file, which is how the prod key is registered.
name_for() {
  local base
  base=$(basename "$1")
  if [ "$base" = "$(basename "$default_key")" ]; then
    echo "$default_name"
  else
    echo "$base"
  fi
}

if [ ! -t 0 ]; then
  echo "==> no terminal to ask on; signing with the default key $default_key (publisher $default_name)" >&2
  echo "    pass PLUGINS_SIGNING_KEY=<path> PLUGINS_SIGNING_KEY_NAME=<name> to choose another." >&2
  echo "$default_key|$default_name"
  exit 0
fi

if [ ${#keys[@]} -eq 0 ]; then
  echo "==> no *.seed found in: $*" >&2
  echo "    run \`make plugins-keygen\`, or pass PLUGINS_SIGNING_KEY=<path-without-.seed>." >&2
  exit 1
fi

echo "Available signing keys:" >&2
i=1
for k in "${keys[@]}"; do
  note=""
  [ -f "$k.pub" ] || note="  (no .pub next to it)"
  printf '  %d) %s   publisher: %s%s\n' "$i" "$k" "$(name_for "$k")" "$note" >&2
  i=$((i + 1))
done

while :; do
  printf 'Select the key to sign with [1-%d]: ' "${#keys[@]}" >&2
  IFS= read -r ans || { echo >&2; echo "==> aborted" >&2; exit 1; }
  if [[ "$ans" =~ ^[0-9]+$ ]] && [ "$ans" -ge 1 ] && [ "$ans" -le "${#keys[@]}" ]; then
    break
  fi
  echo "    invalid choice" >&2
done

key=${keys[$((ans - 1))]}
name=$(name_for "$key")
printf 'Publisher name registered on the host [%s]: ' "$name" >&2
IFS= read -r custom || custom=""
[ -n "$custom" ] && name=$custom

echo "==> signing with $key as publisher $name" >&2
echo "$key|$name"
