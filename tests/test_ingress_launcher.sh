#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TEMP_DIR"' EXIT
mkdir -p "$TEMP_DIR/bin"

# Capture the final Uvicorn argv without starting the application.  The
# options parser is not reached in the normal test environment, but accepting
# -c keeps this harness safe if a host has a mounted options file.
cat > "$TEMP_DIR/bin/python" <<'PY'
#!/bin/sh
if [ "${1:-}" = "-c" ]; then
    exit 0
fi
printf '%s\n' "$*" > "${HAPASS_TEST_ARGS:?}"
PY
chmod +x "$TEMP_DIR/bin/python"

HAPASS_TEST_ARGS="$TEMP_DIR/addon-args" \
PATH="$TEMP_DIR/bin:/usr/bin:/bin" \
SUPERVISOR_TOKEN=synthetic-token \
bash "$ROOT/run.sh" >/dev/null
addon_args="$(<"$TEMP_DIR/addon-args")"
case "$addon_args" in
    *"--no-proxy-headers"*) ;;
    *) echo "add-on launch must disable proxy-header rewriting" >&2; exit 1 ;;
esac

HAPASS_TEST_ARGS="$TEMP_DIR/standalone-args" \
PATH="$TEMP_DIR/bin:/usr/bin:/bin" \
env -u SUPERVISOR_TOKEN bash "$ROOT/run.sh" >/dev/null
standalone_args="$(<"$TEMP_DIR/standalone-args")"
case "$standalone_args" in
    *"--no-proxy-headers"*) echo "standalone launch must retain proxy-header support" >&2; exit 1 ;;
    *) ;;
esac

echo "ingress launcher checks passed"
