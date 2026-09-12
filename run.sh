#!/usr/bin/env bash
set -euo pipefail

OPTIONS="/data/options.json"
ADDON_MODE=0

if [ -n "${SUPERVISOR_TOKEN:-}" ]; then
    ADDON_MODE=1
    echo "[run.sh] Add-on mode — reading options"
    if [ -f "$OPTIONS" ]; then
        eval "$(python -c "
import json, shlex
opts = json.load(open('$OPTIONS'))
mapping = {
    'admin_username': 'ADMIN_USERNAME',
    'admin_password': 'ADMIN_PASSWORD',
    'app_name': 'APP_NAME',
    'contact_message': 'CONTACT_MESSAGE',
    'brand_bg': 'BRAND_BG',
    'brand_primary': 'BRAND_PRIMARY',
    'guest_url': 'GUEST_URL',
}
for key, env in mapping.items():
    val = opts.get(key, '')
    if val:
        print(f'export {env}={shlex.quote(str(val))}')
        ")"
    fi

    export HA_BASE_URL="http://supervisor/core"
    export HA_TOKEN="${SUPERVISOR_TOKEN}"
    export DB_PATH="/data/db.sqlite"
else
    echo "[run.sh] Standalone mode — using environment variables"
fi

UVICORN_ARGS=(main:app --host 0.0.0.0 --port "${PORT:-5880}" --workers 1)
if [ "$ADDON_MODE" -eq 1 ]; then
    # Keep request.client bound to the Supervisor transport peer.  Standalone
    # reverse-proxy deployments retain Uvicorn's normal proxy-header support.
    UVICORN_ARGS+=(--no-proxy-headers)
fi
exec python -m uvicorn "${UVICORN_ARGS[@]}"
