#!/usr/bin/env bash
# MCP server wrapper — loads Supabase service key and runs the server.
set -euo pipefail
source "$HOME/.profile" 2>/dev/null || true

PAT="$(op read "op://Claude/Supabase/PAT")"
export SUPABASE_SERVICE_KEY="$(curl -s "https://api.supabase.com/v1/projects/zbqafrnxsxwbarztrtqp/api-keys" \
  -H "Authorization: Bearer $PAT" | python3 -c "import json,sys; keys=json.load(sys.stdin); print([k['api_key'] for k in keys if k['name']=='service_role'][0])")"

exec node "$(dirname "$0")/dist/index.js" "$@"
