# ThreatNoir IOC MCP Server

Standalone **MCP (Model Context Protocol) server** that lets Claude/Claude Code search and retrieve ThreatNoir IOCs (Indicators of Compromise) directly from the **Supabase REST API** using a service role key.

## Tools

- `search_iocs` — free-text search in IOC `value` (ilike)
- `list_iocs` — list recent IOCs (optionally by type)
- `lookup_ioc` — exact match lookup (eq)

Supported IOC types:

`ip`, `domain`, `hash_md5`, `hash_sha1`, `hash_sha256`, `url`, `cve`, `mitre_attack`, `email`, `malware`

## Configuration

Environment variables:

- `SUPABASE_URL` (optional) — defaults to `https://zbqafrnxsxwbarztrtqp.supabase.co`
- `SUPABASE_SERVICE_KEY` (required) — Supabase **service role** key

## Development

```bash
npm install
npm run build
npm start
```

## MCP settings.json snippet (do not commit secrets)

Add this to your `~/.claude/settings.json` under `mcpServers`:

```json
{
  "threatnoir-iocs": {
    "command": "node",
    "args": ["/home/cruxis/projects/threatnoir-mcp/dist/index.js"],
    "env": {
      "SUPABASE_SERVICE_KEY": "op://Claude/Supabase/service_role_key"
    }
  }
}
```

## Quick protocol smoke test

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | SUPABASE_SERVICE_KEY=test node dist/index.js
```