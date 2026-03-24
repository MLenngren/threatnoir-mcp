# @threatnoir/mcp-iocs

MCP server for querying ThreatNoir IOCs (Indicators of Compromise) from Claude Code, VS Code, or any MCP client.

## Quick Start

1. Get an API key at https://threatnoir.com/settings
2. Add to your `.mcp.json` (or your MCP client's config):

```json
{
  "mcpServers": {
    "threatnoir-iocs": {
      "command": "npx",
      "args": ["-y", "@threatnoir/mcp-iocs"],
      "env": {
        "THREATNOIR_API_KEY": "tn_live_...",
        "THREATNOIR_URL": "https://threatnoir.com"
      }
    }
  }
}
```

Notes:

- `THREATNOIR_URL` is optional (defaults to `https://threatnoir.com`).
- `list_iocs` works without an API key.
- `search_iocs` and `lookup_ioc` require `THREATNOIR_API_KEY`.

## Available Tools

- `search_iocs` — Search ThreatNoir's IOC database by keyword (requires API key)
- `list_iocs` — List the most recent IOCs (optionally filtered by type)
- `lookup_ioc` — Exact match lookup for a specific IOC value (requires API key)

## IOC Types

`ip`, `domain`, `hash_md5`, `hash_sha1`, `hash_sha256`, `url`, `cve`, `mitre_attack`, `email`, `malware`

## Internal mode (ThreatNoir team)

If `SUPABASE_SERVICE_KEY` is set, the server will use the internal Supabase REST API mode (useful for local dev).