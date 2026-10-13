# udh-mcp

Standalone MCP server for matrix-homelab's Universal Document Hub (UDH).
Gives Claude (or any MCP client) direct control over the UDH sync mesh —
publish/ingest/reenrich, per-target enable/disable, conflict resolution,
rollback/delete/quarantine-release/purge-ingested, the global pause
switch, on-demand health/integrity checks, hub/target config tuning,
ingestion-template management, and read access to the document registry,
conflict queue, and (as of 2026-10-13) a document's actual canonical
content and full-text search.

Independent of `synology-proxy-mcp` and mcphub by design — see
`CLAUDE.md` for the full architecture, tool inventory, and why.

## Quick start

```bash
pip install -r requirements.lock.txt
export UDH_AUTH_TOKEN=... WF07_URL=... WF07_AUTH_TOKEN=... WF14_URL=... WF14_AUTH_TOKEN=...
python src/server.py
```

## Test

```bash
cd src && python test_tool_registration.py
```
