# udh-mcp

Standalone MCP server for matrix-homelab's Universal Document Hub (UDH).
Gives Claude (or any MCP client) full parity with UDH Dashboard —
publish/ingest/reenrich, per-target enable/disable, conflict resolution,
rollback/delete/quarantine-release/purge-ingested, the global pause
switch, on-demand health/integrity checks, hub/target config tuning,
ingestion-template management, read access to the document registry,
conflict queue, canonical content, full-text search, dry-run pipeline
simulation, rollback checkpoints, token burn budget controls, semantic
tag clustering, concurrent container fleet health diagnostics, zero-token
legal extraction/custody sealing, Data Dictionary & Error Catalog lookups,
and version/update management.

Independent of `synology-proxy-mcp` and mcphub by design — see
`CLAUDE.md` for the full architecture, tool inventory, and why.

## Performance & Resilience
- **Persistent HTTP Connection Pooling**: Shared `httpx.AsyncClient` pool (`max_keepalive_connections=20`, `max_connections=50`) in `src/core.py` eliminates per-call TLS/TCP handshake overhead.
- **Concurrent Fleet Probing**: `udh_fleet` probes all 5 core UDH services concurrently via `asyncio.gather`.

## Tool Surface (19 Tools)

- `udh_dashboard`: Read-only system snapshot of the Universal Document Hub (WF-14).
- `udh_query`: Read-only document lookups, fulltext search, and content extraction (WF-16).
- `udh_sync`: Day-to-day sync operations: publish, ingest, reenrich, scan_drift, scrape_url, snapshot, sync_outbound, backfill_trilium (WF-07).
- `udh_targets`: Per-target control: set_target_enabled (WF-07).
- `udh_conflicts`: Conflict resolution: resolve_conflict (WF-07).
- `udh_lifecycle`: Restore/overwrite/destroy operations: rollback, confirm_delete, release_quarantine, purge_ingested (WF-07).
- `udh_control`: Emergency brake: set_global_pause (WF-07).
- `udh_health`: On-demand health/integrity checks: check_health, check_integrity (WF-07).
- `udh_config`: Hub/target configuration tuning: update_hub_config, update_target_config (WF-07).
- `udh_templates`: Ingestion template CRUD: list_templates, create_template, update_template, delete_template, set_default_template (WF-07).
- `udh_simulate`: 5-stage dry-run pipeline simulation (Extract -> SimHash 64-bit -> Enrich -> Reconcile -> Outbound).
- `udh_checkpoint`: Instant pipeline rollback checkpoints: create, list, restore, delete.
- `udh_tokens`: Token burn tracking, budget caps, and automated adaptive fallback to local heuristics.
- `udh_tags`: Semantic tag clustering, synonym detection, and 1-click taxonomy consolidation.
- `udh_fleet`: Concurrent 5-service container fleet health beacon, socket latency probes, and `udh-mcp` version metadata.
- `udh_extract`: Zero-token deterministic extraction (citations, statutes, GBP currency, dates, 64-bit SimHash).
- `udh_bundle_seal`: Deterministic SHA-256 chain-of-custody seal & UK ET Schedule of Loss calculator.
- `udh_dictionary`: Query UDH Data Dictionary schemas (`/api/dictionary`) and 100-item Error/Fallback Catalog (`UDH-001`–`UDH-100`).
- `udh_updates`: Check UDH Dashboard/ecosystem version (`/api/version`), check GitHub updates (`/api/updates/check`), and trigger redeploy (`confirm=true`).

## Quick start

```bash
pip install -r requirements.lock.txt
export UDH_AUTH_TOKEN=... WF07_URL=... WF07_AUTH_TOKEN=... WF14_URL=... WF14_AUTH_TOKEN=...
export UDH_DASHBOARD_URL=https://udh-dashboard.nasmatrix.app
python src/server.py
```

## Test

```bash
python src/test_tool_registration.py
```
