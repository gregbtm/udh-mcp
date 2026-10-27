# udh-mcp

Standalone MCP server for matrix-homelab's Universal Document Hub (UDH).
Gives Claude (or any MCP client) direct control over the UDH sync mesh —
publish/ingest/reenrich, per-target enable/disable, conflict resolution,
rollback/delete/quarantine-release/purge-ingested, the global pause
switch, on-demand health/integrity checks, hub/target config tuning,
ingestion-template management, read access to the document registry,
conflict queue, canonical content, full-text search, and (as of 2026-10-27)
dry-run pipeline simulation, rollback checkpoints, token burn budget controls,
semantic tag clustering, and container fleet health diagnostics.

Independent of `synology-proxy-mcp` and mcphub by design — see
`CLAUDE.md` for the full architecture, tool inventory, and why.

## Tool Surface (15 Tools)

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
- `udh_fleet`: Real-time container fleet health beacon and socket latency probes.

## Quick start

```bash
pip install -r requirements.lock.txt
export UDH_AUTH_TOKEN=... WF07_URL=... WF07_AUTH_TOKEN=... WF14_URL=... WF14_AUTH_TOKEN=...
python src/server.py
```

## Test

```bash
python src/test_tool_registration.py
```
