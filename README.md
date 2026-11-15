# udh-mcp

Standalone MCP server for matrix-homelab's **Universal Document Hub (UDH)** — providing **22 tools** with full parity with UDH Dashboard, Option E Strangler-Fig native backend routing (`/api/native/*`), Stage 2 Python scheduler control (`udh_scheduler`), Stage 3 Python target adapters (`udh_adapters`), and zero-config setup helpers (`udh_setup`).

Independent of `synology-proxy-mcp` and `mcphub` by design — see `CLAUDE.md` for the architecture and why.

---

## Quick Connection & Client Setup

### 1. Endpoints & Transport
- **Public MCP URL (via reverse proxy):** `https://udh.nasmatrix.app/mcp`
- **Local Host-Network URL (NAS host):** `http://127.0.0.1:12021/mcp`
- **Transport:** `streamable-http`
- **Auth:** `Authorization: Bearer <UDH_AUTH_TOKEN>` (when `UDH_AUTH_TOKEN` is set)

### 2. Client Configuration (`mcp_config.json` / Claude Desktop / Cursor / Antigravity)

```json
{
  "mcpServers": {
    "udh-mcp": {
      "serverUrl": "https://udh.nasmatrix.app/mcp",
      "headers": {
        "Authorization": "Bearer ${UDH_AUTH_TOKEN}"
      }
    }
  }
}
```

### 3. Docker Compose / Portainer Environment Settings (`stacks/udh-mcp/docker-compose.yml`)

| Variable | Recommended Value | Purpose |
| :--- | :--- | :--- |
| `UDH_MCP_HOST` | `0.0.0.0` | Listen address (`network_mode: "host"`) |
| `UDH_MCP_PORT` | `12021` | Streamable-HTTP port |
| `UDH_PUBLIC_URL` | `https://udh.nasmatrix.app` | Public OAuth/metadata URL |
| `UDH_AUTH_TOKEN` | `<secret>` | Primary admin/full-access Bearer token |
| `UDH_AUTH_TOKEN_READONLY` | `<secret>` | Optional read-only companion token |
| `UDH_AUTH_SCOPES_READONLY` | `read` | Scope assigned to the read-only token |
| `UDH_DASHBOARD_URL` | `http://127.0.0.1:12015` | Direct loopback link to `udh-dashboard` (no proxy hop) |
| `UDH_BACKEND_MODE` | `strangler` or `native` | `native` routes `dashboard_data`/`query`/`dispatch` to `/api/native/*` |
| `UDH_PREFER_NATIVE` | `false` or `true` | Set `true` to prefer `udh-dashboard` `/api/native/*` over n8n |
| `WF07_URL` / `WF07_AUTH_TOKEN` | `https://n8n.nasmatrix.app/webhook/dispatch` | Legacy/strangler WF-07 webhook |
| `WF14_URL` / `WF14_AUTH_TOKEN` | `https://n8n.nasmatrix.app/webhook/udh-dashboard-data` | Legacy/strangler WF-14 webhook |
| `WF16_URL` / `WF16_AUTH_TOKEN` | `https://n8n.nasmatrix.app/webhook/udh-query-api` | Legacy/strangler WF-16 webhook |

> **Tip:** Once connected, call `udh_setup(action="status")` to verify env configuration and live `udh-dashboard` reachability, or `udh_setup(action="quickstart")` for an interactive cheat sheet.

### 4. Scoped Token Tiers
- **`read`**: `udh_dashboard`, `udh_query`, `udh_dictionary`, `udh_setup`, `udh_fleet`, `udh_extract`, `udh_bundle_seal`, `udh_updates(check_*)`, `udh_scheduler(status)`
- **`sync`**: All `read` tools + `udh_sync`, `udh_targets`, `udh_control`, `udh_health`, `udh_config`, `udh_templates`, `udh_simulate`, `udh_checkpoint`, `udh_tokens`, `udh_tags`, `udh_updates(trigger_update)`, `udh_scheduler(run/toggle)`
- **`admin`** (or `*`): All `sync` tools + `udh_conflicts`, `udh_lifecycle` (destructive rollback/delete/purge)

---

## Performance & Resilience
- **Persistent HTTP Connection Pooling**: Shared `httpx.AsyncClient` pool (`max_keepalive_connections=20`, `max_connections=50`) in `src/core.py` eliminates per-call TLS/TCP handshake overhead.
- **Concurrent Fleet Probing**: `udh_fleet` probes all 5 core UDH services concurrently via `asyncio.gather`.
- **Option E Native Routing**: Setting `UDH_BACKEND_MODE=native` or `UDH_PREFER_NATIVE=true` bypasses n8n webhooks and talks directly to `udh-dashboard` over `127.0.0.1:12015`.

---

## Tool Surface (22 Tools)

### Easy Setup, Docs & Diagnostics
- `udh_setup`: Live connection/migration check (`status`), client JSON (`connect_guide`), and 21-tool cheat sheet (`quickstart`).
- `udh_dictionary`: Query UDH Data Dictionary schemas (`/api/dictionary`) and 100-item Error/Fallback Catalog (`UDH-001`–`UDH-100`).
- `udh_fleet`: Concurrent 5-service container fleet health beacon, socket latency probes, and `udh-mcp` version metadata.
- `udh_updates`: Check UDH Dashboard/ecosystem version (`/api/version`), check GitHub updates (`/api/updates/check`), and trigger redeploy (`confirm=true`).

### Read & Query
- `udh_dashboard`: Read-only system snapshot of UDH (WF-14 or `/api/native/dashboard-data`).
- `udh_query`: Read-only document lookups, fulltext search, and content extraction (WF-16 or `/api/native/query`).
- `udh_extract`: Zero-token deterministic extraction (citations, statutes, GBP currency, dates, 64-bit SimHash).
- `udh_bundle_seal`: Deterministic SHA-256 chain-of-custody seal & UK ET Schedule of Loss calculator.

### Option E Stage 2 Scheduler, Stage 3 Adapters & Safe Simulations
- `udh_scheduler`: Inspect (`status`), safely preview (`run` with `dry_run=true` default), execute (`dry_run=false, confirm=true`), or toggle Stage 2 Python cron jobs (`wf05a_inbound_sync`, `wf05b_outbound_sync`, `wf08_health_digest`, `wf12_drift_scanner`, `wf20_silent_drift_sweeper`).
- `udh_adapters`: List (`list`), safely preview (`dispatch`/`pipeline` with `dry_run=true` default), or execute (`dry_run=false, confirm=true`) Stage 3 native Python target adapters (`trilium`, `obsidian`, `notion`, `nocodb`, `paperless`, `affine`, `gmail`, `neo4j`, `meilisearch`, `fastmail`, `firecrawl`, `tasktrove`, `docmost`).
- `udh_simulate`: 5-stage dry-run pipeline simulation (Extract -> SimHash 64-bit -> Enrich -> Reconcile -> Outbound).
- `udh_checkpoint`: Instant pipeline rollback checkpoints (`create`, `list`, `restore`, `delete`).

### Sync, Config & Governance
- `udh_sync`: Day-to-day sync operations (`publish`, `ingest`, `reenrich`, `scan_drift`, `scrape_url`, `snapshot`, `sync_outbound`, `backfill_trilium`).
- `udh_targets`: Per-target control (`set_target_enabled`).
- `udh_control`: Emergency brake (`set_global_pause`).
- `udh_health`: On-demand health/integrity checks (`check_health`, `check_integrity`).
- `udh_config`: Hub/target configuration tuning (`update_hub_config`, `update_target_config`).
- `udh_templates`: Ingestion template CRUD (`list_templates`, `create_template`, `update_template`, `delete_template`, `set_default_template`).
- `udh_tokens`: Token burn tracking, budget caps, and adaptive fallback to local heuristics.
- `udh_tags`: Semantic tag clustering, synonym detection, and 1-click taxonomy consolidation.

### Admin / Destructive (`confirm=true` required)
- `udh_conflicts`: Conflict resolution (`resolve_conflict`).
- `udh_lifecycle`: Restore/overwrite/destroy operations (`rollback`, `confirm_delete`, `release_quarantine`, `purge_ingested`).

---

## Local Development

```bash
pip install -r requirements.lock.txt
export UDH_AUTH_TOKEN=dev-token UDH_DASHBOARD_URL=http://127.0.0.1:12015 UDH_BACKEND_MODE=native
python src/server.py
```
