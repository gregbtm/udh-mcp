# udh-mcp

Standalone MCP server (v2.7.0) for matrix-homelab's **Universal Document Hub (UDH)** — providing **22 tools** and a **50-Feature MCP Programme** (`mcp_enhancements.py`, inspectable via `udh_dictionary(resource="mcp_features")`) with full parity with UDH Dashboard, Option E Strangler-Fig native backend routing (`/api/native/*`), Stage 2 Python scheduler control (`udh_scheduler`), Stage 3/4 Python target adapters (`udh_adapters`), zero-token PII/readability/chunking/conflict NLP (`udh_extract`), and readiness/wiring verification (`udh_setup`).

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

> **Tip — Dedicated Live Validator UI (`/settings/mcp`):** Open `https://udh-dashboard.nasmatrix.app/settings/mcp` (or **Settings -> MCP Connect & Validate**) to test `/healthz`, Bearer `/status`, JSON-RPC `initialize`, and `tools/list` live and copy any of the **5 connection presets** (Remote HTTPS, NAS Loopback `127.0.0.1:12021`, Read-Only Token Tier, Local Python STDIO, or Terminal cURL). Once connected in an AI client, call `udh_setup(action="status")` or `udh_setup(action="connect_guide")`.

### 4. Connection Option Alternatives (5 Presets)
1. **Remote Streamable-HTTP (HTTPS)**: `https://udh.nasmatrix.app/mcp` + `Authorization: Bearer ${UDH_AUTH_TOKEN}` (for off-LAN clients).
2. **Direct NAS / LAN HTTP**: `http://127.0.0.1:12021/mcp` (zero reverse-proxy hop on LAN/NAS).
3. **Least-Privilege Read-Only Token Tier**: Connect with `UDH_AUTH_TOKEN_READONLY` (`read` scope only — safe exploration & extraction).
4. **Local Python STDIO**: Launch `python -m src.server` with `UDH_MCP_TRANSPORT=stdio` and `UDH_DASHBOARD_URL`.
5. **Terminal cURL Smoke Test**: `curl -fsS https://udh.nasmatrix.app/healthz` + `POST /mcp` JSON-RPC `initialize` (or `POST /api/mcp/validate` on UDH Dashboard).

### 5. Scoped Token Tiers
- **`read`**: `udh_dashboard`, `udh_query`, `udh_dictionary`, `udh_setup`, `udh_fleet`, `udh_extract`, `udh_bundle_seal`, `udh_updates(check_*)`, `udh_scheduler(status)`, `udh_config(get_runtime_settings)`
- **`sync`**: All `read` tools + `udh_sync`, `udh_targets`, `udh_control`, `udh_health`, `udh_config` (`update_*`, `reset_runtime_settings`), `udh_templates`, `udh_simulate`, `udh_checkpoint`, `udh_tokens`, `udh_tags`, `udh_updates(trigger_update)`, `udh_scheduler(run/toggle)`
- **`admin`** (or `*`): All `sync` tools + `udh_conflicts`, `udh_lifecycle` (destructive rollback/delete/purge)

---

## Performance & Resilience
- **Persistent HTTP Connection Pooling**: Shared `httpx.AsyncClient` pool (`max_keepalive_connections=20`, `max_connections=50`) in `src/core.py` eliminates per-call TLS/TCP handshake overhead.
- **Concurrent Fleet Probing**: `udh_fleet` probes all core UDH services concurrently via `asyncio.gather` (Dashboard, MCP, Postgres 17 port `5432`, n8n, Qdrant, DBackup, and `udh-worker` heartbeat).
- **50-Feature MCP Enhancement Engine (`src/mcp_enhancements.py`)**: Provides unified 64-bit Blake2b SimHash, UK Legal/Ops acronym alias clustering (`lpp`, `wp`, `et`, `dsar`), PII redaction preview & query scrubbing (`sanitize_pii`), readability scoring, heading-preserving markdown chunking, numeric/date conflict scanning, HMCTS `<50MB` bundle check, Stage 3 DLQ replay & webhook ingest helpers, and full tool catalog introspection.
- **Option E Native Routing**: Setting `UDH_BACKEND_MODE=native` or `UDH_PREFER_NATIVE=true` bypasses n8n webhooks and talks directly to `udh-dashboard` over `127.0.0.1:12015`.

---

## Tool Surface (22 Tools • 50 Features)

### Easy Setup, Docs & Diagnostics
- `udh_setup`: Live connection/migration check (`status`), client JSON + `/settings/mcp` Studio link (`connect_guide`), 22-tool cheat sheet (`quickstart`), Shadow Parity Diff (`parity`), Stage 4 cutover readiness (`cutover_check`), **12-check 17-route site wiring self-check (`wiring_check`)**, and 1-click Postgres schema & n8n seeder (`bootstrap_pg`).
- `udh_dictionary`: Query UDH Data Dictionary schemas (`/api/dictionary`), 100-item Error/Fallback Catalog (`UDH-001`–`UDH-100`), **50-point Context & Language catalog (`resource="context_language"`)**, and **50-Feature MCP catalog (`resource="mcp_features"`)**.
- `udh_fleet`: Concurrent 7-point container & worker fleet probe (`Dashboard`, `MCP`, `Postgres 17`, `n8n`, `Qdrant`, `DBackup`, `udh-worker`), socket latency metrics, and `udh-mcp` v2.7.0 build metadata.
- `udh_updates`: Check UDH Dashboard/ecosystem version (`/api/version`), check GitHub updates (`/api/updates/check`), and trigger redeploy (`confirm=true`).

### Read, Context & Zero-Token Intelligence
- `udh_dashboard`: Read-only system snapshot of UDH with **upfront degraded/conflict/pause alert banners** and n8n->native fallback tier telemetry.
- `udh_query`: 7 read kinds (`get_document`, `search_documents`, `search_fulltext`, `get_content` with `sanitize_pii=true` scrubbing, `list_conflicts`, `list_quarantined`, `recent_operations`).
- `udh_extract`: Zero-token NLP suite (`extract` citations/statutes/GBP/dates/SimHash64, `context_prepare`, `redact_preview` for NHS/NINO/email, `readability` Flesch scoring, `chunk_markdown`, `conflict_scan`).
- `udh_bundle_seal`: Deterministic SHA-256 chain-of-custody seal, **HMCTS `<50MB` upload & page-budget estimator**, and UK ET Schedule of Loss calculator.

### Option E Stage 2 Scheduler, Stage 3/4 Adapters & Safe Simulations
- `udh_scheduler`: Inspect (`status`), preview (`run` with `dry_run=true` default), execute (`dry_run=false, confirm=true`), or toggle all **6 Stage 2 Python cron jobs** (`wf05a_inbound_sync`, `wf05b_outbound_sync`, `wf08_health_digest`, `wf12_drift_scanner`, `wf20_silent_drift_sweeper`, `wf17_vector_reindex`).
- `udh_adapters`: Inspect & control all **23 target adapters** (`list`, `dispatch`, `pipeline`, `extract`, `index`), Stage 4 bridges (`bridges`, `run_bridge`), plus **DLQ inspection & replay (`dlq`, `replay_dlq`)** and **signed webhook ingest (`webhook_ingest`)**.
- `udh_simulate`: 5-stage dry-run pipeline simulation with unified Blake2b 64-bit SimHash & chaos fault injection (`Extract -> SimHash64 -> Enrich -> Reconcile -> Outbound`).
- `udh_checkpoint`: Persistent pipeline snapshots & rollback checkpoints (`create`, `list`, `restore`, `delete`).

### Sync, Config & Governance
- `udh_sync`: 10 operations (`publish`, `ingest`, `reenrich`, `scan_drift`, `scrape_url`, `snapshot`, `sync_outbound`, `backfill_trilium`, `propagate_paperless`, `reindex_vectors`).
- `udh_targets`: Per-target bidirectional enable/disable control (`set_target_enabled`).
- `udh_control`: Emergency brake (`set_global_pause`).
- `udh_health`: On-demand health/integrity checks (`check_health`, `check_integrity`, plus read-only **`wiring_check`**).
- `udh_config`: Full hub/target & live Option E runtime configuration (`update_hub_config` across 18 fields, `update_target_config` across 19 fields, `get_runtime_settings`, `update_runtime_settings`, `reset_runtime_settings`).
- `udh_templates`: Ingestion template CRUD stored in Postgres & registry (`list_templates`, `create_template`, `update_template`, `delete_template`, `set_default_template`).
- `udh_tokens`: Query live token burn metrics, persist daily budget cap (`set_budget` with `confirm=true`), and toggle local heuristic fallback.
- `udh_tags`: Synonym & UK Legal/Ops alias tag clustering (`lpp`, `wp`, `et`, `dsar`), merge plans, and 1-click taxonomy consolidation.

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
