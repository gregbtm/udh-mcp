# udh-mcp — Claude Code Context

Standalone MCP server for matrix-homelab's Universal Document Hub (UDH).
Deliberately independent of `synology-proxy-mcp` and mcphub — this server
holds its own credentials and talks directly to n8n's UDH webhooks over
plain HTTPS. See `matrix-homelab`'s own `CLAUDE.md` for the homelab-wide
picture and `docs/udh/04-udh-architecture.md` for UDH's full design; this
file covers only this server's own code and operational facts.

---

## What this is, and why it's separate

`synology-proxy-mcp` already had a `syno_udh` tool (one dispatch-style
wrapper over WF-07/WF-14) before this repo existed. This project is a
deliberate redo, not a reuse: UDH is its own system with its own blast
radius (it can delete documents, overwrite canonical files, and pause an
entire sync mesh), and it deserves its own dedicated server with tools
decomposed by responsibility — `udh_sync`, `udh_targets`, `udh_conflicts`,
`udh_lifecycle`, `udh_control`, `udh_dashboard`, `udh_query` — rather than
one generic `action=` dispatcher. `syno_udh` is left as-is in the sibling
repo; nothing here imports from or registers with it, mcphub, or any
other MCP server.

## Tool Inventory (7 tools)

| Tool | Backing workflow | Scope needed | Gating |
|---|---|---|---|
| `udh_dashboard` | WF-14 (read) | `read` | None — read-only |
| `udh_query` | WF-16 (read, **new**) | `read` | None — read-only |
| `udh_sync` | WF-07: publish/ingest/reenrich/scan_drift/scrape_url | `sync` | confirm=true |
| `udh_targets` | WF-07: set_target_enabled | `sync` | confirm=true |
| `udh_control` | WF-07: set_global_pause | `sync` | confirm=true |
| `udh_conflicts` | WF-07: resolve_conflict | `admin` | confirm=true + preview |
| `udh_lifecycle` | WF-07: rollback/confirm_delete/release_quarantine | `admin` | confirm=true + preview |

The `sync`/`admin` split mirrors `synology-proxy-mcp`'s own
destructive-vs-additive tiering: `admin` is for actions that **restore,
overwrite, or destroy** existing state (a conflict resolution picks a
winner and discards the loser; `rollback`/`confirm_delete` are
self-explanatory; `release_quarantine` waives a real error signal).
Everything else moves data forward and only needs `sync`.

`set_global_pause`/`set_target_enabled` deliberately need only `sync`,
not `admin` — WF-07's own `UNGATED_ACTIONS` list keeps these two reachable
even while `hub_config.global_pause` is true (the only way to lift a
pause, and a caller disabling a misbehaving target shouldn't be blocked
by the pause that misbehavior triggered). `udh_targets`/`udh_control`
mirror that by staying out of the `admin` tier.

## WF-16: the one genuinely new capability

WF-07 (dispatch) and WF-14 (dashboard) already existed before this
project and are wrapped as-is — see `matrix-homelab/n8n-workflows/
wf07_adhoc_dispatch.json` and `wf14_dashboard_data.json`, and that repo's
`n8n-udh-workflow-facts` skill for their internals.

**WF-16 (`n8n-workflows/wf16_udh_query_api.json`) is new** — added
alongside this server because WF-14 only ever returns one fixed dashboard
shape (hub_config, target_config, recent ops, conflict queue), with no
way to look up one specific document or run a filtered search. WF-16 is
a single read-only webhook, dispatched on a `kind` field:

- `get_document` — `doc_id` or `source_path` → full `doc_registry` row.
- `search_documents` — `case_folder`/`status_filter`/`limit` → matching rows.
- `list_conflicts` — open `conflict_queue` rows.
- `list_quarantined` — `doc_registry` rows with `quarantine_status` set.
- `recent_operations` — `operation_log` rows, optionally filtered by `doc_id`.

**Imported and verified live 2026-10-08.** n8n workflow id `4jc20pd5U0p8ust2`,
active, authenticated via the "UDH Query Auth Header" credential
(`NGwaSRbxc1EgI0ow`). All 5 query kinds (`get_document`,
`search_documents`, `list_conflicts`, `list_quarantined`,
`recent_operations`) confirmed against real data. `WF16_URL`/
`WF16_AUTH_TOKEN` are wired into the live `udh-mcp` stack.

## Auth: scoped multi-token

Same design as `synology-proxy-mcp`'s `MCP_AUTH_TOKEN`/
`MCP_AUTH_TOKEN_<NAME>` system, reimplemented from scratch here (not
imported — this server is standalone) because UDH's blast radius
genuinely warrants it:

- `UDH_AUTH_TOKEN` — always full access (`["*"]`). Unset entirely means
  auth is disabled and every call is allowed, same documented fallback
  `synology-proxy-mcp` uses.
- `UDH_AUTH_TOKEN_<NAME>` + `UDH_AUTH_SCOPES_<NAME>` (comma-separated:
  `read`, `sync`, `admin`) — mint a narrower token. A named token with no
  matching `_SCOPES_` var gets an empty scope list (deny-most), never
  `["*"]` by default.

Hand out a `read`-only token to anything that only needs
`udh_dashboard`/`udh_query` (e.g. a status page), a `sync`-scoped token to
day-to-day automation, and reserve `admin` for whoever actually resolves
conflicts or runs rollbacks.

## Env vars

| Var | Required for | Notes |
|---|---|---|
| `UDH_AUTH_TOKEN` | auth | Unset = unauthenticated `/mcp`, with a startup warning. |
| `UDH_AUTH_TOKEN_<NAME>` / `UDH_AUTH_SCOPES_<NAME>` | scoped tokens | Optional, additive. |
| `UDH_PUBLIC_URL` | OAuth resource metadata | Only meaningful once `UDH_AUTH_TOKEN` is set. |
| `UDH_MCP_HOST` / `UDH_MCP_PORT` | — | Default `0.0.0.0:8090`. |
| `WF07_URL` / `WF07_AUTH_TOKEN` / `WF07_AUTH_HEADER_NAME` | `udh_sync`, `udh_targets`, `udh_conflicts`, `udh_lifecycle`, `udh_control` | Header name defaults to `X-UDH-Dispatch-Token` — **same credential** `apps/udh-dashboard/wf07_client.py` already uses in `matrix-homelab`, not a new secret. |
| `WF14_URL` / `WF14_AUTH_TOKEN` / `WF14_AUTH_HEADER_NAME` | `udh_dashboard` | Defaults to `X-UDH-Dashboard-Token`. Same credential as `dashboard_client.py`. |
| `WF16_URL` / `WF16_AUTH_TOKEN` / `WF16_AUTH_HEADER_NAME` | `udh_query` | Defaults to `X-UDH-Query-Token`. **New** — WF-16 doesn't exist as a live n8n workflow yet; see above. |

## File Layout

```
src/
├── server.py                 # MCP tool definitions, auth, entrypoint
├── core.py                   # HTTP clients for WF-07/WF-14/WF-16
└── test_tool_registration.py # Registration + mocked-HTTP behavior tests
Dockerfile
requirements.txt               # floor+ceiling spec
requirements.lock.txt          # exact pins the Dockerfile installs from
.github/workflows/docker-publish.yml
```

## Deploy

Same GitOps pattern as every other service in this homelab:
push to `main` → `docker-publish.yml` tests, builds `linux/amd64`, pushes
`ghcr.io/<owner>/udh-mcp:latest` → POSTs `PORTAINER_WEBHOOK_UDH_MCP` (once
it exists) → Portainer redeploys from `matrix-homelab/stacks/udh-mcp/`.

**Deployed and verified end-to-end (2026-10-07/2026-10-08):**
1. Portainer stack `udh-mcp` (Stack ID 678), `network_mode: host`,
   running `ghcr.io/gregbtm/udh-mcp:latest` on host port **12021** (reconciled
   and aligned with `matrix-homelab`'s `stacks/udh-mcp/stack.yaml` and
   `docker-compose.yml`, both specifying port 12021).
2. `UDH_AUTH_TOKEN` and `UDH_AUTH_TOKEN_READONLY` minted and stored in
   Infisical under folder `udh-mcp`.
3. `WF07_AUTH_TOKEN`/`WF14_AUTH_TOKEN` confirmed identical to
   `udh-dashboard`'s stack env via `syno_portainer compare_env`.
4. `wf16_udh_query_api.json` imported into n8n (workflow id
   `4jc20pd5U0p8ust2`), active, all 5 query kinds verified against real
   data — see the WF-16 section above.
5. Portainer GitOps webhook enabled (`ForcePullImage=true`) and
   registered as GitHub secret `PORTAINER_WEBHOOK_UDH_MCP`.
6. Claude connector active at `https://udh.nasmatrix.app/mcp`, bearer
   auth `UDH_AUTH_TOKEN`.

## Known gaps / where this goes next

See `ROADMAP.md` for the full, detailed backlog — produced by reviewing
every UDH workflow (WF-01 through WF-16) against this server's current
7-tool surface before anything here was deployed. Short version: no tool
can read actual document content (only registry metadata), WF-08/WF-11
(adapter health, integrity checks) have no external trigger at all, and
`hub_config`/`target_config` are read-only through MCP today. Nothing in
that file is built yet.
