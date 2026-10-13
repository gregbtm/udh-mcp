"""udh-mcp — standalone MCP server for matrix-homelab's Universal Document
Hub (UDH). Independent of synology-proxy-mcp and mcphub: this server holds
its own credentials and talks directly to n8n's UDH webhooks (WF-07
adhoc-dispatch, WF-14 dashboard-data, WF-16 query-api).

Tool surface: 10 tools, decomposed by responsibility rather than one
mega-dispatcher (mirrors how syno_rules/syno_portainer/etc. are split by
subsystem in synology-proxy-mcp, applied to UDH's own action set).
Expanded from 7 to 10 on 2026-10-13, closing the exact gap this file's
own CLAUDE.md had tracked under "Known gaps" (check_health/
check_integrity/update_hub_config/update_target_config/purge_ingested
all existed server-side in matrix-homelab since 2026-10-12 with no MCP
tool exposing them yet) plus two matrix-homelab actions added the same
day (ingestion-template CRUD, Meilisearch full-text search):

  udh_dashboard   Read-only system snapshot (WF-14): hub_config,
                  target_config, recent operations, conflict queue.
  udh_query       Read-only document lookups (WF-16): get_document,
                  search_documents, search_fulltext, get_content,
                  list_conflicts, list_quarantined, recent_operations.
                  New capability this project adds -- WF-14 only ever
                  returns a fixed dashboard shape, not an arbitrary
                  document lookup. get_content (2026-10-13) is the one
                  this server's own ROADMAP.md names as its single
                  highest-value gap (B1): the actual canonical document
                  text, not just registry metadata.
  udh_sync        Day-to-day sync operations (WF-07): publish, ingest,
                  reenrich, scan_drift, scrape_url, snapshot,
                  sync_outbound, backfill_trilium.
  udh_targets     Per-target control (WF-07): set_target_enabled.
  udh_conflicts   Conflict resolution (WF-07): resolve_conflict.
  udh_lifecycle   Restore/overwrite/destroy operations (WF-07): rollback,
                  confirm_delete, release_quarantine, purge_ingested.
  udh_control     Emergency brake (WF-07): set_global_pause.
  udh_health      On-demand health/integrity checks (WF-07): check_health,
                  check_integrity.
  udh_config      Hub/target configuration tuning (WF-07):
                  update_hub_config, update_target_config.
  udh_templates   Ingestion template CRUD (WF-07): list_templates,
                  create_template, update_template, delete_template,
                  set_default_template.

Auth: scoped multi-token, same model as synology-proxy-mcp. UDH_AUTH_TOKEN
is always full access (["*"]). Additional UDH_AUTH_TOKEN_<NAME> +
UDH_AUTH_SCOPES_<NAME> (comma-separated: read, sync, admin) env vars mint
narrower tokens. 'read' covers udh_dashboard/udh_query; 'sync' additionally
covers udh_sync/udh_targets/udh_control/udh_health/udh_config/udh_templates
(day-to-day, non-destructive -- none of these three new tools restore,
overwrite, or destroy document data, only trigger a check or change future
behavior); 'admin' is required for udh_conflicts/udh_lifecycle (restore/
overwrite/destroy, including udh_lifecycle's new purge_ingested action --
it permanently deletes real documents from a target). If UDH_AUTH_TOKEN is
unset entirely, auth is disabled and every call is allowed -- matches
synology-proxy-mcp's own documented behavior for a token-less deployment.

HTTP: /status (GET, liveness + config presence, no secrets)
Env:  UDH_PUBLIC_URL -- this server's own public base URL (informational).
"""
from __future__ import annotations

import functools
import hmac
import logging
import os
import time
from typing import Any, List, Optional

import httpx
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.context import Context
from mcp.types import ToolAnnotations
from pydantic import BaseModel, ConfigDict, Field
from starlette.requests import Request
from starlette.responses import JSONResponse

import core
from core import (
    DESTRUCTIVE_ACTIONS, DISPATCH_ACTIONS, QUERY_KINDS, UNGATED_ACTIONS,
    dashboard_data, dispatch, query,
)

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s — %(message)s")
log = logging.getLogger(__name__)

AUTH_TOKEN = os.getenv("UDH_AUTH_TOKEN", "").strip()
UDH_PUBLIC_URL = os.getenv("UDH_PUBLIC_URL", "").strip().rstrip("/")


# ------------------------------------------------------------------- auth
# Identical shape to synology-proxy-mcp's scoped-token system -- a proven
# design, reimplemented here from scratch (not imported) since this server
# is deliberately standalone.

def _load_scoped_tokens() -> dict[str, list[str]]:
    tokens: dict[str, list[str]] = {}
    if AUTH_TOKEN:
        tokens[AUTH_TOKEN] = ["*"]
    prefix = "UDH_AUTH_TOKEN_"
    for key, value in os.environ.items():
        if not key.startswith(prefix) or not value.strip():
            continue
        name = key[len(prefix):]
        value = value.strip()
        scopes_raw = os.getenv(f"UDH_AUTH_SCOPES_{name}", "").strip()
        tokens[value] = [s.strip() for s in scopes_raw.split(",") if s.strip()]
    return tokens


_SCOPED_TOKENS = _load_scoped_tokens()


def _has_scope(scope: str) -> bool:
    """True if the current request's token grants `scope` (or '*'), or if
    auth is disabled entirely. 'read' < 'sync' < 'admin' is NOT a hierarchy
    here -- each scope is checked explicitly by the handler that needs it,
    same flat model as synology-proxy-mcp's own scopes."""
    if not AUTH_TOKEN:
        return True
    token = get_access_token()
    if token is None:
        return True
    return "*" in token.scopes or scope in token.scopes


class _StaticBearerVerifier(TokenVerifier):
    async def verify_token(self, token: str) -> Optional[AccessToken]:
        if not token:
            return None
        for candidate, scopes in _SCOPED_TOKENS.items():
            if hmac.compare_digest(token, candidate):
                return AccessToken(token=token, client_id="udh-mcp", scopes=scopes)
        return None


def _authorised(request: Request) -> bool:
    """Gate for this file's own /status route."""
    if not AUTH_TOKEN:
        return True
    hdr = request.headers.get("authorization", "")
    if hdr.lower().startswith("bearer "):
        return hmac.compare_digest(hdr[7:].strip(), AUTH_TOKEN)
    return False


def _build_server() -> MCPServer:
    if not AUTH_TOKEN:
        log.warning("UDH_AUTH_TOKEN is not set — /mcp is UNAUTHENTICATED. "
                    "Anyone who can reach this URL can operate on UDH.")
        return MCPServer(name="Universal Document Hub")
    base = UDH_PUBLIC_URL or "https://udh.nasmatrix.app"
    return MCPServer(
        name="Universal Document Hub",
        token_verifier=_StaticBearerVerifier(),
        auth=AuthSettings(
            issuer_url=base,
            resource_server_url=f"{base}/mcp",
            required_scopes=[],
        ),
    )


server = _build_server()


# -------------------------------------------------------------- call log
# In-memory only (no persistent journal in this server -- WF-07/WF-14/WF-16
# already log to n8n's own operation_log for anything that actually
# mutates state; this is just a liveness/debugging aid for /status).

_TOOL_CALL_STATS: dict[str, dict[str, float]] = {}


def _record_tool_call(tool_name: str, duration_ms: float, raised: bool) -> None:
    s = _TOOL_CALL_STATS.setdefault(tool_name, {"count": 0, "errors": 0, "total_ms": 0.0})
    s["count"] += 1
    if raised:
        s["errors"] += 1
    s["total_ms"] += duration_ms


def _logged_tool(fn):
    @functools.wraps(fn)
    async def wrapper(params, ctx):
        started = time.monotonic()
        try:
            result = await fn(params, ctx)
            _record_tool_call(fn.__name__, (time.monotonic() - started) * 1000, raised=False)
            return result
        except Exception:
            _record_tool_call(fn.__name__, (time.monotonic() - started) * 1000, raised=True)
            raise
    return wrapper


def out(text: str, data: Any, fmt: str) -> str:
    import json as _json
    return _json.dumps(data, indent=2, default=str) if fmt == "json" else text


def preview(action: str, resource: Any = None, **extra: Any) -> dict:
    return {"preview": True, "action": action, "resource": resource, **extra}


M = ConfigDict(str_strip_whitespace=True, extra="forbid")
WR = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False)
DE = ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False)
RD = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True)


@server.custom_route("/status", methods=["GET"])
async def status(request: Request) -> JSONResponse:
    if AUTH_TOKEN and not _authorised(request):
        return JSONResponse({"status": "ok"})
    return JSONResponse({
        "status": "ok",
        "auth_required": bool(AUTH_TOKEN),
        "wf07_configured": bool(core.WF07_URL and core.WF07_AUTH_TOKEN),
        "wf14_configured": bool(core.WF14_URL and core.WF14_AUTH_TOKEN),
        "wf16_configured": bool(core.WF16_URL and core.WF16_AUTH_TOKEN),
        "tool_call_stats": _TOOL_CALL_STATS,
    })


# ============================================================== udh_dashboard

class DashboardIn(BaseModel):
    model_config = M
    output: str = Field("text", description="'text' or 'json'.", pattern=r"^(text|json)$")


@server.tool(name="udh_dashboard", title="UDH Dashboard Snapshot", annotations=RD)
@_logged_tool
async def udh_dashboard(params: DashboardIn, ctx: Context) -> str:
    """Read-only system snapshot of the Universal Document Hub, via WF-14:
    hub_config (global_pause, dry_run, batch limits, ...), target_config
    (every connected system's sync_direction/enabled flags/conflict
    settings), recent operation_log entries, and the current conflict_queue.
    No confirm needed — nothing here writes.

    Requires WF14_URL/WF14_AUTH_TOKEN in the environment.
    """
    if not _has_scope("read"):
        return "This token isn't scoped for udh_dashboard — needs 'read' (or '*')."
    ok, text, data = await dashboard_data()
    return out(text, data, params.output) if ok else text


# ================================================================== udh_query

class QueryIn(BaseModel):
    model_config = M
    kind: str = Field(..., description=(
        "get_document | search_documents | list_conflicts | "
        "list_quarantined | recent_operations | search_fulltext | get_content"))
    output: str = Field("text", description="'text' or 'json'.", pattern=r"^(text|json)$")
    doc_id: Optional[str] = Field(None, description="get_document/recent_operations/get_content: the doc's id.")
    source_path: Optional[str] = Field(None, description="get_document/get_content: the NAS source path (alternative to doc_id).")
    case_folder: Optional[str] = Field(None, description="search_documents: filter by top-level case folder.")
    status_filter: Optional[str] = Field(None, description=(
        "search_documents: filter on any <target>_status column value "
        "(e.g. 'pending', 'error')."))
    limit: int = Field(50, description="search_documents/list_*/recent_operations/search_fulltext: max rows (default 50).")
    query: Optional[str] = Field(None, description="search_fulltext (required): the free-text search string.")
    document_type: Optional[str] = Field(None, description="search_fulltext: optional facet filter.")
    sensitivity: Optional[str] = Field(None, description="search_fulltext: optional facet filter.")
    folder: Optional[str] = Field(None, description="search_fulltext: optional facet filter.")


@server.tool(name="udh_query", title="UDH Document & Conflict Query", annotations=RD)
@_logged_tool
async def udh_query(params: QueryIn, ctx: Context) -> str:
    """Read-only lookups against the UDH document registry, via WF-16 (a
    new query-api workflow this project adds alongside WF-07/WF-14 --
    n8n-workflows/wf16_udh_query_api.json in matrix-homelab; not yet
    imported/verified against a live n8n instance).

    Kinds:
      get_document        doc_id=... or source_path=... — full doc_registry
                           row including every <target>_status/_synced_at/
                           _etag column and the provenance chain.
      search_documents     case_folder=..., status_filter=..., limit=...
                           Lists doc_registry rows directly (every
                           ingested document, any processing state).
      search_fulltext      query=... (required), optional document_type/
                           sensitivity/folder facets, limit=... — real
                           typo-tolerant ranked full-text search via
                           Meilisearch (added 2026-10-13). Only covers
                           documents that have actually been *published*
                           (indexed post-WF-03) — not the same document
                           set search_documents lists, and returns a
                           different shape (Meilisearch's indexed fields,
                           not raw doc_registry columns).
      get_content          doc_id=... or source_path=... — the canonical
                           .md file's actual text (front-matter + body),
                           not just its registry metadata (added
                           2026-10-13 — this is "B1" from ROADMAP.md, the
                           single highest-value gap that list named: an
                           LLM operating UDH through this server could not
                           previously see a document's actual content).
      list_conflicts        Open conflict_queue rows needing resolution.
      list_quarantined       doc_registry rows with quarantine_status set.
      recent_operations     doc_id=... (optional) — operation_log entries,
                           newest first.

    No confirm needed — WF-16 only runs read queries, never writes.
    """
    if not _has_scope("read"):
        return "This token isn't scoped for udh_query — needs 'read' (or '*')."
    if params.kind not in QUERY_KINDS:
        return f"Unknown kind '{params.kind}'. Kinds: {', '.join(QUERY_KINDS)}"
    if params.kind == "search_fulltext" and not params.query:
        return "search_fulltext requires 'query'."
    qparams = {k: v for k, v in {
        "doc_id": params.doc_id, "source_path": params.source_path,
        "case_folder": params.case_folder, "status_filter": params.status_filter,
        "limit": params.limit, "query": params.query,
        "document_type": params.document_type, "sensitivity": params.sensitivity,
        "folder": params.folder,
    }.items() if v is not None}
    ok, text, data = await query(params.kind, qparams)
    return out(text, data, params.output) if ok else text


# ==================================================================== udh_sync

class SyncIn(BaseModel):
    model_config = M
    action: str = Field(..., description=(
        "publish | ingest | reenrich | scan_drift | scrape_url | snapshot | "
        "sync_outbound | backfill_trilium"))
    output: str = Field("text", description="'text' or 'json'.", pattern=r"^(text|json)$")
    confirm: bool = Field(False, description="Required for every action here.")
    payload: Optional[dict] = Field(None, description=(
        "Action-specific fields, passed through verbatim to WF-07 alongside "
        "'action'. See matrix-homelab's n8n-udh-workflow-facts skill and "
        "docs/udh/04-udh-architecture.md for each action's exact fields. "
        "snapshot needs {'doc_id': ...}; sync_outbound and backfill_trilium "
        "take no required fields."))


_SYNC_ACTIONS = {"publish", "ingest", "reenrich", "scan_drift", "scrape_url",
                  "snapshot", "sync_outbound", "backfill_trilium"}


@server.tool(name="udh_sync", title="UDH Sync Operations", annotations=WR)
@_logged_tool
async def udh_sync(params: SyncIn, ctx: Context) -> str:
    """Day-to-day UDH sync operations, via WF-07: publish (push canonical
    docs to enabled targets), ingest (pull from a source), reenrich
    (re-run Claude/OpenAI enrichment on a doc), scan_drift (check for
    moved/deleted/changed source files), scrape_url (fetch a URL as a new
    source document), snapshot (immediate FileBrowser pre-op registry
    backup for one doc_id — do this before a risky bulk action), sync_outbound
    (ad-hoc outbound publish sweep across every enabled target, outside its
    normal schedule), backfill_trilium (one-time historical Trilium-vault
    import into the registry). These move data forward rather than restore
    or destroy it — confirm=true is required, but no elevated scope.
    """
    if params.action not in _SYNC_ACTIONS:
        return f"Unknown action '{params.action}'. Actions: {', '.join(sorted(_SYNC_ACTIONS))}"
    if not _has_scope("sync"):
        return f"This token isn't scoped for udh_sync action='{params.action}' — needs 'sync' (or '*')."
    payload = params.payload or {}
    if not params.confirm:
        text = f"Would dispatch '{params.action}' with {payload}. Set confirm=true to proceed."
        return out(text, preview("udh_sync", resource=params.action, payload=payload), params.output)
    ok, text, data = await dispatch(params.action, payload)
    return out(text, data, params.output) if ok else text


# ================================================================= udh_targets

class TargetsIn(BaseModel):
    model_config = M
    output: str = Field("text", description="'text' or 'json'.", pattern=r"^(text|json)$")
    confirm: bool = Field(False, description="Required.")
    target_id: str = Field(..., description="target_config row id to toggle, e.g. 'trilium'.")
    direction: str = Field(..., description="'inbound' or 'outbound'.")
    enabled: bool = Field(..., description="true to enable, false to disable that direction.")


@server.tool(name="udh_targets", title="UDH Target Control", annotations=WR)
@_logged_tool
async def udh_targets(params: TargetsIn, ctx: Context) -> str:
    """Enable or disable one direction (inbound/outbound) for one UDH
    target, via WF-07's set_target_enabled. Stays reachable even while
    hub_config.global_pause is true (WF-07's own UNGATED_ACTIONS) — a
    caller disabling a misbehaving target shouldn't be blocked by the
    pause that misbehavior may have triggered. No elevated scope needed:
    'sync' covers this, same tier as udh_sync/udh_control.
    """
    if params.direction not in ("inbound", "outbound"):
        return "direction must be 'inbound' or 'outbound'."
    if not _has_scope("sync"):
        return "This token isn't scoped for udh_targets — needs 'sync' (or '*')."
    payload = {"target_id": params.target_id, "direction": params.direction,
               "enabled": params.enabled}
    if not params.confirm:
        text = f"Would set {params.target_id}'s {params.direction} to {params.enabled}. Set confirm=true to proceed."
        return out(text, preview("udh_targets", resource=params.target_id, payload=payload), params.output)
    ok, text, data = await dispatch("set_target_enabled", payload)
    return out(text, data, params.output) if ok else text


# ================================================================ udh_conflicts

class ConflictsIn(BaseModel):
    model_config = M
    output: str = Field("text", description="'text' or 'json'.", pattern=r"^(text|json)$")
    confirm: bool = Field(False, description="Required.")
    doc_id: str = Field(..., description="The conflicted document's id (see udh_query list_conflicts).")
    winner_target_id: str = Field(..., description="Which target's version wins — unlocks a 'queue'/'notify_only' conflict.")


@server.tool(name="udh_conflicts", title="UDH Conflict Resolution", annotations=DE)
@_logged_tool
async def udh_conflicts(params: ConflictsIn, ctx: Context) -> str:
    """Resolve a queued conflict (via WF-07 resolve_conflict) by naming
    which target's version wins. Overwrites the canonical document and
    every other target's pending version — needs 'admin' scope in
    addition to confirm=true, same destructive tier as udh_lifecycle.
    Use udh_query(kind='list_conflicts') first to find doc_id.
    """
    if not _has_scope("admin"):
        return "This token isn't scoped for udh_conflicts — needs 'admin' (or '*')."
    payload = {"doc_id": params.doc_id, "winner_target_id": params.winner_target_id}
    if not params.confirm:
        text = (f"Would resolve conflict on doc '{params.doc_id}' in favor of "
                f"'{params.winner_target_id}', overwriting every other pending "
                "version. Set confirm=true to proceed.")
        return out(text, preview("udh_conflicts", resource=params.doc_id,
                   payload=payload, undoable=False), params.output)
    ok, text, data = await dispatch("resolve_conflict", payload)
    return out(text, data, params.output) if ok else text


# ================================================================ udh_lifecycle

class LifecycleIn(BaseModel):
    model_config = M
    action: str = Field(..., description="rollback | confirm_delete | release_quarantine | purge_ingested")
    output: str = Field("text", description="'text' or 'json'.", pattern=r"^(text|json)$")
    confirm: bool = Field(False, description="Required.")
    payload: Optional[dict] = Field(None, description=(
        "Action-specific fields (e.g. doc_id, backup version for rollback). "
        "See docs/udh/04-udh-architecture.md's workflow inventory (WF-10 "
        "rollback) for exact fields. purge_ingested needs "
        "{'target_id': 'trilium'|'obsidian'|'paperless'|'affine'|'notion'}."))


_LIFECYCLE_ACTIONS = {"rollback", "confirm_delete", "release_quarantine", "purge_ingested"}


@server.tool(name="udh_lifecycle", title="UDH Lifecycle Operations", annotations=DE)
@_logged_tool
async def udh_lifecycle(params: LifecycleIn, ctx: Context) -> str:
    """Restore, overwrite, or destroy existing UDH state, via WF-07:
    rollback (restore a canonical file to a previous backup version and
    re-publish), confirm_delete (permanently delete a document),
    release_quarantine (clear a document's quarantine_status after
    repeated sync errors — confirms the underlying issue is fixed), or
    purge_ingested (permanently delete every document doc_registry itself
    recorded as ingested into one target — trilium/obsidian/paperless/
    affine/notion only; never touches a document added to that target by
    any other means, since it identifies documents strictly by the
    per-row ID column doc_registry sets only when UDH's own outbound sync
    wrote there. THIS IS IRREVERSIBLE from UDH's side even where the
    target itself keeps its own trash/archive — see matrix-homelab's
    wf07_client.py docstring for the full safety design). All four need
    'admin' scope in addition to confirm=true.
    """
    if params.action not in _LIFECYCLE_ACTIONS:
        return f"Unknown action '{params.action}'. Actions: {', '.join(sorted(_LIFECYCLE_ACTIONS))}"
    if not _has_scope("admin"):
        return f"This token isn't scoped for udh_lifecycle action='{params.action}' — needs 'admin' (or '*')."
    payload = params.payload or {}
    if not params.confirm:
        text = (f"Would {params.action} with {payload}. This restores, overwrites, "
                f"or destroys existing state. Set confirm=true to proceed.")
        return out(text, preview("udh_lifecycle", resource=params.action,
                   payload=payload, undoable=False), params.output)
    ok, text, data = await dispatch(params.action, payload)
    return out(text, data, params.output) if ok else text


# ================================================================== udh_control

class ControlIn(BaseModel):
    model_config = M
    output: str = Field("text", description="'text' or 'json'.", pattern=r"^(text|json)$")
    confirm: bool = Field(False, description="Required.")
    global_pause: bool = Field(..., description="true to halt every udh_sync/udh_conflicts/udh_lifecycle action; false to resume.")


@server.tool(name="udh_control", title="UDH Global Pause", annotations=WR)
@_logged_tool
async def udh_control(params: ControlIn, ctx: Context) -> str:
    """Set hub_config.global_pause (via WF-07 set_global_pause) — the
    emergency brake for the entire UDH mesh. Stays reachable even while
    already paused (WF-07's own UNGATED_ACTIONS), since this is the only
    way to lift a pause. 'sync' scope covers this.
    """
    if not _has_scope("sync"):
        return "This token isn't scoped for udh_control — needs 'sync' (or '*')."
    payload = {"global_pause": params.global_pause}
    if not params.confirm:
        text = f"Would set global_pause={params.global_pause}. Set confirm=true to proceed."
        return out(text, preview("udh_control", resource="global_pause", payload=payload), params.output)
    ok, text, data = await dispatch("set_global_pause", payload)
    return out(text, data, params.output) if ok else text


# =================================================================== udh_health

class HealthIn(BaseModel):
    model_config = M
    action: str = Field(..., description="check_health | check_integrity")
    output: str = Field("text", description="'text' or 'json'.", pattern=r"^(text|json)$")
    confirm: bool = Field(False, description="Required.")
    target_id: Optional[str] = Field(None, description="check_health: scope to one target_config row (e.g. 'trilium'). Accepted but NOT YET filtered server-side as of 2026-10-13 -- every target is checked regardless.")
    case_folder: Optional[str] = Field(None, description="check_integrity: scope to one case folder. Accepted but NOT YET filtered server-side as of 2026-10-13 -- the whole registry is checked regardless.")


_HEALTH_ACTIONS = {"check_health", "check_integrity"}


@server.tool(name="udh_health", title="UDH Health & Integrity Checks", annotations=WR)
@_logged_tool
async def udh_health(params: HealthIn, ctx: Context) -> str:
    """Trigger an on-demand adapter health check (WF-08) or canonical
    integrity check (WF-11), via WF-07, instead of waiting for their
    normal cron schedule. Added 2026-10-12 server-side in matrix-homelab
    specifically to close the gap this server's own ROADMAP.md named as
    A1/A2: before this, there was no way to ask "is the Notion adapter
    actually working right now" or "did this week's integrity check
    already run, and what did it find" without digging into n8n directly.

    check_health: per-target round-trip test (auth still valid, API still
    responds) -- catches an adapter silently broken before real documents
    fail against it. target_id is accepted but every target is checked
    regardless as of 2026-10-13 (not yet filtered server-side).

    check_integrity: SHA-256 verification of every canonical file plus
    orphaned-target-ID detection. case_folder is accepted but the whole
    registry is checked regardless as of 2026-10-13 (same caveat).

    Both trigger a real workflow run (not free) — confirm=true is
    required, same as udh_sync, but only 'sync' scope, since neither
    restores, overwrites, or destroys anything.
    """
    if params.action not in _HEALTH_ACTIONS:
        return f"Unknown action '{params.action}'. Actions: {', '.join(sorted(_HEALTH_ACTIONS))}"
    if not _has_scope("sync"):
        return f"This token isn't scoped for udh_health action='{params.action}' — needs 'sync' (or '*')."
    payload: dict = {}
    if params.action == "check_health" and params.target_id:
        payload["target_id"] = params.target_id
    if params.action == "check_integrity" and params.case_folder:
        payload["case_folder"] = params.case_folder
    if not params.confirm:
        text = f"Would {params.action} with {payload}. Set confirm=true to proceed."
        return out(text, preview("udh_health", resource=params.action, payload=payload), params.output)
    ok, text, data = await dispatch(params.action, payload)
    return out(text, data, params.output) if ok else text


# =================================================================== udh_config

class ConfigIn(BaseModel):
    model_config = M
    action: str = Field(..., description="update_hub_config | update_target_config")
    output: str = Field("text", description="'text' or 'json'.", pattern=r"^(text|json)$")
    confirm: bool = Field(False, description="Required.")
    target_id: Optional[str] = Field(None, description="update_target_config (required): which target_config row, e.g. 'trilium'.")
    field: str = Field(..., description=(
        "update_hub_config: one of dry_run/max_global_batch/backup_versions_to_keep/"
        "snapshot_keep_count/quarantine_after_errors/lock_timeout_seconds/"
        "lock_retry_count/write_verification/soft_delete_only/echo_suppression/"
        "conflict_timeout_hours/pre_bulk_snapshot/circuit_breaker_threshold/"
        "default_source_of_truth (global_pause is deliberately excluded -- use "
        "udh_control instead, to keep one control path for it). "
        "update_target_config: one of enabled/sync_direction/endpoint/"
        "credential_ref/database_id/source_priority/conflict_action/"
        "max_batch_size/write_verification/circuit_breaker_threshold/dry_run/"
        "poll_interval_mins/conflict_timeout_hours/inbound_workflow_id/"
        "outbound_workflow_id/blocked_sensitivity_levels (target_id itself, "
        "inbound_enabled/outbound_enabled -- use udh_targets instead -- and "
        "last_inbound_check are excluded)."))
    value: Any = Field(..., description="The new value for 'field'. An unrecognised field name is refused by WF-07's own Guard node before any write.")


_CONFIG_ACTIONS = {"update_hub_config", "update_target_config"}


@server.tool(name="udh_config", title="UDH Hub & Target Configuration", annotations=WR)
@_logged_tool
async def udh_config(params: ConfigIn, ctx: Context) -> str:
    """Update one field of hub_config (global settings) or one
    target_config row (per-target settings), via WF-07. Added 2026-10-12
    server-side in matrix-homelab. Structurally verified there, not yet
    confirmed against a live NAS/n8n instance as of 2026-10-13 -- the
    first real use of either action should check the field's new value
    via udh_dashboard afterward rather than trusting this call's own
    response. 'sync' scope + confirm=true (this changes configuration,
    not document data, so it doesn't need 'admin').
    """
    if params.action not in _CONFIG_ACTIONS:
        return f"Unknown action '{params.action}'. Actions: {', '.join(sorted(_CONFIG_ACTIONS))}"
    if params.action == "update_target_config" and not params.target_id:
        return "update_target_config requires target_id."
    if not _has_scope("sync"):
        return f"This token isn't scoped for udh_config action='{params.action}' — needs 'sync' (or '*')."
    payload: dict = {"field": params.field, "value": params.value}
    if params.target_id:
        payload["target_id"] = params.target_id
    if not params.confirm:
        text = f"Would {params.action} with {payload}. Set confirm=true to proceed."
        return out(text, preview("udh_config", resource=params.field, payload=payload), params.output)
    ok, text, data = await dispatch(params.action, payload)
    return out(text, data, params.output) if ok else text


# ================================================================= udh_templates

class TemplatesIn(BaseModel):
    model_config = M
    action: str = Field(..., description=(
        "list_templates | create_template | update_template | "
        "delete_template | set_default_template"))
    output: str = Field("text", description="'text' or 'json'.", pattern=r"^(text|json)$")
    confirm: bool = Field(False, description="Required for every action except list_templates.")
    template_id: Optional[str] = Field(None, description="update/delete/set_default_template (required): the row to act on.")
    name: Optional[str] = Field(None, description="create_template/update_template (required): display name.")
    is_default: bool = Field(False, description="create_template/update_template: make this the template WF-02 reads for every future enrichment.")
    target_scope: str = Field("all", description="create_template/update_template: 'all' or a comma-separated target id list -- descriptive only, not enforced (WF-02 enriches once for every target, see docs/udh/26-ingestion-templates-setup.md).")
    metadata_fields: Optional[dict] = Field(None, description="create_template/update_template: which optional CDF frontmatter fields to write, e.g. {'title': true, 'author': true, 'physical_location': false, 'custom_fields': ['Court']}.")
    docling_settings: Optional[dict] = Field(None, description="create_template/update_template: Docling extraction options, e.g. {'to_formats': 'md', 'do_table_structure': true}.")


_TEMPLATE_ACTIONS = {"list_templates", "create_template", "update_template",
                      "delete_template", "set_default_template"}
_TEMPLATE_WRITE_ACTIONS = _TEMPLATE_ACTIONS - {"list_templates"}


@server.tool(name="udh_templates", title="UDH Ingestion Templates", annotations=WR)
@_logged_tool
async def udh_templates(params: TemplatesIn, ctx: Context) -> str:
    """Manage ingestion templates, via WF-07 — added 2026-10-13 alongside
    matrix-homelab's own Templates dashboard page. The template flagged
    is_default is what wf02_enrich_document.json reads before every
    Docling extraction and canonical-document build: which optional CDF
    frontmatter fields get written, and how Docling converts the source
    file. See docs/udh/26-ingestion-templates-setup.md (matrix-homelab)
    for the full field list and the one-time manual n8n Data Table
    creation step this feature needs before any of these calls succeed.

    list_templates needs no confirm (read-only, lists every row via
    WF-07 — still needs 'sync' scope since it goes through the same
    dispatch webhook as every write here, but nothing it does writes).
    create_template/update_template/delete_template/set_default_template
    all need confirm=true. 'sync' scope covers all five — none of these
    touch existing document data, only future-enrichment configuration.
    """
    if params.action not in _TEMPLATE_ACTIONS:
        return f"Unknown action '{params.action}'. Actions: {', '.join(sorted(_TEMPLATE_ACTIONS))}"
    if not _has_scope("sync"):
        return f"This token isn't scoped for udh_templates action='{params.action}' — needs 'sync' (or '*')."
    if params.action in ("update_template", "delete_template", "set_default_template") and not params.template_id:
        return f"{params.action} requires template_id."
    if params.action in ("create_template", "update_template") and not params.name:
        return f"{params.action} requires name."

    payload: dict = {}
    if params.action == "list_templates":
        ok, text, data = await dispatch("list_templates", {})
        return out(text, data, params.output) if ok else text

    if params.action == "delete_template":
        payload = {"template_id": params.template_id, "confirm": True}
    elif params.action == "set_default_template":
        payload = {"template_id": params.template_id}
    else:  # create_template / update_template
        payload = {
            "name": params.name, "is_default": params.is_default,
            "target_scope": params.target_scope,
            "metadata_fields": params.metadata_fields or {},
            "docling_settings": params.docling_settings or {},
        }
        if params.action == "update_template":
            payload["template_id"] = params.template_id

    if params.action in _TEMPLATE_WRITE_ACTIONS and not params.confirm:
        text = f"Would {params.action} with {payload}. Set confirm=true to proceed."
        return out(text, preview("udh_templates", resource=params.template_id or params.name, payload=payload), params.output)
    ok, text, data = await dispatch(params.action, payload)
    return out(text, data, params.output) if ok else text


def _run() -> None:
    import uvicorn

    port = int(os.getenv("UDH_MCP_PORT", "8090"))
    host = os.getenv("UDH_MCP_HOST", "0.0.0.0")
    log.info("Starting udh-mcp on %s:%d", host, port)

    app = server.streamable_http_app(host=host)
    config = uvicorn.Config(app, host=host, port=port,
                            log_level=server.settings.log_level.lower())
    import asyncio
    asyncio.run(uvicorn.Server(config).serve())


if __name__ == "__main__":
    _run()
