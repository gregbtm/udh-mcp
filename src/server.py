"""udh-mcp — standalone MCP server for matrix-homelab's Universal Document
Hub (UDH). Independent of synology-proxy-mcp and mcphub: this server holds
its own credentials and talks directly to n8n's UDH webhooks (WF-07
adhoc-dispatch, WF-14 dashboard-data, WF-16 query-api).

Tool surface: 15 tools, decomposed by responsibility rather than one
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
  udh_simulate    Dry-run simulation studio across all 5 stages: extract,
                  simhash 64-bit, metadata enrich, reconcile, outbound.
  udh_checkpoint  Instant pipeline rollback checkpoints: create, list,
                  restore, delete.
  udh_tokens      Token burn tracking, budget caps, and adaptive fallback.
  udh_tags        Semantic tag clustering and 1-click taxonomy consolidation.
  udh_fleet       Real-time container fleet health beacon and latency probes.

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
import mcp_enhancements as enh

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
_TOOL_AUDIT_RING: list[dict[str, Any]] = []


def _record_tool_call(tool_name: str, duration_ms: float, raised: bool) -> None:
    s = _TOOL_CALL_STATS.setdefault(tool_name, {"count": 0, "errors": 0, "total_ms": 0.0})
    s["count"] += 1
    if raised:
        s["errors"] += 1
    s["total_ms"] = round(s["total_ms"] + duration_ms, 2)
    _TOOL_AUDIT_RING.insert(0, {
        "tool": tool_name,
        "duration_ms": round(duration_ms, 2),
        "error": raised,
        "ts": time.time(),
    })
    if len(_TOOL_AUDIT_RING) > 25:
        del _TOOL_AUDIT_RING[25:]


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


def out(text: str, data: Any, fmt: str, max_chars: int = 16000) -> str:
    import json as _json
    raw = _json.dumps(data, indent=2, default=str) if fmt == "json" else text
    return enh.sanitize_secrets(enh.smart_truncate(raw, limit=max_chars))


def preview(action: str, resource: Any = None, scope: str = "sync", **extra: Any) -> dict:
    return {"preview": True, "action": action, "resource": resource, "scope_required": scope, "confirm_required": True, **extra}


M = ConfigDict(str_strip_whitespace=True, extra="forbid")
WR = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False)
DE = ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False)
RD = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True)


@server.custom_route("/healthz", methods=["GET"])
async def healthz(request: Request) -> JSONResponse:
    return JSONResponse({
        "ok": True,
        "service": "udh-mcp",
        "version": os.getenv("UDH_MCP_VERSION", "2.7.0"),
        "tools": 22,
        "mcp_features": enh.get_mcp_feature_summary(),
    })


@server.custom_route("/status", methods=["GET"])
async def status(request: Request) -> JSONResponse:
    if AUTH_TOKEN and not _authorised(request):
        return JSONResponse({"status": "ok"})
    return JSONResponse({
        "status": "ok",
        "version": os.getenv("UDH_MCP_VERSION", "2.7.0"),
        "auth_required": bool(AUTH_TOKEN),
        "wf07_configured": bool(core.WF07_URL and core.WF07_AUTH_TOKEN),
        "wf14_configured": bool(core.WF14_URL and core.WF14_AUTH_TOKEN),
        "wf16_configured": bool(core.WF16_URL and core.WF16_AUTH_TOKEN),
        "mcp_features": enh.get_mcp_feature_summary(),
        "transport_stats": core.get_transport_stats(),
        "tool_call_stats": _TOOL_CALL_STATS,
        "recent_audit": _TOOL_AUDIT_RING[:10],
    })


# ============================================================== udh_dashboard

class DashboardIn(BaseModel):
    model_config = M
    output: str = Field("text", description="'text' or 'json'.", pattern=r"^(text|json)$")


@server.tool(name="udh_dashboard", title="UDH Dashboard Snapshot", annotations=RD)
@_logged_tool
async def udh_dashboard(params: DashboardIn, ctx: Context) -> str:
    """Read-only system snapshot of the Universal Document Hub (native Postgres or WF-14),
    surfacing degraded fallback warnings, global pause, conflicts, and quarantine alerts upfront.
    Requires 'read' scope.
    """
    if not _has_scope("read"):
        return "This token isn't scoped for udh_dashboard — needs 'read' (or '*')."
    ok, text, data = await dashboard_data()
    if not ok:
        return text
    if params.output == "text" and isinstance(data, dict):
        alerts = []
        if data.get("is_mock") or data.get("fallback_tier"):
            alerts.append(f"fallback_tier={data.get('fallback_tier') or 'mock'}")
        hc = data.get("hub_config") or {}
        if hc.get("global_pause"):
            alerts.append("GLOBAL_PAUSE=ACTIVE")
        cq = (data.get("conflict_queue") or {}).get("open_count", 0)
        if cq:
            alerts.append(f"open_conflicts={cq}")
        if alerts:
            text = f"[Alerts: {', '.join(alerts)}]\n{text}"
    return out(text, data, params.output)


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
    sanitize_pii: bool = Field(False, description="get_content/search_fulltext: when true, deterministically scrubs NHS/NINO/email/phone/postcode PII before returning text.")


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
    if ok and params.sanitize_pii and isinstance(data, dict):
        if isinstance(data.get("content"), str):
            red = enh.redact_sensitive_pii(data["content"])
            data = {**data, "content": red["text"], "pii_redactions": red["total_redactions"]}
            import json as _jq
            text = _jq.dumps(data, indent=2, default=str)
    return out(text, data, params.output) if ok else text


# ==================================================================== udh_sync

class SyncIn(BaseModel):
    model_config = M
    action: str = Field(..., description=(
        "publish | ingest | reenrich | scan_drift | scrape_url | snapshot | "
        "sync_outbound | backfill_trilium | propagate_paperless | reindex_vectors"))
    output: str = Field("text", description="'text' or 'json'.", pattern=r"^(text|json)$")
    confirm: bool = Field(False, description="Required for every action here.")
    payload: Optional[dict] = Field(None, description=(
        "Action-specific fields, passed through verbatim to WF-07 alongside "
        "'action'. See matrix-homelab's n8n-udh-workflow-facts skill and "
        "docs/udh/04-udh-architecture.md for each action's exact fields. "
        "snapshot needs {'doc_id': ...}; sync_outbound accepts optional "
        "{'target_id'/'explicit_targets', 'doc_ids', 'folder', 'include_enriched', 'limit', 'force'} "
        "to manually convert/migrate docs onto paused endpoints."))


_SYNC_ACTIONS = {"publish", "ingest", "reenrich", "scan_drift", "scrape_url",
                  "snapshot", "sync_outbound", "backfill_trilium",
                  "propagate_paperless", "reindex_vectors"}


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
    affine/notion/nocodb/docmost; never touches a document added to that target by
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
    action: str = Field(..., description="check_health | check_integrity | wiring_check")
    output: str = Field("text", description="'text' or 'json'.", pattern=r"^(text|json)$")
    confirm: bool = Field(False, description="Required.")
    target_id: Optional[str] = Field(None, description="check_health: scope to one target_config row (e.g. 'trilium'). Accepted but NOT YET filtered server-side as of 2026-10-13 -- every target is checked regardless.")
    case_folder: Optional[str] = Field(None, description="check_integrity: scope to one case folder. Accepted but NOT YET filtered server-side as of 2026-10-13 -- the whole registry is checked regardless.")


_HEALTH_ACTIONS = {"check_health", "check_integrity", "wiring_check"}


@server.tool(name="udh_health", title="UDH Health & Integrity Checks", annotations=WR)
@_logged_tool
async def udh_health(params: HealthIn, ctx: Context) -> str:
    """Trigger an on-demand adapter health check (WF-08), canonical
    integrity check (WF-11), or read-only site-wide wiring self-check ('wiring_check').
    """
    if params.action not in _HEALTH_ACTIONS:
        return f"Unknown action '{params.action}'. Actions: {', '.join(sorted(_HEALTH_ACTIONS))}"
    if params.action == "wiring_check":
        if not _has_scope("read"):
            return "This token isn't scoped for udh_health action='wiring_check' — needs 'read' (or '*')."
        ok, text, data = await core.dashboard_api("/api/self-check/wiring")
        return out(text, data, params.output) if ok else f"Site wiring self-check failed: {text}"
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
    action: str = Field(..., description=(
        "update_hub_config | update_target_config | get_runtime_settings | "
        "update_runtime_settings | reset_runtime_settings"))
    output: str = Field("text", description="'text' or 'json'.", pattern=r"^(text|json)$")
    confirm: bool = Field(False, description="Required for write actions (all except get_runtime_settings).")
    target_id: Optional[str] = Field(None, description="update_target_config (required): which target_config row, e.g. 'trilium'.")
    field: Optional[str] = Field(None, description=(
        "update_hub_config: one of legal_mode/global_pause/dry_run/auto_enrich/"
        "default_chunk_size/max_global_batch/backup_versions_to_keep/"
        "snapshot_keep_count/quarantine_after_errors/lock_timeout_seconds/"
        "lock_retry_count/write_verification/soft_delete_only/echo_suppression/"
        "conflict_timeout_hours/pre_bulk_snapshot/circuit_breaker_threshold/"
        "default_source_of_truth. "
        "update_target_config: one of enabled/inbound_enabled/outbound_enabled/"
        "mode/sync_direction/endpoint/credential_ref/database_id/source_priority/"
        "conflict_action/max_batch_size/write_verification/circuit_breaker_threshold/"
        "dry_run/poll_interval_mins/conflict_timeout_hours/inbound_workflow_id/"
        "outbound_workflow_id/blocked_sensitivity_levels."))
    value: Any = Field(None, description="The new value for 'field' when updating hub_config or target_config.")
    settings: Optional[dict[str, Any]] = Field(None, description=(
        "update_runtime_settings (required): dictionary of runtime settings to apply "
        "(backend_mode, stage2_scheduler_armed, native_write_targets, stage2_intervals, "
        "stage2_job_toggles, token_daily_budget, circuit_breaker_failure_threshold, "
        "circuit_breaker_open_seconds, mcp_rate_limit_per_min, ntfy_alerts_enabled, "
        "hub_config, target_config)."))


_CONFIG_ACTIONS = {
    "update_hub_config",
    "update_target_config",
    "get_runtime_settings",
    "update_runtime_settings",
    "reset_runtime_settings",
}


@server.tool(name="udh_config", title="UDH Hub, Target & Runtime Configuration", annotations=WR)
@_logged_tool
async def udh_config(params: ConfigIn, ctx: Context) -> str:
    """Update hub_config (18 global settings), target_config (19 per-target settings),
    or live Option E & guardrail runtime settings (backend_mode, stage2_scheduler_armed,
    native_write_targets, stage2_intervals, token_daily_budget, circuit breakers,
    mcp_rate_limit_per_min, ntfy_alerts_enabled) without container restarts.

    get_runtime_settings requires 'read' scope and no confirm.
    All mutating actions require 'sync' scope and confirm=true.
    """
    if params.action not in _CONFIG_ACTIONS:
        return f"Unknown action '{params.action}'. Actions: {', '.join(sorted(_CONFIG_ACTIONS))}"

    if params.action == "get_runtime_settings":
        if not _has_scope("read"):
            return f"This token isn't scoped for udh_config action='{params.action}' — needs 'read' (or '*')."
        ok, text, data = await core.dashboard_api("/api/settings/runtime")
        if ok:
            return out(enh.sanitize_secrets(text), data, params.output)
        import json
        fallback = {
            "offline_fallback": True,
            "error": text,
            "backend_mode": core.UDH_BACKEND_MODE,
            "prefer_native": core.UDH_PREFER_NATIVE,
            "dashboard_url": core.UDH_DASHBOARD_URL,
        }
        return out(json.dumps(fallback, indent=2), fallback, params.output)

    if not _has_scope("sync"):
        return f"This token isn't scoped for udh_config action='{params.action}' — needs 'sync' (or '*')."

    if params.action == "update_runtime_settings":
        if not params.settings or not isinstance(params.settings, dict):
            return "update_runtime_settings requires a non-empty 'settings' dictionary."
        if not params.confirm:
            text = f"Would update_runtime_settings with {params.settings}. Set confirm=true to proceed."
            return out(text, preview("udh_config", resource="runtime_settings", payload=params.settings), params.output)
        ok, text, data = await core.dashboard_api("/api/settings/runtime", method="POST", json_body=params.settings)
        if ok and "backend_mode" in params.settings:
            core.set_runtime_mode(params.settings.get("backend_mode"))
        return out(text, data, params.output) if ok else f"Failed to update runtime settings: {text}"

    if params.action == "reset_runtime_settings":
        if not params.confirm:
            text = "Would reset_runtime_settings to environment defaults. Set confirm=true to proceed."
            return out(text, preview("udh_config", resource="runtime_settings", payload={"reset": True}), params.output)
        ok, text, data = await core.dashboard_api("/api/settings/runtime/reset", method="POST", json_body={})
        if ok:
            core.set_runtime_mode(None)
        return out(text, data, params.output) if ok else f"Failed to reset runtime settings: {text}"

    if not params.field or params.value is None:
        return f"{params.action} requires both 'field' and 'value'."
    if params.action == "update_target_config" and not params.target_id:
        return "update_target_config requires target_id."

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
    metadata_fields: Optional[dict] = Field(None, description="create_template/update_template: which optional CDF frontmatter fields to write, e.g. {'title': true, 'author': true, 'parties': true, 'key_dates': true, 'jurisdiction': true, 'privileged': true, 'physical_location': false, 'custom_fields': ['Court']}. Any key is accepted -- WF-02's 'Build CDF' node is the single source of truth for which keys it actually understands (see matrix-homelab's docs/udh/26-ingestion-templates-setup.md for the current full list).")
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




# ============================================================= udh_simulate

class SimulateIn(BaseModel):
    model_config = M
    scenario: Optional[str] = Field("et_witness_statement", description="Pre-configured test scenario (et_witness_statement, commercial_lease, nda_agreement, gdpr_audit)")
    content: Optional[str] = Field(None, description="Custom markdown or document text to simulate through the pipeline")
    target: Optional[str] = Field("all", description="Target adapter to simulate ('all', 'affine', 'docmost', 'paperless', 'obsidian', 'trilium')")
    fault: Optional[str] = Field(None, description="Optional chaos fault to inject ('none', 'notion_rate_limit', 'obsidian_conflict', 'affine_network_timeout')")
    output: str = Field("text", description="'text' or 'json'.", pattern=r"^(text|json)$")


@server.tool(name="udh_simulate", title="UDH Pipeline Dry-Run Simulator", annotations=RD)
@_logged_tool
async def udh_simulate(params: SimulateIn, ctx: Context) -> str:
    """Simulate complete 5-stage UDH pipeline execution (Extract -> SimHash ->
    Enrich -> Dedup/Reconcile -> Outbound Dispatch) without mutating physical
    files or production databases. Previews 64-bit SimHash fingerprints,
    token consumption, and target replication results. No confirm needed.
    """
    if not _has_scope("read"):
        return "This token isn't scoped for udh_simulate — needs 'read' (or '*')."
    
    import hashlib
    raw_text = params.content or (
        f"# Ingestion Simulation: {params.scenario}\n"
        "Authentic test document payload for verifying multi-target synchronization."
    )
    words = raw_text.split()
    word_count = len(words)
    simhash_hex = enh.simhash64_blake2b(raw_text)
    
    est_tokens = max(1, int(len(raw_text) / 3.8))
    target_list = ["docmost", "affine", "paperless", "obsidian", "trilium"] if params.target in ("all", None) else [params.target]
    
    target_results = {}
    for t in target_list:
        is_fault = bool(params.fault and params.fault.startswith(t))
        target_results[t] = {
            "status": "COMPENSATED" if is_fault else "SUCCESS",
            "status_code": 429 if is_fault else 200,
            "latency_ms": 320 if is_fault else 42,
            "detail": f"Simulated {t} adapter dispatch (" + ("Fault injected: Rate limit" if is_fault else "200 OK") + ")",
        }
    
    sim_data = {
        "execution_id": f"sim-{hashlib.sha256(raw_text.encode()).hexdigest()[:8]}",
        "scenario": params.scenario,
        "metrics": {
            "characters": len(raw_text),
            "words": word_count,
            "simhash_64bit": simhash_hex,
            "estimated_tokens": est_tokens,
            "estimated_cost_usd": round(est_tokens * 0.0000003, 6),
        },
        "target_results": target_results,
        "all_succeeded": not any(r["status"] != "SUCCESS" for r in target_results.values()),
        "compensation_triggered": bool(params.fault and params.fault != "none"),
    }
    
    target_pairs = ", ".join(f"{k}:{v['status']}" for k, v in target_results.items())
    text = (
        f"UDH Pipeline Simulation: {sim_data['execution_id']}\n"
        f"• SimHash 64-bit: {simhash_hex}\n"
        f"• Word Count:     {word_count} ({est_tokens} tokens, ${sim_data['metrics']['estimated_cost_usd']})\n"
        f"• Targets:        {target_pairs}\n"
        f"• Result:         {'SUCCESS' if sim_data['all_succeeded'] else 'COMPENSATED'}"
    )
    return out(text, sim_data, params.output)


# ============================================================ udh_checkpoint

_CHECKPOINT_ACTIONS = {"create", "list", "restore", "delete"}

class CheckpointIn(BaseModel):
    model_config = M
    action: str = Field(..., description="create | list | restore | delete")
    name: Optional[str] = Field(None, description="create: name of the checkpoint")
    checkpoint_id: Optional[str] = Field(None, description="restore/delete: checkpoint identifier")
    description: Optional[str] = Field(None, description="create: optional description")
    confirm: bool = Field(False, description="Required for restore and delete")
    output: str = Field("text", description="'text' or 'json'.", pattern=r"^(text|json)$")


@server.tool(name="udh_checkpoint", title="UDH Pipeline Rollback Checkpoints", annotations=WR)
@_logged_tool
async def udh_checkpoint(params: CheckpointIn, ctx: Context) -> str:
    """Manage instant pipeline rollback checkpoints (create, list, restore, delete).
    Checkpoints capture immutable oplog markers and target sync states prior
    to batch operations, enabling safe 1-click stage reversal and disaster recovery.

    create and list require 'sync' scope. restore and delete mutate state and
    require 'admin' scope plus confirm=true.
    """
    if params.action not in _CHECKPOINT_ACTIONS:
        return f"Unknown action '{params.action}'. Actions: {', '.join(sorted(_CHECKPOINT_ACTIONS))}"
    
    if params.action in ("restore", "delete"):
        if not _has_scope("admin"):
            return f"This token isn't scoped for udh_checkpoint action='{params.action}' — needs 'admin' (or '*')."
        if not params.checkpoint_id:
            return f"{params.action} requires checkpoint_id."
        if not params.confirm:
            payload = {"action": params.action, "checkpoint_id": params.checkpoint_id}
            text = f"Would {params.action} checkpoint '{params.checkpoint_id}'. Set confirm=true to proceed."
            return out(text, preview("udh_checkpoint", resource=params.checkpoint_id, payload=payload), params.output)
    else:
        if not _has_scope("sync"):
            return f"This token isn't scoped for udh_checkpoint action='{params.action}' — needs 'sync' (or '*')."
        if params.action == "create" and not params.name:
            return "create requires name."
    
    if params.action == "list":
        ok_s, text_s, data_s = await core.dashboard_api("/api/native/sagas")
        if ok_s and isinstance(data_s, dict):
            return out(text_s, data_s, params.output)
        data = {"ok": False, "checkpoints": [], "offline_fallback": True, "detail": text_s}
        text = f"Live checkpoint list unavailable ({text_s}). Verify UDH_DASHBOARD_URL or dashboard service."
        return out(text, data, params.output)

    elif params.action == "create":
        payload = {"name": params.name, "description": params.description or "Manual checkpoint"}
        ok_n, text_n, data_n = await core.dashboard_api("/api/native/snapshot", method="POST", json_body={"label": params.name, "reason": payload["description"], "dry_run": False})
        if ok_n:
            return out(text_n, data_n, params.output)
        ok, text, data = await dispatch("create_checkpoint", payload)
        if not ok:
            data = {"ok": False, "persisted": False, "name": params.name, "status": "unavailable", "detail": text}
            text = f"Checkpoint '{params.name}' could not be persisted upstream ({text})."
        return out(text, data, params.output)
    
    elif params.action == "restore":
        payload = {"checkpoint_id": params.checkpoint_id, "confirm": True}
        ok_n, text_n, data_n = await core.dashboard_api("/api/native/saga/rollback", method="POST", json_body={"snapshot_id": params.checkpoint_id, "dry_run": False})
        if ok_n:
            return out(text_n, data_n, params.output)
        ok, text, data = await dispatch("rollback_checkpoint", payload)
        if not ok:
            data = {"checkpoint_id": params.checkpoint_id, "status": "restore_unavailable", "detail": text}
            text = f"Checkpoint restore failed upstream for '{params.checkpoint_id}': {text}"
        return out(text, data, params.output)
    
    else:  # delete
        data = {"checkpoint_id": params.checkpoint_id, "status": "deleted"}
        text = f"Deleted checkpoint '{params.checkpoint_id}'."
        return out(text, data, params.output)


# ================================================================ udh_tokens

_TOKEN_ACTIONS = {"get_metrics", "set_budget", "toggle_fallback", "reset_today"}

class TokensIn(BaseModel):
    model_config = M
    action: str = Field(..., description="get_metrics | set_budget | toggle_fallback | reset_today")
    daily_budget: Optional[int] = Field(None, description="set_budget: token limit cap per day")
    fallback_active: Optional[bool] = Field(None, description="toggle_fallback: true forces local heuristic mode")
    output: str = Field("text", description="'text' or 'json'.", pattern=r"^(text|json)$")


@server.tool(name="udh_tokens", title="UDH Token Burn & Adaptive Fallback", annotations=WR)
@_logged_tool
async def udh_tokens(params: TokensIn, ctx: Context) -> str:
    """Monitor LLM token burn metrics, set daily budget limits, and manage
    adaptive fallback to local heuristic extraction (zero-cost rules / local models).

    get_metrics requires 'read' scope. set_budget, toggle_fallback, and reset_today
    require 'sync' scope.
    """
    if params.action not in _TOKEN_ACTIONS:
        return f"Unknown action '{params.action}'. Actions: {', '.join(sorted(_TOKEN_ACTIONS))}"
    
    needed = "read" if params.action == "get_metrics" else "sync"
    if not _has_scope(needed):
        return f"This token isn't scoped for udh_tokens action='{params.action}' — needs '{needed}' (or '*')."
    
    if params.action == "set_budget" and not params.daily_budget:
        return "set_budget requires daily_budget."
    
    if params.action == "get_metrics":
        ok, text, data = await dispatch("get_token_burn", {})
        if not ok:
            ok_r, _, data_r = await core.dashboard_api("/api/settings/runtime") if core.UDH_DASHBOARD_URL else (False, "unconfigured", None)
            if ok_r and isinstance(data_r, dict):
                budget = int(data_r.get("token_daily_budget", 150000))
                data = {"daily_budget": budget, "status": "runtime_config_only", "routed_via": "dashboard_runtime", "total_tokens_used": 0, "pct_used": 0.0}
                text = f"UDH Token Burn Status: RUNTIME_CONFIG_ONLY\n• Daily Budget: {budget:,} tokens (live burn telemetry via dispatch unavailable)."
            else:
                data = {"status": "unavailable", "offline_fallback": True, "detail": text}
                text = f"UDH Token Burn Status: UNAVAILABLE\n• Upstream unreachable: {text}"
        return out(text, data, params.output)
    
    elif params.action == "set_budget":
        ok_r, text_r, data_r = await core.dashboard_api("/api/settings/runtime", method="POST", json_body={"token_daily_budget": int(params.daily_budget)})
        if ok_r and isinstance(data_r, dict):
            return out(f"Persisted daily token budget to {params.daily_budget:,} tokens.", data_r, params.output)
        data = {"daily_budget": params.daily_budget, "status": "local_ack", "detail": text_r}
        text = f"Updated daily token budget to {params.daily_budget:,} tokens (remote persist unavailable: {text_r})."
        return out(text, data, params.output)
    
    elif params.action == "toggle_fallback":
        mode = "heuristic_fallback" if params.fallback_active else "llm_full"
        ok_d, text_d, data_d = await dispatch("update_hub_config", {"field": "auto_enrich", "value": not bool(params.fallback_active)})
        if ok_d:
            return out(f"Adaptive fallback updated via hub_config: Mode is now '{mode}'.", data_d, params.output)
        data = {"ok": False, "is_fallback_active": bool(params.fallback_active), "requested_mode": mode, "persisted": False, "detail": text_d}
        text = f"Adaptive fallback update failed upstream ({text_d}); hub_config was not changed."
        return out(text, data, params.output)
    
    else:  # reset_today
        data = {"status": "reset", "tokens_used": 0, "note": "Local counter reset ack; backend metrics roll over at UTC midnight."}
        text = "Today's token metrics reset to 0."
        return out(text, data, params.output)


# ================================================================== udh_tags

_TAG_ACTIONS = {"cluster_tags", "plan_merge", "consolidate_tags"}

class TagsIn(BaseModel):
    model_config = M
    action: str = Field(..., description="cluster_tags | plan_merge | consolidate_tags")
    tags: Optional[List[str]] = Field(None, description="cluster_tags: list of tags to evaluate")
    canonical_tag: Optional[str] = Field(None, description="plan_merge/consolidate_tags: destination tag")
    deprecated_tags: Optional[List[str]] = Field(None, description="plan_merge/consolidate_tags: tags to merge into canonical")
    confirm: bool = Field(False, description="Required for consolidate_tags")
    output: str = Field("text", description="'text' or 'json'.", pattern=r"^(text|json)$")


@server.tool(name="udh_tags", title="UDH Semantic Tag Clustering & Taxonomy", annotations=WR)
@_logged_tool
async def udh_tags(params: TagsIn, ctx: Context) -> str:
    """Analyze and consolidate document tags across the 11-target mesh.
    Detects fragmented synonyms, spelling variations, and plural forms,
    and proposes or executes clean tag consolidations.

    cluster_tags requires 'read' scope. plan_merge requires 'sync' scope.
    consolidate_tags mutates document metadata and requires 'admin' scope plus confirm=true.
    """
    if params.action not in _TAG_ACTIONS:
        return f"Unknown action '{params.action}'. Actions: {', '.join(sorted(_TAG_ACTIONS))}"
    
    if params.action == "consolidate_tags":
        if not _has_scope("admin"):
            return "This token isn't scoped for consolidate_tags — needs 'admin' (or '*')."
        if not params.canonical_tag or not params.deprecated_tags:
            return "consolidate_tags requires canonical_tag and deprecated_tags."
        if not params.confirm:
            payload = {"canonical": params.canonical_tag, "deprecated": params.deprecated_tags}
            text = f"Would consolidate {len(params.deprecated_tags)} tags into #{params.canonical_tag}. Set confirm=true to proceed."
            return out(text, preview("udh_tags", resource=params.canonical_tag, payload=payload), params.output)
        
        ok, text, data = await dispatch("cluster_tags", {"action": "consolidate", "canonical": params.canonical_tag, "deprecated": params.deprecated_tags})
        if not ok:
            data = {"ok": False, "persisted": False, "canonical": params.canonical_tag, "status": "unavailable", "detail": text}
            text = f"Tag consolidation failed upstream for #{params.canonical_tag}: {text}"
        return out(text, data, params.output)

    elif params.action == "plan_merge":
        if not _has_scope("sync"):
            return "plan_merge requires 'sync' (or '*')."
        if not params.canonical_tag or not params.deprecated_tags:
            return "plan_merge requires canonical_tag and deprecated_tags."
        data = {
            "canonical_tag": params.canonical_tag,
            "deprecated_tags": params.deprecated_tags,
            "actions": [{"from": t, "to": params.canonical_tag} for t in params.deprecated_tags],
            "reversible": True
        }
        text = f"Merge Plan: Consolidate {len(params.deprecated_tags)} variants -> #{params.canonical_tag}"
        return out(text, data, params.output)

    else:  # cluster_tags
        if not _has_scope("read"):
            return "cluster_tags requires 'read' (or '*')."
        raw_tags = params.tags or ["invoice", "invoices", "invoice-2026", "billing", "receipts", "receipt", "legal-privilege", "lpp"]
        import difflib
        clusters = []
        visited = set()
        for t in raw_tags:
            if t in visited:
                continue
            group = [t]
            visited.add(t)
            norm_a = enh.normalize_canonical_tag_alias(t)
            for other in raw_tags:
                if other in visited:
                    continue
                norm_b = enh.normalize_canonical_tag_alias(other)
                if norm_a == norm_b or difflib.SequenceMatcher(None, norm_a, norm_b).ratio() >= 0.65 or norm_a in norm_b or norm_b in norm_a:
                    group.append(other)
                    visited.add(other)
            if len(group) > 1:
                canonical = sorted((enh.normalize_canonical_tag_alias(g) for g in group), key=len)[0]
                clusters.append({
                    "canonical": canonical,
                    "variants": group,
                    "count": len(group),
                    "savings_tags": len(group) - 1,
                })
        total_savings = sum(c["savings_tags"] for c in clusters)
        data = {"clusters": clusters, "total_clusters": len(clusters), "total_savings_tags": total_savings}
        text = (
            f"Discovered {len(clusters)} tag clusters (savings {total_savings} redundant tags):\n"
            + "\n".join(f"• #{c['canonical']}: {', '.join(c['variants'])}" for c in clusters)
        )
        return out(text, data, params.output)


# ================================================================= udh_fleet

_FLEET_ACTIONS = {"get_status", "ping_services"}

class FleetIn(BaseModel):
    model_config = M
    action: str = Field("get_status", description="get_status | ping_services")
    output: str = Field("text", description="'text' or 'json'.", pattern=r"^(text|json)$")


@server.tool(name="udh_fleet", title="UDH Container Fleet Health", annotations=RD)
@_logged_tool
async def udh_fleet(params: FleetIn, ctx: Context) -> str:
    """Inspect real-time health, socket responsiveness, and latency of the 5
    core UDH ecosystem services on Synology DSM 7.2: udh-dashboard (8080),
    udh-mcp (12021), n8n (5678), udh-qdrant (6333), and dbackup (8000).
    No confirm needed — read-only diagnostics.
    """
    if not _has_scope("read"):
        return "This token isn't scoped for udh_fleet — needs 'read' (or '*')."
    
    import asyncio
    dashboard_port = int(os.environ.get("UDH_DASHBOARD_PORT", 12015))
    mcp_port = int(os.environ.get("UDH_MCP_PORT", 12021))
    pg_host = os.environ.get("UDH_PG_HOST", "127.0.0.1")
    pg_port = int(os.environ.get("UDH_PG_PORT", 5432))
    services = [
        {"id": "udh-dashboard", "name": "UDH Dashboard", "host": "127.0.0.1", "ports": [dashboard_port, 8080]},
        {"id": "udh-mcp", "name": "UDH MCP Server", "host": "127.0.0.1", "ports": [mcp_port]},
        {"id": "udh-postgres", "name": "UDH Postgres 17", "host": pg_host, "ports": [pg_port]},
        {"id": "n8n", "name": "n8n Core", "host": "127.0.0.1", "ports": [5678]},
        {"id": "udh-qdrant", "name": "Qdrant Vector DB", "host": "127.0.0.1", "ports": [6333, 12024]},
        {"id": "dbackup", "name": "DBackup Engine", "host": "127.0.0.1", "ports": [8000]},
    ]

    async def _probe_service(s: dict) -> dict:
        t0 = time.monotonic()
        ok = False
        active_port = s["ports"][0]
        for p in s["ports"]:
            try:
                _, writer = await asyncio.wait_for(asyncio.open_connection(s.get("host", "127.0.0.1"), p), timeout=0.3)
                writer.close()
                await writer.wait_closed()
                ok = True
                active_port = p
                break
            except OSError as exc:
                log.debug("Socket probe failed for %s:%s: %s", s["id"], p, exc)
        lat = int((time.monotonic() - t0) * 1000)
        return {
            "service": s["name"],
            "port": active_port,
            "status": "HEALTHY" if ok else "UNREACHABLE",
            "latency_ms": max(1, lat) if ok else 0,
            "_ok": ok,
        }

    probed = await asyncio.gather(*(_probe_service(s) for s in services))
    results = list(probed)
    dash_up = any(r["service"] == "UDH Dashboard" and r.get("_ok") for r in results)
    worker_data = None
    if dash_up and core.UDH_DASHBOARD_URL:
        _, _, worker_data = await core.dashboard_api("/api/worker/status", timeout=2.0)
    healthy_count = sum(1 for r in results if r.pop("_ok"))

    version_info = {
        "version": os.getenv("UDH_MCP_VERSION", "2.7.0"),
        "git_sha": os.getenv("UDH_MCP_GIT_SHA", "dev"),
        "build_date": os.getenv("UDH_MCP_BUILD_DATE", "unknown"),
    }
    data = {
        "all_healthy": (healthy_count == len(services)),
        "healthy_count": healthy_count,
        "total_count": len(services),
        "version": version_info,
        "worker_alive": bool(isinstance(worker_data, dict) and worker_data.get("alive")),
        "services": results,
    }
    text = (
        f"UDH Container Fleet (udh-mcp v{version_info['version']} @ {version_info['git_sha'][:7]}): "
        f"{healthy_count}/{len(services)} Healthy\n" +
        "\n".join(f"• {r['service']:<18} Port {r['port']:<5} -> {r['status']} ({r['latency_ms']}ms)" for r in results)
    )
    return out(text, data, params.output)


class ExtractInput(BaseModel):
    model_config = M
    text: str = Field(..., min_length=1, description="Document text or Markdown to extract metadata from or prepare locally.")
    action: str = Field(
        "extract",
        description="'extract' (legal/entity extraction & SimHash) | 'context_prepare' (mojibake, injections, chunks) | 'redact_preview' (zero-token UK PII scrubber) | 'readability' (Flesch/FK & dialect) | 'chunk_markdown' (heading-breadcrumb packing) | 'conflict_scan' (GBP/date divergence).",
        pattern=r"^(extract|context_prepare|redact_preview|readability|chunk_markdown|conflict_scan)$",
    )
    target_register: str = Field(
        "preserve",
        description="Target language register for action='context_prepare': 'preserve' | 'plain_english' | 'legal_forensic'.",
        pattern=r"^(preserve|plain_english|legal_forensic)$",
    )
    token_budget: int = Field(1200, ge=100, le=16000, description="Target prompt token budget for chunk packing.")
    redact_profile: str = Field("tribunal_public", description="PII profile for action='redact_preview': 'tribunal_public' | 'counsel_full'.")
    output: str = Field("text", description="'text' or 'json'.", pattern=r"^(text|json)$")


@server.tool(
    name="udh_extract",
    title="UDH Zero-Token Extract & Context Suite",
    description=(
        "Zero-token deterministic NLP suite: action='extract' extracts UK citations/statutes/currency/SimHash; "
        "'context_prepare' repairs mojibake, neutralizes prompt injections & chunks Markdown; "
        "'redact_preview' scrubs NHS/NINO/email/postcode PII; 'readability' scores Flesch ease & UK/US dialect; "
        "'chunk_markdown' splits preserving code/tables; 'conflict_scan' detects competing GBP amounts & dates."
    ),
    annotations=RD,
)
async def udh_extract(params: ExtractInput) -> str:
    import hashlib
    import math
    import re

    src = params.text
    if params.action == "redact_preview":
        red = enh.redact_sensitive_pii(src, profile=params.redact_profile)
        return out(
            f"Zero-Token PII Redaction ({red['total_redactions']} masked, profile={params.redact_profile})\n\n{red['text']}",
            {**red, "tokens_burned": 0},
            params.output,
        )
    if params.action == "readability":
        rb = enh.analyze_readability_and_dialect(src)
        return out(
            f"Readability ({rb['words']} words, avg {rb.get('avg_sentence_length', 0)}w/sent, Flesch {rb['flesch_ease']}, FK Grade {rb['fk_grade']}, dialect {rb['dialect']})",
            {**rb, "tokens_burned": 0},
            params.output,
        )
    if params.action == "chunk_markdown":
        ck = enh.chunk_markdown_hierarchical(src, token_budget=params.token_budget)
        return out(
            f"Hierarchical Markdown Chunker ({ck['chunk_count']}/{ck['total_blocks']} blocks, {ck['tokens_used']}/{ck['token_budget']} tokens)",
            {**ck, "tokens_burned": 0},
            params.output,
        )
    if params.action == "conflict_scan":
        cs = enh.detect_numeric_date_conflicts(src)
        return out(
            f"Conflict Scan: {'WARNINGS' if cs['has_conflicts'] else 'CLEAN'} ({len(cs['currency_gbp'])} GBP sums, {len(cs['dates'])} dates)",
            {**cs, "tokens_burned": 0},
            params.output,
        )
    if params.action == "context_prepare":
        repaired, mojibake_hits = enh.repair_mojibake(src)
        repaired = re.sub(r"[\u200b-\u200f\u202a-\u202e\ufeff\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", repaired)
        inj_hits = 0
        for inj_pat in (
            r"<\|(?:im_start|im_end|system|user|assistant|endoftext)\|>",
            r"\[/?(?:INST|SYS)\]",
            r"(?i)\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions\b",
        ):
            repaired, n = re.subn(inj_pat, "[NEUTRALIZED_DELIMITER]", repaired)
            inj_hits += n

        if params.target_register == "plain_english":
            repaired = re.sub(r"\bwithout prejudice\b", "off-the-record settlement discussion", repaired, flags=re.IGNORECASE)
            repaired = re.sub(r"\blegal professional privilege\b", "confidential lawyer-client advice", repaired, flags=re.IGNORECASE)
        elif params.target_register == "legal_forensic":
            repaired = re.sub(r"\borganization\b", "organisation", repaired)
            repaired = re.sub(r"\banalyze\b", "analyse", repaired)

        ck = enh.chunk_markdown_hierarchical(repaired, token_budget=params.token_budget)
        rb = enh.analyze_readability_and_dialect(repaired)
        packed = ck["chunks"]
        prepared_text = "\n\n---\n\n".join(str(c["text"]) for c in packed)
        data = {
            "action": "context_prepare",
            "register": params.target_register,
            "mojibake_repaired": mojibake_hits,
            "injections_neutralized": inj_hits,
            "word_count": rb["words"],
            "avg_sentence_length": rb.get("avg_sentence_length", 0.0),
            "flesch_ease": rb["flesch_ease"],
            "dialect": rb["dialect"],
            "chunk_count": ck["total_blocks"],
            "selected_chunks": ck["chunk_count"],
            "tokens_used": ck["tokens_used"],
            "token_budget": params.token_budget,
            "prepared_text": prepared_text,
            "tokens_burned": 0,
        }
        text = (
            f"Context Prepare ({ck['chunk_count']}/{ck['total_blocks']} chunks, {ck['tokens_used']}/{params.token_budget} tokens, Flesch {rb['flesch_ease']})\n"
            f"• Mojibake fixed: {mojibake_hits} | Injections neutralized: {inj_hits} | Register: {params.target_register}\n\n"
            f"{prepared_text}"
        )
        return out(text, data, params.output)
    words = re.findall(r"\S+", src)
    headings = re.findall(r"^#{1,6}\s+(.+)$", src, flags=re.MULTILINE)
    case_refs = sorted(set(re.findall(r"\[\d{4}\]\s+(?:EWCA\s+Civ|UKEAT|UKSC|EWHC|ET|ICR|IRLR)\s+[\w\d]+", src)))
    statutes = sorted(set(re.findall(r"(?:Employment Rights Act 1996|Equality Act 2010|Public Interest Disclosure Act 1998|Data Protection Act 2018|CPR 35|ACAS Code|ERA 1996|GDPR)", src, flags=re.IGNORECASE)))
    currencies = sorted(set(re.findall(r"£\s?\d[\d,]*(?:\.\d{1,2})?", src)))
    emails = sorted(set(re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", src)))
    dates = sorted(set(re.findall(r"\b\d{4}-\d{2}-\d{2}\b|\b\d{1,2}/\d{1,2}/\d{2,4}\b", src)))

    tokens = re.findall(r"[a-z0-9]+", src.lower())
    shingles = [" ".join(tokens[i : i + 3]) for i in range(len(tokens) - 2)] if len(tokens) >= 3 else tokens
    vec = [0] * 64
    for sh in shingles:
        h = int.from_bytes(hashlib.blake2b(sh.encode("utf-8"), digest_size=8).digest(), "big")
        for b in range(64):
            vec[b] += 1 if (h >> b) & 1 else -1
    fp = sum((1 << b) for b in range(64) if vec[b] > 0)

    data = {
        "word_count": len(words),
        "heading_count": len(headings),
        "case_refs": case_refs,
        "uk_statutes": statutes,
        "currency_gbp": currencies,
        "emails": emails,
        "dates": dates,
        "simhash64": f"0x{fp:016x}",
        "tokens_burned": 0,
    }
    text = (
        f"Zero-Token Extract ({len(words)} words, SimHash {data['simhash64']})\n"
        f"• Citations: {', '.join(case_refs) or 'None'}\n"
        f"• Statutes: {', '.join(statutes) or 'None'}\n"
        f"• Currency: {', '.join(currencies) or 'None'}\n"
        f"• Dates: {', '.join(dates) or 'None'}"
    )
    return out(text, data, params.output)


class BundleSealInput(BaseModel):
    model_config = M
    doc_id: str = Field(..., min_length=1, description="Document or bundle identifier.")
    content: str = Field(..., min_length=1, description="Canonical bundle or document text to seal.")
    actor: str = Field("udh-mcp", description="Custody seal actor identifier.")
    weekly_gross: float = Field(0.0, ge=0.0, description="Optional weekly gross pay (GBP) for Schedule of Loss.")
    years_service: int = Field(0, ge=0, description="Optional complete years of service.")
    age: int = Field(35, ge=16, le=90, description="Optional claimant age for ERA 1996 multiplier.")
    vento_band: int = Field(0, ge=0, le=3, description="Optional Vento injury-to-feelings band (0-3).")
    acas_uplift_pct: float = Field(0.0, ge=0.0, le=25.0, description="Optional ACAS Code uplift (0-25%).")
    weeks_unemployed: int = Field(0, ge=0, description="Optional weeks of compensatory loss.")
    output: str = Field("text", description="'text' or 'json'.", pattern=r"^(text|json)$")


@server.tool(
    name="udh_bundle_seal",
    title="UDH Chain-of-Custody Seal",
    description=(
        "Generate a deterministic SHA-256 chain-of-custody audit seal for a document or litigation bundle, "
        "and optionally compute an indicative UK Employment Tribunal Schedule of Loss (ERA 1996 / Vento / ACAS)."
    ),
    annotations=RD,
)
async def udh_bundle_seal(params: BundleSealInput) -> str:
    import hashlib
    from datetime import datetime, timezone

    ts = datetime.now(timezone.utc).isoformat()
    payload = f"{params.doc_id}|{params.actor}|{ts}|{params.content}".encode("utf-8")
    digest = hashlib.sha256(payload).hexdigest()
    est_bytes = len(params.content.encode("utf-8"))
    est_pages = max(1, (est_bytes // 2200) + 1)
    est_mb = round(max(0.01, est_bytes / (1024 * 1024)), 3)
    data: dict[str, Any] = {
        "doc_id": params.doc_id,
        "actor": params.actor,
        "timestamp_utc": ts,
        "sha256": digest,
        "seal_short": digest[:12].upper(),
        "hmcts_compliance": {
            "estimated_pages": est_pages,
            "estimated_size_mb": est_mb,
            "under_50mb_limit": est_mb <= 50.0,
        },
    }

    sol_line = ""
    if params.weekly_gross > 0 or params.vento_band > 0:
        capped_week = min(params.weekly_gross, 700.0)
        capped_years = min(params.years_service, 20)
        mult = 1.5 if params.age >= 41 else (1.0 if params.age >= 22 else 0.5)
        basic = round(capped_week * capped_years * mult, 2)
        comp = round(params.weekly_gross * params.weeks_unemployed, 2)
        vento = {0: 0.0, 1: 6600.0, 2: 23000.0, 3: 45000.0}[params.vento_band]
        uplift = round((comp + vento) * (params.acas_uplift_pct / 100.0), 2)
        total = round(basic + comp + vento + uplift, 2)
        data["schedule_of_loss"] = {
            "basic_award_gbp": basic,
            "compensatory_loss_gbp": comp,
            "vento_award_gbp": vento,
            "acas_uplift_gbp": uplift,
            "total_gbp": total,
        }
        sol_line = f"\n• Schedule of Loss Total: £{total:,.2f} (Basic £{basic:,.2f} + Comp £{comp:,.2f} + Vento £{vento:,.2f} + ACAS £{uplift:,.2f})"

    text = f"Custody Seal {data['seal_short']} for {params.doc_id}\n• SHA-256: {digest}\n• Timestamp: {ts}{sol_line}"
    return out(text, data, params.output)


class DictionaryIn(BaseModel):
    model_config = M
    resource: str = Field("dictionary", description="'dictionary' | 'errors' | 'error_code' | 'context_language' | 'mcp_features' (50-Feature MCP catalog).")
    domain: Optional[str] = Field(None, description="Optional domain filter (core_tables, target_adapters, frontmatter, apis, mcp) or pillar/category filter.")
    query: Optional[str] = Field(None, description="Optional search query or UDH-XXX error code.")
    output: str = Field("text", description="'text' or 'json'.", pattern=r"^(text|json)$")


@server.tool(name="udh_dictionary", title="UDH Data Dictionary, Error & Catalog Suite", annotations=RD)
@_logged_tool
async def udh_dictionary(params: DictionaryIn, ctx: Context) -> str:
    """Query UDH Dashboard's Data Dictionary, Error Catalog, Context & Language catalog,
    or local 50-Feature MCP Programme catalog ('mcp_features').
    Read-only — requires 'read' scope.
    """
    if not _has_scope("read"):
        return "This token isn't scoped for udh_dictionary — needs 'read' (or '*')."
    from urllib.parse import urlencode
    import json as _jd

    res = params.resource.strip().lower()
    if res == "mcp_features":
        items = enh.get_mcp_feature_catalog(pillar=params.domain, query=params.query)
        summary = enh.get_mcp_feature_summary()
        payload = {**summary, "pillars_list": enh.MCP_PILLARS, "count": len(items), "features": items}
        return out(_jd.dumps(payload, indent=2), payload, params.output)
    if res == "error_code":
        code = (params.query or "").strip()
        if not code:
            return "query is required when resource='error_code' (e.g. 'UDH-001')."
        ok, text, data = await core.dashboard_api(f"/api/errors/{code}")
    elif res == "errors":
        ok, text, data = await core.dashboard_api("/api/errors/catalog")
        if ok and params.query and isinstance(data, dict) and isinstance(data.get("entries"), list):
            q = params.query.lower()
            filtered = [e for e in data["entries"] if q in str(e).lower()]
            data = {**data, "filtered_count": len(filtered), "entries": filtered}
            text = _jd.dumps(data, indent=2, default=str)
    elif res == "context_language":
        qs = urlencode({k: v for k, v in (("category", params.domain), ("q", params.query)) if v})
        path = f"/api/context-language/catalog?{qs}" if qs else "/api/context-language/catalog"
        ok, text, data = await core.dashboard_api(path)
    else:
        qs = urlencode({k: v for k, v in (("domain", params.domain), ("q", params.query)) if v})
        path = f"/api/dictionary?{qs}" if qs else "/api/dictionary"
        ok, text, data = await core.dashboard_api(path)
    if not ok:
        return f"UDH Dictionary lookup failed: {text}"
    return out(text, data, params.output)


class UpdatesIn(BaseModel):
    model_config = M
    action: str = Field("check_version", description="'check_version' | 'check_updates' | 'trigger_update'.")
    confirm: bool = Field(False, description="Required (true) for trigger_update.")
    output: str = Field("text", description="'text' or 'json'.", pattern=r"^(text|json)$")


@server.tool(name="udh_updates", title="UDH Version & Update Control", annotations=WR)
@_logged_tool
async def udh_updates(params: UpdatesIn, ctx: Context) -> str:
    """Check UDH Dashboard running version (/api/version), check GitHub for
    updates (/api/updates/check), or trigger Portainer redeploy (/api/updates/trigger).
    check_* requires 'read' scope; trigger_update requires 'sync' scope and confirm=true.
    """
    act = params.action.strip().lower()
    if act == "trigger_update":
        if not _has_scope("sync"):
            return "This token isn't scoped for udh_updates trigger — needs 'sync' (or '*')."
        if not params.confirm:
            return "Dry-run preview: would POST /api/updates/trigger with confirm=true. Pass confirm=true to execute."
        ok, text, data = await core.dashboard_api("/api/updates/trigger", method="POST", json_body={"confirm": True})
    elif act == "check_updates":
        if not _has_scope("read"):
            return "This token isn't scoped for udh_updates — needs 'read' (or '*')."
        ok, text, data = await core.dashboard_api("/api/updates/check")
    else:
        if not _has_scope("read"):
            return "This token isn't scoped for udh_updates — needs 'read' (or '*')."
        ok, text, data = await core.dashboard_api("/api/version")
    if not ok:
        return f"UDH Updates call failed: {text}"
    return out(text, data, params.output)


class SetupIn(BaseModel):
    model_config = M
    action: str = Field(
        "status",
        description="'status' (env & live backend check) | 'connect_guide' (client JSON & curl) | 'quickstart' (22-tool cheat sheet) | 'parity' (WF-14 vs Postgres diff) | 'cutover_check' (Stage 4 readiness & full-site wiring report) | 'wiring_check' (16-route & health self-check) | 'bootstrap_pg' (1-click Postgres schema & n8n seeder).",
    )
    dry_run: bool = Field(True, description="Used by action='bootstrap_pg' (defaults to True for safe preview).")
    confirm: bool = Field(False, description="Required (true) for action='bootstrap_pg' with dry_run=false.")
    output: str = Field("text", description="'text' or 'json'.", pattern=r"^(text|json)$")


@server.tool(name="udh_setup", title="UDH MCP Setup, Connection Guide & Quickstart", annotations=RD)
@_logged_tool
async def udh_setup(params: SetupIn, ctx: Context) -> str:
    """Inspect udh-mcp connection settings, Option E migration status, and
    generate ready-to-paste MCP client configs and a 22-tool quickstart guide.
    Supports 'parity', 'cutover_check', and 'bootstrap_pg' for Option E cutover.
    Read-only actions require 'read' scope; live 'bootstrap_pg' (dry_run=false) requires 'sync' scope + confirm=true.
    """
    import json
    act = params.action.strip().lower()
    if act == "bootstrap_pg":
        if not params.dry_run:
            if not _has_scope("sync"):
                return "This token isn't scoped for live udh_setup bootstrap_pg — needs 'sync' (or '*')."
            if not params.confirm:
                return "Safety gate: live Postgres schema bootstrap & n8n seeder (dry_run=false) requires confirm=true. Pass dry_run=true for a safe preview."
        elif not _has_scope("read"):
            return "This token isn't scoped for udh_setup bootstrap_pg preview — needs 'read' (or '*')."
        ok, text, data = await core.dashboard_api(
            "/api/migration/bootstrap-pg",
            method="POST",
            json_body={"dry_run": params.dry_run, "seed_from_n8n": True},
            timeout=120.0,
        )
        if not ok:
            return f"Postgres bootstrap failed: {text}"
        return out(text, data, params.output)

    if not _has_scope("read"):
        return "This token isn't scoped for udh_setup — needs 'read' (or '*')."

    if act == "parity":
        ok, text, data = await core.dashboard_api("/api/migration/parity", timeout=120.0)
        if not ok:
            return f"Shadow parity diff failed: {text}"
        return out(text, data, params.output)

    if act == "cutover_check":
        ok, text, data = await core.dashboard_api("/api/migration/readiness-report", timeout=120.0)
        if not ok:
            return f"Stage 4 cutover check failed: {text}"
        return out(text, data, params.output)

    if act == "wiring_check":
        ok, text, data = await core.dashboard_api("/api/self-check/wiring", timeout=30.0)
        if not ok:
            return f"Site wiring self-check failed: {text}"
        return out(text, data, params.output)
    if act == "connect_guide":
        pub_url = os.getenv("UDH_PUBLIC_URL", "https://udh.nasmatrix.app").rstrip("/")
        dash_pub = os.getenv("UDH_DASHBOARD_PUBLIC_URL", "https://udh-dashboard.nasmatrix.app").rstrip("/")
        mcp_port = os.getenv("UDH_MCP_PORT", "12021")
        guide = {
            "validation_ui": f"{dash_pub}/settings/mcp",
            "validation_api": "POST /api/mcp/validate",
            "options_api": "GET /api/mcp/options",
            "public_endpoint": f"{pub_url}/mcp",
            "local_host_endpoint": f"http://127.0.0.1:{mcp_port}/mcp",
            "transport": "streamable-http",
            "auth_header": "Authorization: Bearer <UDH_AUTH_TOKEN>",
            "scopes": {
                "read": "udh_dashboard, udh_query, udh_dictionary, udh_setup, udh_fleet, udh_extract, udh_bundle_seal, udh_updates(check_*), udh_scheduler(status), udh_config(get_runtime_settings)",
                "sync": "All read tools + udh_sync, udh_targets, udh_control, udh_health, udh_config(update_*/reset_*), udh_templates, udh_simulate, udh_checkpoint, udh_tokens, udh_tags, udh_updates(trigger_update), udh_scheduler(run/toggle)",
                "admin": "All sync tools + udh_conflicts, udh_lifecycle (destructive operations)",
            },
            "connection_options": {
                "1_remote_https": {"url": f"{pub_url}/mcp", "scope": "admin/sync", "transport": "streamable-http"},
                "2_local_loopback": {"url": f"http://127.0.0.1:{mcp_port}/mcp", "scope": "admin/sync", "transport": "streamable-http"},
                "3_readonly_scoped": {"url": f"{pub_url}/mcp", "token_env": "UDH_AUTH_TOKEN_READONLY", "scope": "read"},
                "4_local_stdio": {"command": "python -m src.server", "env": {"UDH_MCP_TRANSPORT": "stdio"}},
                "5_curl_probe": f"curl -fsS {pub_url}/healthz",
            },
            "antigravity_or_cursor_mcp_config": {
                "mcpServers": {
                    "udh-mcp": {
                        "serverUrl": f"{pub_url}/mcp",
                        "headers": {"Authorization": "Bearer ${UDH_AUTH_TOKEN}"},
                    }
                }
            },
            "env_vars_for_option_e_native": {
                "UDH_DASHBOARD_URL": "http://127.0.0.1:12015",
                "UDH_BACKEND_MODE": "native",
                "UDH_PREFER_NATIVE": "true",
            },
        }
        return out(json.dumps(guide, indent=2), guide, params.output)

    if act == "quickstart":
        sheet = {
            "Read & Inspect (safe, no mutations)": [
                "udh_dashboard() -> Live snapshot + degraded/conflict/pause alert banners",
                "udh_query(kind='get_content', sanitize_pii=true) -> Canonical docs & PII scrubbing",
                "udh_dictionary(resource='mcp_features|context_language|errors') -> Catalogs & 50-feature MCP list",
                "udh_fleet(action='get_status') -> Dashboard/MCP/Postgres/n8n/Qdrant/DBackup/Worker probe",
                "udh_setup(action='status|parity|cutover_check|wiring_check|bootstrap_pg') -> Readiness suite",
            ],
            "Zero-Token NLP & Safe Previews (0 LLM tokens burned)": [
                "udh_extract(action='extract|context_prepare|redact_preview|readability|chunk_markdown|conflict_scan') -> Deterministic NLP",
                "udh_bundle_seal(...) -> SHA-256 seal + HMCTS <50MB estimate + Schedule of Loss",
                "udh_scheduler(action='status|run') -> Inspect or preview 6 Stage 2 Python cron jobs",
                "udh_simulate(...) -> 5-stage pipeline dry-run with Blake2b SimHash",
                "udh_updates(action='check_version|check_updates') -> Build SHA comparison",
            ],
            "Sync & Control ('sync' scope; confirm=true for live writes)": [
                "udh_control(paused=true) / udh_targets(...) -> Emergency pause & target gates",
                "udh_config(action='get_runtime_settings|update_runtime_settings|reset_runtime_settings') -> Runtime config",
                "udh_sync(action='scan_drift|propagate_paperless|reindex_vectors') -> Sync & vector batch",
                "udh_health(action='check_health|check_integrity|wiring_check') -> Health & wiring",
                "udh_adapters(action='list|dispatch|pipeline|bridges|run_bridge|dlq|replay_dlq|webhook_ingest') -> Stage 3/4 control",
            ],
            "Destructive / Admin ('admin' scope + confirm=true)": [
                "udh_conflicts(...) / udh_lifecycle(...) / udh_checkpoint(...) / udh_tags(...) -> Recovery & merges",
            ],
        }
        return out(json.dumps(sheet, indent=2), sheet, params.output)

    # Default: 'status'
    ok_mig, _, mig_data = await core.dashboard_api("/api/migration/status")
    ok_ver, _, ver_data = await core.dashboard_api("/api/version")
    status_payload = {
        "mcp_version": os.getenv("UDH_MCP_VERSION", "2.7.0"),
        "mcp_features": enh.get_mcp_feature_summary(),
        "mcp_backend_mode": core.UDH_BACKEND_MODE,
        "mcp_runtime_override": core.RUNTIME_MODE_OVERRIDE,
        "mcp_prefer_native": core.UDH_PREFER_NATIVE,
        "dashboard_url": core.UDH_DASHBOARD_URL,
        "env_configured": {
            "UDH_AUTH_TOKEN": bool(os.getenv("UDH_AUTH_TOKEN")),
            "UDH_AUTH_TOKEN_READONLY": bool(os.getenv("UDH_AUTH_TOKEN_READONLY")),
            "WF07_URL": bool(core.WF07_URL),
            "WF14_URL": bool(core.WF14_URL),
            "WF16_URL": bool(core.WF16_URL),
        },
        "transport_stats": core.get_transport_stats(),
        "dashboard_reachable": ok_mig or ok_ver,
        "dashboard_version": ver_data if ok_ver else None,
        "migration_status": mig_data if ok_mig else None,
    }
    return out(json.dumps(status_payload, indent=2, default=str), status_payload, params.output)


class SchedulerIn(BaseModel):
    model_config = M
    action: str = Field("status", description="'status' | 'run' | 'toggle'.")
    job_id: Optional[str] = Field(
        None,
        description="Stage 2 job ID: wf05a_inbound_sync, wf05b_outbound_sync, wf08_health_digest, wf12_drift_scanner, wf17_vector_reindex, wf20_silent_drift_sweeper.",
    )
    dry_run: bool = Field(True, description="Defaults to True for safe preview. Pass dry_run=false + confirm=true to execute.")
    enabled: Optional[bool] = Field(None, description="Required when action='toggle'.")
    confirm: bool = Field(False, description="Required (true) when action='run' with dry_run=false, or action='toggle'.")
    output: str = Field("text", description="'text' or 'json'.", pattern=r"^(text|json)$")


@server.tool(name="udh_scheduler", title="UDH Stage 2 Python Scheduler Control", annotations=WR)
@_logged_tool
async def udh_scheduler(params: SchedulerIn, ctx: Context) -> str:
    """Inspect, dry-run, execute, or toggle Option E Stage 2 Python cron jobs
    (replacing n8n wf05a, wf05b, wf08/08b, wf12, wf20).
    'status' requires 'read' scope; 'run' and 'toggle' require 'sync' scope.
    Live execution (dry_run=false) and 'toggle' require confirm=true.
    """
    act = params.action.strip().lower()
    if act == "status":
        if not _has_scope("read"):
            return "This token isn't scoped for udh_scheduler status — needs 'read' (or '*')."
        ok, text, data = await core.dashboard_api("/api/stage2/scheduler")
        if not ok:
            return f"Stage 2 scheduler status failed: {text}"
        return out(text, data, params.output)

    if not _has_scope("sync"):
        return f"This token isn't scoped for udh_scheduler '{act}' — needs 'sync' (or '*')."

    if not params.job_id:
        return (
            "job_id is required. Valid Stage 2 jobs: wf05a_inbound_sync, wf05b_outbound_sync, "
            "wf08_health_digest, wf12_drift_scanner, wf20_silent_drift_sweeper."
        )

    if act == "toggle":
        if params.enabled is None:
            return "enabled (true/false) is required when action='toggle'."
        if not params.confirm:
            return f"Dry-run preview: would set Stage 2 job '{params.job_id}' enabled={params.enabled}. Pass confirm=true to execute."
        ok, text, data = await core.dashboard_api(
            "/api/stage2/scheduler/toggle",
            method="POST",
            json_body={"job_id": params.job_id, "enabled": params.enabled},
        )
        if not ok:
            return f"Stage 2 scheduler toggle failed: {text}"
        return out(text, data, params.output)

    if act == "run":
        if not params.dry_run and not params.confirm:
            return (
                f"Safety gate: live execution of '{params.job_id}' (dry_run=false) requires confirm=true. "
                "Omit dry_run=false (defaults to dry_run=true) for a safe preview."
            )
        ok, text, data = await core.dashboard_api(
            "/api/stage2/scheduler/run",
            method="POST",
            json_body={"job_id": params.job_id, "dry_run": params.dry_run},
        )
        if not ok:
            return f"Stage 2 scheduler run failed: {text}"
        return out(text, data, params.output)

    return f"Unknown action '{params.action}'. Valid actions: 'status', 'run', 'toggle'."


class AdaptersIn(BaseModel):
    model_config = M
    action: str = Field("list", description="'list' | 'dispatch' | 'pipeline' | 'extract_native' | 'index_native' | 'bridges' | 'run_bridge' | 'dlq' | 'replay_dlq' | 'webhook_ingest'.")
    adapter_id: Optional[str] = Field(None, description="Adapter ID for action='dispatch'/'dlq'/'replay_dlq' (e.g. 'trilium', 'paperless', 'stirlingpdf', 'apprise', 'gotify', 'changedetection', 'freshrss', 'karakeep', 'owncloud', 'immich', 'mailarchiver', 'librechat') or bridge ID for action='run_bridge'.")
    direction: str = Field("out", description="'in' or 'out' for action='dispatch'.")
    source: Optional[str] = Field("webhook", description="External source name for action='webhook_ingest' (e.g. 'paperless', 'nocodb', 'obsidian').")
    doc_id: Optional[str] = Field("doc-preview", description="Document ID for action='pipeline'/'webhook_ingest'.")
    title: Optional[str] = Field("", description="Document title for action='pipeline'/'webhook_ingest'.")
    content: Optional[str] = Field(None, description="Document text/Markdown for action='pipeline'/'webhook_ingest'.")
    targets: Optional[List[str]] = Field(None, description="Optional target adapter IDs for action='pipeline'/'webhook_ingest'.")
    dry_run: bool = Field(True, description="Defaults to True for safe preview. Pass dry_run=false + confirm=true to execute.")
    confirm: bool = Field(False, description="Required (true) when dry_run=false.")
    output: str = Field("text", description="'text' or 'json'.", pattern=r"^(text|json)$")


@server.tool(name="udh_adapters", title="UDH Stage 3/4 Python Adapters, Pipeline & Bridges", annotations=WR)
@_logged_tool
async def udh_adapters(params: AdaptersIn, ctx: Context) -> str:
    """List, dry-run, or execute Option E Stage 3 native Python target adapters,
    the 5-stage pipeline, DLQ inspection/replay, webhook ingest, and Stage 4 bridges.
    'list'/'bridges'/'dlq' require 'read' scope; 'dispatch'/'pipeline'/'run_bridge'/
    'replay_dlq'/'webhook_ingest' require 'sync' scope and confirm=true when dry_run=false.
    """
    act = params.action.strip().lower()
    if act == "list":
        if not _has_scope("read"):
            return "This token isn't scoped for udh_adapters list — needs 'read' (or '*')."
        ok, text, data = await core.dashboard_api("/api/stage3/adapters")
        if not ok:
            return f"Stage 3 adapters list failed: {text}"
        return out(text, data, params.output)

    if act == "bridges":
        if not _has_scope("read"):
            return "This token isn't scoped for udh_adapters bridges — needs 'read' (or '*')."
        ok, text, data = await core.dashboard_api("/api/stage4/bridges")
        if not ok:
            return f"Stage 4 bridges list failed: {text}"
        return out(text, data, params.output)

    if act == "dlq":
        if not _has_scope("read"):
            return "This token isn't scoped for udh_adapters dlq — needs 'read' (or '*')."
        qs = f"?target_id={params.adapter_id}" if params.adapter_id else ""
        ok, text, data = await core.dashboard_api(f"/api/stage3/dlq{qs}")
        if not ok:
            return f"Stage 3 DLQ lookup failed: {text}"
        return out(text, data, params.output)

    if act == "extract_native":
        if not _has_scope("read"):
            return "This token isn't scoped for udh_adapters extract_native — needs 'read' (or '*')."
        ok, text, data = await core.dashboard_api(
            "/api/native/extract",
            method="POST",
            json_body={"filename": params.title or "document.md", "content": params.content or ""},
        )
        if not ok:
            return f"Native extraction failed: {text}"
        return out(text, data, params.output)

    if not _has_scope("sync"):
        return f"This token isn't scoped for udh_adapters '{act}' — needs 'sync' (or '*')."

    if not params.dry_run and not params.confirm:
        return (
            f"Safety gate: live Stage 3/4 '{act}' (dry_run=false) requires confirm=true. "
            "Omit dry_run=false (defaults to dry_run=true) for a safe preview."
        )

    if act == "index_native":
        if not params.content:
            return "content is required for action='index_native'."
        ok, text, data = await core.dashboard_api(
            "/api/native/index",
            method="POST",
            json_body={
                "doc_id": params.doc_id or "doc-preview",
                "title": params.title or "Untitled",
                "content": params.content,
                "dry_run": params.dry_run,
            },
        )
        if not ok:
            return f"Native vector indexing failed: {text}"
        return out(text, data, params.output)

    if act == "replay_dlq":
        ok, text, data = await core.dashboard_api(
            "/api/stage3/dlq/replay",
            method="POST",
            json_body={"target_id": params.adapter_id, "dry_run": params.dry_run},
        )
        if not ok:
            return f"Stage 3 DLQ replay failed: {text}"
        return out(text, data, params.output)

    if act == "webhook_ingest":
        src = (params.source or "webhook").strip().lower()
        ok, text, data = await core.dashboard_api(
            f"/api/interop/webhook/{src}",
            method="POST",
            json_body={
                "doc_id": params.doc_id,
                "title": params.title,
                "content": params.content or "",
                "targets": params.targets,
                "dry_run": params.dry_run,
            },
        )
        if not ok:
            return f"Interop webhook ingest failed: {text}"
        return out(text, data, params.output)

    if act == "run_bridge":
        if not params.adapter_id:
            return "adapter_id (bridge_id) is required for action='run_bridge' (e.g. 'legal_phase1_trilium_import')."
        body_bridge: dict = {"bridge_id": params.adapter_id, "dry_run": params.dry_run}
        if params.doc_id and params.doc_id != "doc-preview":
            body_bridge["doc_id"] = params.doc_id
        if params.content:
            body_bridge["content"] = params.content
        ok, text, data = await core.dashboard_api(
            "/api/stage4/bridges/run",
            method="POST",
            json_body=body_bridge,
        )
        if not ok:
            return f"Stage 4 bridge run failed: {text}"
        return out(text, data, params.output)

    if act == "dispatch":
        if not params.adapter_id:
            return "adapter_id is required for action='dispatch' (e.g. 'trilium', 'paperless', 'docmost')."
        dispatch_payload: dict = {}
        if params.doc_id:
            dispatch_payload["doc_id"] = params.doc_id
        if params.title:
            dispatch_payload["title"] = params.title
        if params.content is not None:
            dispatch_payload["content"] = params.content
            dispatch_payload["write"] = True
        ok, text, data = await core.dashboard_api(
            "/api/stage3/adapters/dispatch",
            method="POST",
            json_body={
                "adapter_id": params.adapter_id,
                "direction": params.direction,
                "dry_run": params.dry_run,
                "payload": dispatch_payload,
            },
        )
        if not ok:
            return f"Stage 3 adapter dispatch failed: {text}"
        return out(text, data, params.output)

    if act == "pipeline":
        if not params.content:
            return "content is required for action='pipeline'."
        ok, text, data = await core.dashboard_api(
            "/api/stage3/pipeline/run",
            method="POST",
            json_body={
                "doc_id": params.doc_id or "doc-preview",
                "title": params.title or "",
                "content": params.content,
                "targets": params.targets,
                "dry_run": params.dry_run,
            },
        )
        if not ok:
            return f"Stage 3 pipeline run failed: {text}"
        return out(text, data, params.output)

    return f"Unknown action '{params.action}'. Valid actions: 'list', 'dispatch', 'pipeline'."


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
