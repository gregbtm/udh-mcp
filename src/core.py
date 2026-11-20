"""udh-mcp core: HTTP clients talking directly to matrix-homelab's n8n
Universal Document Hub webhooks (WF-07 adhoc-dispatch, WF-14 dashboard-data,
WF-16 query-api). No dependency on synology-proxy-mcp or mcphub -- this
server owns its own credentials and talks to n8n over plain HTTPS webhooks,
same transport every other UDH caller (the dashboard app, this server) uses.

Env vars (all required for the matching tool group to work; each group
fails with a clear message rather than a confusing one if unset):
  WF07_URL, WF07_AUTH_TOKEN, WF07_AUTH_HEADER_NAME (default X-UDH-Dispatch-Token)
      -- every write action (udh_sync, udh_targets, udh_conflicts,
      udh_lifecycle, udh_control).
  WF14_URL, WF14_AUTH_TOKEN, WF14_AUTH_HEADER_NAME (default X-UDH-Dashboard-Token)
      -- udh_dashboard (read-only).
  WF16_URL, WF16_AUTH_TOKEN, WF16_AUTH_HEADER_NAME (default X-UDH-Query-Token)
      -- udh_query (read-only). WF-16 is a workflow this project added
      alongside WF-07/14 -- see n8n-workflows/wf16_udh_query_api.json in
      matrix-homelab. Imported and verified live 2026-10-08 (workflow id
      4jc20pd5U0p8ust2) -- see CLAUDE.md. get_content and search_fulltext
      were added to it 2026-10-13 and are structurally verified only
      (every new node's JS executed directly, not just syntax-checked;
      not yet exercised against this specific live workflow import).
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from typing import Optional

import httpx

import mcp_enhancements as enh

WF07_URL = os.environ.get("WF07_URL", "").strip().rstrip("/")
WF07_AUTH_TOKEN = os.environ.get("WF07_AUTH_TOKEN", "").strip()
WF07_AUTH_HEADER_NAME = os.environ.get("WF07_AUTH_HEADER_NAME", "X-UDH-Dispatch-Token").strip()

WF14_URL = os.environ.get("WF14_URL", "").strip().rstrip("/")
WF14_AUTH_TOKEN = os.environ.get("WF14_AUTH_TOKEN", "").strip()
WF14_AUTH_HEADER_NAME = os.environ.get("WF14_AUTH_HEADER_NAME", "X-UDH-Dashboard-Token").strip()

WF16_URL = os.environ.get("WF16_URL", "").strip().rstrip("/")
WF16_AUTH_TOKEN = os.environ.get("WF16_AUTH_TOKEN", "").strip()
WF16_AUTH_HEADER_NAME = os.environ.get("WF16_AUTH_HEADER_NAME", "X-UDH-Query-Token").strip()

UDH_DASHBOARD_URL = os.environ.get("UDH_DASHBOARD_URL", "https://udh-dashboard.nasmatrix.app").strip().rstrip("/")
UDH_PREFER_NATIVE = os.environ.get("UDH_PREFER_NATIVE", "false").strip().lower() in ("1", "true", "yes")
UDH_BACKEND_MODE = os.environ.get("UDH_BACKEND_MODE", "strangler").strip().lower()
RUNTIME_MODE_OVERRIDE: Optional[str] = None


def set_runtime_mode(mode: Optional[str]) -> None:
    """Sync live backend routing mode override inside udh-mcp without restart."""
    global RUNTIME_MODE_OVERRIDE
    RUNTIME_MODE_OVERRIDE = mode.strip().lower() if isinstance(mode, str) and mode.strip() else None


def _use_native_backend() -> bool:
    """True when udh-mcp should call udh-dashboard's native /api/native/* endpoints instead of n8n."""
    if RUNTIME_MODE_OVERRIDE is not None:
        if RUNTIME_MODE_OVERRIDE == "native":
            return True
        if RUNTIME_MODE_OVERRIDE == "n8n":
            return False
    return UDH_BACKEND_MODE == "native" or UDH_PREFER_NATIVE

_REAL_ASYNC_CLIENT = httpx.AsyncClient
_POOL_CLIENT: Optional[httpx.AsyncClient] = None
_TRANSPORT_STATS: dict[str, dict[str, float]] = {}
_READ_CACHE: dict[str, tuple[float, tuple]] = {}


def _record_transport(backend: str, duration_ms: float, ok: bool) -> None:
    s = _TRANSPORT_STATS.setdefault(backend, {"calls": 0, "errors": 0, "total_ms": 0.0, "last_ms": 0.0})
    s["calls"] += 1
    if not ok:
        s["errors"] += 1
    s["total_ms"] = round(s["total_ms"] + duration_ms, 2)
    s["last_ms"] = round(duration_ms, 2)


def get_transport_stats() -> dict[str, dict[str, float]]:
    return {k: dict(v) for k, v in _TRANSPORT_STATS.items()}


def invalidate_read_cache(prefix: str = "") -> int:
    if not prefix:
        n = len(_READ_CACHE)
        _READ_CACHE.clear()
        return n
    keys = [k for k in _READ_CACHE if k.startswith(prefix)]
    for k in keys:
        _READ_CACHE.pop(k, None)
    return len(keys)


def _get_pooled_client() -> httpx.AsyncClient:
    """Return a shared persistent AsyncClient with connection pooling."""
    global _POOL_CLIENT
    if _POOL_CLIENT is None or _POOL_CLIENT.is_closed:
        _POOL_CLIENT = _REAL_ASYNC_CLIENT(
            limits=httpx.Limits(max_keepalive_connections=20, max_connections=50),
        )
    return _POOL_CLIENT


async def _http_call(method: str, url: str, *, headers: Optional[dict] = None,
                     json_body: Optional[dict] = None, timeout: float = 30.0,
                     backend_label: str = "http") -> httpx.Response:
    """Execute an HTTP call using the shared connection pool with correlation ID, stats & bounded retry."""
    req_headers = {**(headers or {}), "X-Request-ID": uuid.uuid4().hex[:12]}
    t0 = time.monotonic()
    if httpx.AsyncClient is not _REAL_ASYNC_CLIENT:
        async with httpx.AsyncClient(timeout=timeout) as h:
            try:
                resp = await (h.get(url, headers=req_headers) if method.upper() == "GET" else getattr(h, method.lower())(url, headers=req_headers, json=json_body))
                _record_transport(backend_label, (time.monotonic() - t0) * 1000.0, resp.status_code < 400)
                return resp
            except Exception:
                _record_transport(backend_label, (time.monotonic() - t0) * 1000.0, False)
                raise
    import asyncio
    client = _get_pooled_client()
    is_idempotent = method.upper() in ("GET", "HEAD", "OPTIONS")
    max_attempts = 2 if is_idempotent else 1
    for attempt in range(max_attempts):
        try:
            resp = await client.request(method, url, headers=req_headers, json=json_body, timeout=timeout)
            if is_idempotent and resp.status_code in (429, 502, 503, 504) and attempt == 0:
                await asyncio.sleep(0.1)
                continue
            _record_transport(backend_label, (time.monotonic() - t0) * 1000.0, resp.status_code < 400)
            return resp
        except httpx.TransportError:
            # Never retry non-idempotent POST/mutating requests on TransportError/ReadTimeout
            if not is_idempotent or attempt + 1 >= max_attempts:
                _record_transport(backend_label, (time.monotonic() - t0) * 1000.0, False)
                raise
            await asyncio.sleep(0.1)


async def dashboard_api(path: str, method: str = "GET",
                        json_body: Optional[dict] = None, timeout: float = 15.0,
                        cache_ttl: float = 0.0) -> tuple:
    """Call UDH Dashboard REST API with optional TTL caching and sanitized error hints."""
    cache_key = f"dash:{method}:{path}"
    if cache_ttl > 0 and method.upper() == "GET" and httpx.AsyncClient is _REAL_ASYNC_CLIENT:
        cached = _READ_CACHE.get(cache_key)
        if cached and (time.monotonic() - cached[0]) < cache_ttl:
            return cached[1]
    url = f"{UDH_DASHBOARD_URL}{path}"
    headers = {"Accept": "application/json"}
    api_token = os.environ.get("UDH_API_TOKEN", "").strip()
    if api_token:
        headers["Authorization"] = f"Bearer {api_token}"
        headers["X-UDH-API-Token"] = api_token
    try:
        r = await _http_call(method, url, headers=headers,
                             json_body=json_body, timeout=timeout, backend_label="dashboard_api")
        if r.status_code != 200:
            err = enh.map_http_status_to_udh_error(r.status_code, r.text[:300])
            return False, f"HTTP {r.status_code} ({err['error_code']}): {err['remediation']} | {enh.sanitize_secrets(r.text[:200])}", None
        data = r.json() if r.content else {}
    except Exception as e:
        return False, f"{type(e).__name__}: {enh.sanitize_secrets(str(e))}", None
    res = (True, json.dumps(data, indent=2, default=str), data)
    if cache_ttl > 0 and method.upper() == "GET" and httpx.AsyncClient is _REAL_ASYNC_CLIENT:
        _READ_CACHE[cache_key] = (time.monotonic(), res)
    return res

# WF-07's own Global Pause Gate node (matrix-homelab's n8n-workflows/
# wf07_adhoc_dispatch.json VALID_ACTIONS list) -- keep in sync if that
# list ever changes there. Synced 2026-10-13 to add thirteen actions added
# to that list across 2026-10-12/13's matrix-homelab sessions: snapshot/
# sync_outbound/backfill_trilium (pre-existing WF-09/WF-05b/WF-15
# wrappers this server never exposed), update_hub_config/
# update_target_config/check_health/check_integrity/purge_ingested (the
# exact gap udh-mcp's own CLAUDE.md "Known gaps" section named), and
# list_templates/create_template/update_template/delete_template/
# set_default_template (new the same day, for the ingestion-templates
# feature).
DISPATCH_ACTIONS = [
    "publish", "ingest", "reenrich", "resolve_conflict", "rollback",
    "saga_rollback", "scan_drift", "confirm_delete", "scrape_url",
    "release_quarantine", "set_global_pause", "set_target_enabled",
    "snapshot", "sync_outbound", "backfill_trilium", "propagate_paperless",
    "reindex_vectors", "update_hub_config", "update_target_config",
    "check_health", "check_integrity", "purge_ingested", "list_templates",
    "create_template", "update_template", "delete_template",
    "set_default_template", "dry_run_pipeline", "create_checkpoint",
    "rollback_checkpoint", "cluster_tags", "get_token_burn",
    "get_target_copy", "adapter_dispatch",
]
LONG_ACTIONS = frozenset({
    "purge_ingested", "sync_outbound", "ingest", "reenrich", "publish",
    "backfill_trilium", "reindex_vectors", "rollback", "saga_rollback",
    "check_health", "check_integrity", "scan_drift", "scrape_url",
    "propagate_paperless",
})
# Actions that restore, overwrite, or destroy existing state rather than
# move data forward. purge_ingested added 2026-10-13 -- it permanently
# deletes real documents from a target (matrix-homelab's
# wf07_client.py's own purge_target_ingested() docstring: "THIS IS
# IRREVERSIBLE from UDH's side"), the same destructive tier as
# confirm_delete.
DESTRUCTIVE_ACTIONS = {"rollback", "confirm_delete", "resolve_conflict",
                        "release_quarantine", "purge_ingested", "rollback_checkpoint"}
# Ungated at the WF-07 layer itself (UNGATED_ACTIONS) -- must keep working
# even while hub_config.global_pause is true, so a paused system can still
# be un-paused and a misbehaving target can still be disabled.
UNGATED_ACTIONS = {"set_global_pause", "set_target_enabled"}
# Native-only Python capabilities that n8n WF-07 does not implement; always route directly
# to udh-dashboard's /api/native/dispatch even while global routing is in 'strangler' mode.
NATIVE_ONLY_DISPATCH_ACTIONS = frozenset({
    "create_checkpoint", "rollback_checkpoint", "cluster_tags",
    "get_token_burn", "dry_run_pipeline", "adapter_dispatch",
    "hydrate_pg_content",
})


async def _dispatch_native(action: str, payload: Optional[dict], timeout: float) -> tuple:
    ok, text, data = await dashboard_api(
        "/api/native/dispatch",
        method="POST",
        json_body={"action": action, **(payload or {})},
        timeout=timeout,
    )
    if not ok:
        return False, text, data
    invalidate_read_cache()
    if isinstance(data, dict) and data.get("halted"):
        return False, data.get("message") or f"Native gate halted action '{action}'", data
    if isinstance(data, dict):
        data.setdefault("routed_via", "native")
    return True, f"Dispatched '{action}' (native): {json.dumps(data, default=str)[:500]}", data


async def _dispatch_n8n(action: str, payload: Optional[dict], timeout: float) -> tuple:
    if not WF07_URL or not WF07_AUTH_TOKEN:
        return False, "WF07_URL / WF07_AUTH_TOKEN not configured.", None
    body = {"action": action, **(payload or {})}
    idem = hashlib.sha256(f"{action}:{json.dumps(body, sort_keys=True, default=str)}".encode("utf-8")).hexdigest()[:16]
    try:
        r = await _http_call(
            "POST",
            WF07_URL,
            headers={WF07_AUTH_HEADER_NAME: WF07_AUTH_TOKEN,
                     "X-UDH-Idempotency-Key": idem,
                     "Content-Type": "application/json",
                     "Accept": "application/json"},
            json_body=body,
            timeout=timeout,
            backend_label="n8n_wf07",
        )
        if r.status_code != 200:
            err = enh.map_http_status_to_udh_error(r.status_code, r.text[:300])
            return False, f"HTTP {r.status_code} ({err['error_code']}): {err['remediation']}", None
        try:
            data = r.json() if r.content else {}
        except Exception:
            return False, f"WF-07 response was not valid JSON: {enh.sanitize_secrets(r.text[:300])}", None
    except Exception as e:
        return False, f"{type(e).__name__}: {enh.sanitize_secrets(str(e))}", None

    invalidate_read_cache()
    if isinstance(data, dict) and data.get("halted"):
        return False, data.get("message") or f"WF-07 halted action '{action}'", data
    if isinstance(data, dict):
        data.setdefault("routed_via", "n8n")
    return True, f"Dispatched '{action}': {json.dumps(data, default=str)[:500]}", data


def _is_timeout_failure(text: str) -> bool:
    low = (text or "").lower()
    return ("timeout" in low or "504" in low or "deadline" in low)


async def dispatch(action: str, payload: Optional[dict] = None,
                    timeout: Optional[float] = None) -> tuple:
    """POST one action to native /api/native/dispatch or WF-07 webhook with safe failover.

    In 'strangler' harmony mode:
      - NATIVE_ONLY_DISPATCH_ACTIONS or execute_native=True route directly to Python/Postgres.
      - Standard workflows route via n8n WF-07 with /api/native/dispatch fallback.
    Once officially switched to 'native' (_use_native_backend() == True):
      - All dispatches run on Python/Postgres with n8n WF-07 retained strictly as redundancy failover.
    """
    if timeout is None:
        timeout = 180.0 if action in LONG_ACTIONS else 60.0

    force_native = action in NATIVE_ONLY_DISPATCH_ACTIONS or bool((payload or {}).get("execute_native"))
    if _use_native_backend() or force_native:
        ok, text, data = await _dispatch_native(action, payload, timeout)
        if ok or (isinstance(data, dict) and data.get("halted")) or _is_timeout_failure(text):
            return ok, text, data
        if action not in NATIVE_ONLY_DISPATCH_ACTIONS and WF07_URL and WF07_AUTH_TOKEN:
            fb_ok, fb_text, fb_data = await _dispatch_n8n(action, payload, timeout)
            if fb_ok and isinstance(fb_data, dict):
                fb_data["routed_via"] = "n8n_fallback"
                fb_text = f"Dispatched '{action}' (n8n_fallback): {json.dumps(fb_data, default=str)[:500]}"
            return fb_ok, fb_text, fb_data
        return ok, text, data

    ok, text, data = await _dispatch_n8n(action, payload, timeout)
    if ok or (isinstance(data, dict) and data.get("halted")) or _is_timeout_failure(text) or not (WF07_URL and WF07_AUTH_TOKEN):
        return ok, text, data
    if UDH_DASHBOARD_URL:
        fb_ok, fb_text, fb_data = await _dispatch_native(action, payload, timeout)
        if fb_ok and isinstance(fb_data, dict):
            fb_data["routed_via"] = "native_fallback"
            fb_text = f"Dispatched '{action}' (native_fallback): {json.dumps(fb_data, default=str)[:500]}"
        if fb_ok or (isinstance(fb_data, dict) and fb_data.get("halted")):
            return fb_ok, fb_text, fb_data
    return ok, text, data


async def _dashboard_n8n(timeout: float) -> tuple:
    if not WF14_URL or not WF14_AUTH_TOKEN:
        return False, "WF14_URL / WF14_AUTH_TOKEN not configured.", None
    try:
        r = await _http_call(
            "GET",
            WF14_URL,
            headers={WF14_AUTH_HEADER_NAME: WF14_AUTH_TOKEN, "Accept": "application/json"},
            timeout=timeout,
            backend_label="n8n_wf14",
        )
        if r.status_code != 200:
            return False, f"HTTP {r.status_code}: {r.text[:300]}", None
        data = r.json() if r.content else {}
    except Exception as e:
        return False, f"{type(e).__name__}: {e}", None
    if isinstance(data, dict):
        data.setdefault("routed_via", "n8n")
    return True, json.dumps(data, indent=2, default=str), data


async def dashboard_data(timeout: float = 30.0, execute_native: bool = False) -> tuple:
    """GET native /api/native/dashboard-data or WF-14 webhook with automatic failover."""
    if _use_native_backend() or execute_native:
        ok, text, data = await dashboard_api("/api/native/dashboard-data", method="GET", timeout=timeout)
        if ok:
            if isinstance(data, dict):
                data.setdefault("routed_via", "native")
            return ok, json.dumps(data, indent=2, default=str), data
        if WF14_URL and WF14_AUTH_TOKEN:
            fb_ok, fb_text, fb_data = await _dashboard_n8n(timeout)
            if fb_ok and isinstance(fb_data, dict):
                fb_data["routed_via"] = "n8n_fallback"
                fb_text = json.dumps(fb_data, indent=2, default=str)
            return fb_ok, fb_text, fb_data
        return ok, text, data

    ok, text, data = await _dashboard_n8n(timeout)
    if ok or not (WF14_URL and WF14_AUTH_TOKEN):
        return ok, text, data
    if UDH_DASHBOARD_URL:
        fb_ok, fb_text, fb_data = await dashboard_api("/api/native/dashboard-data", method="GET", timeout=timeout)
        if fb_ok and isinstance(fb_data, dict):
            fb_data["routed_via"] = "native_fallback"
            fb_text = json.dumps(fb_data, indent=2, default=str)
            return True, fb_text, fb_data
    return ok, text, data


QUERY_KINDS = ["get_document", "search_documents", "list_conflicts",
               "list_quarantined", "recent_operations", "search_fulltext",
               "get_content"]


async def _query_native(kind: str, params: Optional[dict], timeout: float) -> tuple:
    ok, text, data = await dashboard_api(
        "/api/native/query",
        method="POST",
        json_body={"kind": kind, **(params or {})},
        timeout=timeout,
    )
    if not ok:
        return False, text, data
    if isinstance(data, dict) and data.get("error"):
        return False, str(data["error"]), data
    if isinstance(data, dict):
        data.setdefault("routed_via", "native")
    return True, json.dumps(data, indent=2, default=str), data


async def _query_n8n(kind: str, params: Optional[dict], timeout: float) -> tuple:
    if not WF16_URL or not WF16_AUTH_TOKEN:
        return False, "WF16_URL / WF16_AUTH_TOKEN not configured.", None
    body = {"kind": kind, **(params or {})}
    try:
        r = await _http_call(
            "POST",
            WF16_URL,
            headers={WF16_AUTH_HEADER_NAME: WF16_AUTH_TOKEN,
                     "Content-Type": "application/json",
                     "Accept": "application/json"},
            json_body=body,
            timeout=timeout,
            backend_label="n8n_wf16",
        )
        if r.status_code != 200:
            return False, f"HTTP {r.status_code}: {r.text[:300]}", None
        data = r.json() if r.content else {}
    except Exception as e:
        return False, f"{type(e).__name__}: {e}", None
    if isinstance(data, dict) and data.get("error"):
        return False, str(data["error"]), data
    if isinstance(data, dict):
        data.setdefault("routed_via", "n8n")
    return True, json.dumps(data, indent=2, default=str), data


async def query(kind: str, params: Optional[dict] = None,
                 timeout: float = 30.0, execute_native: bool = False) -> tuple:
    """POST a query to native /api/native/query or WF-16 with automatic failover."""
    if kind not in QUERY_KINDS:
        return False, f"Unknown query kind '{kind}'. Kinds: {', '.join(QUERY_KINDS)}", None

    if _use_native_backend() or execute_native:
        ok, text, data = await _query_native(kind, params, timeout)
        if ok or (isinstance(data, dict) and data.get("error")):
            return ok, text, data
        if WF16_URL and WF16_AUTH_TOKEN:
            fb_ok, fb_text, fb_data = await _query_n8n(kind, params, timeout)
            if fb_ok and isinstance(fb_data, dict):
                fb_data["routed_via"] = "n8n_fallback"
                fb_text = json.dumps(fb_data, indent=2, default=str)
            return fb_ok, fb_text, fb_data
        return ok, text, data

    ok, text, data = await _query_n8n(kind, params, timeout)
    if ok or (isinstance(data, dict) and data.get("error")) or not (WF16_URL and WF16_AUTH_TOKEN):
        return ok, text, data
    if UDH_DASHBOARD_URL:
        fb_ok, fb_text, fb_data = await _query_native(kind, params, timeout)
        if fb_ok and isinstance(fb_data, dict):
            fb_data["routed_via"] = "native_fallback"
            fb_text = json.dumps(fb_data, indent=2, default=str)
            return True, fb_text, fb_data
    return ok, text, data
