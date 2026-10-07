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
      -- udh_query (read-only). WF-16 is a NEW workflow this project adds
      alongside WF-07/14 -- see n8n-workflows/wf16_udh_query_api.json in
      matrix-homelab. Not yet imported/verified against a live n8n instance
      as of this writing (same discipline as every other UDH workflow file
      built without live access) -- udh_query reports a clear connection
      error rather than a confusing one until it is.
"""
from __future__ import annotations

import json
import os
from typing import Optional

import httpx

WF07_URL = os.environ.get("WF07_URL", "").strip().rstrip("/")
WF07_AUTH_TOKEN = os.environ.get("WF07_AUTH_TOKEN", "").strip()
WF07_AUTH_HEADER_NAME = os.environ.get("WF07_AUTH_HEADER_NAME", "X-UDH-Dispatch-Token").strip()

WF14_URL = os.environ.get("WF14_URL", "").strip().rstrip("/")
WF14_AUTH_TOKEN = os.environ.get("WF14_AUTH_TOKEN", "").strip()
WF14_AUTH_HEADER_NAME = os.environ.get("WF14_AUTH_HEADER_NAME", "X-UDH-Dashboard-Token").strip()

WF16_URL = os.environ.get("WF16_URL", "").strip().rstrip("/")
WF16_AUTH_TOKEN = os.environ.get("WF16_AUTH_TOKEN", "").strip()
WF16_AUTH_HEADER_NAME = os.environ.get("WF16_AUTH_HEADER_NAME", "X-UDH-Query-Token").strip()

# WF-07's own Global Pause Gate node (matrix-homelab's n8n-workflows/
# wf07_adhoc_dispatch.json VALID_ACTIONS list) -- keep in sync if that
# list ever changes there.
DISPATCH_ACTIONS = [
    "publish", "ingest", "reenrich", "resolve_conflict", "rollback",
    "scan_drift", "confirm_delete", "scrape_url", "release_quarantine",
    "set_global_pause", "set_target_enabled",
]
# Actions that restore, overwrite, or destroy existing state rather than
# move data forward.
DESTRUCTIVE_ACTIONS = {"rollback", "confirm_delete", "resolve_conflict",
                        "release_quarantine"}
# Ungated at the WF-07 layer itself (UNGATED_ACTIONS) -- must keep working
# even while hub_config.global_pause is true, so a paused system can still
# be un-paused and a misbehaving target can still be disabled.
UNGATED_ACTIONS = {"set_global_pause", "set_target_enabled"}


async def dispatch(action: str, payload: Optional[dict] = None,
                    timeout: float = 60.0) -> tuple:
    """POST one action to WF-07's adhoc-dispatch webhook. Returns (ok, text, data).

    Mirrors matrix-homelab's apps/udh-dashboard/wf07_client.py exactly --
    same env var names, same {"halted": true} handling for an unknown
    action or a global-pause block.
    """
    if not WF07_URL or not WF07_AUTH_TOKEN:
        return False, "WF07_URL / WF07_AUTH_TOKEN not configured.", None
    body = {"action": action, **(payload or {})}
    try:
        async with httpx.AsyncClient(timeout=timeout) as h:
            r = await h.post(WF07_URL,
                              headers={WF07_AUTH_HEADER_NAME: WF07_AUTH_TOKEN,
                                       "Content-Type": "application/json",
                                       "Accept": "application/json"},
                              json=body)
            if r.status_code != 200:
                return False, f"HTTP {r.status_code}: {r.text[:300]}", None
            try:
                data = r.json() if r.content else {}
            except Exception:
                return False, f"WF-07 response was not valid JSON: {r.text[:300]}", None
    except Exception as e:
        return False, f"{type(e).__name__}: {e}", None

    if isinstance(data, dict) and data.get("halted"):
        return False, data.get("message") or f"WF-07 halted action '{action}'", data
    return True, f"Dispatched '{action}': {json.dumps(data, default=str)[:500]}", data


async def dashboard_data(timeout: float = 30.0) -> tuple:
    """GET WF-14's dashboard-data webhook. Returns (ok, text, data). Read-only."""
    if not WF14_URL or not WF14_AUTH_TOKEN:
        return False, "WF14_URL / WF14_AUTH_TOKEN not configured.", None
    try:
        async with httpx.AsyncClient(timeout=timeout) as h:
            r = await h.get(WF14_URL, headers={WF14_AUTH_HEADER_NAME: WF14_AUTH_TOKEN,
                                                "Accept": "application/json"})
            if r.status_code != 200:
                return False, f"HTTP {r.status_code}: {r.text[:300]}", None
            data = r.json() if r.content else {}
    except Exception as e:
        return False, f"{type(e).__name__}: {e}", None
    return True, json.dumps(data, indent=2, default=str), data


QUERY_KINDS = ["get_document", "search_documents", "list_conflicts",
               "list_quarantined", "recent_operations"]


async def query(kind: str, params: Optional[dict] = None,
                 timeout: float = 30.0) -> tuple:
    """POST a query to WF-16's query-api webhook. Returns (ok, text, data).
    Read-only -- WF-16 (n8n-workflows/wf16_udh_query_api.json in
    matrix-homelab) only ever runs Postgres SELECTs, never writes.
    """
    if kind not in QUERY_KINDS:
        return False, f"Unknown query kind '{kind}'. Kinds: {', '.join(QUERY_KINDS)}", None
    if not WF16_URL or not WF16_AUTH_TOKEN:
        return False, "WF16_URL / WF16_AUTH_TOKEN not configured.", None
    body = {"kind": kind, **(params or {})}
    try:
        async with httpx.AsyncClient(timeout=timeout) as h:
            r = await h.post(WF16_URL,
                              headers={WF16_AUTH_HEADER_NAME: WF16_AUTH_TOKEN,
                                       "Content-Type": "application/json",
                                       "Accept": "application/json"},
                              json=body)
            if r.status_code != 200:
                return False, f"HTTP {r.status_code}: {r.text[:300]}", None
            data = r.json() if r.content else {}
    except Exception as e:
        return False, f"{type(e).__name__}: {e}", None
    if isinstance(data, dict) and data.get("error"):
        return False, str(data["error"]), data
    return True, json.dumps(data, indent=2, default=str), data
