"""
Tool-registration and behavior test for udh-mcp — mirrors synology-proxy-mcp's
test_tool_registration.py discipline: cheap, structural checks (the server
imports, all tools register) plus mocked-HTTP behavior checks for every
scope gate, confirm gate, and the WF-07 halted-response handling. No live
n8n call — that's a separate, deliberate live-session verification step
(see CLAUDE.md).

Run: python3 src/test_tool_registration.py
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("UDH_AUTH_TOKEN", "t")

import server  # noqa: E402
import core  # noqa: E402

EXPECTED_TOOLS = {
    "udh_dashboard", "udh_query", "udh_sync", "udh_targets",
    "udh_conflicts", "udh_lifecycle", "udh_control",
}

failed = []


def check(name: str, cond: bool) -> None:
    status = "PASS" if cond else "FAIL"
    print(f"{status}  {name}")
    if not cond:
        failed.append(name)


class _FakeCtx:
    pass


class _Resp:
    def __init__(self, status_code, body):
        self.status_code = status_code
        self._body = body
        self.content = b"x"

    def json(self):
        return self._body

    @property
    def text(self):
        import json as _json
        return _json.dumps(self._body)


class _FakeHTTP:
    def __init__(self, post_resp=None, get_resp=None):
        self.post_resp = post_resp or _Resp(200, {"ok": True})
        self.get_resp = get_resp or _Resp(200, {"hub_config": {}})
        self.calls = {"posts": [], "gets": []}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *e):
        return False

    async def post(self, url, headers=None, json=None):
        self.calls["posts"].append((url, headers, json))
        return self.post_resp

    async def get(self, url, headers=None):
        self.calls["gets"].append((url, headers))
        return self.get_resp


async def main() -> None:
    tools = await server.server.list_tools()
    names = {t.name for t in tools}
    check(f"all {len(EXPECTED_TOOLS)} tools registered (found {len(names)})",
          names == EXPECTED_TOOLS)

    from mcp.server.auth.middleware.auth_context import auth_context_var
    from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
    from mcp.server.auth.provider import AccessToken

    def ctx_with_scopes(*scopes):
        return auth_context_var.set(
            AuthenticatedUser(AccessToken(token="x", client_id="c", scopes=list(scopes))))

    # ---- scope gating: read ----
    restricted = ctx_with_scopes("sync")  # has sync, not read
    try:
        r = await server.udh_dashboard(server.DashboardIn(), _FakeCtx())
        check("udh_dashboard refuses a token without 'read' scope",
              "read" in r.lower() and "scoped" in r.lower())
    finally:
        auth_context_var.reset(restricted)

    restricted = ctx_with_scopes("sync")
    try:
        r = await server.udh_query(server.QueryIn(kind="list_conflicts"), _FakeCtx())
        check("udh_query refuses a token without 'read' scope",
              "read" in r.lower() and "scoped" in r.lower())
    finally:
        auth_context_var.reset(restricted)

    # ---- scope gating: sync ----
    restricted = ctx_with_scopes("read")  # has read, not sync
    try:
        r = await server.udh_sync(server.SyncIn(action="publish", confirm=True), _FakeCtx())
        check("udh_sync refuses a token without 'sync' scope",
              "sync" in r.lower() and "scoped" in r.lower())
    finally:
        auth_context_var.reset(restricted)

    restricted = ctx_with_scopes("read")
    try:
        r = await server.udh_targets(
            server.TargetsIn(target_id="trilium", direction="inbound",
                             enabled=False, confirm=True), _FakeCtx())
        check("udh_targets refuses a token without 'sync' scope",
              "sync" in r.lower() and "scoped" in r.lower())
    finally:
        auth_context_var.reset(restricted)

    restricted = ctx_with_scopes("read")
    try:
        r = await server.udh_control(server.ControlIn(global_pause=True, confirm=True), _FakeCtx())
        check("udh_control refuses a token without 'sync' scope",
              "sync" in r.lower() and "scoped" in r.lower())
    finally:
        auth_context_var.reset(restricted)

    # ---- scope gating: admin ----
    restricted = ctx_with_scopes("sync")  # has sync, not admin
    try:
        r = await server.udh_conflicts(
            server.ConflictsIn(doc_id="d1", winner_target_id="trilium", confirm=True), _FakeCtx())
        check("udh_conflicts refuses a token without 'admin' scope",
              "admin" in r.lower() and "scoped" in r.lower())
    finally:
        auth_context_var.reset(restricted)

    restricted = ctx_with_scopes("sync")
    try:
        r = await server.udh_lifecycle(
            server.LifecycleIn(action="rollback", confirm=True), _FakeCtx())
        check("udh_lifecycle refuses a token without 'admin' scope",
              "admin" in r.lower() and "scoped" in r.lower())
    finally:
        auth_context_var.reset(restricted)

    # ---- confirm=false previews (no HTTP call made) ----
    admin_ctx = ctx_with_scopes("admin")
    try:
        fake = _FakeHTTP()

        class _Shim:
            AsyncClient = staticmethod(lambda *a, **k: fake)
        _oh = core.httpx
        core.httpx = _Shim
        core.WF07_URL = "https://n8n.test/webhook/dispatch"
        core.WF07_AUTH_TOKEN = "wf07-token"
        try:
            r = await server.udh_lifecycle(
                server.LifecycleIn(action="confirm_delete", confirm=False,
                                   payload={"doc_id": "d1"}), _FakeCtx())
            check("udh_lifecycle confirm=false previews without calling WF-07",
                  "confirm=true" in r and fake.calls["posts"] == [])

            r = await server.udh_conflicts(
                server.ConflictsIn(doc_id="d1", winner_target_id="trilium", confirm=False),
                _FakeCtx())
            check("udh_conflicts confirm=false previews without calling WF-07",
                  "confirm=true" in r and fake.calls["posts"] == [])

            # ---- real dispatch with admin scope + confirm=true ----
            r = await server.udh_lifecycle(
                server.LifecycleIn(action="rollback", confirm=True,
                                   payload={"doc_id": "d1"}), _FakeCtx())
            check("udh_lifecycle dispatches to WF-07 with admin scope + confirm",
                  "Dispatched" in r and len(fake.calls["posts"]) == 1)
            url, headers, body = fake.calls["posts"][0]
            check("udh_lifecycle posts to WF07_URL with the configured auth header",
                  url == "https://n8n.test/webhook/dispatch"
                  and headers["X-UDH-Dispatch-Token"] == "wf07-token")
            check("udh_lifecycle's request body carries action + payload fields",
                  body == {"action": "rollback", "doc_id": "d1"})
        finally:
            core.httpx = _oh
    finally:
        auth_context_var.reset(admin_ctx)

    # ---- set_global_pause / set_target_enabled build their own payload ----
    sync_ctx = ctx_with_scopes("sync")
    try:
        fake = _FakeHTTP()

        class _Shim2:
            AsyncClient = staticmethod(lambda *a, **k: fake)
        _oh = core.httpx
        core.httpx = _Shim2
        core.WF07_URL = "https://n8n.test/webhook/dispatch"
        core.WF07_AUTH_TOKEN = "wf07-token"
        try:
            r = await server.udh_control(server.ControlIn(global_pause=True, confirm=True), _FakeCtx())
            check("udh_control dispatches set_global_pause with sync scope",
                  "Dispatched" in r
                  and fake.calls["posts"][0][2] == {"action": "set_global_pause", "global_pause": True})

            fake.calls["posts"].clear()
            r = await server.udh_targets(
                server.TargetsIn(target_id="t1", direction="outbound", enabled=False, confirm=True),
                _FakeCtx())
            check("udh_targets builds its payload from dedicated fields",
                  "Dispatched" in r
                  and fake.calls["posts"][0][2] == {"action": "set_target_enabled",
                                                     "target_id": "t1", "direction": "outbound",
                                                     "enabled": False})

            # ---- halted response surfaces as failure ----
            fake.post_resp = _Resp(200, {"halted": True, "message": "hub_config.global_pause is true"})
            fake.calls["posts"].clear()
            r = await server.udh_sync(server.SyncIn(action="publish", confirm=True), _FakeCtx())
            check("udh_sync surfaces a halted WF-07 response as a failure, not success",
                  "global_pause" in r and "Dispatched" not in r)
        finally:
            core.httpx = _oh
    finally:
        auth_context_var.reset(sync_ctx)

    # ---- udh_dashboard / udh_query read path ----
    read_ctx = ctx_with_scopes("read")
    try:
        fake = _FakeHTTP(get_resp=_Resp(200, {"hub_config": {"global_pause": False}}))

        class _Shim3:
            AsyncClient = staticmethod(lambda *a, **k: fake)
        _oh = core.httpx
        core.httpx = _Shim3
        core.WF14_URL = "https://n8n.test/webhook/dashboard"
        core.WF14_AUTH_TOKEN = "wf14-token"
        core.WF16_URL = "https://n8n.test/webhook/query"
        core.WF16_AUTH_TOKEN = "wf16-token"
        try:
            r = await server.udh_dashboard(server.DashboardIn(), _FakeCtx())
            check("udh_dashboard GETs WF14_URL with its own auth header",
                  fake.calls["gets"][-1][0] == "https://n8n.test/webhook/dashboard"
                  and fake.calls["gets"][-1][1]["X-UDH-Dashboard-Token"] == "wf14-token"
                  and "hub_config" in r)

            fake.post_resp = _Resp(200, {"doc_id": "d1", "case_folder": "EP"})
            r = await server.udh_query(
                server.QueryIn(kind="get_document", doc_id="d1"), _FakeCtx())
            check("udh_query posts to WF16_URL with its own auth header and kind",
                  fake.calls["posts"][-1][0] == "https://n8n.test/webhook/query"
                  and fake.calls["posts"][-1][1]["X-UDH-Query-Token"] == "wf16-token"
                  and fake.calls["posts"][-1][2]["kind"] == "get_document"
                  and fake.calls["posts"][-1][2]["doc_id"] == "d1"
                  and "d1" in r)

            fake.post_resp = _Resp(200, {"error": "doc not found"})
            r = await server.udh_query(
                server.QueryIn(kind="get_document", doc_id="nope"), _FakeCtx())
            check("udh_query surfaces a WF-16 {'error': ...} body as a failure",
                  "doc not found" in r)
        finally:
            core.httpx = _oh
    finally:
        auth_context_var.reset(read_ctx)

    # ---- unconfigured env gives a clear message, not a crash ----
    unset_ctx = ctx_with_scopes("*")
    try:
        _owf07u, _owf07t = core.WF07_URL, core.WF07_AUTH_TOKEN
        core.WF07_URL, core.WF07_AUTH_TOKEN = "", ""
        try:
            r = await server.udh_sync(server.SyncIn(action="ingest", confirm=True), _FakeCtx())
            check("udh_sync reports missing WF07 config plainly",
                  "WF07_URL" in r and "not configured" in r)
        finally:
            core.WF07_URL, core.WF07_AUTH_TOKEN = _owf07u, _owf07t
    finally:
        auth_context_var.reset(unset_ctx)

    print(f"\n{'ALL PASS' if not failed else 'FAILURES: ' + ', '.join(failed)}")
    if failed:
        sys.exit(1)


asyncio.run(main())
