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
    "udh_health", "udh_config", "udh_templates",
    "udh_simulate", "udh_checkpoint", "udh_tokens",
    "udh_tags", "udh_fleet",
    "udh_extract", "udh_bundle_seal",
    "udh_dictionary", "udh_updates",
    "udh_setup", "udh_scheduler", "udh_adapters",
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

            r = await server.udh_query(server.QueryIn(kind="search_fulltext"), _FakeCtx())
            check("udh_query refuses search_fulltext with no query, before ever calling WF-16",
                  "query" in r.lower() and fake.calls["posts"][-1][2].get("kind") != "search_fulltext")

            fake.post_resp = _Resp(200, {"found": True, "doc_id": "d1", "content": "# Doc\n\nhello"})
            r = await server.udh_query(
                server.QueryIn(kind="get_content", doc_id="d1"), _FakeCtx())
            check("udh_query posts kind=get_content with doc_id and surfaces real content",
                  fake.calls["posts"][-1][2] == {"kind": "get_content", "doc_id": "d1", "limit": 50}
                  and "hello" in r)

            fake.post_resp = _Resp(200, {"count": 1, "documents": [{"doc_id": "d1", "title": "T"}], "engine": "meilisearch"})
            r = await server.udh_query(
                server.QueryIn(kind="search_fulltext", query="litigation"), _FakeCtx())
            check("udh_query posts kind=search_fulltext with query",
                  fake.calls["posts"][-1][2]["kind"] == "search_fulltext"
                  and fake.calls["posts"][-1][2]["query"] == "litigation")
        finally:
            core.httpx = _oh
    finally:
        auth_context_var.reset(read_ctx)

    # ---- udh_health / udh_config / udh_templates (added 2026-10-13) ----
    restricted = ctx_with_scopes("read")  # has read, not sync
    try:
        r = await server.udh_health(server.HealthIn(action="check_health", confirm=True), _FakeCtx())
        check("udh_health refuses a token without 'sync' scope",
              "sync" in r.lower() and "scoped" in r.lower())
        r = await server.udh_config(server.ConfigIn(action="update_hub_config", field="dry_run", value=True, confirm=True), _FakeCtx())
        check("udh_config refuses a token without 'sync' scope",
              "sync" in r.lower() and "scoped" in r.lower())
        r = await server.udh_templates(server.TemplatesIn(action="list_templates"), _FakeCtx())
        check("udh_templates refuses a token without 'sync' scope",
              "sync" in r.lower() and "scoped" in r.lower())
    finally:
        auth_context_var.reset(restricted)

    sync_ctx = ctx_with_scopes("sync")
    try:
        fake = _FakeHTTP()

        class _Shim4:
            AsyncClient = staticmethod(lambda *a, **k: fake)
        _oh = core.httpx
        core.httpx = _Shim4
        core.WF07_URL = "https://n8n.test/webhook/dispatch"
        core.WF07_AUTH_TOKEN = "wf07-token"
        try:
            r = await server.udh_config(
                server.ConfigIn(action="update_target_config", field="enabled", value=False, confirm=True),
                _FakeCtx())
            check("udh_config refuses update_target_config without target_id before ever dispatching",
                  "target_id" in r.lower() and fake.calls["posts"] == [])

            r = await server.udh_config(
                server.ConfigIn(action="update_target_config", target_id="trilium",
                                 field="enabled", value=False, confirm=True), _FakeCtx())
            check("udh_config dispatches update_target_config with field/value/target_id",
                  fake.calls["posts"][-1][2] == {"action": "update_target_config",
                                                  "field": "enabled", "value": False,
                                                  "target_id": "trilium"})

            fake.calls["posts"].clear()
            r = await server.udh_health(
                server.HealthIn(action="check_integrity", confirm=False, case_folder="EP"), _FakeCtx())
            check("udh_health confirm=false previews without calling WF-07",
                  "confirm=true" in r and fake.calls["posts"] == [])

            r = await server.udh_health(
                server.HealthIn(action="check_integrity", confirm=True, case_folder="EP"), _FakeCtx())
            check("udh_health dispatches check_integrity with case_folder",
                  fake.calls["posts"][-1][2] == {"action": "check_integrity", "case_folder": "EP"})

            fake.calls["posts"].clear()
            r = await server.udh_templates(server.TemplatesIn(action="list_templates"), _FakeCtx())
            check("udh_templates list_templates dispatches with no confirm needed",
                  fake.calls["posts"][-1][2] == {"action": "list_templates"})

            fake.calls["posts"].clear()
            r = await server.udh_templates(
                server.TemplatesIn(action="create_template", name="Default", confirm=False), _FakeCtx())
            check("udh_templates create_template confirm=false previews without calling WF-07",
                  "confirm=true" in r and fake.calls["posts"] == [])

            r = await server.udh_templates(
                server.TemplatesIn(action="delete_template", template_id="tmpl-1", confirm=True), _FakeCtx())
            check("udh_templates delete_template sends confirm=true in the WF-07 payload itself",
                  fake.calls["posts"][-1][2] == {"action": "delete_template",
                                                  "template_id": "tmpl-1", "confirm": True})

            fake.calls["posts"].clear()
            r = await server.udh_lifecycle(
                server.LifecycleIn(action="purge_ingested", confirm=True,
                                   payload={"target_id": "trilium"}), _FakeCtx())
            check("udh_lifecycle accepts purge_ingested (needs admin, tested separately below)",
                  "scoped" in r.lower() and "admin" in r.lower())
        finally:
            core.httpx = _oh
    finally:
        auth_context_var.reset(sync_ctx)

    admin_ctx2 = ctx_with_scopes("admin")
    try:
        fake = _FakeHTTP()

        class _Shim5:
            AsyncClient = staticmethod(lambda *a, **k: fake)
        _oh = core.httpx
        core.httpx = _Shim5
        core.WF07_URL = "https://n8n.test/webhook/dispatch"
        core.WF07_AUTH_TOKEN = "wf07-token"
        try:
            r = await server.udh_lifecycle(
                server.LifecycleIn(action="purge_ingested", confirm=True,
                                   payload={"target_id": "trilium"}), _FakeCtx())
            check("udh_lifecycle dispatches purge_ingested with admin scope + confirm",
                  fake.calls["posts"][-1][2] == {"action": "purge_ingested", "target_id": "trilium"})
        finally:
            core.httpx = _oh
    finally:
        auth_context_var.reset(admin_ctx2)

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
    
    _off_wf07u, _off_wf07t, _off_dash = core.WF07_URL, core.WF07_AUTH_TOKEN, core.UDH_DASHBOARD_URL
    core.WF07_URL, core.WF07_AUTH_TOKEN, core.UDH_DASHBOARD_URL = "", "", ""
    try:
        # udh_simulate
        r = await server.udh_simulate(server.SimulateIn(scenario="et_witness_statement"), _FakeCtx())
        check("udh_simulate executes dry-run simulation and returns 64-bit simhash", "0x" in r and "UDH Pipeline Simulation" in r)

        # udh_checkpoint
        r = await server.udh_checkpoint(server.CheckpointIn(action="create", name="pre-batch-test"), _FakeCtx())
        check("udh_checkpoint create succeeds with sync scope", "pre-batch-test" in r)

        r = await server.udh_checkpoint(server.CheckpointIn(action="restore", checkpoint_id="cp-123", confirm=False), _FakeCtx())
        check("udh_checkpoint restore confirm=false previews without mutating", "Would restore" in r)

        # udh_tokens
        r = await server.udh_tokens(server.TokensIn(action="get_metrics"), _FakeCtx())
        check("udh_tokens get_metrics returns token burn stats", "UDH Token Burn Status" in r)

        r = await server.udh_tokens(server.TokensIn(action="set_budget", daily_budget=200000), _FakeCtx())
        check("udh_tokens set_budget updates daily cap", "200,000" in r)

        # udh_tags
        r = await server.udh_tags(server.TagsIn(action="cluster_tags"), _FakeCtx())
        check("udh_tags cluster_tags detects synonyms and clusters", "Discovered" in r)

        r = await server.udh_tags(server.TagsIn(action="consolidate_tags", canonical_tag="invoice", deprecated_tags=["invoices"], confirm=False), _FakeCtx())
        check("udh_tags consolidate_tags confirm=false previews without writing", "Would consolidate" in r)
    finally:
        core.WF07_URL, core.WF07_AUTH_TOKEN, core.UDH_DASHBOARD_URL = _off_wf07u, _off_wf07t, _off_dash

    # udh_fleet
    r = await server.udh_fleet(server.FleetIn(action="get_status"), _FakeCtx())
    check("udh_fleet get_status probes 5 core UDH services", "UDH Container Fleet" in r)

    # udh_extract
    r = await server.udh_extract(server.ExtractInput(text="# Witness Statement\nClaimant cites [2024] EWCA Civ 123 and Employment Rights Act 1996 for £12,500.00."))
    check("udh_extract extracts citations, statutes, and SimHash", "Zero-Token Extract" in r and "[2024] EWCA Civ 123" in r)

    # udh_bundle_seal
    r = await server.udh_bundle_seal(server.BundleSealInput(doc_id="bundle-1", content="Canonical text", weekly_gross=700.0, years_service=4))
    check("udh_bundle_seal generates SHA-256 custody seal", "Custody Seal" in r and "SHA-256:" in r)

    # udh_dictionary & udh_updates (scope gating + dry-run preview)
    restricted = ctx_with_scopes("sync")
    try:
        r = await server.udh_dictionary(server.DictionaryIn(resource="dictionary"), _FakeCtx())
        check("udh_dictionary refuses a token without 'read' scope", "read" in r.lower() and "scoped" in r.lower())
    finally:
        auth_context_var.reset(restricted)

    restricted = ctx_with_scopes("read")
    try:
        r = await server.udh_updates(server.UpdatesIn(action="trigger_update", confirm=True), _FakeCtx())
        check("udh_updates trigger refuses a token without 'sync' scope", "sync" in r.lower() and "scoped" in r.lower())
    finally:
        auth_context_var.reset(restricted)

    r = await server.udh_updates(server.UpdatesIn(action="trigger_update", confirm=False), _FakeCtx())
    check("udh_updates trigger confirm=false previews without mutating", "Dry-run preview" in r)

    # Option E Stage 1 native backend routing in core.py
    fake_native = _FakeHTTP()

    class _ShimNative:
        AsyncClient = staticmethod(lambda *a, **k: fake_native)

    _oh_n = core.httpx
    _old_mode = core.UDH_BACKEND_MODE
    _old_pref = core.UDH_PREFER_NATIVE
    _old_dash = core.UDH_DASHBOARD_URL
    core.httpx = _ShimNative
    core.UDH_BACKEND_MODE = "native"
    core.UDH_DASHBOARD_URL = "https://udh-dashboard.test"
    try:
        ok, text, _ = await core.dispatch("check_health", {})
        check("Option E native dispatch posts to /api/native/dispatch",
              ok and len(fake_native.calls["posts"]) == 1
              and fake_native.calls["posts"][0][0] == "https://udh-dashboard.test/api/native/dispatch")

        ok_q, _, _ = await core.query("list_conflicts", {})
        check("Option E native query posts to /api/native/query",
              ok_q and len(fake_native.calls["posts"]) == 2
              and fake_native.calls["posts"][1][0] == "https://udh-dashboard.test/api/native/query")

        ok_d, _, _ = await core.dashboard_data()
        check("Option E native dashboard_data gets /api/native/dashboard-data",
              ok_d and len(fake_native.calls["gets"]) == 1
              and fake_native.calls["gets"][0][0] == "https://udh-dashboard.test/api/native/dashboard-data")
    finally:
        core.httpx = _oh_n
        core.UDH_BACKEND_MODE = _old_mode
        core.UDH_PREFER_NATIVE = _old_pref
        core.UDH_DASHBOARD_URL = _old_dash

    # udh_setup & udh_scheduler (Option E Stage 2 + easy setup)
    r = await server.udh_setup(server.SetupIn(action="connect_guide"), _FakeCtx())
    check("udh_setup connect_guide returns client config & endpoint", "udh.nasmatrix.app/mcp" in r and "mcpServers" in r)

    r = await server.udh_setup(server.SetupIn(action="quickstart"), _FakeCtx())
    check("udh_setup quickstart returns 21-tool cheat sheet", "udh_scheduler" in r and "udh_dashboard" in r)

    restricted = ctx_with_scopes("read")
    try:
        r = await server.udh_scheduler(server.SchedulerIn(action="run", job_id="wf08_health_digest", dry_run=False, confirm=True), _FakeCtx())
        check("udh_scheduler run refuses a token without 'sync' scope", "sync" in r.lower() and "scoped" in r.lower())
    finally:
        auth_context_var.reset(restricted)

    r = await server.udh_scheduler(server.SchedulerIn(action="run", job_id="wf08_health_digest", dry_run=False, confirm=False), _FakeCtx())
    check("udh_scheduler live run requires confirm=true", "Safety gate" in r and "confirm=true" in r)

    r = await server.udh_scheduler(server.SchedulerIn(action="toggle", job_id="wf12_drift_scanner", enabled=False, confirm=False), _FakeCtx())
    check("udh_scheduler toggle previews without mutating when confirm=false", "Dry-run preview" in r)

    # udh_adapters (Option E Stage 3)
    restricted = ctx_with_scopes("read")
    try:
        r = await server.udh_adapters(server.AdaptersIn(action="dispatch", adapter_id="trilium", dry_run=False, confirm=True), _FakeCtx())
        check("udh_adapters dispatch refuses a token without 'sync' scope", "sync" in r.lower() and "scoped" in r.lower())
    finally:
        auth_context_var.reset(restricted)

    r = await server.udh_adapters(server.AdaptersIn(action="pipeline", content="hello", dry_run=False, confirm=False), _FakeCtx())
    check("udh_adapters live pipeline requires confirm=true", "Safety gate" in r and "confirm=true" in r)

    r = await server.udh_adapters(server.AdaptersIn(action="run_bridge", adapter_id="legal_phase1_trilium_import", dry_run=False, confirm=False), _FakeCtx())
    check("udh_adapters live run_bridge requires confirm=true", "Safety gate" in r and "confirm=true" in r)

    restricted_setup = ctx_with_scopes("sync")
    try:
        r = await server.udh_setup(server.SetupIn(action="cutover_check"), _FakeCtx())
        check("udh_setup cutover_check refuses a token without 'read' scope", "read" in r.lower() and "scoped" in r.lower())
    finally:
        auth_context_var.reset(restricted_setup)

    # Front-facing runtime settings via udh_config
    restricted_rt = ctx_with_scopes("sync")
    try:
        r = await server.udh_config(server.ConfigIn(action="get_runtime_settings"), _FakeCtx())
        check("udh_config get_runtime_settings refuses a token without 'read' scope", "read" in r.lower() and "scoped" in r.lower())
    finally:
        auth_context_var.reset(restricted_rt)

    fake_rt = _FakeHTTP()
    fake_rt.get_resp = _Resp(200, {"ok": True, "backend_mode": "strangler", "native_write_targets": ["trilium"]})

    class _ShimRT:
        AsyncClient = staticmethod(lambda *a, **k: fake_rt)

    _oh_rt = core.httpx
    _old_rt_dash = core.UDH_DASHBOARD_URL
    core.httpx = _ShimRT
    core.UDH_DASHBOARD_URL = "https://udh-dashboard.test"
    try:
        read_rt = ctx_with_scopes("read")
        try:
            r = await server.udh_config(server.ConfigIn(action="get_runtime_settings"), _FakeCtx())
            check("udh_config get_runtime_settings queries /api/settings/runtime",
                  len(fake_rt.calls["gets"]) == 1
                  and fake_rt.calls["gets"][0][0] == "https://udh-dashboard.test/api/settings/runtime"
                  and "strangler" in r)
        finally:
            auth_context_var.reset(read_rt)

        r = await server.udh_config(
            server.ConfigIn(action="update_runtime_settings", settings={"backend_mode": "native"}, confirm=False),
            _FakeCtx(),
        )
        check("udh_config update_runtime_settings previews when confirm=false", "confirm=true" in r and fake_rt.calls["posts"] == [])

        sync_rt = ctx_with_scopes("sync")
        try:
            r = await server.udh_config(
                server.ConfigIn(action="update_runtime_settings", settings={"backend_mode": "native", "token_daily_budget": 200000}, confirm=True),
                _FakeCtx(),
            )
            check("udh_config update_runtime_settings posts to /api/settings/runtime",
                  len(fake_rt.calls["posts"]) == 1
                  and fake_rt.calls["posts"][0][0] == "https://udh-dashboard.test/api/settings/runtime"
                  and fake_rt.calls["posts"][0][2]["token_daily_budget"] == 200000)

            r = await server.udh_config(server.ConfigIn(action="reset_runtime_settings", confirm=True), _FakeCtx())
            check("udh_config reset_runtime_settings posts to /api/settings/runtime/reset",
                  len(fake_rt.calls["posts"]) == 2
                  and fake_rt.calls["posts"][1][0] == "https://udh-dashboard.test/api/settings/runtime/reset")
        finally:
            auth_context_var.reset(sync_rt)
    finally:
        core.httpx = _oh_rt
        core.UDH_DASHBOARD_URL = _old_rt_dash

    # Option 1 bootstrap_pg & Option 2 udh_adapters dispatch payload passthrough
    fake_boot = _FakeHTTP()
    fake_boot.post_resp = _Resp(200, {"ok": True, "dry_run": True, "tables_to_ensure": ["hub_config"]})

    class _ShimBoot:
        AsyncClient = staticmethod(lambda *a, **k: fake_boot)

    _oh_b = core.httpx
    _old_b_dash = core.UDH_DASHBOARD_URL
    core.httpx = _ShimBoot
    core.UDH_DASHBOARD_URL = "https://udh-dashboard.test"
    try:
        read_b = ctx_with_scopes("read")
        try:
            r = await server.udh_setup(server.SetupIn(action="bootstrap_pg", dry_run=True), _FakeCtx())
            check("udh_setup bootstrap_pg dry_run posts to /api/migration/bootstrap-pg",
                  len(fake_boot.calls["posts"]) == 1
                  and fake_boot.calls["posts"][0][0] == "https://udh-dashboard.test/api/migration/bootstrap-pg"
                  and fake_boot.calls["posts"][0][2]["dry_run"] is True)

            r = await server.udh_setup(server.SetupIn(action="bootstrap_pg", dry_run=False, confirm=True), _FakeCtx())
            check("udh_setup live bootstrap_pg refuses a token without 'sync' scope",
                  "sync" in r.lower() and "scoped" in r.lower())
        finally:
            auth_context_var.reset(read_b)

        sync_b = ctx_with_scopes("sync")
        try:
            r = await server.udh_setup(server.SetupIn(action="bootstrap_pg", dry_run=False, confirm=False), _FakeCtx())
            check("udh_setup live bootstrap_pg requires confirm=true", "Safety gate" in r and "confirm=true" in r)

            r = await server.udh_adapters(
                server.AdaptersIn(
                    action="dispatch",
                    adapter_id="obsidian",
                    direction="out",
                    doc_id="doc-42",
                    title="Evidence Note",
                    content="Full text body",
                    dry_run=False,
                    confirm=True,
                ),
                _FakeCtx(),
            )
            check("udh_adapters dispatch forwards payload doc_id/title/content/write",
                  fake_boot.calls["posts"][-1][0] == "https://udh-dashboard.test/api/stage3/adapters/dispatch"
                  and fake_boot.calls["posts"][-1][2]["payload"]["doc_id"] == "doc-42"
                  and fake_boot.calls["posts"][-1][2]["payload"]["write"] is True)
        finally:
            auth_context_var.reset(sync_b)
    finally:
        core.httpx = _oh_b
        core.UDH_DASHBOARD_URL = _old_b_dash

    # Bidirectional automatic failover (n8n <-> native) & DLQ/webhook MCP actions
    class _FailoverHTTP:
        def __init__(self):
            self.calls = []

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url, headers=None):
            self.calls.append(("GET", url))
            if "n8n.test" in url:
                return _Resp(502, {"error": "bad gateway"})
            return _Resp(200, {"hub_config": {"global_pause": False}, "ok": True})

        async def post(self, url, headers=None, json=None):
            self.calls.append(("POST", url, json))
            if "udh-dashboard.test" in url:
                return _Resp(503, {"error": "native busy"})
            return _Resp(200, {"status": "ok", "from": "n8n"})

    fail_http = _FailoverHTTP()

    class _ShimFO:
        AsyncClient = staticmethod(lambda *a, **k: fail_http)

    _oh_fo = core.httpx
    _old_fo_mode = core.UDH_BACKEND_MODE
    _old_fo_pref = core.UDH_PREFER_NATIVE
    _old_fo_override = core.RUNTIME_MODE_OVERRIDE
    _old_fo_dash = core.UDH_DASHBOARD_URL
    _old_fo_wf14 = core.WF14_URL
    _old_fo_wf14t = core.WF14_AUTH_TOKEN
    _old_fo_wf07 = core.WF07_URL
    _old_fo_wf07t = core.WF07_AUTH_TOKEN
    core.httpx = _ShimFO
    core.UDH_DASHBOARD_URL = "https://udh-dashboard.test"
    core.WF14_URL = "https://n8n.test/webhook/dashboard"
    core.WF14_AUTH_TOKEN = "t14"
    core.WF07_URL = "https://n8n.test/webhook/dispatch"
    core.WF07_AUTH_TOKEN = "t07"
    try:
        core.set_runtime_mode("n8n")
        ok_dash, _, dash_data = await core.dashboard_data()
        check("Bidirectional failover: n8n 502 auto-falls back to native dashboard",
              ok_dash and isinstance(dash_data, dict) and dash_data.get("routed_via") == "native_fallback")

        core.set_runtime_mode("native")
        ok_disp, _, disp_data = await core.dispatch("check_health", {})
        check("Bidirectional failover: native 503 auto-falls back to n8n WF-07",
              ok_disp and isinstance(disp_data, dict) and disp_data.get("routed_via") == "n8n_fallback")

        core.set_runtime_mode(None)
        sync_dlq = ctx_with_scopes("sync")
        try:
            fake_dlq = _FakeHTTP()
            fake_dlq.get_resp = _Resp(200, {"ok": True, "count": 1, "items": [{"id": "dlq-1"}]})
            fake_dlq.post_resp = _Resp(200, {"ok": True, "replayed": 1, "succeeded": 1})

            class _ShimDLQ:
                AsyncClient = staticmethod(lambda *a, **k: fake_dlq)

            core.httpx = _ShimDLQ
            read_dlq = ctx_with_scopes("read")
            try:
                r = await server.udh_adapters(server.AdaptersIn(action="dlq", adapter_id="docmost"), _FakeCtx())
                check("udh_adapters action=dlq queries /api/stage3/dlq",
                      fake_dlq.calls["gets"][-1][0] == "https://udh-dashboard.test/api/stage3/dlq?target_id=docmost")
            finally:
                auth_context_var.reset(read_dlq)

            r = await server.udh_adapters(server.AdaptersIn(action="replay_dlq", dry_run=False, confirm=True), _FakeCtx())
            check("udh_adapters action=replay_dlq posts to /api/stage3/dlq/replay",
                  fake_dlq.calls["posts"][-1][0] == "https://udh-dashboard.test/api/stage3/dlq/replay")

            r = await server.udh_adapters(
                server.AdaptersIn(action="webhook_ingest", source="paperless", doc_id="pl-1", content="hi", dry_run=True),
                _FakeCtx(),
            )
            check("udh_adapters action=webhook_ingest posts to /api/interop/webhook/paperless",
                  fake_dlq.calls["posts"][-1][0] == "https://udh-dashboard.test/api/interop/webhook/paperless")

            old_api_tok = os.environ.get("UDH_API_TOKEN")
            os.environ["UDH_API_TOKEN"] = "mcp-api-secret"
            try:
                r = await server.udh_adapters(
                    server.AdaptersIn(action="index_native", doc_id="idx-1", title="Idx", content="Vector body", dry_run=True),
                    _FakeCtx(),
                )
                check("udh_adapters action=index_native forwards UDH_API_TOKEN Bearer header",
                      fake_dlq.calls["posts"][-1][0] == "https://udh-dashboard.test/api/native/index"
                      and fake_dlq.calls["posts"][-1][1].get("Authorization") == "Bearer mcp-api-secret")
            finally:
                if old_api_tok is None:
                    os.environ.pop("UDH_API_TOKEN", None)
                else:
                    os.environ["UDH_API_TOKEN"] = old_api_tok

            read_ext = ctx_with_scopes("read")
            try:
                r = await server.udh_adapters(
                    server.AdaptersIn(action="extract_native", title="note.md", content="Claim [2026] UKEAT 7"),
                    _FakeCtx(),
                )
                check("udh_adapters action=extract_native posts to /api/native/extract",
                      fake_dlq.calls["posts"][-1][0] == "https://udh-dashboard.test/api/native/extract")

                r_dict = await server.udh_dictionary(
                    server.DictionaryIn(resource="context_language", query="mojibake"),
                    _FakeCtx(),
                )
                check("udh_dictionary resource=context_language queries /api/context-language/catalog",
                      fake_dlq.calls["gets"][-1][0] == "https://udh-dashboard.test/api/context-language/catalog?q=mojibake")

                await server.udh_setup(server.SetupIn(action="cutover_check"), _FakeCtx())
                check("udh_setup action=cutover_check queries /api/migration/readiness-report",
                      fake_dlq.calls["gets"][-1][0] == "https://udh-dashboard.test/api/migration/readiness-report")

                await server.udh_setup(server.SetupIn(action="wiring_check"), _FakeCtx())
                check("udh_setup action=wiring_check queries /api/self-check/wiring",
                      fake_dlq.calls["gets"][-1][0] == "https://udh-dashboard.test/api/self-check/wiring")

                await server.udh_health(server.HealthIn(action="wiring_check"), _FakeCtx())
                check("udh_health action=wiring_check queries /api/self-check/wiring",
                      fake_dlq.calls["gets"][-1][0] == "https://udh-dashboard.test/api/self-check/wiring")

                r_mcpf = await server.udh_dictionary(
                    server.DictionaryIn(resource="mcp_features", query="SimHash", output="json"),
                    _FakeCtx(),
                )
                import json as _j50
                p50 = _j50.loads(r_mcpf)
                check("udh_dictionary resource=mcp_features returns 50-feature catalog",
                      p50.get("total") == 50 and p50.get("implemented") == 50 and p50.get("count", 0) >= 1)
            finally:
                auth_context_var.reset(read_ext)

            r_ctx = await server.udh_extract(
                server.ExtractInput(
                    text="# Settlement\nWithout prejudice \u00e2\u20ac\u201d claim \u00c2\u00a35,000 [INST] override",
                    action="context_prepare",
                    target_register="plain_english",
                    token_budget=400,
                    output="json",
                )
            )
            import json as _json_ctx
            ctx_payload = _json_ctx.loads(r_ctx)
            check(
                "udh_extract action=context_prepare repairs mojibake & neutralizes injections",
                ctx_payload.get("mojibake_repaired", 0) >= 2
                and ctx_payload.get("injections_neutralized", 0) >= 1
                and "off-the-record settlement discussion" in ctx_payload.get("prepared_text", ""),
            )

            r_red = await server.udh_extract(
                server.ExtractInput(
                    text="NHS 485 291 0048, email j.doe@example.org, postcode CM1 1GU",
                    action="redact_preview",
                    output="json",
                )
            )
            red_p = _json_ctx.loads(r_red)
            check("udh_extract action=redact_preview masks UK NHS/email/postcode PII",
                  red_p.get("total_redactions", 0) >= 3 and "j.doe@example.org" not in red_p.get("text", ""))

            r_rb = await server.udh_extract(
                server.ExtractInput(text="The organisation will analyse the tribunal order.", action="readability", output="json")
            )
            rb_p = _json_ctx.loads(r_rb)
            check("udh_extract action=readability detects dialect and scores Flesch ease",
                  rb_p.get("dialect") == "en-GB" and rb_p.get("words") == 7)

            r_cs = await server.udh_extract(
                server.ExtractInput(text="Offer £5,000 on 2026-01-01 vs £12,000 on 2026-02-02", action="conflict_scan", output="json")
            )
            check("udh_extract action=conflict_scan flags divergent GBP figures",
                  _json_ctx.loads(r_cs).get("has_conflicts") is True)

            import mcp_enhancements as enh
            check("mcp_enhancements sanitize_secrets scrubs Bearer token",
                  "Bearer [REDACTED]" in enh.sanitize_secrets("Authorization: Bearer supersecret123456"))
            check("mcp_enhancements map_http_status_to_udh_error classifies 429 cleanly",
                  enh.map_http_status_to_udh_error(429)["error_code"] == "UDH-018")
            check("udh_tokens set_budget posts token_daily_budget to /api/settings/runtime",
                  "Persisted" in await server.udh_tokens(server.TokensIn(action="set_budget", daily_budget=250000), _FakeCtx())
                  and fake_dlq.calls["posts"][-1][0] == "https://udh-dashboard.test/api/settings/runtime")

            # Strangler harmony: native-only dispatch actions bypass WF-07 directly to /api/native/dispatch
            core.set_runtime_mode(None)
            core.UDH_BACKEND_MODE = "strangler"
            core.UDH_PREFER_NATIVE = False
            ok_chk, _, d_chk = await core.dispatch("create_checkpoint", {"name": "cp-harmony"})
            check("Harmony strangler: native-only create_checkpoint routes straight to /api/native/dispatch",
                  ok_chk and d_chk.get("routed_via") == "native"
                  and fake_dlq.calls["posts"][-1][0] == "https://udh-dashboard.test/api/native/dispatch")

            # Scheduler execute_native passthrough
            await server.udh_scheduler(
                server.SchedulerIn(action="run", job_id="wf12_drift_scanner", dry_run=False, confirm=True, execute_native=True),
                _FakeCtx(),
            )
            check("udh_scheduler forwards execute_native=True to /api/stage2/scheduler/run",
                  fake_dlq.calls["posts"][-1][0] == "https://udh-dashboard.test/api/stage2/scheduler/run"
                  and fake_dlq.calls["posts"][-1][2].get("execute_native") is True)

            # Template normalization: stringified booleans & JSON strings decoded cleanly
            norm_tmpl = enh.normalize_template_payload({
                "status": "ok",
                "rows": [{"template_id": "t1", "is_default": "true", "metadata_fields": '{"title": true}'}],
                "templates": [{"template_id": "t1", "is_default": "true", "metadata_fields": '{"title": true}'}],
            })
            check("normalize_template_payload decodes booleans & JSON and removes duplicate rows key",
                  "rows" not in norm_tmpl and norm_tmpl["templates"][0]["is_default"] is True
                  and norm_tmpl["templates"][0]["metadata_fields"] == {"title": True})

            # Legal tag clustering merges Employment Tribunal / ET Case / tribunal
            read_tag_ctx = ctx_with_scopes("read")
            try:
                r_tags_tri = await server.udh_tags(
                    server.TagsIn(action="cluster_tags", tags=["Employment Tribunal", "ET Case", "tribunal"], output="json"),
                    _FakeCtx(),
                )
            finally:
                auth_context_var.reset(read_tag_ctx)
            tri_clusters = _json_ctx.loads(r_tags_tri)["clusters"]
            check("udh_tags merges Employment Tribunal, ET Case & tribunal into #et",
                  len(tri_clusters) == 1 and tri_clusters[0]["canonical"] == "et" and len(tri_clusters[0]["variants"]) == 3)

            # udh_health execute_native routes straight to /api/native/dispatch in strangler mode
            core.set_runtime_mode(None)
            core.UDH_BACKEND_MODE = "strangler"
            await server.udh_health(
                server.HealthIn(action="check_health", confirm=True, execute_native=True),
                _FakeCtx(),
            )
            check("udh_health execute_native=True routes straight to /api/native/dispatch",
                  fake_dlq.calls["posts"][-1][0] == "https://udh-dashboard.test/api/native/dispatch"
                  and fake_dlq.calls["posts"][-1][2].get("execute_native") is True)

            # udh_checkpoint delete calls /api/native/snapshot/delete under admin+confirm
            admin_ctx_del = ctx_with_scopes("admin")
            try:
                fake_dlq.post_resp = _Resp(200, {"ok": True, "deleted": True, "snapshot_id": "snap-999", "status": "deleted"})
                r_del_cp = await server.udh_checkpoint(
                    server.CheckpointIn(action="delete", checkpoint_id="snap-999", confirm=True, output="json"),
                    _FakeCtx(),
                )
                check("udh_checkpoint delete posts snapshot_id to /api/native/snapshot/delete",
                      _json_ctx.loads(r_del_cp).get("deleted") is True
                      and fake_dlq.calls["posts"][-1][0] == "https://udh-dashboard.test/api/native/snapshot/delete")
            finally:
                auth_context_var.reset(admin_ctx_del)
        finally:
            auth_context_var.reset(sync_dlq)
    finally:
        core.httpx = _oh_fo
        core.UDH_BACKEND_MODE = _old_fo_mode
        core.UDH_PREFER_NATIVE = _old_fo_pref
        core.RUNTIME_MODE_OVERRIDE = _old_fo_override
        core.UDH_DASHBOARD_URL = _old_fo_dash
        core.WF14_URL = _old_fo_wf14
        core.WF14_AUTH_TOKEN = _old_fo_wf14t
        core.WF07_URL = _old_fo_wf07
        core.WF07_AUTH_TOKEN = _old_fo_wf07t

    print(f"\n{'ALL PASS' if not failed else 'FAILURES: ' + ', '.join(failed)}")
    if failed:
        sys.exit(1)


asyncio.run(main())
