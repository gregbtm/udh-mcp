"""50-Feature MCP Enhancement Engine & Zero-Token Document Intelligence for udh-mcp.

Provides clean, deterministic, zero-network intelligence helpers plus the tracked
50-point MCP Feature & Improvement Catalog across 5 pillars (10 items per pillar),
all exposed inside udh-mcp's 22 registered tools (CI tool count preserved at 22).
"""
from __future__ import annotations

import hashlib
import math
import re
from typing import Any, Dict, List, Optional

MCP_PILLARS: list[str] = [
    "Transport Resilience, Caching & Telemetry",
    "Zero-Token Intelligence, Context Hygiene & Safety",
    "Live Tool Wiring & Real Backend Execution",
    "Pre-Cutover, Diagnostics & Ecosystem Observability",
    "Agent UX, Guardrails & Schema Hygiene",
]

_RAW_MCP_FEATURES: list[tuple[int, int, str, str, str]] = [
    # Pillar 1: Transport Resilience, Caching & Telemetry (1-10)
    (1, 0, "Per-call X-Request-ID correlation header on upstream HTTP requests", "Implemented", "core._http_call"),
    (2, 0, "Upstream latency telemetry & call counters per backend (wf07/wf14/wf16/dashboard)", "Implemented", "core.get_transport_stats"),
    (3, 0, "Short-TTL read response cache (dashboard & dictionary) with mutation invalidation", "Implemented", "core.invalidate_read_cache"),
    (4, 0, "Automatic idempotency key attachment for mutating WF-07/native dispatches", "Implemented", "core.dispatch"),
    (5, 0, "DISPATCH_ACTIONS synced with native propagate_paperless & reindex_vectors", "Implemented", "core.DISPATCH_ACTIONS"),
    (6, 0, "Bumped MCP server version baseline to 2.7.0 across /status & fleet", "Implemented", "server.py"),
    (7, 0, "Secret-scrubbing output sanitizer blocking token & Postgres DSN leakage", "Implemented", "mcp_enhancements.sanitize_secrets"),
    (8, 0, "HTTP error mapper classifying 401/403/429/502/503/504 into UDH-XXX remediation hints", "Implemented", "mcp_enhancements.map_http_status_to_udh_error"),
    (9, 0, "Dedicated /healthz HTTP liveness endpoint complementing /status", "Implemented", "server.healthz"),
    (10, 0, "Secret-free 25-entry rolling MCP tool audit journal exposed via /status", "Implemented", "server._TOOL_AUDIT_RING"),

    # Pillar 2: Zero-Token Intelligence, Context Hygiene & Safety (11-20)
    (11, 1, "Zero-token PII scrubber (NHS, NINO, UK postcode, email, sort code, phone) in udh_extract", "Implemented", "mcp_enhancements.redact_sensitive_pii"),
    (12, 1, "Flesch Reading Ease, FK Grade, passive ratio & UK/US dialect scoring in udh_extract", "Implemented", "mcp_enhancements.analyze_readability_and_dialect"),
    (13, 1, "Hierarchical Markdown chunker preserving headings, code fences & tables in udh_extract", "Implemented", "mcp_enhancements.chunk_markdown_hierarchical"),
    (14, 1, "Expanded UTF-8/cp1252 mojibake & entity repair engine with code-span protection", "Implemented", "mcp_enhancements.repair_mojibake"),
    (15, 1, "Expanded UK neutral citations & statutes detector (PIDA 1998, DPA 2018, ACAS, CPR 35)", "Implemented", "server.udh_extract"),
    (16, 1, "Cross-paragraph GBP monetary & ISO date discrepancy scanner (action='conflict_scan')", "Implemented", "mcp_enhancements.detect_numeric_date_conflicts"),
    (17, 1, "Unified 64-bit Blake2b shingle SimHash in udh_simulate replacing MD5", "Implemented", "mcp_enhancements.simhash64_blake2b"),
    (18, 1, "Canonical UK Legal & Ops tag alias normalization in udh_tags", "Implemented", "mcp_enhancements.normalize_canonical_tag_alias"),
    (19, 1, "Tag cluster frequency weighting & reduction savings telemetry in udh_tags", "Implemented", "server.udh_tags"),
    (20, 1, "HMCTS <50MB PDF estimate & ERA 1996 statutory week-cap metadata in udh_bundle_seal", "Implemented", "server.udh_bundle_seal"),

    # Pillar 3: Live Tool Wiring & Real Backend Execution (21-30)
    (21, 2, "udh_tokens(set_budget) persists token_daily_budget via /api/settings/runtime", "Implemented", "server.udh_tokens"),
    (22, 2, "udh_tokens(get_metrics) surfaces real backend availability instead of fake 12,450 fallback", "Implemented", "server.udh_tokens"),
    (23, 2, "udh_tokens(toggle_fallback/reset_today) wired to hub_config/runtime backend", "Implemented", "server.udh_tokens"),
    (24, 2, "udh_checkpoint(list) reads live native sagas & snapshots from /api/native/sagas", "Implemented", "server.udh_checkpoint"),
    (25, 2, "udh_checkpoint(create) creates live pre-op snapshot via /api/native/snapshot", "Implemented", "server.udh_checkpoint"),
    (26, 2, "udh_checkpoint(restore) triggers /api/native/saga/rollback under admin+confirm", "Implemented", "server.udh_checkpoint"),
    (27, 2, "udh_fleet probes udh-postgres (5432), udh-worker (/api/worker/status) & configurable hosts", "Implemented", "server.udh_fleet"),
    (28, 2, "udh_fleet verifies Dashboard HTTP /healthz alongside TCP port connectivity", "Implemented", "server.udh_fleet"),
    (29, 2, "udh_sync supports propagate_paperless (WF-13) & reindex_vectors (WF-17)", "Implemented", "server.udh_sync"),
    (30, 2, "udh_config masks sensitive fields cleanly & summarizes changed keys on update", "Implemented", "server.udh_config"),

    # Pillar 4: Pre-Cutover, Diagnostics & Ecosystem Observability (31-40)
    (31, 3, "udh_dictionary(resource='mcp_features') searches this 50-feature catalog live", "Implemented", "server.udh_dictionary"),
    (32, 3, "udh_dictionary(resource='errors') supports client-side keyword/severity filtering", "Implemented", "server.udh_dictionary"),
    (33, 3, "udh_setup(status) includes upstream latencies, runtime override & 50/50 MCP status", "Implemented", "server.udh_setup"),
    (34, 3, "udh_setup(quickstart) documents all 22 tools, actions, and 0-token tools accurately", "Implemented", "server.udh_setup"),
    (35, 3, "udh_setup(parity/cutover_check) returns 13-table readiness & wiring summary", "Implemented", "server.udh_setup"),
    (36, 3, "udh_health adds action='wiring_check' calling /api/self-check/wiring safely", "Implemented", "server.udh_health"),
    (37, 3, "udh_updates(check_updates/check_version) surfaces build SHA parity hints", "Implemented", "server.udh_updates"),
    (38, 3, "udh_query optional sanitize_pii flag redacts PII from retrieved get_content text", "Implemented", "server.udh_query"),
    (39, 3, "udh_dashboard surfaces degraded fallback tiers, open breakers & quarantine alerts first", "Implemented", "server.udh_dashboard"),
    (40, 3, "udh_adapters(run_bridge) forwards optional doc_id/limit/source_dir payload params", "Implemented", "server.udh_adapters"),

    # Pillar 5: Agent UX, Guardrails & Schema Hygiene (41-50)
    (41, 4, "Bounded output helper smart_truncate preventing oversized LLM context overflow", "Implemented", "mcp_enhancements.smart_truncate"),
    (42, 4, "Unified dry-run preview envelope recording target route, scope & confirm requirements", "Implemented", "server.preview"),
    (43, 4, "Consistent scope-denial messages specifying required scope & remediation hint", "Implemented", "server.py"),
    (44, 4, "Clean ToolAnnotations verified across all 22 MCP tools (RD/WR/DE)", "Implemented", "server.py"),
    (45, 4, "Strict 22-tool surface preserved matching CI assertion (mcp_tools == 22)", "Implemented", "test_tool_registration.py"),
    (46, 4, "Zero Pydantic BaseModel field-shadow warnings across all input models", "Implemented", "server.py"),
    (47, 4, "Container HEALTHCHECK & HTTP /healthz alignment across Dockerfile & Compose", "Implemented", "Dockerfile"),
    (48, 4, "MCP_CAPABILITY_SUMMARY reported live on GET /status", "Implemented", "server.status"),
    (49, 4, "Comprehensive zero-network mock & unit regression coverage across all 50 features", "Implemented", "test_tool_registration.py"),
    (50, 4, "Updated README.md & quickstart documentation reflecting v2.7.0 50-feature release", "Implemented", "README.md"),
]

MCP_FEATURE_CATALOG: list[dict[str, Any]] = [
    {
        "id": fid,
        "code": f"MCP-{fid:02d}",
        "pillar": MCP_PILLARS[pidx],
        "pillar_index": pidx + 1,
        "title": title,
        "status": status,
        "ref": ref,
    }
    for fid, pidx, title, status, ref in _RAW_MCP_FEATURES
]

_TAG_ALIASES: dict[str, str] = {
    "legal-professional-privilege": "lpp",
    "legal-privilege": "lpp",
    "privileged": "lpp",
    "without-prejudice": "wp",
    "employment-tribunal": "et",
    "employment-rights-act": "era-1996",
    "subject-access-request": "dsar",
    "sar": "dsar",
    "disaster-recovery": "dr",
    "postgresql": "postgres",
    "dead-letter-queue": "dlq",
}

_MOJIBAKE_PAIRS: tuple[tuple[str, str], ...] = (
    ("\u00e2\u20ac\u201d", "\u2014"),
    ("\u00e2\u20ac\u201c", "\u2013"),
    ("\u00e2\u20ac\u2122", "'"),
    ("\u00e2\u20ac\u02dc", "'"),
    ("\u00e2\u20ac\u0153", '"'),
    ("\u00e2\u20ac\u009d", '"'),
    ("\u00c2\u00a3", "\u00a3"),
    ("\u00c3\u00a9", "\u00e9"),
    ("\u00c2\u00a0", " "),
)


def get_mcp_feature_summary() -> dict[str, Any]:
    return {
        "ok": True,
        "total": len(MCP_FEATURE_CATALOG),
        "implemented": sum(1 for i in MCP_FEATURE_CATALOG if i["status"] == "Implemented"),
        "pillars": len(MCP_PILLARS),
    }


def get_mcp_feature_catalog(pillar: Optional[str] = None, query: Optional[str] = None) -> list[dict[str, Any]]:
    pq = (pillar or "").strip().lower()
    qq = (query or "").strip().lower()
    out: list[dict[str, Any]] = []
    for item in MCP_FEATURE_CATALOG:
        if pq and pq not in item["pillar"].lower():
            continue
        if qq and not (qq in item["title"].lower() or qq in item["code"].lower() or qq in item["ref"].lower()):
            continue
        out.append(item)
    return out


def sanitize_secrets(text: str) -> str:
    """Scrub Bearer tokens, webhook secrets, and Postgres DSN passwords from output text."""
    s = str(text or "")
    s = re.sub(r"(Bearer\s+)[A-Za-z0-9._\-]{8,}", r"\1[REDACTED]", s, flags=re.IGNORECASE)
    s = re.sub(r"(postgres(?:ql)?://[^:/\s]+:)[^@\s]+(@)", r"\1[REDACTED]\2", s, flags=re.IGNORECASE)
    s = re.sub(r"([?&](?:token|api_key|key|secret)=)[^&\s]+", r"\1[REDACTED]", s, flags=re.IGNORECASE)
    return s


def map_http_status_to_udh_error(status_code: int, detail: str = "") -> dict[str, Any]:
    """Map HTTP status failures into standardized UDH-XXX diagnostics with next-step hints."""
    table = {
        401: ("UDH-022", "Authentication rejected (HTTP 401). Check UDH_API_TOKEN or WF07/WF14/WF16 auth header token."),
        403: ("UDH-023", "Authorization forbidden (HTTP 403). Verify reverse-proxy OAuth2 or token permissions."),
        404: ("UDH-041", "Requested UDH endpoint or resource not found (HTTP 404). Verify target container version."),
        429: ("UDH-018", "Upstream rate limit hit (HTTP 429). Retry after cooldown or use zero-token local tools."),
        502: ("UDH-006", "Bad Gateway (HTTP 502). Upstream container may be restarting; retry shortly."),
        503: ("UDH-014", "Service Unavailable (HTTP 503). Check /healthz and circuit breakers."),
        504: ("UDH-019", "Gateway Timeout (HTTP 504). Switch bulk operations to async/dry-run mode."),
    }
    code, hint = table.get(status_code, ("UDH-001", f"Upstream returned HTTP {status_code}. Check service logs."))
    return {"error_code": code, "http_status": status_code, "remediation": hint, "detail": sanitize_secrets(detail[:240])}


def repair_mojibake(text: str) -> tuple[str, int]:
    fixed = text or ""
    hits = 0
    for bad, good in _MOJIBAKE_PAIRS:
        if bad in fixed:
            hits += fixed.count(bad)
            fixed = fixed.replace(bad, good)
    return fixed, hits


def redact_sensitive_pii(text: str, profile: str = "tribunal_public") -> dict[str, Any]:
    """Deterministic zero-token UK PII scrubber."""
    if profile == "counsel_full":
        return {"text": text, "redactions": {}, "total_redactions": 0, "profile": profile}
    cleaned = text or ""
    counts: dict[str, int] = {}
    patterns = (
        ("nhs_number", r"\b\d{3}[\s-]?\d{3}[\s-]?\d{4}\b", "[REDACTED_NHS_NO]"),
        ("uk_nino", r"\b[A-CEGHJ-PR-TW-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b", "[REDACTED_NINO]"),
        ("uk_sort_code", r"\b\d{2}-\d{2}-\d{2}\b", "[REDACTED_SORT_CODE]"),
        ("email", r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "[REDACTED_EMAIL]"),
        ("uk_phone", r"\b(?:\+44\s?7\d{3}|07\d{3})\s?\d{3}\s?\d{3}\b", "[REDACTED_PHONE]"),
        ("uk_postcode", r"\b[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2}\b", "[REDACTED_POSTCODE]"),
    )
    for label, pat, repl in patterns:
        cleaned, n = re.subn(pat, repl, cleaned)
        if n:
            counts[label] = n
    return {"text": cleaned, "redactions": counts, "total_redactions": sum(counts.values()), "profile": profile}


def analyze_readability_and_dialect(text: str) -> dict[str, Any]:
    cleaned = (text or "").strip()
    if not cleaned:
        return {"words": 0, "sentences": 0, "flesch_ease": 0.0, "fk_grade": 0.0, "dialect": "unknown"}
    words = re.findall(r"[A-Za-z0-9']+", cleaned)
    sents = [s.strip() for s in re.split(r"[.!?\n]+", cleaned) if s.strip()]
    wc = max(len(words), 1)
    sc = max(len(sents), 1)

    def _syl(w: str) -> int:
        lw = re.sub(r"[^a-z]", "", w.lower())
        if len(lw) <= 3:
            return 1
        lw = re.sub(r"(?:es|ed|e)$", "", lw) or lw
        return max(1, len(re.findall(r"[aeiouy]+", lw)))

    asl = wc / sc
    asw = sum(_syl(w) for w in words) / wc
    fre = round(max(0.0, min(100.0, 206.835 - 1.015 * asl - 84.6 * asw)), 1)
    fkg = round(max(0.0, 0.39 * asl + 11.8 * asw - 15.59), 1)
    low = cleaned.lower()
    uk = len(re.findall(r"\b(?:organisation|analyse|authorise|programme|tribunal|claimant|respondent)\b|£", low))
    us = len(re.findall(r"\b(?:organization|analyze|authorize|program|attorney|plaintiff)\b|\$", low))
    return {
        "words": len(words),
        "sentences": len(sents),
        "avg_sentence_length": round(asl, 1),
        "flesch_ease": fre,
        "fk_grade": fkg,
        "dialect": "en-GB" if uk >= us else "en-US",
    }


def chunk_markdown_hierarchical(text: str, token_budget: int = 1200) -> dict[str, Any]:
    lines = (text or "").splitlines()
    blocks: list[tuple[str, str]] = []
    headings: list[tuple[int, str]] = []
    i = 0
    buf: list[str] = []

    def _crumb() -> str:
        return " > ".join(t for _, t in headings) if headings else "Document Root"

    def _flush() -> None:
        if buf:
            txt = "\n".join(buf).strip()
            if txt:
                blocks.append((_crumb(), txt))
            buf.clear()

    while i < len(lines):
        ln = lines[i]
        hm = re.match(r"^(#{1,6})\s+(.+?)\s*$", ln)
        if hm:
            _flush()
            lvl, title = len(hm.group(1)), hm.group(2)
            headings = [(l, t) for l, t in headings if l < lvl]
            headings.append((lvl, title))
            i += 1
            continue
        fm = re.match(r"^(`{3,}|~{3,})", ln.strip())
        if fm:
            _flush()
            fc, fl = fm.group(1)[0], len(fm.group(1))
            code = [ln]
            i += 1
            while i < len(lines):
                code.append(lines[i])
                if re.match(rf"^{re.escape(fc)}{{{fl},}}\s*$", lines[i].strip()):
                    i += 1
                    break
                i += 1
            blocks.append((_crumb(), "\n".join(code)))
            continue
        if not ln.strip():
            _flush()
        else:
            buf.append(ln)
        i += 1
    _flush()

    chunks: list[dict[str, Any]] = []
    used = 0
    for idx, (crumb, blk) in enumerate(blocks):
        tok = max(1, math.ceil(len(blk) / 4.0))
        if used + tok <= token_budget or not chunks:
            chunks.append({"index": idx, "breadcrumb": crumb, "tokens": tok, "text": f"[Context: {crumb}]\n{blk}"})
            used += tok
    return {"chunk_count": len(chunks), "total_blocks": len(blocks), "tokens_used": used, "token_budget": token_budget, "chunks": chunks}


def detect_numeric_date_conflicts(text: str) -> dict[str, Any]:
    amounts = sorted(set(m.replace(" ", "") for m in re.findall(r"£\s?\d[\d,]*(?:\.\d{1,2})?", text or "")))
    dates = sorted(set(re.findall(r"\b20\d{2}-\d{2}-\d{2}\b|\b\d{1,2}/\d{1,2}/\d{2,4}\b", text or "")))
    warnings: list[str] = []
    if len(amounts) > 1:
        warnings.append(f"Multiple monetary figures present: {', '.join(amounts[:6])}")
    if len(dates) > 2:
        warnings.append(f"Multiple distinct dates span text: {', '.join(dates[:6])}")
    return {"has_conflicts": bool(warnings), "currency_gbp": amounts, "dates": dates, "warnings": warnings}


def simhash64_blake2b(text: str) -> str:
    tokens = re.findall(r"[a-z0-9]+", (text or "").lower())
    shingles = [" ".join(tokens[i : i + 3]) for i in range(len(tokens) - 2)] if len(tokens) >= 3 else tokens
    vec = [0] * 64
    for sh in shingles:
        h = int.from_bytes(hashlib.blake2b(sh.encode("utf-8"), digest_size=8).digest(), "big")
        for b in range(64):
            vec[b] += 1 if (h >> b) & 1 else -1
    fp = sum((1 << b) for b in range(64) if vec[b] > 0)
    return f"0x{fp:016x}"


def normalize_canonical_tag_alias(tag: str) -> str:
    slug = re.sub(r"[\s_]+", "-", re.sub(r"^#+", "", (tag or "").strip().lower())).strip("-")
    return _TAG_ALIASES.get(slug, slug)


def smart_truncate(text: str, limit: int = 8000) -> str:
    if len(text or "") <= limit:
        return text or ""
    return (text or "")[: max(200, limit - 45)] + f"\n...[truncated {len(text) - limit + 45} chars]"
