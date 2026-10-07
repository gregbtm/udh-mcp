# udh-mcp Improvement Roadmap

Backlog produced by a full review of the Universal Document Hub (all 16
n8n workflows, WF-01 through WF-16) against udh-mcp's current 7-tool
surface, done before any live deployment. Nothing here is built yet —
this is the list of gaps and improvements, kept separate from `CLAUDE.md`
(which documents what exists) per this homelab's own Scope Discipline
convention (see `matrix-homelab-gitops-facts`).

Each item names whether it needs a new/changed n8n workflow (matrix-homelab
side) or is purely a udh-mcp server change, since those are very different
amounts of work and risk.

---

## A. Workflows with zero external surface today

These run on cron or are only ever called internally by another workflow.
Nothing — not udh-mcp, not the dashboard, not a human — can trigger or
read them on demand. This is the single biggest coverage gap: a system
whose health/integrity checks can't be asked for is a system you can only
find out is broken after the fact.

### A1. WF-08 adapter-health-check
**What it does:** per-target round-trip check — write a canary record to
each adapter and confirm it comes back, catching an adapter that's
silently broken (auth expired, API changed) before real documents start
failing against it.

**Gap:** `WF-14`'s own dashboard payload *explicitly omits* this data —
its own build notes say "no real source exists for it yet". There is
currently no way to answer "is the Notion adapter actually working right
now" without triggering a real sync and watching it fail.

**Proposed addition:** new tool `udh_health`:
- `check(target_id=None)` — run WF-08 now, for one target or all of
  them. Needs a new webhook trigger on WF-08 (currently internal/cron
  only).
- `last_result(target_id=None)` — read the most recent health-check
  result without re-running it (cheap, for a dashboard-style poll).

**n8n work needed:** add a webhook trigger node to WF-08, store its
results somewhere WF-14/WF-16 can read (a new `health_check_log` table,
or reuse `operation_log` with `operation='health_check'`).

### A2. WF-11 integrity-check
**What it does:** weekly SHA-256 verification of every canonical file,
flags orphaned target IDs.

**Gap:** same as WF-08 — `WF-14` omits this too, for the same stated
reason. A corrupted canonical file or an orphaned Trilium note sits
undetected for up to a week, and there's no way to ask "did the weekly
check already run, and what did it find?" without digging into n8n's
own execution log directly.

**Proposed addition:** new tool `udh_integrity`:
- `check(case_folder=None)` — trigger WF-11 now, optionally scoped to
  one case folder rather than the whole registry (a full-registry check
  could be slow against a large corpus).
- `last_report()` — read the most recent report (hash mismatches,
  orphaned IDs, counts).

**n8n work needed:** webhook trigger on WF-11, persisted report row
(a new `integrity_report` table or `operation_log` entries).

### A3. WF-09 pre-op-snapshot
**What it does:** exports the full `doc_registry` to
`/doc-hub/snapshots/registry-<iso>.json` before a bulk operation.

**Gap:** only ever called automatically, immediately before something
risky. There's no way to take a safety snapshot on demand before a
human-initiated risky action (e.g. "I'm about to bulk-resolve 12
conflicts, snapshot first").

**Proposed addition:** expose as its own action inside `udh_lifecycle`
(`action='snapshot'`) or a dedicated `udh_snapshot` tool —
`create()` / `list()` (what snapshots exist, how old is the newest one).

**n8n work needed:** webhook trigger on WF-09; it already writes to a
predictable path, so `list()` could just need a FileStation-style
directory read (out of scope for n8n, in scope for whatever reads that
path — possibly `syno_files` on the `synology-proxy-mcp` side instead,
worth considering before building a second path to the same data).

### A4. WF-01 scan-source / WF-01b refetch-folder
**What it does:** WF-01 walks the entire `/legal` NAS tree looking for
new/changed files; WF-01b re-scans one specific folder on demand (already
webhook-triggered — it's the "existing Phase 0b" workflow, unchanged).

**Gap:** `udh_sync`'s `scan_drift` action checks **existing** registry
entries for drift (moved/deleted/changed) — it does not discover **new**
files that have never been registered. There's no "go look at the NAS
again from scratch" action, and no MCP wrapper for the one folder-level
refetch that already has a webhook.

**Proposed addition:**
- Add `rescan_folder` to `udh_sync`'s action list, wrapping WF-01b's
  existing webhook directly (lowest-effort item in this whole doc — the
  trigger already exists, it just isn't wrapped).
- A separate, explicitly heavier `rescan_all` action for WF-01 itself —
  gate this one behind `admin` scope even though it's not destructive,
  since a full NAS walk is expensive and shouldn't be callable casually.

**n8n work needed:** none for `rescan_folder` (webhook already exists).
WF-01 itself needs a new webhook trigger for `rescan_all`.

### A5. WF-05a/WF-05b schedulers
**What it does:** WF-05a polls inbound sources on a schedule per-target;
WF-05b runs an outbound publish wave on a schedule.

**Gap:** cron-only. Testing a newly-configured or newly-debugged target
means waiting for its next scheduled tick rather than being able to say
"run this target's inbound poll right now."

**Proposed addition:** `udh_sync` gains `poll_target(target_id)` /
`publish_wave()` actions that fire the scheduler's own logic
out-of-band.

**n8n work needed:** webhook triggers on both WF-05a and WF-05b (neither
has one today — they're pure `Schedule Trigger` nodes).

### A6. WF-15 historical-trilium-backfill
**What it does:** one-time tool that backfilled the existing Trilium
vault into the registry.

**Gap:** no trigger surface at all — fine if it's genuinely one-and-done,
but if a second Trilium vault or a new case folder's historical notes
ever need the same treatment, there's currently no way to run it again
without going into n8n directly.

**Proposed addition:** low priority. If it comes up again, wrap it as an
`admin`-scoped action in `udh_lifecycle` rather than building a dedicated
tool for a one-time operation.

---

## B. Document content access — the sharpest functional gap

`udh_query` returns **metadata** (`doc_registry` rows) — never the
canonical document's actual text. Any scenario shaped like "summarize
this document," "what does the version TriliumNext has differ from
Notion's," or "show me what `udh_conflicts` is about to discard" is
currently unanswerable through this server. An LLM operating UDH through
udh-mcp today is blind to the one thing a document hub's whole job is to
hold: the documents.

### B1. `udh_query(kind='get_content')`
Returns the canonical `.md` file's full body (front-matter + content) for
a given `doc_id`, not just its registry row. The highest-value single
addition in this entire document — almost every other improvement here
is about *operating* UDH; this one is about actually *reading* it.

### B2. `udh_query(kind='get_target_version')`
For a given `doc_id` + `target_id`, fetch what's actually live in that
target system right now (e.g. the current Trilium note body), not the
canonical copy. Lets a caller compare before resolving a conflict instead
of trusting `winner_target_id` blind — today `udh_conflicts` picks a
winner without ever showing what's being discarded.

**n8n work needed:** B1 is a straightforward addition to WF-16 (read the
file at `canonical_path`, same pattern `get_document` already uses for
the registry row). B2 needs per-target read logic WF-16 doesn't have
today — realistically it means calling each target's own inbound
adapter's read path, which is more involved; scope this one carefully
before committing to it.

---

## C. hub_config / target_config are read-only through MCP

`udh_dashboard` reads `hub_config`/`target_config` in full. Nothing
writes any of it except the two fields WF-07 already exposes
(`global_pause`, per-target `enabled`). Every other field — the knobs
that actually tune how aggressively or cautiously UDH behaves — can only
be changed by hand-editing the n8n Data Table UI directly, invisible to
any MCP client and to any audit trail this server keeps.

### C1. `udh_config` (new tool) — hub_config field setters
- `get()` — already available via `udh_dashboard`, but add a direct
  path so a caller doesn't need the whole dashboard payload just to read
  config.
- `set(dry_run=..., max_global_batch=..., quarantine_after_errors=...,
  circuit_breaker_threshold=..., conflict_timeout_hours=...,
  backup_versions_to_keep=..., lock_timeout_seconds=...,
  snapshot_keep_count=..., pre_bulk_snapshot=...)` — any subset, merged
  onto current values (same "fetch current, merge caller's change,
  resend everything" pattern `synology-proxy-mcp`'s `dsm_security_set()`
  had to adopt after its own partial-update bug).

**Gating:** `admin` scope — these knobs affect every target at once
(`circuit_breaker_threshold` especially: set it wrong and either nothing
ever halts on errors, or everything halts on a blip).

### C2. Richer `udh_targets` — per-target field setters
Today: only `inbound_enabled`/`outbound_enabled`. Missing, all real
`target_config` columns with no setter:
- `sync_direction` (the enum itself, not just the two booleans —
  `paused` is the one true single-target emergency brake and currently
  unreachable)
- `source_priority` (who wins conflicts)
- `conflict_action` (`source_wins`/`auto_merge`/`notify_only`/`queue`/`ignore`)
- `poll_interval_mins`
- `blocked_sensitivity_levels` (the comma-separated CDF sensitivity gate
  — currently only settable by hand, meaning there's no way to
  programmatically tighten what an external SaaS target like Notion can
  receive)
- `max_batch_size`

**Proposed shape:** either extend `udh_targets` with a generic
`set_field(target_id, field, value)`, or add dedicated actions per field
if validation needs to differ per field (e.g. `conflict_action` has a
fixed enum, `poll_interval_mins` just needs to be a positive integer).

**n8n work needed:** both C1 and C2 need new WF-07 actions (or a single
generic `set_hub_config`/`set_target_config` action each) — these are
n8n changes, not just udh-mcp changes, and not small ones: every field
touched needs its own validation on the n8n side too, matching WF-07's
existing per-action guard-node pattern.

---

## D. Operational safety nets missing

### D1. Stale lock detection
`doc_registry.locked_by`/`locked_at` exist specifically so a workflow mid-
operation can mark a row as held, with `lock_timeout_seconds` (default
300s) defining how long a lock is allowed to sit before something should
notice. Nothing surfaces this today — a doc stuck locked past its
timeout (a crashed workflow execution, for instance) is invisible.

**Proposed addition:** `udh_query(kind='list_locked')` — rows where
`locked_at` is older than `lock_timeout_seconds`, i.e. genuinely stuck,
not just currently-in-flight.

### D2. Dedup check before `scrape_url`
Calling `scrape_url` twice for the same URL has no guard — it creates a
second source document rather than recognizing the URL was already
ingested. No duplicate-detection exists anywhere in the current action
set.

**Proposed addition:** either (a) a pre-check kind on `udh_query` —
`kind='find_by_url'` — that a caller is expected to run first, or (b)
build the check directly into `udh_sync`'s `scrape_url` handling so it's
not optional. (b) is safer (can't be skipped by an impatient caller) but
is an n8n change to WF-07 itself, not just udh-mcp.

### D3. Bulk conflict resolution
`udh_conflicts` resolves exactly one `doc_id` at a time. After an outage
or a bulk operation, conflicts can pile up faster than they can
reasonably be resolved one call at a time.

**Proposed addition:** `udh_conflicts` gains a `resolve_all(target_id=
None, strategy='source_wins')` action — sweep every open conflict
(optionally filtered to one target) and apply one strategy uniformly.
Needs care: this is strictly more destructive than the existing
single-doc action (undoable-per-doc becomes undoable-per-dozens-of-docs),
so it should require an explicit `confirm=true` **and** probably a dry-
run preview listing exactly which docs it would touch before it touches
them.

### D4. Target decommissioning
No way to retire a `target_config` row at all — connected systems that
get permanently dropped (e.g. a Paperless-NGX instance decommissioned)
leave a dead row in `target_config` forever, and every dashboard/query
call keeps reporting on it.

**Proposed addition:** `udh_targets` gains a `retire(target_id,
confirm=true)` action — `admin`-gated, and should refuse if the target
still has pending/error-status documents rather than silently stranding
them.

---

## E. Server-side design improvements (udh-mcp itself — no n8n changes)

Gaps against `synology-proxy-mcp`'s own established conventions — these
are quality/operability issues, not UDH coverage gaps, and every one of
them is buildable without touching n8n at all.

### E1. No rate limiting
`udh_sync`/`udh_lifecycle` can trigger expensive operations across many
documents. A leaked or brute-forced token has no per-IP throttle today —
`synology-proxy-mcp` has had one (`MCP_RATE_LIMIT_PER_MIN`, a fixed-window
counter) since its own V12 security pass. Same shape would port directly.

### E2. No persistent audit trail
`_TOOL_CALL_STATS` is in-memory only (confirmed in `server.py` — it's a
bare module-level dict). Restart the container and every record of which
token called which tool, when, is gone. `synology-proxy-mcp` has a real
`journal()` writing to persistent storage specifically so a write's
history survives a restart.

### E3. No `/metrics` endpoint
No Prometheus-format series for call counts/error rates/latency per
tool — can't be wired into this homelab's existing Grafana setup the way
`synology-proxy-mcp`'s own `/metrics` route already is. The raw data
(`_TOOL_CALL_STATS`) already exists in memory; this is purely a
formatting/route addition, the cheapest item in this whole section.

### E4. No MCP *resources*
Every piece of state is reached via a tool call. `hub_config`,
`target_config`, and the open `conflict_queue` would be more naturally
exposed as readable MCP resources (e.g. `udh://hub-config`,
`udh://targets`, `udh://conflicts`) per the `mcp-builder` skill's own
guidance on resources-vs-tools — a resource is for "read this piece of
stable state," a tool is for "perform this action," and right now
everything here is modeled as the latter even where the former fits
better. `synology-proxy-mcp` already does this (`rules://all`,
`snapshot://latest`, `health://history`).

### E5. No MCP *prompts*
No canned investigation flows. `synology-proxy-mcp` ships
`onboard_service`, `monthly_review`, `investigate_domain`,
`security_review` as first-class MCP prompts — reusable, named
multi-step procedures a client can invoke directly rather than an LLM
having to reconstruct the right sequence of tool calls from scratch each
time. Candidates for udh-mcp:
- `investigate_conflict` — pull the conflicting doc's full history
  (`recent_operations`), both targets' current content (once B2 exists),
  and the registry row, in one shot.
- `onboard_new_target` — the checklist for adding a target_config row +
  verifying its adapter pair, reusable rather than re-derived per target.
- `incident_triage` — "something's broken": `udh_health` check → `
  udh_query(kind='list_locked')` → `udh_dashboard` recent errors, as one
  guided sequence.

### E6. Fixed timeouts, no override
`dispatch()`/`query()` use fixed 60s/30s timeouts. `publish`/`scan_drift`
can legitimately run long across many documents (recall
`synology-proxy-mcp`'s own hard-won lesson: a slow-but-succeeding DSM
write at 302s was indistinguishable from a hang at a 60s client timeout —
see that repo's `CLAUDE.md` "DSM API Hard-Won Facts"). udh-mcp risks the
exact same failure mode the moment a `publish` across a large batch
takes longer than 60 seconds. Needs a per-action timeout, not a single
global one, mirroring `DSM_HARD_TIMEOUT_SECONDS`'s "never shorter than
what the call site needs" design.

### E7. No per-call dry-run passthrough
`hub_config.dry_run` is global-only. There's no way to simulate a single
`udh_sync` action without flipping the entire system into simulation
mode for everything else running at the same time. A per-call
`dry_run=true` param (passed through to WF-07, which would need to honor
it per-call rather than only reading the global flag) would let a caller
test one action safely without affecting concurrent operations.

---

## Priority call

Ranked by how soon each gap actually bites in real use, not by how
interesting it is to build:

1. **B1 (`get_content`)** and **D1 (`list_locked`)** — an LLM operating
   this system blind to document content or stuck locks is the most
   likely source of a confusing failure, and both are cheap (WF-16
   additions, no new workflow needed for D1 at all).
2. **A1/A2 (WF-08 health, WF-11 integrity)** — "can't tell if something's
   broken" is a real operational blind spot today, not a hypothetical
   one.
3. **D2/D3 (dedup check, bulk conflict resolve)** — safety nets that
   matter most exactly when things have already started going wrong.
4. **C1/C2 (config read-only)** and **E1-E7 (server hardening)** — real,
   but about operability and polish rather than a missing capability;
   nothing here currently causes a wrong answer, just a less convenient
   or less observable one.
