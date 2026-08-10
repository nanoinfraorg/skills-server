# Architecture

## Agent Skill format

Skills are validated against the same `SKILL.md` frontmatter format
documented in nanoinfra's `skill-creator` skill and at
<https://agentskills.io/specification>: `name` (1-64 chars, lowercase
letters/digits/hyphens, no leading/trailing/consecutive hyphens) and
`description` (required, max 1024 chars), plus optional
`scripts/`/`references/`/`assets/` directories.

## Versioning model

Every successful publish creates a new, immutable `skill_versions` row
rather than overwriting anything: `skill_versions` is the full history
(one row per version, `version` a monotonic integer starting at 1), and
`skills` is a thin pointer holding `current_version` plus an aggregate
download counter that keeps incrementing across every version. Search,
trending, the detail endpoint, and downloads all resolve through
`current_version`.

Submitting again for a `skill_id` that's already published is an update,
not a new skill -- there's no separate "update" endpoint, it's the same
submit → pending → admin approve → publish flow. On publish, the new
version's row is inserted and the pointer moves to it; every earlier
version's row stays.

- `GET /api/v1/skills/{id}/versions` lists the whole history.
- `GET /api/v1/skills/{id}/versions/{version}` returns one version plus
  its latest scan report.

A version the scan shield later blocks (manual rescan or the daily
scheduler) is marked `quarantined`, not deleted. Search and trending
exclude a quarantined current version; detail/versions still show it,
clearly marked. Download treats it as not-found (see
[design-choices.md](design-choices.md)).

## Workflow

1. **Submit** -- `POST /api/v1/submissions` (zip + `skill_id` +
   `display_name` + `submitter`). Validated immediately (missing
   `SKILL.md`, unsafe paths, oversized archive, bad `skill_id`) and
   stored as `pending`.
2. **Preview** (optional) -- `POST /api/v1/scan/{submission_id}` shows the
   scan shield's verdict without approving/rejecting anything.
3. **Moderate** -- an admin lists pending submissions and approves or
   rejects each one.
4. **Pipeline + scan** (on approve) -- the archive is re-validated from
   scratch (frontmatter, zip path-safety, size caps) as the authoritative
   gate, then run through the scan shield. Both run synchronously in the
   approve request.
5. **Publish** -- if the pipeline passes and the scan isn't `blocked`,
   every file is committed into `nanoinfraorg/skills` under `<skill_id>/`
   via the GitHub Contents API, a new `skill_versions` row is created,
   and the skill becomes visible in the public catalog. Otherwise the
   submission is auto-rejected with the failure/scan summary as the
   reason.
6. **Discover** -- the public catalog serves published, non-quarantined
   skills via search and trending (by downloads); detail/versions also
   surface quarantined skills, clearly marked; download serves the
   current version's archive (unless quarantined).

## The scan shield

Every archive that passes pipeline validation runs through
`internal/scan` before it's published:

- **Text-only check** -- every file must decode as valid UTF-8 with no
  NUL bytes. A deliberately simple heuristic, not full MIME sniffing.
- **Hidden/invisible Unicode detection** -- zero-width characters
  (ZWSP/ZWNJ/ZWJ/ZWNBSP), Trojan Source bidi controls (U+202A-U+202E,
  U+2066-U+2069), and the Unicode Tags block (U+E0000-U+E007F, the
  2024-disclosed ASCII-smuggling technique for hiding LLM-readable,
  human-invisible instructions). A leading BOM on the first file read is
  allowed; every other occurrence is flagged with file, codepoint, and
  line.
- **Static suspicious-pattern check** -- a short, best-effort list:
  pipe-to-shell one-liners (`curl|sh`, `wget|bash`) and long
  base64-like blobs (200+ chars), as a proxy for obfuscated payloads.
- **Optional LLM classification** -- if `LLM_API_BASE`/`LLM_API_KEY`/
  `LLM_MODEL` are all set, the skill's text content (capped at 40,000
  chars) is classified as `safe`/`suspicious`/`malicious` by an
  OpenAI-compatible endpoint. Unset or unparseable → skipped, never
  blocks a scan.

**Verdict**: `blocked` if the text-only check fails, or any hidden-char
finding exists, or any static pattern matches (deterministic hard
gates). `flagged` if none of those tripped but the LLM says
`suspicious`/`malicious`. `pass` otherwise. The LLM verdict can only
downgrade a clean scan to `flagged` for human review -- it can never
escalate to `blocked` on its own.

A `blocked` verdict during approval auto-rejects the submission.
`flagged`/`pass` proceed to publish; the scan result is stored either
way.

A daily scheduler (`DAILY_SCAN_INTERVAL`, default `24h`) re-scans every
non-quarantined skill's current version and quarantines any that newly
come back `blocked` -- catching skills published before the shield
existed, or before a scanner change.

## VirusTotal integration

An optional second, third-party opinion alongside the scan shield above:
[VirusTotal](https://www.virustotal.com)'s multi-engine antivirus sweep
(~70 independent AV engines) against the same published archive.
Implemented in `internal/virustotal`, wrapping the official
[`github.com/VirusTotal/vt-go`](https://github.com/VirusTotal/vt-go)
client.

**Optional, unconfigured by default.** If `VIRUSTOTAL_API_KEY` is unset,
this entire feature is skipped: no upload is attempted, the background
poller never starts, and no "VirusTotal" entry ever appears in the skill
detail page's Security Audits panel -- not even a "not configured"
placeholder. This mirrors the scan shield's own optional LLM
classification pass exactly.

**Why async, unlike the scan shield.** The scan shield's checks
(text-only, hidden characters, static patterns, optional LLM) all run
synchronously inline in the approve request -- they're fast and bounded.
VirusTotal's actual multi-engine analysis is neither: it can take
anywhere from a few seconds to a couple of minutes, since the upload is
queued behind dozens of independent AV engines outside this server's
control. Running that inline would make every approve request that slow
(or far slower during a VirusTotal outage), so this is instead a
fire-and-forget upload plus a background poller -- the same
"synchronous core + async re-check" shape the daily scan scheduler above
already established for a different problem (catching skills that later
turn out bad), applied here to a different one (waiting on a slow third
party):

1. **Upload, on publish.** Right after `ApproveSubmissionCore`
   (`internal/api/admin.go`) successfully publishes a new skill version,
   it launches a goroutine (`context.Background()`, not the request's
   own context, which is canceled the instant the response is sent) that
   re-zips the already-validated, already-in-memory file contents (no
   second disk read, no re-fetch from GitHub) and uploads that archive to
   VirusTotal. A successful upload inserts a `virustotal_scans` row with
   status `pending` and VirusTotal's analysis ID. An upload error
   (network, rate limit, invalid key) is logged and creates no row at
   all -- the panel shows nothing for VirusTotal on that skill, identical
   to VirusTotal not being configured. Either way, the approve request
   itself has already returned; nothing here can slow it down or fail it.
2. **Poll, in the background.** A separate goroutine
   (`internal/virustotal.Run`, started from `main.go` only when
   `VIRUSTOTAL_API_KEY` is set) ticks every `VIRUSTOTAL_POLL_INTERVAL`
   (default `3m` -- VirusTotal's free tier is rate-limited to roughly 4
   requests/minute and ~500/day, so this is deliberately much less
   aggressive than `DAILY_SCAN_INTERVAL`) and checks every `pending` row.
   Still queued → left alone. A transient check failure (network error,
   429 rate limit, ...) is logged and the row stays `pending` for the
   next tick -- never retried in a hot loop, and one bad row never stops
   the rest of that pass. Completed → the per-engine stats
   (`malicious`/`suspicious`/`harmless`/`undetected` counts) and a GUI
   permalink are recorded and the row flips to `completed`. If VirusTotal
   returns a definitive "completed" response whose stats aren't in the
   expected shape, the row flips to `error` instead (so the poller stops
   spending API calls on something that will never resolve) -- a
   different failure mode from a transient one, which stays `pending`.
3. **Backfill, in the daily scheduler.** A skill version published before
   `VIRUSTOTAL_API_KEY` was ever set has no `virustotal_scans` row and so
   never shows a VirusTotal entry -- the exact same "published before the
   feature existed" gap the daily scheduler's own scan-shield re-scan
   already exists to close (see above). So each daily pass
   (`internal/scheduler.RunOnce`) also checks, for every active skill's
   current version, whether a `virustotal_scans` row exists yet; if not
   (and VirusTotal is configured), it uploads exactly once, the same
   fire-and-forget way `ApproveSubmissionCore` does. A version that
   already has a row -- in any status, including `error` -- is never
   re-uploaded: this backfill is a one-time catch-up per version, not a
   recurring re-check, so it can't turn into a second daily source of
   VirusTotal API calls on top of the poller's own.

**Verdict mapping.** `internal/virustotal.ComputeVerdict(malicious,
suspicious int64) string` maps the completed stats to the Security Audits
panel's `pass`/`warn`/`fail` vocabulary:

- `fail` if any engine reports the file outright malicious -- the
  strongest signal VirusTotal offers.
- `warn` (not `fail`) if none reported malicious but at least one
  reported merely "suspicious" -- a softer, heuristics-only signal that's
  prone to false positives across ~70 independent engines, so it's a
  human-review flag rather than a hard finding.
- `pass` otherwise.

**Deliberate scoping decision: no auto-quarantine.** Unlike the scan
shield's daily re-scan, which quarantines a skill the moment it comes
back `blocked`, nothing in `internal/virustotal` ever calls
`store.SetSkillVersionStatus`. Multiple independent AV engines produce
false positives regularly enough (a heuristic "suspicious" verdict on a
handful of engines, out of ~70, is common for entirely legitimate
scripts) that auto-quarantining on a VirusTotal finding alone would be a
much bigger policy decision than "add a badge to a panel". This phase
only records and displays the result; deciding whether/how a VirusTotal
finding should ever affect a skill's availability is left for later, and
is called out explicitly in `internal/virustotal/poller.go`'s doc
comments.

Data lives in its own `virustotal_scans` table (not a column on `scans`):
VirusTotal's shape -- an analysis id, per-engine stats, a permalink --
doesn't fit `scans`' shape, and conflating "our own deterministic+LLM
shield" with "a third-party multi-engine AV sweep" in one table would
make both harder to reason about.
