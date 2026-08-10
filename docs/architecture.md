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
