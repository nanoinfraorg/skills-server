# skills-server

A small, self-hosted Agent Skills marketplace: submission intake, admin
moderation, an automatic validate-then-publish pipeline, a security scan
shield, full version history, a daily re-scan scheduler, and a read-only
public catalog. It exists to replace `nanoinfra`'s dependency on the
Chinese-hosted `skillhub.cn` service with a self-hosted alternative backed by
a private GitHub repository (`nanoinfraorg/skills`) as the durable artifact
store. (`skills.sh` support in `nanoinfra` is unaffected and unrelated to
this service.)

The "Agent Skill" format this server validates against (`SKILL.md`
frontmatter with required `name`/`description` fields, optional
`scripts/`/`references/`/`assets/` directories) is documented both in
nanoinfra's `skill-creator` skill and, equivalently, in the public spec at
<https://agentskills.io/specification>. Frontmatter validation here checks
the constraints from that spec: `name` is 1-64 chars, lowercase
letters/digits/hyphens with no leading/trailing/consecutive hyphens;
`description` is required and capped at 1024 characters.

## Versioning model

Every successful publish creates a new, immutable `skill_versions` row
rather than overwriting anything: `skill_versions` is the full version
history (one row per version, `version` a monotonic integer starting at 1),
and `skills` is a thin pointer holding just `current_version` plus an
aggregate download counter that keeps incrementing across every version.
Search, trending, the detail endpoint, and downloads all resolve through
`current_version`.

Submitting again for a `skill_id` that already has a published skill is
treated as an update, not a new skill: the same submit -> pending -> admin
approve -> publish flow handles both (there's no separate "update"
endpoint). On a successful publish, the new version's row is inserted, and
the pointer moves to it; every earlier version's row stays in the table.
`GET /api/v1/skills/{id}/versions` lists that whole history, and
`GET /api/v1/skills/{id}/versions/{version}` returns one version's full
detail plus its latest scan report.

A version the scan shield later finds to be blocked (via a manual admin
rescan or the daily scheduler) is marked `quarantined` rather than deleted.
A quarantined current version is excluded from search and trending
specifically (so it stops circulating), but the detail and versions
endpoints still show it, clearly marked, since an admin or the submitter
needs to be able to see why it was pulled. The download endpoint also
treats a quarantined current version as not-found -- see "Design choices"
below for why that's a deliberate extension beyond the versioning design's
literal wording.

## The scan shield

Every archive that passes pipeline validation (SKILL.md frontmatter,
zip-slip/traversal/symlink safety, size caps) is then run through
`internal/scan`, a small security scanner, before it's published:

- **Text-only check**: every file must decode as valid UTF-8 with no NUL
  bytes. This is a deliberately simple heuristic (not full MIME sniffing) to
  catch "binary disguised as text".
- **Hidden/invisible Unicode character detection**: scans every file's
  decoded runes for zero-width characters (ZWSP/ZWNJ/ZWJ/ZWNBSP), Trojan
  Source bidi control characters (U+202A-U+202E, U+2066-U+2069), and the
  Unicode Tags block (U+E0000-U+E007F, the 2024-disclosed ASCII-smuggling
  technique for hiding LLM-readable, human-invisible instructions). A
  leading BOM on the very first file read is allowed; every other
  occurrence is flagged with its file, codepoint, and line number.
- **Static suspicious-pattern check**: a short, documented, best-effort
  regexp list -- pipe-to-shell one-liners (`curl ... | sh` / `| bash`,
  `wget ... | sh` / `| bash`) and long base64-like blobs (200+ characters),
  as a proxy for obfuscated payloads hiding in a text file.
- **Optional LLM classification**: if `LLM_API_BASE`, `LLM_API_KEY`, and
  `LLM_MODEL` are all set, the skill's concatenated text content (capped at
  40,000 characters) is sent to an OpenAI-compatible `/chat/completions`
  endpoint, asking it to classify the content as `"safe"`, `"suspicious"`,
  or `"malicious"`. If any of the three env vars is unset, this step is
  skipped entirely; if the provider's response can't be parsed, the
  assessment is recorded as absent and a warning is logged -- either way,
  this step never blocks a scan from completing.

**Verdict**: `blocked` if the text-only check fails, OR any hidden-character
finding exists, OR any static pattern matches -- these three are
deterministic hard gates. `flagged` if none of those tripped but the LLM
assessment says `"suspicious"` or `"malicious"`. `pass` otherwise. The LLM
verdict is informational only: it can downgrade an otherwise-clean scan to
`flagged` for a human admin to review, but it can never escalate a scan to
`blocked` on its own -- LLM classification is probabilistic and
provider-dependent, so a human makes the final call on anything not already
caught deterministically.

A `blocked` verdict during approval auto-rejects the submission (the same
auto-reject path a pipeline-validation failure already uses) with the
findings summarized in the rejection reason. `flagged` and `pass` both
proceed to publish; the scan result is stored either way, against the
submission and, once published, against the resulting skill version.

A daily scheduler (`internal/scheduler`, interval configurable via
`DAILY_SCAN_INTERVAL`, default `24h`) re-scans every non-quarantined
skill's current version and quarantines any that newly come back
`blocked` -- this exists to catch skills published before the shield
existed, or that a later scanner change would now flag.

## Workflow

1. **Submit**: `POST /api/v1/submissions` with a zip archive (must contain a
   root `SKILL.md`) plus `skill_id`, `display_name`, and `submitter` fields.
   The archive is validated immediately (missing `SKILL.md`, unsafe paths,
   oversized archives, invalid `skill_id` are all rejected here) and, if it
   passes, stored with status `pending`.
2. **Preview (optional)**: a submitter or admin can call
   `POST /api/v1/scan/{submission_id}` to see the scan shield's verdict
   before an admin decides, without approving/rejecting anything.
3. **Moderate**: an admin lists pending submissions
   (`GET /api/v1/admin/submissions?status=pending`) and either approves or
   rejects each one.
4. **Pipeline + scan** (on approve): the archive is *re-validated from
   scratch* -- SKILL.md frontmatter/structure, zip path-safety (zip-slip,
   absolute paths, symlinks, `..` traversal, duplicate entries, size caps)
   -- as the authoritative, tamper-resistant gate, then run through the scan
   shield described above. Both run synchronously inside the approve
   request (see "Design choices" below for why).
5. **Publish**: if the pipeline passes and the scan verdict isn't `blocked`,
   every file in the archive is committed into `nanoinfraorg/skills` under
   `<skill_id>/` on `main` via the GitHub Contents API, a new
   `skill_versions` row is created (bumping `current_version` if this
   `skill_id` was already published), the submission's status becomes
   `approved`, and the skill becomes visible in the public catalog. If the
   pipeline fails or the scan is `blocked`, the submission is auto-rejected
   with the failure/scan summary recorded as the reason.
6. **Discover**: the public, unauthenticated catalog serves published,
   non-quarantined skills via search and a trending listing (ordered by
   downloads); a per-skill detail endpoint and the versions endpoints also
   surface quarantined skills, clearly marked; a download endpoint serves
   the current version's archive (unless quarantined).

## Running locally

```bash
cp .env.example .env
# edit .env: set SUBMITTER_TOKEN, ADMIN_TOKEN, GITHUB_TOKEN
export $(grep -v '^#' .env | xargs)
go run ./cmd/skills-server
```

The server fails to start (loudly, with a clear log message) if
`SUBMITTER_TOKEN`, `ADMIN_TOKEN`, or `GITHUB_TOKEN` are unset or empty —
there is no insecure default. `DB_PATH`, `SUBMISSIONS_DIR`, `PUBLISHED_DIR`,
`PORT`, `GITHUB_REPO`, `LLM_API_BASE`/`LLM_API_KEY`/`LLM_MODEL`, and
`DAILY_SCAN_INTERVAL` all have sane (or empty/disabled) defaults -- see
`.env.example`. The process listens for `SIGINT`/`SIGTERM` and shuts the
HTTP server down gracefully, which also stops the daily scan scheduler's
background goroutine cleanly.

## Design choices

A few things the task intentionally left up to implementation judgment:

- **Version numbering**: `skill_versions.version` is a simple monotonic
  integer starting at 1, incremented each time a new submission for the
  same `skill_id` is successfully published. This was chosen over a
  submitter-supplied version string because the submission schema in the
  spec for this service doesn't include a version field, and a
  server-assigned monotonic counter needs no client cooperation and can't
  regress or collide.
- **Download path**: `GET /api/v1/skills/{id}/download` serves a locally
  archived copy (`data/published/<skill_id>.zip`, written at publish time
  from the same bytes that passed the pipeline) rather than fetching live
  from GitHub on every request. The private `nanoinfraorg/skills` repo is
  the durable source-of-truth / audit trail (every published file is a real
  commit, reviewable and revertible there), but the actual read path avoids
  a live dependency on GitHub's API and avoids re-zipping files fetched via
  the Contents/Trees API on every download.
- **Download of a quarantined skill returns 404**: the task's wording only
  calls out search and trending as excluding a quarantined current version
  from their results, and says the detail/versions endpoints should still
  show one (clearly marked). Download isn't named either way. This
  implementation treats a quarantined current version as not-found for
  download too, since serving the very archive the shield just blocked
  would defeat the shield's purpose; search/trending/detail/versions all
  behave exactly as specified.
- **`text_only_failures` isn't a persisted column**: the design's `scans`
  table schema lists `text_only_ok` (a bool) but no column for *which*
  file(s) failed that check, even though the scan shield's spec asks the
  checker to "record which file(s) failed". This implementation includes
  that file list on the live `scan.Report` returned directly by
  `POST /api/v1/scan/{id}` and `POST /api/v1/admin/skills/{id}/rescan` (and
  uses it to build the auto-rejection reason on a blocked pipeline scan),
  but a scan reloaded later from storage (`GET /api/v1/scan/{id}`, the
  versions endpoints) only has the persisted bool, per the given schema.
- **Synchronous pipeline + scan**: `POST .../approve` runs the whole
  validate-then-publish pipeline and the scan shield inline in the HTTP
  request rather than enqueuing a background job. At this service's scale
  (single operator, small archives, infrequent approvals) a background job
  queue would add a "submitted but not yet published" limbo state and a
  queue/worker to build and test for no real benefit. If GitHub's publish
  call fails (as opposed to the pipeline validation or the scan itself
  failing), the submission is left `pending` rather than auto-rejected,
  since an infra hiccup isn't a judgment about the skill's validity — retry
  the approve once GitHub is reachable again.
- **`GET /api/v1/scan/{id}` requires auth**: the design doc specifies "either
  token" auth for the `POST` scan-preview endpoint but doesn't explicitly
  say whether the `GET` (read the latest report) needs auth. This
  implementation requires the same either-token auth on both, since a scan
  report can describe exactly why a submission looked suspicious, which
  isn't information this service otherwise exposes unauthenticated.
- **GitHub client**: hand-rolled against `net/http` (3 REST calls: GET a
  file's sha, PUT to create/update it, repeated per file) rather than
  pulling in `go-github` + `oauth2`. The Contents API is small enough that a
  dependency didn't seem worth it, and it keeps the whole service's
  non-stdlib dependency surface to just the SQLite driver.
- **Package boundaries**: `internal/pipeline` (archive + frontmatter
  validation, pure functions, no I/O dependencies beyond the filesystem),
  `internal/scan` (the security scan shield, including the optional LLM
  call), `internal/scheduler` (the daily re-scan ticker loop),
  `internal/store` (all SQL lives here, nowhere else), `internal/github`
  (the publish client), `internal/api` (HTTP handlers + routing +
  logging), `internal/config` (env var loading). `cmd/skills-server` just
  wires these together. `internal/store`'s `Scan` type holds findings as
  pre-serialized JSON strings rather than `internal/scan`'s structured
  types, specifically so the SQL-only package never needs to import the
  scanner (`internal/scan.BuildScanRow` does that serialization instead,
  shared by both `internal/api` and `internal/scheduler`). This keeps the
  security-critical validation and scanning logic (`internal/pipeline`,
  `internal/scan`) testable in complete isolation from HTTP and SQL.
- **Test framework**: stdlib `testing` + `httptest` throughout, per the
  spec's guidance — no third-party assertion library. The GitHub publish
  step is tested against a fake `Publisher` interface (for the HTTP
  handler tests) and separately against a real `httptest.Server` standing
  in for the GitHub API (for the client's own tests); the scan shield's LLM
  call is likewise tested against an `httptest.Server` standing in for an
  OpenAI-compatible provider. Nothing in the test suite touches the
  network.

## Environment variables

See `.env.example` for the full list with descriptions. Required (server
exits at startup if missing): `SUBMITTER_TOKEN`, `ADMIN_TOKEN`,
`GITHUB_TOKEN`. Optional with defaults: `GITHUB_REPO`
(`nanoinfraorg/skills`), `DB_PATH` (`./data/skills-server.db`),
`SUBMISSIONS_DIR` (`./data/submissions`), `PUBLISHED_DIR`
(`./data/published`), `PORT` (`8080`), `DAILY_SCAN_INTERVAL` (`24h`).
Optional, all-or-nothing (the LLM classification pass is skipped if any is
unset): `LLM_API_BASE`, `LLM_API_KEY`, `LLM_MODEL`.

## Endpoints

All routes are under `/api/v1` except the health check.

### `GET /healthz`

No auth. Plain liveness check.

```bash
curl http://localhost:8080/healthz
```

### `POST /api/v1/submissions`

Requires `X-Submitter-Token`. Multipart form with fields `skill_id`,
`display_name`, `submitter`, and a zip file in the `archive` field.
Submitting an already-published `skill_id` is an update, not an error --
it goes through the same review flow and becomes a new version on approval.

```bash
curl -X POST http://localhost:8080/api/v1/submissions \
  -H "X-Submitter-Token: $SUBMITTER_TOKEN" \
  -F skill_id=pdf-editor \
  -F display_name="PDF Editor" \
  -F submitter="alice@example.com" \
  -F archive=@pdf-editor.zip
```

`201 Created`: `{"id": "<uuid>", "status": "pending"}`. `4xx` on invalid
`skill_id`, missing fields, missing/unsafe `SKILL.md`, an oversized
archive, or a missing/wrong submitter token.

### `POST /api/v1/scan/{submission_id}`

Requires either `X-Submitter-Token` or `X-Admin-Token`. Re-runs the scan
shield against a *pending* submission's already-uploaded archive and
returns the report; does not approve, reject, or publish anything.

```bash
curl -X POST http://localhost:8080/api/v1/scan/<submission_id> \
  -H "X-Submitter-Token: $SUBMITTER_TOKEN"
```

`200 OK` with the scan report (see the shape under `GET /api/v1/scan/{id}`
below). `409` if the submission isn't pending. `422` if the archive no
longer passes pipeline validation.

### `GET /api/v1/scan/{submission_id}`

Requires either `X-Submitter-Token` or `X-Admin-Token`. Returns the most
recent scan report recorded for that submission.

```bash
curl http://localhost:8080/api/v1/scan/<submission_id> \
  -H "X-Admin-Token: $ADMIN_TOKEN"
```

`200 OK`:

```json
{
  "id": 1,
  "target_type": "submission",
  "target_id": "<submission_id>",
  "trigger": "manual",
  "verdict": "pass",
  "text_only_ok": true,
  "hidden_chars_findings": [],
  "static_pattern_findings": [],
  "llm_assessment": null,
  "scanned_at": "2026-01-01T00:00:00Z"
}
```

`404` if no scan has run for this submission yet.

### `GET /api/v1/admin/submissions?status=pending`

Requires `X-Admin-Token`. `status` is optional (`pending` / `approved` /
`rejected`; omit for all).

```bash
curl http://localhost:8080/api/v1/admin/submissions?status=pending \
  -H "X-Admin-Token: $ADMIN_TOKEN"
```

### `POST /api/v1/admin/submissions/{id}/approve`

Requires `X-Admin-Token`. Runs the pipeline and the scan shield
synchronously.

```bash
curl -X POST http://localhost:8080/api/v1/admin/submissions/<id>/approve \
  -H "X-Admin-Token: $ADMIN_TOKEN"
```

`200 OK` either way:
`{"outcome": "published", "skill_id": "...", "version": 1, "scan_verdict": "pass"}`
or `{"outcome": "rejected", "reason": "..."}` (the reason mentions the scan
shield if that's what caused the rejection).

### `POST /api/v1/admin/submissions/{id}/reject`

Requires `X-Admin-Token`. JSON body `{"reason": "..."}`. No pipeline run.

```bash
curl -X POST http://localhost:8080/api/v1/admin/submissions/<id>/reject \
  -H "X-Admin-Token: $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"reason": "duplicate of an existing skill"}'
```

### `POST /api/v1/admin/skills/{id}/rescan`

Requires `X-Admin-Token`. Re-runs the scan shield against the skill's
*current* published version, using the already-archived local zip copy (no
GitHub refetch). A `blocked` verdict immediately quarantines that version.

```bash
curl -X POST http://localhost:8080/api/v1/admin/skills/pdf-editor/rescan \
  -H "X-Admin-Token: $ADMIN_TOKEN"
```

`200 OK`: `{"scan": { ... }, "quarantined": false}`.

### `GET /api/v1/search?q=...`

No auth. Case-insensitive substring search over published, non-quarantined
skills.

```bash
curl "http://localhost:8080/api/v1/search?q=pdf"
```

### `GET /api/v1/trending`

No auth. Published, non-quarantined skills ordered by downloads, top 20.

```bash
curl http://localhost:8080/api/v1/trending
```

### `GET /api/v1/skills/{id}`

No auth. Detail for one published skill's current version; `404` if not
found or not yet published. A quarantined current version is still
returned here, with `"status": "quarantined"`.

```bash
curl http://localhost:8080/api/v1/skills/pdf-editor
```

### `GET /api/v1/skills/{id}/versions`

No auth. Lists every version of one skill's history, newest first.

```bash
curl http://localhost:8080/api/v1/skills/pdf-editor/versions
```

### `GET /api/v1/skills/{id}/versions/{version}`

No auth. One version's full detail plus its latest scan report (`null` if
none has run).

```bash
curl http://localhost:8080/api/v1/skills/pdf-editor/versions/1
```

### `GET /api/v1/skills/{id}/download`

No auth. Streams the current version's zip archive and increments the
skill's (aggregate, cross-version) download counter. A quarantined current
version behaves as `404`.

```bash
curl -OJ http://localhost:8080/api/v1/skills/pdf-editor/download
```

## Development

```bash
go build ./...
go vet ./...
gofmt -l .      # should print nothing
go test ./... -count=1
```
