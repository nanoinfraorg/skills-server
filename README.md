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
# edit .env: set SUBMITTER_TOKEN, ADMIN_TOKEN, GITHUB_TOKEN, GOOGLE_CLIENT_ID,
# GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URL, ADMIN_EMAILS
export $(grep -v '^#' .env | xargs)
go run ./cmd/skills-server
```

The server fails to start (loudly, with a clear log message) if
`SUBMITTER_TOKEN`, `ADMIN_TOKEN`, `GITHUB_TOKEN`, `GOOGLE_CLIENT_ID`,
`GOOGLE_CLIENT_SECRET`, `GOOGLE_REDIRECT_URL`, or `ADMIN_EMAILS` are unset or
empty — there is no insecure default. `DB_PATH`, `SUBMISSIONS_DIR`,
`PUBLISHED_DIR`, `PORT`, `GITHUB_REPO`, `LLM_API_BASE`/`LLM_API_KEY`/
`LLM_MODEL`, `DAILY_SCAN_INTERVAL`, `SUBMITTER_EMAILS`, and `SESSION_TTL` all
have sane (or empty/disabled/permissive) defaults -- see `.env.example`. The
process listens for `SIGINT`/`SIGTERM` and shuts the HTTP server down
gracefully, which also stops the daily scan scheduler's background goroutine
cleanly.

Deploying behind a reverse proxy (Caddy, Nginx, ...) that terminates TLS?
Set `PUBLIC_BASE_URL` (e.g. `PUBLIC_BASE_URL=https://skills.nanoinfra.org`)
so the session cookie still gets the `Secure` attribute -- see
`.env.example` for why this can't be inferred from the request alone in
that setup.

`GOOGLE_CLIENT_ID`/`GOOGLE_CLIENT_SECRET` must be created by you, the
operator, in Google Cloud Console -- this can't be automated: go to **APIs &
Services -> Credentials -> Create Credentials -> OAuth client ID -> Web
application**, and register `GOOGLE_REDIRECT_URL` as an authorized redirect
URI on that client.

## Authentication

There are two independent, equally valid ways to authenticate every
protected endpoint -- the original shared-secret headers, unchanged, and
"Sign in with Google" as a second, parallel option added later. A request
is authenticated if *either* is present and valid; neither can be used to
weaken the other.

- **Shared tokens** (original): `X-Submitter-Token` for
  `POST /api/v1/submissions` and the either-auth scan-preview endpoints;
  `X-Admin-Token` for everything under `/api/v1/admin/*` and the rescan
  endpoint.
- **Google OAuth session cookie**: `GET /auth/google/login` redirects to
  Google's consent screen; `GET /auth/google/callback` completes the
  Authorization Code flow and sets an HTTP-only `skills_server_session`
  cookie; `POST /auth/logout` clears it. The session's role (`admin` or
  `submitter`) is computed once at login time from the `ADMIN_EMAILS` /
  `SUBMITTER_EMAILS` allowlists and stored on the session row, not
  re-derived per request.

**Role precedence** is the same hierarchy the two shared tokens already
have implicitly (a service holding the admin token can do everything a
submitter token can, since they're just two separate secrets for two
separate privilege levels): an `admin`-role session satisfies both
admin-only and submitter-only routes; a `submitter`-role session satisfies
only submitter-only (and either-auth) routes.

When a submission is created by a request authenticated via a session
cookie rather than `X-Submitter-Token`, the session's verified email always
replaces whatever the client put in the `submitter` form field -- once
there's a real, Google-verified identity behind the request, that identity
wins, and the field can no longer be spoofed.

```bash
# Browser flow: visit this URL, complete Google's consent screen, and the
# callback sets the session cookie automatically.
open http://localhost:8080/auth/google/login

# Everything else works exactly as with a token, just swap the header for
# a cookie:
curl http://localhost:8080/api/v1/admin/submissions?status=pending \
  --cookie "skills_server_session=<value from the browser's cookie jar>"

curl -X POST http://localhost:8080/auth/logout \
  --cookie "skills_server_session=<value>"
```

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
- **OAuth "state" storage**: an in-memory `sync.Mutex`-guarded map
  (`internal/auth.StateStore`), not a cookie or the database. State only
  needs to survive one browser round trip through Google's consent screen
  (10-minute TTL, single-use -- consumed and deleted on the first callback
  that presents it, valid or not, to block replay), and skills-server is a
  single-process deployment, so an in-memory map is sufficient; it would
  need to move into the shared store (or an external cache) for a
  horizontally-scaled deployment. This is documented as an assumption on
  `StateStore` itself.
- **Sessions have no cleanup job**: `sessions` rows are never proactively
  deleted when they expire -- `GetSession` just treats an expired row as
  not-found on lookup (a lazy check, sufficient for correctness). The table
  grows unboundedly as old sessions expire; a periodic
  `DELETE FROM sessions WHERE expires_at < ?` is straightforward future
  work, called out on `store.Session`'s doc comment.
- **Session cookie's `Secure` attribute**: set when the request itself
  arrived over TLS (`r.TLS != nil`), not via a configurable
  "trust this reverse proxy" flag. This keeps local (plain-http) dev
  working out of the box; a deployment behind a TLS-terminating reverse
  proxy would see `r.TLS == nil` even though the browser used HTTPS
  end-to-end, so the cookie would be set without `Secure` there (still
  `HttpOnly` + `SameSite=Lax` either way). Honoring `X-Forwarded-Proto`
  behind a trusted proxy is reasonable future work if that becomes this
  service's real deployment shape.
- **ID token verification is behind a small interface**
  (`internal/auth.IDTokenVerifier`), the same "fake in tests" pattern the
  existing `Publisher` interface uses to keep the real GitHub API out of
  the test suite: go-oidc's real verifier (JWKS fetching/caching,
  signature/issuer/audience/expiry checks) implements it in production;
  tests inject a fake returning fixed claims. The OAuth code exchange
  itself isn't behind an interface -- tests instead point
  `oauth2.Config.Endpoint.TokenURL` at an `httptest.Server`, the same
  technique already used for the GitHub Contents API and the scan shield's
  LLM call.
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
`GITHUB_TOKEN`, `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`,
`GOOGLE_REDIRECT_URL`, `ADMIN_EMAILS`. Optional with defaults: `GITHUB_REPO`
(`nanoinfraorg/skills`), `DB_PATH` (`./data/skills-server.db`),
`SUBMISSIONS_DIR` (`./data/submissions`), `PUBLISHED_DIR`
(`./data/published`), `PORT` (`8080`), `DAILY_SCAN_INTERVAL` (`24h`),
`SESSION_TTL` (`24h`). Optional, all-or-nothing (the LLM classification
pass is skipped if any is unset): `LLM_API_BASE`, `LLM_API_KEY`,
`LLM_MODEL`. Optional, permissive-if-unset (see "Authentication" above):
`SUBMITTER_EMAILS`. Optional, empty by default: `PUBLIC_BASE_URL` (e.g.
`https://skills.nanoinfra.org`) -- set this behind a TLS-terminating reverse
proxy so the session cookie's `Secure` attribute is decided from the
public-facing scheme instead of the (always-plain-HTTP-from-the-proxy's
perspective) inbound request; see `.env.example` for the full rationale.

## Endpoints

All routes are under `/api/v1` except the health check and the `/auth/*`
routes below. Every "Requires `X-Submitter-Token`" / "Requires
`X-Admin-Token`" / "Requires either" note below also accepts the
equivalent-or-higher-privileged `skills_server_session` cookie from "Sign
in with Google" -- see "Authentication" above for the precedence rules;
it's not repeated on every endpoint.

### `GET /healthz`

No auth. Plain liveness check.

```bash
curl http://localhost:8080/healthz
```

### `GET /auth/google/login`

No auth (this *is* the auth flow). Redirects (`302`) to Google's OAuth
consent screen, requesting the `openid email profile` scopes.

```bash
open http://localhost:8080/auth/google/login
```

### `GET /auth/google/callback`

No auth. Google redirects here after consent, with `code` and `state`
query parameters. On success, sets the `skills_server_session` cookie and
returns a small human-readable confirmation page. `400` on a missing,
expired, or already-used `state`; `403` if the Google account's email
isn't verified, or isn't on the appropriate allowlist (`ADMIN_EMAILS` /
`SUBMITTER_EMAILS`); `502` if the code exchange with Google fails.

### `POST /auth/logout`

No auth required (a request with no session cookie is a no-op, not an
error). Deletes the session named by the `skills_server_session` cookie,
if any, and clears the cookie.

```bash
curl -X POST http://localhost:8080/auth/logout \
  --cookie "skills_server_session=<value>"
```

Always `200 OK`.

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

## Docker

The provided `Dockerfile` is a multi-stage build: `golang:1.26-alpine` compiles
a fully static binary (`CGO_ENABLED=0` -- `internal/store`'s SQLite driver,
`modernc.org/sqlite`, is pure Go, so no C toolchain or libsqlite3 is needed
anywhere), and the final image is `gcr.io/distroless/static-debian12:nonroot`
-- no shell, no package manager, runs as a non-root user, ca-certificates
already present (needed for the outbound HTTPS calls this server makes: the
GitHub Contents API, Google's OAuth/OIDC endpoints, and the optional LLM
endpoint). Deliberately minimal, for a service whose whole purpose is acting
as a security shield against untrusted, submitted content.

```bash
docker build -t skills-server .
docker run --rm -p 8080:8080 \
  --env-file .env \
  -v skills-server-data:/data \
  skills-server
```

`/data` (the SQLite database, pending-submission archives, and published-skill
archives) is the only state that needs to survive a restart -- mount a named
volume or bind mount there in any real deployment. There's no Docker
`HEALTHCHECK` in the image (distroless has no `curl`/`wget` to run one from
inside the container); point your orchestrator's own health check (Docker
Compose, a Kubernetes liveness/readiness probe, ...) at `GET /healthz` over
HTTP instead.

## CI/CD

`.github/workflows/ci.yml` runs on every push to `main`, every `v*.*.*` tag,
and every pull request targeting `main`:

1. **`test`** -- `go build`, `go vet`, a `gofmt -l` format check, and
   `go test ./... -race`.
2. **`docker`** (`needs: test`) -- builds the image for `linux/amd64` and
   `linux/arm64`. On a pull request this only *builds* (validating the
   Dockerfile compiles), nothing is pushed. On a push to `main` or a version
   tag, it also pushes to `ghcr.io/nanoinfraorg/skills-server`, tagged with
   the branch name, the commit SHA, `latest` (on `main`), and the semver
   tag/major.minor (on a `v*.*.*` tag) -- using the workflow's automatic
   `GITHUB_TOKEN`, no separate registry credential to create or rotate.

Pull the built image once it's pushed:

```bash
docker pull ghcr.io/nanoinfraorg/skills-server:latest
```

Since `nanoinfraorg/skills-server` is a private repo, the package GHCR
creates from it is **private by default** -- pulling it (from another
machine, a deploy host, etc.) needs `docker login ghcr.io` first, with a
GitHub PAT that has `read:packages` scope (or a fine-grained token scoped to
this repo's packages).

To cut a versioned release, tag and push:

```bash
git tag v0.1.0
git push origin v0.1.0
```
