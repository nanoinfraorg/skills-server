# skills-server

A small, self-hosted Agent Skills marketplace: submission intake, admin
moderation, an automatic validate-then-publish pipeline, and a read-only
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

## Workflow

1. **Submit**: `POST /api/v1/submissions` with a zip archive (must contain a
   root `SKILL.md`) plus `skill_id`, `display_name`, and `submitter` fields.
   The archive is validated immediately (missing `SKILL.md`, unsafe paths,
   oversized archives, invalid `skill_id` are all rejected here) and, if it
   passes, stored with status `pending`.
2. **Moderate**: an admin lists pending submissions
   (`GET /api/v1/admin/submissions?status=pending`) and either approves or
   rejects each one.
3. **Pipeline** (on approve): the archive is *re-validated from scratch* —
   SKILL.md frontmatter/structure, zip path-safety (zip-slip, absolute
   paths, symlinks, `..` traversal, duplicate entries, size caps) — as the
   authoritative, tamper-resistant gate. This runs synchronously inside the
   approve request (see "Design choices" below for why).
4. **Publish**: if the pipeline passes, every file in the archive is
   committed into `nanoinfraorg/skills` under `<skill_id>/` on `main` via the
   GitHub Contents API, the submission's status becomes `approved`, and the
   skill becomes visible in the public catalog. If the pipeline fails, the
   submission is auto-rejected with the pipeline's failure reason recorded.
5. **Discover**: the public, unauthenticated catalog serves published skills
   only, via search, a trending listing (ordered by downloads), a per-skill
   detail endpoint, and a download endpoint.

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
`PORT`, and `GITHUB_REPO` all have sane defaults (see `.env.example`).

## Design choices

A few things the task intentionally left up to implementation judgment:

- **Version numbering**: `skills.version` is a simple monotonic integer
  starting at 1, incremented each time a new submission for the same
  `skill_id` is successfully published. This was chosen over a
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
- **Synchronous pipeline**: `POST .../approve` runs the whole
  validate-then-publish pipeline inline in the HTTP request rather than
  enqueuing a background job. At this service's scale (single operator,
  small archives, infrequent approvals) a background job queue would add a
  "submitted but not yet published" limbo state and a queue/worker to build
  and test for no real benefit. If GitHub's publish call fails (as opposed
  to the pipeline validation itself failing), the submission is left
  `pending` rather than auto-rejected, since an infra hiccup isn't a
  judgment about the skill's validity — retry the approve once GitHub is
  reachable again.
- **GitHub client**: hand-rolled against `net/http` (3 REST calls: GET a
  file's sha, PUT to create/update it, repeated per file) rather than
  pulling in `go-github` + `oauth2`. The Contents API is small enough that a
  dependency didn't seem worth it, and it keeps the whole service's
  non-stdlib dependency surface to just the SQLite driver.
- **Package boundaries**: `internal/pipeline` (archive + frontmatter
  validation, pure functions, no I/O dependencies beyond the filesystem),
  `internal/store` (all SQL lives here, nowhere else), `internal/github`
  (the publish client), `internal/api` (HTTP handlers + routing +
  logging), `internal/config` (env var loading). `cmd/skills-server` just
  wires these together. This keeps the security-critical validation logic
  (`internal/pipeline`) testable in complete isolation from HTTP and SQL.
- **Test framework**: stdlib `testing` + `httptest` throughout, per the
  spec's guidance — no third-party assertion library. The GitHub publish
  step is tested against a fake `Publisher` interface (for the HTTP
  handler tests) and separately against a real `httptest.Server` standing
  in for the GitHub API (for the client's own tests), so nothing touches
  the network.

## Environment variables

See `.env.example` for the full list with descriptions. Required (server
exits at startup if missing): `SUBMITTER_TOKEN`, `ADMIN_TOKEN`,
`GITHUB_TOKEN`. Optional with defaults: `GITHUB_REPO`
(`nanoinfraorg/skills`), `DB_PATH` (`./data/skills-server.db`),
`SUBMISSIONS_DIR` (`./data/submissions`), `PUBLISHED_DIR`
(`./data/published`), `PORT` (`8080`).

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

### `GET /api/v1/admin/submissions?status=pending`

Requires `X-Admin-Token`. `status` is optional (`pending` / `approved` /
`rejected`; omit for all).

```bash
curl http://localhost:8080/api/v1/admin/submissions?status=pending \
  -H "X-Admin-Token: $ADMIN_TOKEN"
```

### `POST /api/v1/admin/submissions/{id}/approve`

Requires `X-Admin-Token`. Runs the pipeline synchronously.

```bash
curl -X POST http://localhost:8080/api/v1/admin/submissions/<id>/approve \
  -H "X-Admin-Token: $ADMIN_TOKEN"
```

`200 OK` either way: `{"outcome": "published", "skill_id": "...", "version": 1}`
or `{"outcome": "rejected", "reason": "..."}`.

### `POST /api/v1/admin/submissions/{id}/reject`

Requires `X-Admin-Token`. JSON body `{"reason": "..."}`. No pipeline run.

```bash
curl -X POST http://localhost:8080/api/v1/admin/submissions/<id>/reject \
  -H "X-Admin-Token: $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"reason": "duplicate of an existing skill"}'
```

### `GET /api/v1/search?q=...`

No auth. Case-insensitive substring search over published skills.

```bash
curl "http://localhost:8080/api/v1/search?q=pdf"
```

### `GET /api/v1/trending`

No auth. Published skills ordered by downloads, top 20.

```bash
curl http://localhost:8080/api/v1/trending
```

### `GET /api/v1/skills/{id}`

No auth. Detail for one published skill; `404` if not found or not yet
published.

```bash
curl http://localhost:8080/api/v1/skills/pdf-editor
```

### `GET /api/v1/skills/{id}/download`

No auth. Streams the skill's zip archive and increments its download
counter.

```bash
curl -OJ http://localhost:8080/api/v1/skills/pdf-editor/download
```

## Development

```bash
go build ./...
go vet ./...
gofmt -l .      # should print nothing
go test ./...
```
