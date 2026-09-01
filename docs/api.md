# API reference

All routes are under `/api/v1` except the health check and `/auth/*`. See
[authentication.md](authentication.md) for what "Requires X" means and
the session-cookie equivalent accepted everywhere a token is.

### `GET /healthz`

No auth. Plain liveness check.

```bash
curl http://localhost:8080/healthz
```

### `GET /auth/google/login`

No auth (this *is* the auth flow). Redirects (`302`) to Google's consent
screen, requesting `openid email profile`.

```bash
open http://localhost:8080/auth/google/login
```

### `GET /auth/google/callback`

No auth. Google redirects here with `code`/`state`. On success, sets the
session cookie and redirects (`302`) to `/` (the HTML UI's home page --
see [web-ui.md](web-ui.md)). `400` on a missing/expired/reused `state`;
`403` if the email isn't verified or not on the appropriate allowlist;
`502` if the code exchange fails.

### `POST /auth/logout`

No auth required (a request with no session cookie is a no-op). Deletes
the session and clears the cookie. Always `200 OK`.

```bash
curl -X POST http://localhost:8080/auth/logout \
  --cookie "skills_server_session=<value>"
```

### `POST /api/v1/submissions`

Requires `X-Submitter-Token`. Multipart form: `skill_id`, `display_name`,
`submitter`, and a zip file in `archive`. Submitting an already-published
`skill_id` is an update, not an error.

```bash
curl -X POST http://localhost:8080/api/v1/submissions \
  -H "X-Submitter-Token: $SUBMITTER_TOKEN" \
  -F skill_id=pdf-editor \
  -F display_name="PDF Editor" \
  -F submitter="alice@example.com" \
  -F archive=@pdf-editor.zip
```

`201 Created`: `{"id": "<uuid>", "status": "pending"}`. `4xx` on invalid
`skill_id`, missing fields, missing/unsafe `SKILL.md`, oversized
archive, or a missing/wrong token.

### `POST /api/v1/scan/{submission_id}`

Requires either token. Re-runs the scan shield against a *pending*
submission's archive and returns the report; approves/rejects nothing.

```bash
curl -X POST http://localhost:8080/api/v1/scan/<submission_id> \
  -H "X-Submitter-Token: $SUBMITTER_TOKEN"
```

`200 OK` with the scan report (shape below). `409` if not pending. `422`
if the archive no longer passes pipeline validation.

### `GET /api/v1/scan/{submission_id}`

Requires either token. Returns the most recent scan report for that
submission.

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

`404` if no scan has run yet.

### `GET /api/v1/admin/submissions?status=pending`

Requires `X-Admin-Token`. `status` optional (`pending`/`approved`/
`rejected`; omit for all).

```bash
curl http://localhost:8080/api/v1/admin/submissions?status=pending \
  -H "X-Admin-Token: $ADMIN_TOKEN"
```

### `POST /api/v1/admin/submissions/{id}/approve`

Requires `X-Admin-Token`. Runs the pipeline and scan shield
synchronously.

```bash
curl -X POST http://localhost:8080/api/v1/admin/submissions/<id>/approve \
  -H "X-Admin-Token: $ADMIN_TOKEN"
```

`200 OK` either way:
`{"outcome": "published", "skill_id": "...", "version": 1, "scan_verdict": "pass"}`
or `{"outcome": "rejected", "reason": "..."}`.

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
*current* published version (local archived copy, no GitHub refetch). A
`blocked` verdict immediately quarantines that version.

```bash
curl -X POST http://localhost:8080/api/v1/admin/skills/pdf-editor/rescan \
  -H "X-Admin-Token: $ADMIN_TOKEN"
```

`200 OK`: `{"scan": { ... }, "quarantined": false}`.

### `GET /api/v1/search?q=...&kind=...`

No auth. Case-insensitive substring search over published,
non-quarantined skills. Every row carries `kind` — `skill`,
`agent-plugin` or `connector` — omitted on rows published before the
kinds existed, which a client reads as a plain skill.

`kind` narrows the result. Its absence does not filter, so a client that
predates the parameter still sees the whole catalog.

```bash
curl "http://localhost:8080/api/v1/search?q=pdf"
curl "http://localhost:8080/api/v1/search?q=crm&kind=connector"
```

### `GET /api/v1/trending`

No auth. Published, non-quarantined skills ordered by downloads, top 20.

```bash
curl http://localhost:8080/api/v1/trending
```

### `GET /api/v1/skills/{id}`

No auth. Current version's detail; `404` if not found/published. A
quarantined current version still returns, with `"status":
"quarantined"`.

Carries `grants`: what installing this package would allow, read from the
archived copy rather than stored, because the archive is the authority and
a stored summary can drift from it.

```json
{
  "skill_id": "acme-crm",
  "kind": "connector",
  "grants": {
    "kind": "connector",
    "operations": [
      {"name": "create_contact", "class": "mutate.remote", "method": "POST", "path": "/v1/contacts"},
      {"name": "list_contacts", "class": "read", "method": "GET", "path": "/v1/contacts"}
    ],
    "classes": ["read", "mutate.remote"],
    "hosts": ["api.acme.example"],
    "scopes": ["crm.read", "crm.write"]
  }
}
```

Two properties a client should rely on:

- **`grants` is absent, not empty, when the archive cannot be read.** An
  absent answer and "this package asks for nothing" are different
  statements, and rendering the first as the second is how an install
  screen understates what it is about to allow.
- **Only this endpoint carries it.** Search and trending would each have to
  open every archive to answer, and a client listing a catalog is not yet
  deciding anything.

```bash
curl http://localhost:8080/api/v1/skills/pdf-editor
```

### `GET /api/v1/skills/{id}/versions`

No auth. Every version, newest first.

```bash
curl http://localhost:8080/api/v1/skills/pdf-editor/versions
```

### `GET /api/v1/skills/{id}/versions/{version}`

No auth. One version's detail plus its latest scan report (`null` if
none).

```bash
curl http://localhost:8080/api/v1/skills/pdf-editor/versions/1
```

### `GET /api/v1/skills/{id}/download`

No auth. Streams the current version's zip and increments the
(aggregate) download counter. A quarantined current version is `404`.

```bash
curl -OJ http://localhost:8080/api/v1/skills/pdf-editor/download
```
