# Design choices

Judgment calls made where the spec left things open.

- **Version numbering**: a server-assigned monotonic integer, not a
  submitter-supplied string -- the submission schema has no version
  field, and a server-assigned counter needs no client cooperation and
  can't regress or collide.
- **Download path**: serves a locally archived copy
  (`data/published/<skill_id>.zip`, written at publish time) rather than
  fetching live from GitHub per request. The private `nanoinfraorg/skills`
  repo is the durable audit trail; the read path avoids a live GitHub
  dependency.
- **Download of a quarantined skill is 404**: not explicitly specified
  (only search/trending were called out) -- serving the archive the
  shield just blocked would defeat its purpose.
- **`text_only_failures` isn't a persisted column**: the `scans` schema
  only has `text_only_ok` (bool). The file list is included on live
  reports (`POST /scan`, rescan) and used to build rejection reasons, but
  a reloaded scan (`GET /scan`, versions) only has the bool.
- **Synchronous pipeline + scan**: runs inline in the approve request,
  no background job queue -- at this scale (single operator, small
  archives, infrequent approvals) a queue adds a limbo state and
  infrastructure for no real benefit. If GitHub's publish call itself
  fails, the submission stays `pending` (retryable); a pipeline/scan
  failure auto-rejects.
- **`GET /api/v1/scan/{id}` requires auth**: not explicitly specified for
  the `GET` (only the `POST` preview endpoint was) -- a scan report can
  describe exactly why a submission looked suspicious, which isn't
  otherwise exposed unauthenticated.
- **GitHub client**: hand-rolled against `net/http` (GET sha + PUT
  contents per file) instead of `go-github`/`oauth2` -- the Contents API
  is small enough that the dependency didn't seem worth it, and it keeps
  the non-stdlib surface to just the SQLite driver plus the OAuth/OIDC
  libraries.
- **Package boundaries**: `internal/pipeline` (archive + frontmatter
  validation, no I/O beyond the filesystem), `internal/scan` (the shield,
  including the LLM call), `internal/scheduler` (daily re-scan),
  `internal/store` (all SQL), `internal/github` (publish client),
  `internal/api` (HTTP), `internal/config` (env vars), `internal/auth`
  (OAuth/OIDC). `internal/store.Scan` holds findings as pre-serialized
  JSON strings so the SQL-only package never imports the scanner
  (`internal/scan.BuildScanRow` does that serialization). Keeps
  `internal/pipeline`/`internal/scan` testable in isolation from HTTP and
  SQL.
- **OAuth "state" storage**: an in-memory, mutex-guarded map, not a
  cookie or the database. State only needs to survive one round trip
  through Google's consent screen (10-minute TTL, single-use), and this
  is a single-process deployment -- would need to move to a shared store
  for horizontal scaling.
- **Sessions have no cleanup job**: an expired row is just treated as
  not-found on lookup (lazy check). The table grows unboundedly; a
  periodic delete is straightforward future work.
- **Session cookie's `Secure` attribute**: driven by `PUBLIC_BASE_URL`
  when set (its scheme is authoritative), else by `r.TLS != nil`. The
  fallback alone breaks behind a TLS-terminating reverse proxy (this
  process only ever sees plain HTTP there) -- see
  [deployment.md](deployment.md).
- **ID token verification behind an interface**
  (`internal/auth.IDTokenVerifier`), same "fake in tests" pattern as the
  `Publisher` interface: go-oidc's real verifier in production, a fake
  returning fixed claims in tests. The OAuth code exchange itself is
  tested by pointing `oauth2.Config.Endpoint.TokenURL` at an
  `httptest.Server`.
- **Test framework**: stdlib `testing` + `httptest` throughout, no
  third-party assertion library. Nothing in the test suite touches the
  network -- GitHub, the LLM call, and OAuth/OIDC are all faked or
  pointed at `httptest.Server`.
- **Web UI: plain HTML forms, no htmx**: every form is a full-page
  `<form>` POST with a redirect, not partial-page updates -- simple
  enough, given zero existing JS tooling, that a vendored client-side
  library wasn't judged to meaningfully simplify anything. See
  [web-ui.md](web-ui.md).
- **Web UI: CSRF token lives on the session row**, not a signed
  double-submit cookie -- sessions already persist server-side in SQLite,
  so validating the token is the same `store.GetSession` lookup the
  handler already does to authenticate the request, with no second
  cookie to mint or verify. See [web-ui.md](web-ui.md).
- **`POST /auth/logout` keeps no CSRF requirement** even though the new
  nav renders it as a form: a forged logout only logs the victim out (no
  data read, changed, or exposed), and the endpoint is documented/tested
  as callable via `curl` plus a bare session cookie, which adding a CSRF
  requirement there would break.
- **Pico CSS, vendored, not a CDN link**: a small, classless framework
  (MIT) -- write semantic HTML, get a reasonably clean look, no utility
  classes or build step. Consistent with this project's existing
  no-outbound-dependency posture.
