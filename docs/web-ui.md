# Web UI

A server-rendered HTML UI on top of the JSON API and Google OAuth session
system, served by the same binary (`internal/web`, wired onto the same
`*http.ServeMux` as `internal/api` in `cmd/skills-server/main.go`). No
Node.js, no JS framework, no build step: `html/template` (stdlib) plus one
vendored CSS file, both embedded into the binary via `//go:embed`.

Every page and form action is a thin wrapper around logic that already
exists: read pages call the same `store.Store` queries the JSON API's own
read endpoints call; write actions (submit, approve, reject, rescan) call
the same `api.Handler` "Core" functions (`CreateSubmissionCore`,
`ApproveSubmissionCore`, `RejectSubmissionCore`, `RescanSkillCore`) the
JSON API's own write endpoints call. Nothing here re-implements
validation, publishing, scanning, or persistence.

## Pages

| Route | Auth | Description |
|---|---|---|
| `GET /` | none | Home: "Sign in with Google" if signed out; a welcome + nav links if signed in. |
| `GET /skills` | none | Public directory: `?q=...` searches (same as `GET /api/v1/search`); no query shows trending (same as `GET /api/v1/trending`). |
| `GET /skills/{id}` | none | Detail + full version history (same as `GET /api/v1/skills/{id}` + `.../versions`). A quarantined current version is shown, clearly marked, not hidden. |
| `GET /submit` | submitter or admin session | Upload form: `skill_id`, `display_name`, a `.zip` file. There is no submitter field -- it's always the session's verified email. |
| `POST /submit` | submitter or admin session, CSRF | Validates and creates the submission via `CreateSubmissionCore`. Redirects to `/my/submissions` on success; re-renders the form with the same inline error text the JSON API would return on failure. |
| `GET /my/submissions` | any session | The session's own submissions and their status (`store.Store.ListSubmissionsBySubmitter`, added for this page). |
| `GET /admin` | admin session | Pending submissions (with latest scan verdict, if any) and every published skill (with quarantine status), each with a CSRF-protected form action. |
| `POST /admin/submissions/{id}/approve` | admin session, CSRF | Calls `ApproveSubmissionCore`; redirects to `/admin` with the outcome (published+version+verdict, or rejected+reason) as a query-string banner. |
| `POST /admin/submissions/{id}/reject` | admin session, CSRF | Calls `RejectSubmissionCore` with the form's `reason` field. |
| `POST /admin/skills/{id}/rescan` | admin session, CSRF | Calls `RescanSkillCore`; shows the resulting verdict and whether the skill was quarantined. |
| `GET /static/*` | none | Vendored static assets (see below). |

An unauthenticated request to a page requiring a session is redirected
(`302`) to `GET /auth/google/login` -- there's no separate HTML login
form, since signing in with Google *is* the login flow (see
[authentication.md](authentication.md)). A session that exists but lacks
the required role (e.g. a submitter hitting `/admin`) gets a `403` page
instead of a redirect loop.

`GET /auth/google/callback` (`internal/api`) now redirects (`302`) to `/`
on success instead of returning a standalone confirmation string, so login
lands back in the UI. Its error responses (`400`/`403`/`502`) are
unchanged.

## CSRF protection

Every state-changing HTML form here (`/submit`, and the three admin
actions) relies on the session cookie for auth, which a cross-site form
submission can trigger automatically -- unlike the JSON API, which is
either header-authenticated (`X-Submitter-Token`/`X-Admin-Token`, which a
cross-site request cannot set) or has no HTML forms pointed at it.

Mechanism: a per-session token (`store.Session.CSRFToken`), generated once
at login alongside the session id itself (`internal/api`'s
`GoogleCallback`) and stored on the session row. Every protected form
embeds it as a hidden `csrf_token` field; every protected POST handler
(`internal/web/csrf.go`'s `validCSRF`) compares the submitted value against
the current session's own token in constant time, rejecting the request
(`403`, action not performed) before the underlying `*Core` function ever
runs if it's missing or wrong.

This was chosen over a signed double-submit cookie because sessions
already persist server-side in SQLite: validating the token is just the
same `store.GetSession` lookup the handler already performed to
authenticate the request, with no second cookie to mint or verify.

Token-header-authenticated JSON API requests need no CSRF token and are
unaffected -- see [authentication.md](authentication.md).

`POST /auth/logout` (pre-existing, from the Google OAuth phase) is
deliberately left as-is, without a CSRF requirement: it's called from this
UI's nav as a plain form, but a forged logout has no meaningful impact
beyond logging the victim out (no data is read, changed, or exposed), and
the endpoint is documented and tested as callable via `curl` + a bare
session cookie, which a CSRF requirement would break.

## Vendored static assets

`internal/web/static/`, embedded via `//go:embed` and served at
`/static/*`:

- `pico.min.css` -- [Pico CSS](https://picocss.com) v2.1.1, a small,
  classless CSS framework (MIT-licensed; see `pico.LICENSE.md` in the same
  directory). No utility classes, no build step -- write semantic HTML and
  it looks reasonably clean.

Nothing is loaded from a CDN, matching this project's existing
self-reliant posture on outbound dependencies (see
[design-choices.md](design-choices.md)). No JS framework or bundler is
used either: every form is a plain HTML `<form>` with a full-page
redirect, which is simple enough that a client-side library (even a small,
vendored one like htmx) wasn't judged to meaningfully simplify anything
here.
