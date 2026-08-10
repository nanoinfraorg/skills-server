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
| `GET /skills/{id}` | none | Detail + full version history (same as `GET /api/v1/skills/{id}` + `.../versions`), plus the current version's actual `SKILL.md` content and a flat listing of every file in its archive (read from the local `PublishedDir/<id>.zip` copy). `SKILL.md` defaults to a plain escaped-text view; `?view=preview` opts into a sanitized Markdown-rendered view (see below). A quarantined current version is shown, clearly marked, not hidden. A logged-in session sees an "Edit / submit new version" link to `/submit?skill_id=<id>`. |
| `GET /submit` | submitter or admin session | Submission form: `skill_id`, `display_name`, two optional "Skill Card" fields (`owner`, `risks` -- see below), and either a `.zip` file *or* a `SKILL.md` textarea (see below). There is no submitter field -- it's always the session's verified email. An optional `?skill_id=<id>` pre-fills the form with that skill's current display name, `owner`/`risks`, and `SKILL.md` content, and locks the `skill_id` field (readonly), for the "Edit / submit new version" link from the detail page. |
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

## Skill contents on the detail page

`GET /skills/{id}` reads the skill's locally-archived zip copy
(`PublishedDir/<id>.zip` -- the same file `GET /api/v1/skills/{id}/download`
serves) via `internal/pipeline`'s existing zip helpers (`ValidateArchive`
for the entry listing, `ReadFiles` for content) and renders the current
version's `SKILL.md` text plus a flat listing of every entry in the archive
(`scripts/`, `references/`, `assets/`, whatever it contains). If the archive
is missing or unreadable, the page still renders (metadata only) with a
fallback message; this is logged as a warning, since every published skill
should have one.

`SKILL.md` itself has two views, toggled by a `?view=` query parameter and a
plain `raw | preview` text link pair directly under the "SKILL.md" heading
(no JS -- just two links to the same URL with a different query string):

- **`raw`** (`GET /skills/{id}` or `?view=raw`, the default): the exact
  behavior this page has always had. The content is rendered as plain
  escaped text inside a `<pre>` block -- `html/template` auto-escapes it by
  default -- with no Markdown processing at all.
- **`preview`** (`?view=preview`): the same content rendered as
  Markdown-to-HTML via [goldmark](https://github.com/yuin/goldmark)
  (`internal/web/markdown.go`'s `renderMarkdownPreview`), for a visitor who
  wants to see it the way it'd look on GitHub instead of as a flat text
  block.

This *used* to be a settled "never render this as HTML" decision, precisely
because `SKILL.md` is untrusted, third-party-submitted content shown to
every unauthenticated visitor of a public page -- naively piping it through
a Markdown renderer would be a straightforward stored-XSS hole. Adding the
`preview` view without reopening that hole depends on two things both being
true at once, not just "goldmark renders it":

1. **Raw HTML is never passed through.** goldmark has a `WithUnsafe()`
   renderer option that would make it emit raw HTML blocks and inline HTML
   found in the Markdown source (a literal `<script>...</script>`, an
   `<img onerror=...>`, etc.) verbatim. `renderMarkdownPreview` never sets
   it. goldmark's own default (confirmed by reading
   `renderer/html/html.go` directly, not assumed) is to drop raw HTML
   entirely and write a `<!-- raw HTML omitted -->` comment in its place --
   so a raw `<script>` block in a submitted `SKILL.md` never reaches the
   response at all, not even escaped.
2. **Every link/image URL is checked against an explicit scheme
   allowlist.** Standard Markdown syntax alone -- `[text](url)`,
   `![alt](url)`, no raw HTML involved -- can still produce a dangerous
   `href`/`src` (`javascript:`, `data:`, ...) that (1) above doesn't touch.
   goldmark's own default HTML renderer already blocks a handful of
   specific dangerous schemes on its own, but that's a narrower blocklist
   than this needs (it doesn't cover every non-http(s)/mailto scheme, and a
   literal-prefix check like that one is themself bypassable by a URL with
   an embedded tab/newline the way browsers parse it). `renderMarkdownPreview`
   instead registers its own goldmark `parser.ASTTransformer`
   (`schemeAllowlistTransformer`) that walks the parsed Markdown tree before
   rendering and blanks the destination of every link/image whose scheme
   isn't exactly `http`, `https`, or `mailto` -- after first stripping the
   same control characters a browser's URL parser strips, so that trick
   doesn't help. A blanked destination renders as an empty `href=""`/
   `src=""`: present in the markup, but not a URL that navigates anywhere or
   loads anything.

Only once both of those have run is the resulting HTML string wrapped in
`template.HTML` (which is what tells `html/template` *not* to auto-escape
it) -- see `internal/web/markdown.go` for the whole thing kept in one
function so it's auditable in one read, and `internal/web/web_test.go` for
tests that submit actual attack payloads (`<script>`, an `onerror` handler,
`javascript:`/`data:` URLs) through `?view=preview` and assert none of them
reach the response in an executable form, alongside a test that legitimate
Markdown (headings, lists, fenced code, a real `https://` link) really does
render as HTML. See [design-choices.md](design-choices.md) for why an AST
transformer was chosen over a second, post-render HTML-sanitizer
dependency.

## Skill Card

The detail page also shows a small "Skill Card" section, between the
description/downloads line and the Security Audits panel below. It is a
deliberately narrow subset of NVIDIA's "Skill Card" governance template --
most of that template's sections already have an equivalent elsewhere in
this project (Description is the existing description field, References is
the Security Audits panel, Skill output is implicit in `SKILL.md`, Version
is already shown) or were judged overkill for a marketplace with a handful
of skills (deployment geography, formal license/terms metadata, ethical
considerations, signing identifiers). Only three lines are shown:

- **Owner** -- an optional, submitter-provided free-text field (`owner` on
  `store.Submission`/`store.SkillVersion`) naming who's accountable for the
  skill (a name, email, or team) -- deliberately "beyond the submitter's
  auth identity", since accountability doesn't always match whoever happens
  to click submit. Rendered only when set on the detail page; no
  placeholder is shown otherwise, matching this page's existing "don't
  render a placeholder for absent optional data" convention (see the
  VirusTotal audit row below). On `GET /submit`, when Owner would otherwise
  be blank (a fresh submission, or an edit of a version that never set one),
  the field is *suggested-filled* with the logged-in session's own verified
  email (`internal/web/pages.go`'s `SubmitForm`) -- a visible, fully
  editable nudge against an accidentally-empty field, not a hidden
  server-side default: the visitor sees it, can clear or change it, and
  whatever's in the field when they submit (including empty) is exactly
  what's stored. Once set, though, it's rendered as-is only to a
  *signed-in* visitor of the detail page; an anonymous visitor sees a
  masked placeholder ("hidden -- sign in to view") instead, since Owner
  very often ends up holding a real email address (the suggested-fill
  above) and this page has no auth requirement at all. Risks and the
  static license line have no such PII concern and stay visible either
  way.
- **Risks and mitigations** -- an optional, submitter-provided free-text
  field (`risks`) describing what could go wrong with the skill and how
  that's mitigated (e.g. "runs arbitrary shell commands -- review scripts/
  before granting broad permissions"). Rendered as plain escaped text, same
  as `SKILL.md` elsewhere on this page -- no Markdown rendering. Also
  rendered only when set.
- **License or terms** -- always shown, but it is a *static* sentence, not a
  stored field: "check the skill's own repository for license details",
  linking to the skill's path in the published GitHub repository
  (`https://github.com/<repo>/tree/main/<github_path>`, built from
  `api.Handler.GitHubRepo` and the version's `GitHubPath`) when a repo is
  configured. This server has no license-metadata system and deliberately
  doesn't invent one: `SKILL.md` is a portable, cross-project format this
  server doesn't own, so requiring or trusting a submitter-typed license
  string would add schema surface for data nobody actually verifies. Instead
  the notice points visitors at the skill's real source.

Both `owner` and `risks` are optional everywhere -- omitting them is not an
error, and a submission from before this feature existed simply has both as
empty strings (see the idempotent `ALTER TABLE` migration in
`internal/store/store.go` for how an already-running deployment's database
picks up the two new columns without losing data). They are
submitter-provided at submission time (`POST /submit`'s `owner`/`risks`
form fields, pre-filled from the current version on the edit-prefill flow
just like `display_name`/`skill_md` already are) and carried forward
verbatim onto the published `skill_versions` row at approval time
(`ApproveSubmissionCore`) -- never derived from `SKILL.md` frontmatter,
unlike `Description`.

## Security Audits panel

The detail page also shows a "Security Audits" list: one named check per
row, each with a PASS/WARN/FAIL/PENDING badge (`internal/web`'s
`securityAudit`). The type is a slice specifically so more than one check
can be shown without changing this shape.

The first entry, **NanoInfra Scanner**, is always present, mapped directly
from the current version's own scan shield verdict (`internal/scan.Verdict`
via `store.GetLatestScan` -- the same row the JSON API's
`GET /api/v1/skills/{id}/versions/{version}` already reads, looked up by
the version's row id via the newly-exported `api.ScanIDString`): `pass` →
PASS, `flagged` → WARN (an LLM-only, informational finding -- see
`scan.ComputeVerdict`'s doc comment on why that's never escalated),
`blocked` → FAIL. No scan recorded yet → PENDING.

A second entry, **VirusTotal**, appears only when a `virustotal_scans` row
exists for the current version -- i.e. `VIRUSTOTAL_API_KEY` is configured
and the fire-and-forget upload for this version actually started (see
[architecture.md](architecture.md#virustotal-integration) for the full
async upload-then-poll design and its verdict mapping). No row at all
(unconfigured, or the upload itself failed) → no VirusTotal row is
rendered, not even a placeholder -- exactly the same "silently skip" shape
the LLM classification pass already has. `internal/web/pages.go`'s
`virusTotalAudit` does this mapping and deliberately never surfaces a
row's raw `error_detail` text on this public, unauthenticated page.

## Two ways to submit: zip upload or pasted SKILL.md

`POST /submit` accepts either a `.zip` file (the `archive` multipart field,
as before) or a plain `SKILL.md` string (the `skill_md` textarea field). If
`archive` is present it's used; otherwise a non-empty `skill_md` is
materialized into an in-memory, single-entry zip (`archive/zip` into a
`bytes.Buffer`, no temp file -- see `buildSkillMDZip` in
`internal/web/pages.go`) and used instead. Either way, exactly one
`io.Reader` over zip bytes reaches `CreateSubmissionCore` -- the same
function a real multipart upload always used -- so there is no second
validation or pipeline path for "text mode": a pasted `SKILL.md` missing
`name`/`description`, or whose `name` doesn't match the posted `skill_id`,
is rejected by the exact same `pipeline.ValidateArchive` check a zip upload
would fail. Submitting with neither field is a `400`.

There is no separate "edit" concept. The skill detail page's "Edit / submit
new version" link (`/submit?skill_id=<id>`) only pre-fills this same form
with the existing skill's display name and current `SKILL.md` content
(read the same way as the detail page, above) and renders `skill_id`
read-only -- a UI hint against accidentally retargeting the edit at a
different skill, not a server-side lock. The resulting `POST` is handled
identically to any other submission: it goes through the normal
pending → admin approve → pipeline → publish flow, and (like the pre-existing
"re-submitting an already-published `skill_id` is a new version, not an
error" behavior) creates a new version of that `skill_id` once approved.

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

## Branding: footer and equal-height skill cards

Every page's footer (`layout.html`) links `skills-server` to this
project's own GitHub repository
(https://github.com/nanoinfraorg/skills-server) and credits
"nanoinfra.org" (https://nanoinfra.org) as the parent project -- that link
is live even before nanoinfra.org itself has a public site up, since the
footer's job is attribution, not proof the destination is fully built out
yet.

The `/skills` directory's cards (`skills.html`) sit in Pico's `.grid`,
which already stretches every `<article>` in a row to match its tallest
sibling (CSS Grid's default `align-items: stretch`) -- but without help,
each card's footer just sits wherever its description text happens to
end, so a short description leaves an awkward gap before the footer while
a long one pushes it right up against the text. A small page-scoped
`<style>` block (`.skill-cards > article { display: flex; flex-direction:
column }` plus `flex: 1` on the description) pins every card's footer to
the same bottom edge regardless of description length, so a row of cards
reads as a tidy grid instead of cards of visibly different shapes.

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
