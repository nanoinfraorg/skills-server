# Authentication

Two independent, equally valid ways to authenticate every protected
endpoint: the original shared-secret headers, and "Sign in with Google"
added later. A request is authenticated if *either* is present and
valid; neither weakens the other.

- **Shared tokens**: `X-Submitter-Token` for `POST /api/v1/submissions`
  and the either-auth scan-preview endpoints; `X-Admin-Token` for
  everything under `/api/v1/admin/*` and the rescan endpoint.
- **Google OAuth session cookie**: `GET /auth/google/login` redirects to
  Google's consent screen; `GET /auth/google/callback` completes the
  flow and sets an HTTP-only `skills_server_session` cookie; `POST
  /auth/logout` clears it. The session's role (`admin`/`submitter`) is
  computed once at login from the `ADMIN_EMAILS`/`SUBMITTER_EMAILS`
  allowlists and stored on the session, not re-derived per request.

**Role precedence** mirrors the tokens' own implicit hierarchy: an
`admin` session satisfies both admin-only and submitter-only routes; a
`submitter` session satisfies only submitter-only (and either-auth)
routes.

When a submission is created via a session cookie rather than
`X-Submitter-Token`, the session's verified email always replaces
whatever the client put in the `submitter` field -- a real, Google-verified
identity can't be spoofed.

```bash
# Browser flow: visit, complete Google's consent screen, the callback
# sets the session cookie automatically.
open http://localhost:8080/auth/google/login

# Everything else works exactly as with a token, just swap the header
# for a cookie:
curl http://localhost:8080/api/v1/admin/submissions?status=pending \
  --cookie "skills_server_session=<value from the browser's cookie jar>"

curl -X POST http://localhost:8080/auth/logout \
  --cookie "skills_server_session=<value>"
```

Setting up Google OAuth (`GOOGLE_CLIENT_ID`/`GOOGLE_CLIENT_SECRET`) is a
manual step in Google Cloud Console -- see
[deployment.md](deployment.md).
