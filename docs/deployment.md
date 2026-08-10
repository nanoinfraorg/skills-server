# Deployment

## Running locally

```bash
cp .env.example .env
# edit .env -- see "Environment variables" below
export $(grep -v '^#' .env | xargs)
go run ./cmd/skills-server
```

`GOOGLE_CLIENT_ID`/`GOOGLE_CLIENT_SECRET` must be created by you in Google
Cloud Console -- **APIs & Services → Credentials → Create Credentials →
OAuth client ID → Web application** -- and `GOOGLE_REDIRECT_URL`
registered there as an authorized redirect URI. This can't be automated.

The process listens for `SIGINT`/`SIGTERM` and shuts down gracefully,
stopping the daily scan scheduler cleanly.

## Environment variables

See `.env.example` for the full list with inline descriptions.

**Required** (server exits at startup if missing): `SUBMITTER_TOKEN`,
`ADMIN_TOKEN`, `GITHUB_TOKEN`, `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`,
`GOOGLE_REDIRECT_URL`, `ADMIN_EMAILS`.

**Optional**, with defaults: `GITHUB_REPO` (`nanoinfraorg/skills`),
`DB_PATH` (`./data/skills-server.db`), `SUBMISSIONS_DIR`
(`./data/submissions`), `PUBLISHED_DIR` (`./data/published`), `PORT`
(`8080`), `DAILY_SCAN_INTERVAL` (`24h`), `SESSION_TTL` (`24h`).

**Optional**, all-or-nothing (LLM classification is skipped if any is
unset): `LLM_API_BASE`, `LLM_API_KEY`, `LLM_MODEL`.

**Optional**, permissive if unset (see
[authentication.md](authentication.md)): `SUBMITTER_EMAILS`.

**Optional**, empty by default: `PUBLIC_BASE_URL` (e.g.
`https://skills.nanoinfra.org`) -- set this behind a TLS-terminating
reverse proxy so the session cookie's `Secure` attribute is decided from
the public-facing scheme instead of the inbound request (which is always
plain HTTP from the proxy's perspective).

## Docker

Multi-stage build: `golang:1.26-alpine` compiles a fully static binary
(`CGO_ENABLED=0` -- the SQLite driver, `modernc.org/sqlite`, is pure Go,
no C toolchain needed), on top of `gcr.io/distroless/static-debian12:nonroot`
-- no shell, no package manager, non-root, ca-certificates already
present for the outbound GitHub/Google/LLM calls this server makes.

```bash
docker build -t skills-server .
docker run --rm -p 8080:8080 \
  --env-file .env \
  -v skills-server-data:/data \
  skills-server
```

`/data` (the database plus pending/published archives) is the only state
that needs to survive a restart -- mount a volume there in any real
deployment. No Docker `HEALTHCHECK` (distroless has no `curl`/`wget`);
point your orchestrator's health check at `GET /healthz` instead.

## CI/CD

`.github/workflows/ci.yml`, on every push to `main`, every `v*.*.*` tag,
and every PR targeting `main`:

1. **`test`** -- build, vet, `gofmt -l` check, `go test ./... -race`.
2. **`docker`** (`needs: test`) -- builds the `linux/amd64` image. PRs
   only build (no push). Pushes to `main` or a version tag also push to
   `ghcr.io/nanoinfraorg/skills-server`, tagged with branch, commit SHA,
   `latest` (on `main`), and semver/major.minor (on a tag) -- via the
   workflow's own `GITHUB_TOKEN`, no separate registry credential.
3. **`release`** (`needs: docker`, tags only) -- creates a GitHub Release
   for the tag with auto-generated notes plus the exact image reference.

```bash
# Pull the built image
docker pull ghcr.io/nanoinfraorg/skills-server:latest

# Cut a versioned release (builds, pushes, and creates the Release)
git tag v0.1.0
git push origin v0.1.0
```

`nanoinfraorg/skills-server` is private, so the GHCR package is private
by default -- pulling from elsewhere needs `docker login ghcr.io` with a
PAT that has `read:packages` scope.
