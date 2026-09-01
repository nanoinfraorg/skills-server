# skills-server

A small, self-hosted Agent Skills marketplace: submission intake, admin
moderation, an automatic validate-then-publish pipeline, a security scan
shield, full version history, a daily re-scan scheduler, and a read-only
public catalog. Backed by a private GitHub repo (`nanoinfraorg/skills`)
as the durable artifact store. Built to replace `nanoinfra`'s dependency
on the Chinese-hosted `skillhub.cn` service (`skills.sh` support in
`nanoinfra` is separate and unaffected).

## Quickstart

```bash
cp .env.example .env
# fill in the required values -- see docs/deployment.md
export $(grep -v '^#' .env | xargs)
go run ./cmd/skills-server
```

Or with Docker:

```bash
docker build -t skills-server .
docker run --rm -p 8080:8080 --env-file .env -v skills-server-data:/data skills-server
```

## Development

```bash
go build ./...
go vet ./...
gofmt -l .      # should print nothing
go test ./... -count=1
```

## Changelog and releases

[`CHANGELOG.md`](CHANGELOG.md) is the record of what changed, in
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/) form. A release body is that file's
section for the version, read by CI rather than written twice.

**A change writes its own entry, in the same commit, under `## [Unreleased]`.** One line per change
a consumer of this catalog can observe, naming the effect and not the mechanism. Categories, in this
order and only the ones a version needs: Added, Changed, Deprecated, Removed, Fixed, Security.

Releasing means renaming `Unreleased` to the version with today's date and opening a fresh one. A
tag whose version has no section, or whose section is empty, fails CI before an image is pushed —
four releases here shipped with a body that was a broken image line and a compare link, which is
what that gate exists to prevent.

Do not tag unless it was asked for. Landed work waits in `Unreleased` at no cost.

## Documentation

- [Architecture](docs/architecture.md) -- Agent Skill format, versioning
  model, the submit-to-publish workflow, the scan shield
- [API reference](docs/api.md) -- every endpoint, with curl examples
- [Authentication](docs/authentication.md) -- shared tokens and Google
  OAuth, side by side
- [Web UI](docs/web-ui.md) -- the server-rendered HTML UI, its pages, and
  its CSRF protection
- [Deployment](docs/deployment.md) -- running locally, environment
  variables, Docker, CI/CD
- [Design choices](docs/design-choices.md) -- judgment calls made where
  requirements left things open
