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
