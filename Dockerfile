# syntax=docker/dockerfile:1

# --- build ------------------------------------------------------------------
# modernc.org/sqlite is a pure-Go SQLite driver (no cgo), which is exactly
# why it was chosen in internal/store -- it lets CGO_ENABLED=0 produce a
# fully static binary here, with no C toolchain, glibc, or libsqlite3 needed
# in either stage.
#
# amd64 only, by design (see .github/workflows/ci.yml) -- no multi-arch, so
# no cross-compilation or QEMU concerns here.
FROM golang:1.26-alpine AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -trimpath \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/skills-server \
    ./cmd/skills-server

# Pre-create the runtime data directories here (in a stage with a shell) so
# the final, distroless stage can COPY them in with the right ownership --
# distroless has no shell/mkdir to do this itself.
RUN mkdir -p /data/submissions /data/published

# --- runtime -----------------------------------------------------------------
# distroless/static: no shell, no package manager, ca-certificates already
# included (needed for the outbound HTTPS calls this server makes -- GitHub's
# API, Google's OAuth/OIDC endpoints, an optional LLM endpoint, and an
# optional VirusTotal endpoint) -- a deliberately minimal attack surface for
# a service whose whole purpose is acting as a security shield against
# untrusted, submitted content.
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app

# distroless/static:nonroot's fixed, documented uid:gid.
COPY --from=build --chown=65532:65532 /data /data
COPY --from=build /out/skills-server /app/skills-server

ENV DB_PATH=/data/skills-server.db \
    SUBMISSIONS_DIR=/data/submissions \
    PUBLISHED_DIR=/data/published \
    PORT=8080

# /data holds the SQLite database plus pending/published skill archives --
# the only state this process needs to survive a restart. Mount a named
# volume or bind mount here in production.
VOLUME ["/data"]
EXPOSE 8080

# No Docker HEALTHCHECK: distroless has no curl/wget to run one from inside
# the container. Point your orchestrator's health check (Docker Compose,
# Kubernetes liveness/readiness probe, etc.) at GET /healthz over HTTP
# instead -- see README.md.
USER nonroot:nonroot
ENTRYPOINT ["/app/skills-server"]
