# Changelog

All notable changes to skills-server are recorded here.

The format follows [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

A line names an effect a consumer of this catalog can observe. This server has one consumer that
matters — a nanoinfra deployment installing from it — so an API change is the kind of thing that
belongs here rather than in a commit log nobody reads.

## [Unreleased]

## [0.4.0] — 2026-08-31

### Added

- `GET /api/v1/search` takes `kind`, so a client browsing for one kind asks for that kind instead
  of fetching the catalog and discarding most of it. Its absence does not filter, so a client that
  predates the parameter still sees everything.
- `GET /api/v1/skills/{id}` carries `grants`: the operations a connector would perform with a live
  credential, each with its capability class, the hosts a token could reach, and the scopes it
  would carry. Read from the archive, because the archive is the authority and a stored summary can
  drift from it.
- Every catalog row carries `kind` — `skill`, `agent-plugin` or `connector`. Omitted on a row
  published before the kinds existed, which a client reads as a plain skill.

### Changed

- `grants` is absent rather than empty when an archive cannot be read. An absent answer and "this
  package asks for nothing" are different statements, and an install screen rendering the first as
  the second understates what it is about to allow.
- Search and trending deliberately carry no `grants`: answering would open every archive in the
  catalog, and a client listing is not yet deciding anything.

## [0.3.0] — 2026-08-31

### Changed

- **Approving a submission returns at once.** The button held the request for the whole publish, so
  approving ten things meant waiting through ten publishes. The approval claims the submission and
  the publish runs behind it, with the version row as the commit point.
- An approval reuses the scan already recorded for those bytes instead of re-scanning them.

### Fixed

- A claimed submission cannot be published twice. `ReconcilePublishing` recovers one abandoned by a
  restart, and the core accepts a submission that is `pending` **or** `publishing` so the claim can
  be held to the end.

## [0.2.0] — 2026-08-31

### Added

- **The catalog is three kinds, and says which.** The directory filters by kind, and a row states
  what a reader is installing rather than leaving them to infer it from a name.
- A connector's detail page shows what it grants: every operation with its capability class, the
  hosts its credential may address, and the scopes that credential would carry. A connector
  declaring no credential says so.

## [0.1.0] — 2026-08-31

First tagged release. A self-hosted catalog with a submission pipeline, a security scan shield and
versioned publishing.

### Added

- **A third package kind, `connector`**, validated from `connector.json` at the archive root against
  a pinned `$schema` — because a connector grants a credential, which a skill does not.
- Agent Plugins v1 packages are accepted alongside skill archives.
- The kind is stored and served, so a listing can say what each row is.
- Auto-quarantine on a malicious VirusTotal verdict, with a link to the full report.
- An opt-in sanitized Markdown preview of `SKILL.md`.
- The directory paginates as a sortable table, and the site follows the nanoinfra.org design system.

### Security

- The Skill Card Owner field is masked from anonymous visitors.

[Unreleased]: https://github.com/nanoinfraorg/skills-server/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/nanoinfraorg/skills-server/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/nanoinfraorg/skills-server/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/nanoinfraorg/skills-server/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/nanoinfraorg/skills-server/releases/tag/v0.1.0
