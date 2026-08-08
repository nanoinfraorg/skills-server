// Package config loads and validates skills-server runtime configuration from
// environment variables. All required secrets are read once at startup; if a
// required value is missing the process exits immediately rather than run
// with an open door.
package config

import (
	"fmt"
	"os"
)

// Config holds all runtime configuration for the skills-server process.
type Config struct {
	// Port is the TCP port the HTTP server listens on.
	Port string
	// DBPath is the filesystem path to the SQLite database file.
	DBPath string
	// SubmitterToken authenticates POST /api/v1/submissions requests via the
	// X-Submitter-Token header.
	SubmitterToken string
	// AdminToken authenticates the /api/v1/admin/* endpoints via the
	// X-Admin-Token header.
	AdminToken string
	// GitHubToken is a PAT with repo scope on GitHubRepo, used to publish
	// approved skills via the Contents API.
	GitHubToken string
	// GitHubRepo is the "owner/name" of the private GitHub repo used as the
	// durable artifact store for published skills.
	GitHubRepo string
	// SubmissionsDir is where uploaded (pending-review) zip archives are
	// stored on local disk.
	SubmissionsDir string
	// PublishedDir is where the validated zip archives of published skills
	// are archived locally so downloads can be served without re-hitting
	// GitHub on every request.
	PublishedDir string
}

// Load reads configuration from the environment, applying defaults where the
// spec allows them, and fails loudly (logs and exits the process) if any
// required secret is missing or empty. This is intentional: a missing token
// must never silently degrade to "no auth required".
func Load() Config {
	cfg := Config{
		Port:           envOr("PORT", "8080"),
		DBPath:         envOr("DB_PATH", "./data/skills-server.db"),
		SubmitterToken: os.Getenv("SUBMITTER_TOKEN"),
		AdminToken:     os.Getenv("ADMIN_TOKEN"),
		GitHubToken:    os.Getenv("GITHUB_TOKEN"),
		GitHubRepo:     envOr("GITHUB_REPO", "nanoinfraorg/skills"),
		SubmissionsDir: envOr("SUBMISSIONS_DIR", "./data/submissions"),
		PublishedDir:   envOr("PUBLISHED_DIR", "./data/published"),
	}

	var missing []string
	if cfg.SubmitterToken == "" {
		missing = append(missing, "SUBMITTER_TOKEN")
	}
	if cfg.AdminToken == "" {
		missing = append(missing, "ADMIN_TOKEN")
	}
	if cfg.GitHubToken == "" {
		missing = append(missing, "GITHUB_TOKEN")
	}
	if len(missing) > 0 {
		fmt.Fprintf(os.Stderr,
			"skills-server: refusing to start with missing required environment variable(s): %v\n"+
				"set these before starting the server; there is no insecure default.\n", missing)
		os.Exit(1)
	}

	return cfg
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
