// Package config loads and validates skills-server runtime configuration from
// environment variables. All required secrets are read once at startup; if a
// required value is missing the process exits immediately rather than run
// with an open door.
package config

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// defaultDailyScanInterval is how often the daily re-scan scheduler ticks
// when DAILY_SCAN_INTERVAL is unset.
const defaultDailyScanInterval = 24 * time.Hour

// defaultSessionTTL is how long a Google OAuth session cookie (see
// internal/auth, internal/api's GoogleCallback) remains valid when
// SESSION_TTL is unset.
const defaultSessionTTL = 24 * time.Hour

// defaultVirusTotalPollInterval is how often the VirusTotal background
// poller (internal/virustotal) checks on pending analyses when
// VIRUSTOTAL_POLL_INTERVAL is unset. VirusTotal's free-tier API is
// rate-limited to roughly 4 requests/minute and ~500/day, so this is
// deliberately much less aggressive than DAILY_SCAN_INTERVAL's own default.
const defaultVirusTotalPollInterval = 3 * time.Minute

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
	// LLMAPIBase, LLMAPIKey, and LLMModel configure the scan shield's
	// optional LLM classification pass (internal/scan). All three are
	// optional; if any is empty, the LLM pass is skipped entirely and never
	// blocks a scan from completing.
	LLMAPIBase string
	LLMAPIKey  string
	LLMModel   string
	// DailyScanInterval is how often the daily re-scan scheduler
	// (internal/scheduler) re-scans every published skill's current
	// version. Defaults to 24h.
	DailyScanInterval time.Duration
	// VirusTotalAPIKey optionally enables the VirusTotal integration
	// (internal/virustotal): a fire-and-forget upload of every newly
	// published skill version's archive for VirusTotal's multi-engine AV
	// analysis, checked by a background poller and shown as a second
	// "Security Audits" entry once complete. Optional, matching
	// LLMAPIBase/LLMAPIKey/LLMModel's pattern exactly: if unset, the whole
	// feature is skipped -- no upload, no poller, no panel entry, not even
	// a placeholder.
	VirusTotalAPIKey string
	// VirusTotalPollInterval is how often the background poller checks on
	// pending VirusTotal analyses. Meaningless if VirusTotalAPIKey is
	// unset. Defaults to 3m.
	VirusTotalPollInterval time.Duration
	// GoogleClientID, GoogleClientSecret, and GoogleRedirectURL configure
	// "Sign in with Google" (internal/auth, internal/api's
	// /auth/google/login and /auth/google/callback), the second, parallel
	// authentication method alongside SubmitterToken/AdminToken. All three
	// are required -- the operator must create an OAuth client themselves
	// in Google Cloud Console (APIs & Services -> Credentials -> Create
	// Credentials -> OAuth client ID -> Web application) and register
	// GoogleRedirectURL as an authorized redirect URI there; this is a
	// manual, human, external setup step that cannot be automated here.
	GoogleClientID     string
	GoogleClientSecret string
	GoogleRedirectURL  string
	// AdminEmails is the allowlist of Google account emails (lowercased,
	// trimmed) that log in with RoleAdmin. Required -- there is no
	// insecure "anyone is an admin" default.
	AdminEmails []string
	// SubmitterEmails is the allowlist of Google account emails (lowercased,
	// trimmed) that log in with RoleSubmitter. Optional: if empty, *any*
	// Google account with a verified email may authenticate as a
	// submitter. This is intentionally permissive -- see
	// internal/auth.DetermineRole's doc comment for the reasoning (a
	// submission only ever reaches "pending" and never publishes anything
	// by itself).
	SubmitterEmails []string
	// SessionTTL is how long a Google OAuth session cookie remains valid.
	// Defaults to 24h.
	SessionTTL time.Duration
	// PublicBaseURL is the externally-visible scheme+host this server is
	// reachable at (e.g. "https://skills.nanoinfra.org"), as seen by a real
	// client -- not necessarily what this process itself observes on the
	// wire. It exists because a deployment fronted by a TLS-terminating
	// reverse proxy (Caddy, Nginx, ...) hands this process plain HTTP even
	// though the browser used HTTPS end-to-end, so relying on the request's
	// own r.TLS to decide the session cookie's Secure attribute silently
	// produces a non-Secure cookie in that (extremely common) deployment
	// shape. When set, its scheme is authoritative for that decision instead
	// of r.TLS. Optional: if empty, falls back to the original r.TLS check
	// (correct only for a server directly terminating its own TLS, or for
	// plain-HTTP local development).
	PublicBaseURL string
}

// Load reads configuration from the environment, applying defaults where the
// spec allows them, and fails loudly (logs and exits the process) if any
// required secret is missing or empty. This is intentional: a missing token
// must never silently degrade to "no auth required".
func Load() Config {
	cfg := Config{
		Port:               envOr("PORT", "8080"),
		DBPath:             envOr("DB_PATH", "./data/skills-server.db"),
		SubmitterToken:     os.Getenv("SUBMITTER_TOKEN"),
		AdminToken:         os.Getenv("ADMIN_TOKEN"),
		GitHubToken:        os.Getenv("GITHUB_TOKEN"),
		GitHubRepo:         envOr("GITHUB_REPO", "nanoinfraorg/skills"),
		SubmissionsDir:     envOr("SUBMISSIONS_DIR", "./data/submissions"),
		PublishedDir:       envOr("PUBLISHED_DIR", "./data/published"),
		LLMAPIBase:         os.Getenv("LLM_API_BASE"),
		LLMAPIKey:          os.Getenv("LLM_API_KEY"),
		LLMModel:           os.Getenv("LLM_MODEL"),
		VirusTotalAPIKey:   os.Getenv("VIRUSTOTAL_API_KEY"),
		GoogleClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		GoogleClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		GoogleRedirectURL:  os.Getenv("GOOGLE_REDIRECT_URL"),
		AdminEmails:        parseEmailList(os.Getenv("ADMIN_EMAILS")),
		SubmitterEmails:    parseEmailList(os.Getenv("SUBMITTER_EMAILS")),
		PublicBaseURL:      strings.TrimRight(os.Getenv("PUBLIC_BASE_URL"), "/"),
	}

	cfg.DailyScanInterval = defaultDailyScanInterval
	if raw := os.Getenv("DAILY_SCAN_INTERVAL"); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skills-server: invalid DAILY_SCAN_INTERVAL %q: %v\n", raw, err)
			os.Exit(1)
		}
		cfg.DailyScanInterval = d
	}

	cfg.SessionTTL = defaultSessionTTL
	if raw := os.Getenv("SESSION_TTL"); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skills-server: invalid SESSION_TTL %q: %v\n", raw, err)
			os.Exit(1)
		}
		cfg.SessionTTL = d
	}

	cfg.VirusTotalPollInterval = defaultVirusTotalPollInterval
	if raw := os.Getenv("VIRUSTOTAL_POLL_INTERVAL"); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skills-server: invalid VIRUSTOTAL_POLL_INTERVAL %q: %v\n", raw, err)
			os.Exit(1)
		}
		cfg.VirusTotalPollInterval = d
	}

	if cfg.PublicBaseURL != "" &&
		!strings.HasPrefix(cfg.PublicBaseURL, "http://") &&
		!strings.HasPrefix(cfg.PublicBaseURL, "https://") {
		fmt.Fprintf(os.Stderr,
			"skills-server: invalid PUBLIC_BASE_URL %q: must start with http:// or https://\n",
			cfg.PublicBaseURL)
		os.Exit(1)
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
	if cfg.GoogleClientID == "" {
		missing = append(missing, "GOOGLE_CLIENT_ID")
	}
	if cfg.GoogleClientSecret == "" {
		missing = append(missing, "GOOGLE_CLIENT_SECRET")
	}
	if cfg.GoogleRedirectURL == "" {
		missing = append(missing, "GOOGLE_REDIRECT_URL")
	}
	if len(cfg.AdminEmails) == 0 {
		missing = append(missing, "ADMIN_EMAILS")
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

// parseEmailList splits a comma-separated env var value into a normalized
// (lowercased, trimmed, empty entries dropped) slice, or nil if raw is
// empty -- used for ADMIN_EMAILS and SUBMITTER_EMAILS, both compared
// case-insensitively against the verified email claim from Google.
func parseEmailList(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
