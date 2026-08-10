// Command skills-server runs the self-hosted Agent Skills marketplace HTTP
// service: submission intake, admin moderation, an automatic
// validate-then-publish pipeline backed by a private GitHub repository, a
// security scan shield with an optional LLM classification pass, a daily
// re-scan scheduler, and a public read-only catalog with full version
// history.
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nanoinfraorg/skills-server/internal/api"
	"github.com/nanoinfraorg/skills-server/internal/auth"
	"github.com/nanoinfraorg/skills-server/internal/config"
	"github.com/nanoinfraorg/skills-server/internal/github"
	"github.com/nanoinfraorg/skills-server/internal/scan"
	"github.com/nanoinfraorg/skills-server/internal/scheduler"
	"github.com/nanoinfraorg/skills-server/internal/store"
	"github.com/nanoinfraorg/skills-server/internal/virustotal"
	"github.com/nanoinfraorg/skills-server/internal/web"
)

// shutdownTimeout bounds how long the HTTP server waits for in-flight
// requests to finish on SIGINT/SIGTERM before giving up.
const shutdownTimeout = 10 * time.Second

// version is overridden at build time via
// -ldflags "-X main.version=<git describe or tag>" (see Dockerfile and
// .github/workflows/ci.yml), so a running container's logs identify exactly
// which build produced it. "dev" is what you get from a plain `go run`/`go
// build` with no ldflags.
var version = "dev"

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	cfg := config.Load() // exits the process if a required secret is missing

	if err := os.MkdirAll(cfg.SubmissionsDir, 0o755); err != nil {
		logger.Error("create submissions directory", "error", err)
		os.Exit(1)
	}
	if err := os.MkdirAll(cfg.PublishedDir, 0o755); err != nil {
		logger.Error("create published directory", "error", err)
		os.Exit(1)
	}

	db, err := store.Open(cfg.DBPath)
	if err != nil {
		logger.Error("open database", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	ghClient := github.New(cfg.GitHubToken, cfg.GitHubRepo)

	scanConfig := scan.Config{
		LLMAPIBase: cfg.LLMAPIBase,
		LLMAPIKey:  cfg.LLMAPIKey,
		LLMModel:   cfg.LLMModel,
	}

	// vtClient stays nil -- and the whole VirusTotal integration stays
	// off -- unless VIRUSTOTAL_API_KEY was actually set, exactly like the
	// scan shield's optional LLM classification pass above.
	var vtClient virustotal.Client
	if cfg.VirusTotalAPIKey != "" {
		vtClient = virustotal.NewClient(cfg.VirusTotalAPIKey)
	}

	// ctx is canceled on SIGINT/SIGTERM, giving the daily scan scheduler (a
	// background goroutine with no other way to know the process is
	// stopping) a clean way to stop its ticker loop.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// NewGoogleVerifier makes a network call (OIDC discovery against
	// Google) once at startup; a failure here (e.g. no network, or a
	// misconfigured GOOGLE_CLIENT_ID) is treated the same as a missing
	// required secret -- fail loud, don't start in a half-working state.
	idTokenVerifier, err := auth.NewGoogleVerifier(ctx, cfg.GoogleClientID)
	if err != nil {
		logger.Error("discover google oidc provider", "error", err)
		os.Exit(1)
	}

	handler := &api.Handler{
		Store:             db,
		Publisher:         ghClient,
		Logger:            logger,
		SubmitterToken:    cfg.SubmitterToken,
		AdminToken:        cfg.AdminToken,
		SubmissionsDir:    cfg.SubmissionsDir,
		PublishedDir:      cfg.PublishedDir,
		GitHubRepo:        cfg.GitHubRepo,
		ScanConfig:        scanConfig,
		GoogleOAuthConfig: auth.NewGoogleOAuthConfig(cfg.GoogleClientID, cfg.GoogleClientSecret, cfg.GoogleRedirectURL),
		IDTokenVerifier:   idTokenVerifier,
		StateStore:        auth.NewStateStore(),
		AdminEmails:       cfg.AdminEmails,
		SubmitterEmails:   cfg.SubmitterEmails,
		SessionTTL:        cfg.SessionTTL,
		PublicBaseURL:     cfg.PublicBaseURL,
		VirusTotalClient:  vtClient,
	}

	go scheduler.Run(ctx, cfg.DailyScanInterval, scheduler.Deps{
		Store:        db,
		Logger:       logger,
		PublishedDir: cfg.PublishedDir,
		ScanConfig:   scanConfig,
	})

	// The VirusTotal background poller only runs when the integration is
	// actually configured -- starting it with no client would just spin,
	// finding pending rows that could never exist since nothing ever
	// uploads without vtClient set.
	if vtClient != nil {
		go virustotal.Run(ctx, cfg.VirusTotalPollInterval, virustotal.Deps{
			Store:  db,
			Client: vtClient,
			Logger: logger,
		})
	}

	mux := api.NewMux(handler)
	// The HTML UI (internal/web) is registered onto the same mux as the
	// JSON API: it takes every route the JSON API doesn't (/, /skills,
	// /submit, /my/submissions, /admin, ...), calling through to the same
	// *api.Handler -- its store queries and its shared "Core" business
	// logic -- rather than duplicating any of it. See docs/web-ui.md.
	web.Register(mux, web.New(handler, logger))
	server := &http.Server{Addr: ":" + cfg.Port, Handler: api.WithLogging(logger, mux)}

	go func() {
		<-ctx.Done()
		logger.Info("shutdown signal received, stopping http server")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			logger.Error("http server shutdown", "error", err)
		}
	}()

	logger.Info("skills-server starting", "version", version, "addr", server.Addr, "github_repo", cfg.GitHubRepo, "db_path", cfg.DBPath, "daily_scan_interval", cfg.DailyScanInterval, "public_base_url", cfg.PublicBaseURL, "virustotal_enabled", vtClient != nil)

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("server exited", "error", err)
		os.Exit(1)
	}
}
