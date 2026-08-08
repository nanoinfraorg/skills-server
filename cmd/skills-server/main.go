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
	"github.com/nanoinfraorg/skills-server/internal/config"
	"github.com/nanoinfraorg/skills-server/internal/github"
	"github.com/nanoinfraorg/skills-server/internal/scan"
	"github.com/nanoinfraorg/skills-server/internal/scheduler"
	"github.com/nanoinfraorg/skills-server/internal/store"
)

// shutdownTimeout bounds how long the HTTP server waits for in-flight
// requests to finish on SIGINT/SIGTERM before giving up.
const shutdownTimeout = 10 * time.Second

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

	handler := &api.Handler{
		Store:          db,
		Publisher:      ghClient,
		Logger:         logger,
		SubmitterToken: cfg.SubmitterToken,
		AdminToken:     cfg.AdminToken,
		SubmissionsDir: cfg.SubmissionsDir,
		PublishedDir:   cfg.PublishedDir,
		GitHubRepo:     cfg.GitHubRepo,
		ScanConfig:     scanConfig,
	}

	// ctx is canceled on SIGINT/SIGTERM, giving the daily scan scheduler (a
	// background goroutine with no other way to know the process is
	// stopping) a clean way to stop its ticker loop.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go scheduler.Run(ctx, cfg.DailyScanInterval, scheduler.Deps{
		Store:        db,
		Logger:       logger,
		PublishedDir: cfg.PublishedDir,
		ScanConfig:   scanConfig,
	})

	mux := api.NewMux(handler)
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

	logger.Info("skills-server starting", "addr", server.Addr, "github_repo", cfg.GitHubRepo, "db_path", cfg.DBPath, "daily_scan_interval", cfg.DailyScanInterval)

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("server exited", "error", err)
		os.Exit(1)
	}
}
