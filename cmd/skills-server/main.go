// Command skills-server runs the self-hosted Agent Skills marketplace HTTP
// service: submission intake, admin moderation, an automatic
// validate-then-publish pipeline backed by a private GitHub repository, and
// a public read-only catalog.
package main

import (
	"log/slog"
	"net/http"
	"os"

	"github.com/nanoinfraorg/skills-server/internal/api"
	"github.com/nanoinfraorg/skills-server/internal/config"
	"github.com/nanoinfraorg/skills-server/internal/github"
	"github.com/nanoinfraorg/skills-server/internal/store"
)

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

	handler := &api.Handler{
		Store:          db,
		Publisher:      ghClient,
		Logger:         logger,
		SubmitterToken: cfg.SubmitterToken,
		AdminToken:     cfg.AdminToken,
		SubmissionsDir: cfg.SubmissionsDir,
		PublishedDir:   cfg.PublishedDir,
		GitHubRepo:     cfg.GitHubRepo,
	}

	mux := api.NewMux(handler)
	addr := ":" + cfg.Port
	logger.Info("skills-server starting", "addr", addr, "github_repo", cfg.GitHubRepo, "db_path", cfg.DBPath)

	if err := http.ListenAndServe(addr, api.WithLogging(logger, mux)); err != nil {
		logger.Error("server exited", "error", err)
		os.Exit(1)
	}
}
