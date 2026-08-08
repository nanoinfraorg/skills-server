// Package scheduler runs the daily re-scan of every published skill's
// current version, quarantining any that the security scan shield
// (internal/scan) newly finds to be "blocked". It exists to catch skills
// that were published before the shield existed, or whose content the
// shield's deterministic checks would now flag for some other reason (e.g.
// a pattern added after publish).
package scheduler

import (
	"context"
	"log/slog"
	"path/filepath"
	"strconv"
	"time"

	"github.com/nanoinfraorg/skills-server/internal/scan"
	"github.com/nanoinfraorg/skills-server/internal/store"
)

// Deps holds everything the scheduler needs to run one pass.
type Deps struct {
	Store        *store.Store
	Logger       *slog.Logger
	PublishedDir string
	ScanConfig   scan.Config
	// Now returns the current time; overridable in tests for determinism.
	Now func() time.Time
}

func (d Deps) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

// Run starts the daily re-scan loop on a time.NewTicker(interval) and blocks
// until ctx is canceled, at which point it stops the ticker and returns.
// Callers typically run this in its own goroutine from main.go.
func Run(ctx context.Context, interval time.Duration, deps Deps) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	deps.Logger.Info("daily scan scheduler started", "interval", interval)
	for {
		select {
		case <-ctx.Done():
			deps.Logger.Info("daily scan scheduler stopped")
			return
		case <-ticker.C:
			RunOnce(ctx, deps)
		}
	}
}

// RunOnce performs a single daily-re-scan pass: every non-quarantined
// skill's current version is re-scanned (trigger=daily), and any that come
// back "blocked" is immediately quarantined. It never returns an error --
// per-skill failures are logged and skipped so one bad archive can't stop
// the whole run -- and logs a one-line summary when done.
func RunOnce(ctx context.Context, deps Deps) {
	skills, err := deps.Store.ListActiveSkillDetails(ctx)
	if err != nil {
		deps.Logger.Error("daily scan: list active skills", "error", err)
		return
	}

	scanned := 0
	quarantined := 0
	for _, sk := range skills {
		archivePath := filepath.Join(deps.PublishedDir, sk.SkillID+".zip")
		report, err := scan.RunOnArchive(ctx, archivePath, sk.SkillID, deps.ScanConfig)
		if err != nil {
			deps.Logger.Warn("daily scan: could not scan skill", "skill_id", sk.SkillID, "error", err)
			continue
		}
		scanned++

		sv, err := deps.Store.GetSkillVersion(ctx, sk.SkillID, sk.Version)
		if err != nil {
			deps.Logger.Warn("daily scan: could not load skill version to attach scan", "skill_id", sk.SkillID, "version", sk.Version, "error", err)
			continue
		}

		row, err := scan.BuildScanRow(report, store.ScanTargetSkillVersion, strconv.FormatInt(sv.ID, 10), store.ScanTriggerDaily, deps.now())
		if err != nil {
			deps.Logger.Warn("daily scan: could not build scan row", "skill_id", sk.SkillID, "error", err)
			continue
		}
		if _, err := deps.Store.CreateScan(ctx, row); err != nil {
			deps.Logger.Warn("daily scan: could not record scan", "skill_id", sk.SkillID, "error", err)
		}

		if report.Verdict == scan.VerdictBlocked {
			if err := deps.Store.SetSkillVersionStatus(ctx, sk.SkillID, sk.Version, store.SkillVersionQuarantined); err != nil {
				deps.Logger.Warn("daily scan: could not quarantine skill version", "skill_id", sk.SkillID, "version", sk.Version, "error", err)
				continue
			}
			quarantined++
			deps.Logger.Warn("daily scan: quarantined skill version", "skill_id", sk.SkillID, "version", sk.Version)
		}
	}

	deps.Logger.Info("daily scan run complete", "scanned", scanned, "quarantined", quarantined, "total_active", len(skills))
}
