package virustotal

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/nanoinfraorg/skills-server/internal/store"
)

// Deps holds everything the poller needs to run one pass.
type Deps struct {
	Store  *store.Store
	Client Client
	Logger *slog.Logger
	// Now returns the current time; overridable in tests for determinism.
	Now func() time.Time
}

func (d Deps) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

// Run starts the background polling loop on a time.NewTicker(interval) and
// blocks until ctx is canceled, at which point it stops the ticker and
// returns. Callers typically run this in its own goroutine from main.go,
// exactly like internal/scheduler.Run, and only when VirusTotal is actually
// configured (see cmd/skills-server/main.go).
func Run(ctx context.Context, interval time.Duration, deps Deps) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	deps.Logger.Info("virustotal poller started", "interval", interval)
	for {
		select {
		case <-ctx.Done():
			deps.Logger.Info("virustotal poller stopped")
			return
		case <-ticker.C:
			RunOnce(ctx, deps)
		}
	}
}

// RunOnce performs a single poll pass: every pending virustotal_scans row
// is checked once against VirusTotal. A row still queued is left untouched.
// A row whose analysis completed has its per-engine stats recorded
// (store.UpdateVirusTotalScanResult) and its status flips to "completed".
//
// This never quarantines a skill version, regardless of what the stats say
// -- see this package's doc comment ("Scoping decision") for why that's a
// deliberate, separate policy decision left for later, not an oversight.
// RunOnce only ever calls store methods that touch virustotal_scans.
//
// A transient failure to check one analysis (network error, VirusTotal's
// ~4-requests/minute free-tier rate limit, a 5xx, ...) is logged and that
// row is left "pending" for the next tick -- it is never retried in a hot
// loop within this pass, and one bad/rate-limited row never stops the rest
// of the batch from being checked. A definitively malformed completed
// analysis (ErrMalformedAnalysis) is treated differently: the row is marked
// "error" so the poller stops spending API calls on something that will
// never resolve.
func RunOnce(ctx context.Context, deps Deps) {
	pending, err := deps.Store.ListPendingVirusTotalScans(ctx)
	if err != nil {
		deps.Logger.Error("virustotal poll: list pending scans", "error", err)
		return
	}

	checked := 0
	completed := 0
	for _, row := range pending {
		analysis, err := deps.Client.GetAnalysis(ctx, row.AnalysisID)
		if err != nil {
			if errors.Is(err, ErrMalformedAnalysis) {
				if merr := deps.Store.MarkVirusTotalScanError(ctx, row.ID, err.Error(), deps.now()); merr != nil {
					deps.Logger.Error("virustotal poll: mark malformed analysis as error", "error", merr, "id", row.ID)
					continue
				}
				deps.Logger.Warn("virustotal poll: analysis had an unexpected shape, marking error (won't be retried)",
					"analysis_id", row.AnalysisID, "skill_version_id", row.SkillVersionID, "error", err)
				continue
			}
			// Network error, rate limit (429), invalid/revoked key, or any
			// other transient failure: log and move on. The row stays
			// "pending" and will be picked up again on the next tick --
			// never retried immediately, so this can't turn into a hot
			// loop against a rate-limited API.
			deps.Logger.Warn("virustotal poll: check analysis failed, will retry next tick",
				"analysis_id", row.AnalysisID, "skill_version_id", row.SkillVersionID, "error", err)
			continue
		}
		checked++

		if analysis.Status != StatusCompleted {
			continue // still queued; nothing to do this tick
		}

		if err := deps.Store.UpdateVirusTotalScanResult(
			ctx, row.ID, analysis.Malicious, analysis.Suspicious, analysis.Harmless, analysis.Undetected,
			analysis.Permalink, deps.now(),
		); err != nil {
			deps.Logger.Error("virustotal poll: record completed result", "error", err, "id", row.ID)
			continue
		}
		completed++
		deps.Logger.Info("virustotal poll: analysis completed",
			"skill_version_id", row.SkillVersionID, "malicious", analysis.Malicious, "suspicious", analysis.Suspicious)
	}

	deps.Logger.Info("virustotal poll run complete", "checked", checked, "completed", completed, "total_pending", len(pending))
}
