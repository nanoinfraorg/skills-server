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
// A completed analysis whose verdict is "fail" (ComputeVerdict -- at least
// one engine reports the file outright malicious, not merely "suspicious")
// quarantines that skill version (store.SetSkillVersionStatus), the same
// mechanism and status the scan shield's own "blocked" verdict already
// uses. This is deliberately narrower than the scoping this package
// originally shipped with ("never quarantines... a bigger policy decision
// than a badge"): a "warn" (suspicious-only, heuristic, prone to false
// positives across ~70 engines) still never quarantines anything -- only
// "fail", a real cross-engine malware detection, does. RunOnce only
// touches virustotal_scans itself otherwise.
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

		if ComputeVerdict(analysis.Malicious, analysis.Suspicious) == "fail" {
			quarantineOnFailVerdict(ctx, deps, row.SkillVersionID, analysis.Malicious)
		}
	}

	deps.Logger.Info("virustotal poll run complete", "checked", checked, "completed", completed, "total_pending", len(pending))
}

// quarantineOnFailVerdict looks up skillVersionID's actual skill_id/version
// (store.SetSkillVersionStatus needs that pair, not the row id
// virustotal_scans stores) and quarantines it. A lookup or update failure
// is logged, not retried or escalated -- the virustotal_scans row itself
// was already recorded successfully by the time this runs, so a failure
// here just means the FAIL badge shows without the skill actually being
// pulled from availability; that's a real gap but not one worth blocking
// the rest of this poll pass over, matching this function's callers'
// general "log and move on" posture.
func quarantineOnFailVerdict(ctx context.Context, deps Deps, skillVersionID int64, malicious int64) {
	sv, err := deps.Store.GetSkillVersionByID(ctx, skillVersionID)
	if err != nil {
		deps.Logger.Error("virustotal poll: could not look up skill version to quarantine", "error", err, "skill_version_id", skillVersionID)
		return
	}
	if err := deps.Store.SetSkillVersionStatus(ctx, sv.SkillID, sv.Version, store.SkillVersionQuarantined); err != nil {
		deps.Logger.Error("virustotal poll: could not quarantine skill version", "error", err, "skill_id", sv.SkillID, "version", sv.Version)
		return
	}
	deps.Logger.Warn("virustotal poll: quarantined skill version on a malicious VirusTotal verdict",
		"skill_id", sv.SkillID, "version", sv.Version, "malicious_engines", malicious)
}
