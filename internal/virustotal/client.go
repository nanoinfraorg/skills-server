// Package virustotal implements the optional VirusTotal (see
// https://www.virustotal.com) second opinion on a published skill's
// archive: a multi-engine antivirus sweep run by a third party, alongside
// (not instead of) our own scan shield (internal/scan).
//
// Unlike the scan shield, which runs synchronously inline in the approve
// request, VirusTotal's actual analysis is slow and unpredictable --
// anywhere from a few seconds to a couple of minutes, because it's queued
// behind dozens of independent AV engines. Running that inline would make
// every approve request that slow (or slower, on a VirusTotal outage), so
// this package instead uses a fire-and-forget upload at publish time (see
// UploadAndRecord, called from a background goroutine by
// internal/api/admin.go's ApproveSubmissionCore) plus a background poller
// (see Run/RunOnce) that checks on pending analyses at a modest interval --
// the same "synchronous core + async re-check" shape
// internal/scheduler already established for a different problem (catching
// skills that later turn out bad), applied here to a different one
// (waiting for a slow third party).
//
// Scoping decision: only a "fail" verdict (ComputeVerdict -- at least one
// engine reports the file outright malicious, a real detection rather than
// a heuristic guess) quarantines the skill version automatically
// (RunOnce's quarantineOnFailVerdict, via the same store.SetSkillVersionStatus
// the scan shield's own "blocked" verdict already uses). A "warn"
// (suspicious-only) verdict never does: false positives on a heuristic
// "suspicious" flag are common enough, across the ~70 engines VirusTotal
// aggregates, that treating that tier as a hard finding would flag
// legitimate skills too often -- it stays a badge for a human to weigh, not
// an automatic action. See ComputeVerdict's and RunOnce's doc comments.
//
// The whole feature is optional: if VIRUSTOTAL_API_KEY is unset,
// cmd/skills-server/main.go never constructs a Client, never starts the
// poller, and internal/web's Security Audits panel never shows a
// VirusTotal entry at all -- the same "unset means skip entirely, not a
// placeholder" behavior internal/scan's optional LLM classification pass
// already has.
package virustotal

import (
	"context"
	"errors"
	"fmt"
	"io"

	vt "github.com/VirusTotal/vt-go"
)

// StatusQueued and StatusCompleted are the two analysis statuses
// VirusTotal's API reports while polling (see Client.GetAnalysis's doc
// comment). There is no third "failed" status on VirusTotal's side --
// ErrMalformedAnalysis below is this package's own concept for "we got a
// definitive response but couldn't make sense of it".
const (
	StatusQueued    = "queued"
	StatusCompleted = "completed"
)

// ErrMalformedAnalysis is returned by Client.GetAnalysis when VirusTotal
// reports an analysis as StatusCompleted but its stats aren't in the
// expected shape (a missing or non-numeric stats.* attribute). RunOnce
// treats this as a permanent failure for that one analysis -- it marks the
// row "error" (store.MarkVirusTotalScanError) so the poller stops retrying
// it -- as opposed to a transient network or rate-limit error, which
// RunOnce leaves "pending" for the next tick.
var ErrMalformedAnalysis = errors.New("virustotal: completed analysis had an unexpected stats shape")

// Analysis is the subset of a VirusTotal analysis object's attributes this
// package cares about. While Status is StatusQueued, only Status is
// meaningful; the stats fields and Permalink are populated once Status
// becomes StatusCompleted.
type Analysis struct {
	Status string
	// Malicious, Suspicious, Harmless, and Undetected are per-engine vote
	// counts across VirusTotal's ~70 AV engines: how many considered the
	// file malicious, suspicious (flagged on heuristics, not a definitive
	// detection), harmless (definitively clean), or didn't have an opinion
	// (undetected, e.g. because the file type isn't one that engine scans).
	Malicious  int64
	Suspicious int64
	Harmless   int64
	Undetected int64
	// Permalink is a human-facing VirusTotal GUI URL for this analysis, for
	// an admin or visitor who wants the full per-engine breakdown.
	Permalink string
}

// Client is the minimal VirusTotal capability this package needs: uploading
// a file for asynchronous multi-engine analysis, and checking on a
// previously started one. NewClient returns the real implementation,
// wrapping github.com/VirusTotal/vt-go; tests inject a fake, the same
// "fake in tests" pattern internal/api.Publisher and
// internal/auth.IDTokenVerifier already use to keep a real third-party API
// out of the test suite -- no test in this codebase may ever make a real
// call to VirusTotal.
type Client interface {
	// Upload sends r (named filename) to VirusTotal for scanning and
	// returns as soon as the upload completes -- it does not wait for the
	// multi-engine analysis to finish. The returned string is the analysis
	// ID (not a file hash), suitable for a later GetAnalysis call.
	Upload(ctx context.Context, r io.Reader, filename string) (analysisID string, err error)
	// GetAnalysis checks on a previously started analysis by id. While the
	// analysis is still running, the returned Analysis has Status
	// StatusQueued and its other fields are zero. Once VirusTotal reports
	// it StatusCompleted, the stats fields and Permalink are populated. An
	// error means the check itself failed -- see ErrMalformedAnalysis's doc
	// comment for the one case that's treated as permanent rather than
	// transient.
	GetAnalysis(ctx context.Context, analysisID string) (*Analysis, error)
}

// vtClient adapts the real github.com/VirusTotal/vt-go client to Client.
type vtClient struct {
	cli *vt.Client
}

// NewClient returns a Client backed by a real VirusTotal API key.
func NewClient(apiKey string) Client {
	return &vtClient{cli: vt.NewClient(apiKey)}
}

// Upload implements Client.
//
// vt-go's FileScanner.Scan takes no context.Context -- it builds its own
// *http.Request internally (see vt-go's filescan.go) with no support for
// cancellation -- so ctx cannot actually cancel an in-flight upload today.
// It's accepted anyway for symmetry with GetAnalysis and so a future vt-go
// version (or a swapped-in implementation) that does support cancellation
// can use it without an interface change.
func (c *vtClient) Upload(_ context.Context, r io.Reader, filename string) (string, error) {
	obj, err := c.cli.NewFileScanner().Scan(r, filename, nil)
	if err != nil {
		return "", fmt.Errorf("virustotal upload: %w", err)
	}
	return obj.ID(), nil
}

// GetAnalysis implements Client. See ErrMalformedAnalysis's doc comment for
// when this returns it instead of a plain error.
func (c *vtClient) GetAnalysis(_ context.Context, analysisID string) (*Analysis, error) {
	obj, err := c.cli.GetObject(vt.URL("analyses/%s", analysisID))
	if err != nil {
		return nil, fmt.Errorf("virustotal get analysis: %w", err)
	}

	status, err := obj.GetString("status")
	if err != nil {
		return nil, fmt.Errorf("%w: missing/non-string status: %v", ErrMalformedAnalysis, err)
	}
	if status != StatusCompleted {
		return &Analysis{Status: status}, nil
	}

	malicious, mErr := obj.GetInt64("stats.malicious")
	suspicious, sErr := obj.GetInt64("stats.suspicious")
	harmless, hErr := obj.GetInt64("stats.harmless")
	undetected, uErr := obj.GetInt64("stats.undetected")
	if statsErr := errors.Join(mErr, sErr, hErr, uErr); statsErr != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedAnalysis, statsErr)
	}

	return &Analysis{
		Status:     status,
		Malicious:  malicious,
		Suspicious: suspicious,
		Harmless:   harmless,
		Undetected: undetected,
		// VirusTotal's API doesn't return a ready-made permalink attribute
		// on the analysis object itself; this is VirusTotal's documented
		// GUI URL pattern for a file analysis, constructed rather than
		// read off the object.
		Permalink: fmt.Sprintf("https://www.virustotal.com/gui/file-analysis/%s", analysisID),
	}, nil
}

// ComputeVerdict maps a completed analysis's per-engine stats to the
// Security Audits panel's pass/warn/fail vocabulary:
//
//   - "fail" if any engine reports the file outright malicious --
//     the strongest signal VirusTotal offers.
//   - "warn" if none reported malicious but at least one reported
//     "suspicious" -- a softer, heuristics-only signal that's prone to
//     false positives across ~70 independent engines, so it's surfaced for
//     human review rather than treated as a hard finding.
//   - "pass" otherwise.
//
// This mirrors internal/scan.ComputeVerdict's three-tier shape (blocked/
// flagged/pass) but is a deliberately separate function: nothing in this
// package ever quarantines a skill based on this verdict (see the package
// doc comment's Scoping decision) -- it only drives a badge.
func ComputeVerdict(malicious, suspicious int64) string {
	switch {
	case malicious > 0:
		return "fail"
	case suspicious > 0:
		return "warn"
	default:
		return "pass"
	}
}
