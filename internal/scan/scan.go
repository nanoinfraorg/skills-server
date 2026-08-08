// Package scan implements the security "shield" that runs against a skill
// archive's already-validated file contents (see internal/pipeline) before
// it is published, republished, or left in the public catalog: a text-only
// sanity check, hidden/invisible Unicode character detection, a small set
// of high-signal static suspicious patterns, and an optional LLM-based
// classification pass. See Run and ComputeVerdict for the exact verdict
// rule.
//
// The scanner runs on top of pipeline validation, not instead of it: every
// caller here is expected to have already run pipeline.ValidateArchive (or
// use RunOnArchive, which does so itself) so the file list it scans is
// already known to be path-safe and structurally valid.
package scan

import (
	"context"

	"github.com/nanoinfraorg/skills-server/internal/pipeline"
)

// Verdict is the scanner's overall conclusion about one archive.
type Verdict string

const (
	VerdictPass    Verdict = "pass"
	VerdictFlagged Verdict = "flagged"
	VerdictBlocked Verdict = "blocked"
)

// HiddenCharFinding is one occurrence of a hidden/invisible Unicode
// character found in a text file (see hidden.go).
type HiddenCharFinding struct {
	File      string `json:"file"`
	Rune      string `json:"rune"`
	Codepoint string `json:"codepoint"`
	Line      int    `json:"line"`
}

// StaticPatternFinding is one match of a high-signal suspicious pattern
// (see patterns.go).
type StaticPatternFinding struct {
	File    string `json:"file"`
	Pattern string `json:"pattern"`
	Line    int    `json:"line"`
	Excerpt string `json:"excerpt"`
}

// LLMAssessment is the parsed result of the optional LLM classification
// pass (see llm.go). Risk is one of "safe", "suspicious", or "malicious".
type LLMAssessment struct {
	Risk        string `json:"risk"`
	Explanation string `json:"explanation"`
}

// Report is the full outcome of one scan run.
type Report struct {
	Verdict    Verdict
	TextOnlyOK bool
	// TextOnlyFailures lists the files that failed the text-only check
	// (invalid UTF-8, or a NUL byte). This is intentionally not one of the
	// fields persisted on the store.Scan row (the scans table only has a
	// text_only_ok bool) -- it exists so a live Report (as returned
	// directly by the scan-preview/rescan endpoints, and used to build an
	// auto-rejection reason) can say exactly which file(s) failed, per the
	// design doc's requirement to "record which file(s) failed". A scan
	// reloaded from storage later will not have this list.
	TextOnlyFailures      []string
	HiddenCharFindings    []HiddenCharFinding
	StaticPatternFindings []StaticPatternFinding
	LLMAssessment         *LLMAssessment
}

// Config configures the optional LLM classification pass. The deterministic
// checks (text-only, hidden characters, static patterns) never need
// configuration and always run.
type Config struct {
	LLMAPIBase string
	LLMAPIKey  string
	LLMModel   string
	// HTTPClient is used for the LLM call; a client with a bounded timeout
	// is used if nil. Tests inject a fake to avoid a real network call.
	HTTPClient httpDoer
}

// llmConfigured reports whether all three LLM settings are present; if any
// is empty the LLM pass is skipped entirely and LLMAssessment stays nil.
func (c Config) llmConfigured() bool {
	return c.LLMAPIBase != "" && c.LLMAPIKey != "" && c.LLMModel != ""
}

// Run scans every file's content and returns the full report, including the
// verdict computed by ComputeVerdict. files is typically the output of
// pipeline.ReadFiles for an archive that already passed
// pipeline.ValidateArchive; Run does not repeat path-safety validation.
//
// files[0] is treated as "the first file read" for the leading-BOM
// exemption in hidden-character detection (see scanHiddenChars) -- callers
// should pass files in a stable, meaningful order (pipeline.ReadFiles
// preserves the archive's own entry order, which is what RunOnArchive and
// every caller in this codebase uses).
func Run(ctx context.Context, files []pipeline.FileContent, cfg Config) Report {
	var report Report
	report.TextOnlyOK = true

	var textFiles []pipeline.FileContent
	for _, f := range files {
		if !isTextOnly(f.Content) {
			report.TextOnlyOK = false
			report.TextOnlyFailures = append(report.TextOnlyFailures, f.Path)
			continue
		}
		textFiles = append(textFiles, f)
	}

	for i, f := range textFiles {
		isFirstFile := i == 0
		report.HiddenCharFindings = append(report.HiddenCharFindings, scanHiddenChars(f.Path, f.Content, isFirstFile)...)
		report.StaticPatternFindings = append(report.StaticPatternFindings, scanStaticPatterns(f.Path, f.Content)...)
	}

	if cfg.llmConfigured() {
		report.LLMAssessment = classifyWithLLM(ctx, concatText(textFiles), cfg)
	}

	report.Verdict = ComputeVerdict(report.TextOnlyOK, report.HiddenCharFindings, report.StaticPatternFindings, report.LLMAssessment)
	return report
}

// RunOnArchive re-validates archivePath with pipeline.ValidateArchive
// (expectedSkillID may be empty to skip the frontmatter name-match check)
// and, if that succeeds, reads its files and runs Run against them. It
// exists so callers that only have an archive path on disk -- the admin
// rescan endpoint and the daily scheduler, which both re-scan an
// already-published archive rather than a fresh upload -- don't need to
// duplicate the validate-then-read-then-scan sequence.
func RunOnArchive(ctx context.Context, archivePath, expectedSkillID string, cfg Config) (Report, error) {
	result, err := pipeline.ValidateArchive(archivePath, expectedSkillID)
	if err != nil {
		return Report{}, err
	}
	files, err := pipeline.ReadFiles(archivePath, result.Entries)
	if err != nil {
		return Report{}, err
	}
	return Run(ctx, files, cfg), nil
}

// ComputeVerdict implements the shield's verdict rule:
//
//   - "blocked" if the text-only check failed, OR any hidden-character
//     finding exists, OR any static suspicious pattern matched. These three
//     are deterministic, hard-gate checks.
//   - "flagged" if none of the above tripped but the (optional) LLM
//     assessment says "suspicious" or "malicious".
//   - "pass" otherwise.
//
// The LLM verdict is informational only: it can downgrade an otherwise
// clean deterministic scan to "flagged" for a human admin to review, but it
// can never escalate a scan to "blocked" on its own. This is a deliberate
// decision, not an oversight -- LLM classification is probabilistic and
// provider-dependent, so a human should make the final call on content that
// isn't already caught by the deterministic checks; auto-rejecting on an
// LLM's say-so alone would let a flaky or adversarially-prompted model
// silently block legitimate submissions.
func ComputeVerdict(textOnlyOK bool, hidden []HiddenCharFinding, static []StaticPatternFinding, llm *LLMAssessment) Verdict {
	if !textOnlyOK || len(hidden) > 0 || len(static) > 0 {
		return VerdictBlocked
	}
	if llm != nil && (llm.Risk == "suspicious" || llm.Risk == "malicious") {
		return VerdictFlagged
	}
	return VerdictPass
}
