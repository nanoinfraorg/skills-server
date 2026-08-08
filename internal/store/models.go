package store

import "time"

// SubmissionStatus is the lifecycle state of a skill submission.
type SubmissionStatus string

const (
	StatusPending  SubmissionStatus = "pending"
	StatusApproved SubmissionStatus = "approved"
	StatusRejected SubmissionStatus = "rejected"
)

// Submission is one uploaded candidate skill, pending or decided.
type Submission struct {
	ID              string
	SkillID         string
	DisplayName     string
	Submitter       string
	Status          SubmissionStatus
	RejectionReason *string
	ArchivePath     string
	CreatedAt       time.Time
	DecidedAt       *time.Time
}

// SkillVersionStatus is the lifecycle state of one published skill version.
type SkillVersionStatus string

const (
	// SkillVersionPublished is the normal state for a version that passed
	// the pipeline and the scan shield (or was only flagged, not blocked).
	SkillVersionPublished SkillVersionStatus = "published"
	// SkillVersionQuarantined marks a version the scan shield later found
	// (via a manual admin rescan or the daily scheduler) to contain a
	// blocked-severity finding. A quarantined version is excluded from
	// search/trending but still visible via the detail and versions
	// endpoints, so an admin or the submitter can see why it was pulled.
	SkillVersionQuarantined SkillVersionStatus = "quarantined"
)

// SkillVersion is one row of a skill's version history. skill_versions
// holds one row per published version (never overwritten in place); Version
// is a simple monotonic integer starting at 1, incremented each time a new
// submission for the same SkillID is successfully published. See the
// README for why this was chosen over submitter-supplied version strings.
type SkillVersion struct {
	ID           int64
	SkillID      string
	Version      int64
	SubmissionID string
	DisplayName  string
	Description  string
	GitHubPath   string
	PublishedAt  time.Time
	Status       SkillVersionStatus
}

// Skill is the thin "current version" pointer for one published skill_id.
// It no longer holds the skill's display data directly (that now lives,
// per-version, in SkillVersion) -- callers that need the current version's
// display data should use GetSkillDetail/SearchSkills/TrendingSkills, which
// join through to skill_versions.
type Skill struct {
	SkillID        string
	CurrentVersion int64
	// Downloads is an aggregate across all versions: it keeps incrementing
	// on every download regardless of which version is current.
	Downloads int64
	CreatedAt time.Time
}

// SkillDetail is a denormalized view combining a skill's thin pointer row
// with its current version's display data, as returned by GetSkillDetail,
// SearchSkills, TrendingSkills, and ListActiveSkillDetails.
type SkillDetail struct {
	SkillID      string
	DisplayName  string
	Description  string
	Version      int64
	SubmissionID string
	GitHubPath   string
	PublishedAt  time.Time
	Status       SkillVersionStatus
	Downloads    int64
	CreatedAt    time.Time
}

// ScanTargetType identifies what kind of thing a scan ran against.
type ScanTargetType string

const (
	ScanTargetSubmission   ScanTargetType = "submission"
	ScanTargetSkillVersion ScanTargetType = "skill_version"
)

// ScanTrigger identifies what caused a scan to run.
type ScanTrigger string

const (
	ScanTriggerManual   ScanTrigger = "manual"
	ScanTriggerPipeline ScanTrigger = "pipeline"
	ScanTriggerOnUpdate ScanTrigger = "on_update"
	ScanTriggerDaily    ScanTrigger = "daily"
)

// ScanVerdict is the scan shield's overall conclusion. See
// internal/scan.ComputeVerdict for exactly how it's derived.
type ScanVerdict string

const (
	ScanVerdictPass    ScanVerdict = "pass"
	ScanVerdictFlagged ScanVerdict = "flagged"
	ScanVerdictBlocked ScanVerdict = "blocked"
)

// Scan is one persisted run of the security scan shield (internal/scan)
// against either a pending submission's archive or a published skill
// version's archive.
//
// The finding fields are stored as pre-serialized JSON (produced by the api
// package from a scan.Report) rather than structured Go types, so this
// package -- which owns all SQL and nothing else -- does not need to depend
// on internal/scan's finding types. HiddenCharsFindingsJSON and
// StaticPatternFindingsJSON are always a JSON array ("[]" if there were no
// findings); LLMAssessmentJSON is nil when no LLM was configured for the
// run.
type Scan struct {
	ID                        int64
	TargetType                ScanTargetType
	TargetID                  string
	Trigger                   ScanTrigger
	Verdict                   ScanVerdict
	TextOnlyOK                bool
	HiddenCharsFindingsJSON   string
	StaticPatternFindingsJSON string
	LLMAssessmentJSON         *string
	ScannedAt                 time.Time
}
