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
	// Owner and Risks are optional, submitter-provided free text for the
	// "Skill Card" governance fields shown on the detail page: who's
	// accountable for this skill, and what could go wrong with it plus how
	// that's mitigated. Like DisplayName, an empty string means "not
	// provided" -- there is no separate has-a-value flag, and no validation
	// requires either to be set.
	Owner string
	Risks string
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
	// Owner and Risks are carried forward from the submission that produced
	// this version (see ApproveSubmissionCore) -- submitter-provided, not
	// derived from SKILL.md frontmatter, since SKILL.md is a portable format
	// this server doesn't own. Empty means "not provided", same convention
	// as Submission's fields of the same name.
	Owner string
	Risks string
	// Kind is what a reader is installing: pipeline.KindSkill,
	// KindAgentPlugin or KindConnector, read from the archive at approval
	// time. A skill is text the agent reads; a connector declares requests a
	// deployment will make with a live credential. The listing has to say
	// which one, which is why this is stored rather than re-derived per
	// request -- a search page would otherwise open every archive.
	Kind string
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
	// Owner and Risks mirror the current version's SkillVersion fields of
	// the same name -- see SkillVersion's doc comment.
	Owner string
	Risks string
}

// SessionRole is the privilege level of an authenticated Google OAuth
// session (see internal/auth.DetermineRole, which computes it once at
// login time; it is then stored on the session row rather than
// re-derived per request).
type SessionRole string

const (
	SessionRoleAdmin     SessionRole = "admin"
	SessionRoleSubmitter SessionRole = "submitter"
)

// RoleSatisfies reports whether an authenticated session with role have is
// privileged enough for a route that requires role need. Admin is treated
// as strictly more privileged than submitter -- the same hierarchy the
// existing two-shared-token scheme already has implicitly, by using two
// separate tokens for two separate privilege levels: an admin session
// satisfies a submitter-level requirement, but a submitter session does
// not satisfy an admin-level one.
func RoleSatisfies(have, need SessionRole) bool {
	if have == SessionRoleAdmin {
		return true
	}
	return have == need
}

// Session is one authenticated Google OAuth session, looked up by the
// opaque, cryptographically random id stored in the session cookie
// (internal/api's GoogleCallback sets it; SessionCookieName names it).
//
// Known limitation (v1): expired sessions are never proactively deleted by
// a background job -- GetSession treats an expired row as not-found on
// lookup, which is sufficient for correctness, but the sessions table
// grows unboundedly over time as old sessions expire. A periodic cleanup
// (e.g. "DELETE FROM sessions WHERE expires_at < ?") is future work, the
// same tradeoff the daily scan scheduler's docs elsewhere in this codebase
// call out for other unbounded-growth cases.
type Session struct {
	ID        string
	Email     string
	Role      SessionRole
	CreatedAt time.Time
	ExpiresAt time.Time
	// CSRFToken is a per-session, cryptographically random value generated
	// once at login (alongside the session id) and used by internal/web to
	// protect every state-changing HTML form: each form embeds it as a
	// hidden field, and the handler rejects the POST unless the submitted
	// value matches this one exactly. It is never sent anywhere except
	// inside a same-origin-rendered HTML page, so a cross-site form (which
	// can forge the session cookie's presence via the browser, but cannot
	// read this value) cannot produce a request that passes validation. See
	// internal/web's CSRF doc comment for the full rationale.
	CSRFToken string
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

// VirusTotalScanStatus is the lifecycle state of one VirusTotal analysis
// row. See internal/virustotal's package doc comment for the full
// upload-then-poll design this tracks.
type VirusTotalScanStatus string

const (
	// VirusTotalScanPending means the archive was uploaded and VirusTotal
	// accepted it for analysis, but the analysis hasn't completed yet (or
	// the background poller hasn't successfully checked on it yet).
	VirusTotalScanPending VirusTotalScanStatus = "pending"
	// VirusTotalScanCompleted means the analysis finished and its
	// per-engine stats were recorded.
	VirusTotalScanCompleted VirusTotalScanStatus = "completed"
	// VirusTotalScanError means the poller got a definitive response from
	// VirusTotal but it wasn't in the expected shape (see
	// internal/virustotal.ErrMalformedAnalysis) -- a permanent failure for
	// this one analysis, not a transient network/rate-limit error (which
	// leaves the row "pending" for the next tick to retry instead).
	VirusTotalScanError VirusTotalScanStatus = "error"
)

// VirusTotalScan is one persisted VirusTotal analysis row: one per
// fire-and-forget upload triggered by a successful publish
// (internal/api/admin.go's ApproveSubmissionCore), later filled in by the
// background poller (internal/virustotal) once VirusTotal's multi-engine
// analysis completes. Unlike Scan (our own scan shield, synchronous and
// always resolved by the time a row exists), a VirusTotalScan row can sit
// "pending" for anywhere from seconds to a couple of minutes.
//
// The count/permalink fields are nil until Status is "completed"; ErrorDetail
// is nil unless Status is "error". Both are pointers rather than
// zero-valuable ints/strings so a genuinely-zero count ("0 engines flagged
// this file") is never confused with "not yet known".
type VirusTotalScan struct {
	ID              int64
	SkillVersionID  int64
	AnalysisID      string
	Status          VirusTotalScanStatus
	MaliciousCount  *int64
	SuspiciousCount *int64
	HarmlessCount   *int64
	UndetectedCount *int64
	Permalink       *string
	ErrorDetail     *string
	CreatedAt       time.Time
	CheckedAt       time.Time
}

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
