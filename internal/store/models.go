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

// Skill is one published skill visible in the public catalog.
//
// Version is a simple monotonic integer starting at 1, incremented each time
// a new submission for the same skill_id is successfully published. See the
// README for why this was chosen over submitter-supplied version strings.
type Skill struct {
	SkillID     string
	DisplayName string
	Description string
	Version     int64
	Submitter   string
	PublishedAt time.Time
	GitHubPath  string
	Downloads   int64
}
