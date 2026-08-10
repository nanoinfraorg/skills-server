package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/nanoinfraorg/skills-server/internal/scan"
	"github.com/nanoinfraorg/skills-server/internal/store"
)

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

// submissionDTO is the JSON shape returned for a submission.
type submissionDTO struct {
	ID              string  `json:"id"`
	SkillID         string  `json:"skill_id"`
	DisplayName     string  `json:"display_name"`
	Submitter       string  `json:"submitter"`
	Status          string  `json:"status"`
	RejectionReason *string `json:"rejection_reason,omitempty"`
	CreatedAt       string  `json:"created_at"`
	DecidedAt       *string `json:"decided_at,omitempty"`
	Owner           string  `json:"owner,omitempty"`
	Risks           string  `json:"risks,omitempty"`
}

func toSubmissionDTO(s store.Submission) submissionDTO {
	dto := submissionDTO{
		ID:              s.ID,
		SkillID:         s.SkillID,
		DisplayName:     s.DisplayName,
		Submitter:       s.Submitter,
		Status:          string(s.Status),
		RejectionReason: s.RejectionReason,
		CreatedAt:       s.CreatedAt.UTC().Format(time.RFC3339),
		Owner:           s.Owner,
		Risks:           s.Risks,
	}
	if s.DecidedAt != nil {
		formatted := s.DecidedAt.UTC().Format(time.RFC3339)
		dto.DecidedAt = &formatted
	}
	return dto
}

// skillDTO is the JSON shape returned for a published skill, denormalized
// from its thin pointer row and its current version. Status is always
// included so a quarantined current version is clearly marked rather than
// silently omitted (search/trending exclude quarantined skills entirely;
// the detail endpoint that uses this DTO does not).
type skillDTO struct {
	SkillID        string `json:"skill_id"`
	DisplayName    string `json:"display_name"`
	Description    string `json:"description"`
	CurrentVersion int64  `json:"current_version"`
	Status         string `json:"status"`
	PublishedAt    string `json:"published_at"`
	GitHubPath     string `json:"github_path"`
	Downloads      int64  `json:"downloads"`
	CreatedAt      string `json:"created_at"`
}

func toSkillDTO(s store.SkillDetail) skillDTO {
	return skillDTO{
		SkillID:        s.SkillID,
		DisplayName:    s.DisplayName,
		Description:    s.Description,
		CurrentVersion: s.Version,
		Status:         string(s.Status),
		PublishedAt:    s.PublishedAt.UTC().Format(time.RFC3339),
		GitHubPath:     s.GitHubPath,
		Downloads:      s.Downloads,
		CreatedAt:      s.CreatedAt.UTC().Format(time.RFC3339),
	}
}

func toSkillDTOs(skills []store.SkillDetail) []skillDTO {
	out := make([]skillDTO, 0, len(skills))
	for _, s := range skills {
		out = append(out, toSkillDTO(s))
	}
	return out
}

// skillVersionSummaryDTO is one entry in the GET .../versions listing.
type skillVersionSummaryDTO struct {
	ID          int64  `json:"id"`
	Version     int64  `json:"version"`
	PublishedAt string `json:"published_at"`
	Status      string `json:"status"`
}

func toSkillVersionSummaryDTO(sv store.SkillVersion) skillVersionSummaryDTO {
	return skillVersionSummaryDTO{
		ID:          sv.ID,
		Version:     sv.Version,
		PublishedAt: sv.PublishedAt.UTC().Format(time.RFC3339),
		Status:      string(sv.Status),
	}
}

func toSkillVersionSummaryDTOs(versions []store.SkillVersion) []skillVersionSummaryDTO {
	out := make([]skillVersionSummaryDTO, 0, len(versions))
	for _, sv := range versions {
		out = append(out, toSkillVersionSummaryDTO(sv))
	}
	return out
}

// skillVersionDetailDTO is the full detail for one skill version, plus its
// latest scan report if one has run.
type skillVersionDetailDTO struct {
	ID           int64    `json:"id"`
	SkillID      string   `json:"skill_id"`
	Version      int64    `json:"version"`
	SubmissionID string   `json:"submission_id"`
	DisplayName  string   `json:"display_name"`
	Description  string   `json:"description"`
	GitHubPath   string   `json:"github_path"`
	PublishedAt  string   `json:"published_at"`
	Status       string   `json:"status"`
	Scan         *scanDTO `json:"scan,omitempty"`
	Owner        string   `json:"owner,omitempty"`
	Risks        string   `json:"risks,omitempty"`
}

func toSkillVersionDetailDTO(sv store.SkillVersion, latestScan *scanDTO) skillVersionDetailDTO {
	return skillVersionDetailDTO{
		ID:           sv.ID,
		SkillID:      sv.SkillID,
		Version:      sv.Version,
		SubmissionID: sv.SubmissionID,
		DisplayName:  sv.DisplayName,
		Description:  sv.Description,
		GitHubPath:   sv.GitHubPath,
		PublishedAt:  sv.PublishedAt.UTC().Format(time.RFC3339),
		Status:       string(sv.Status),
		Scan:         latestScan,
		Owner:        sv.Owner,
		Risks:        sv.Risks,
	}
}

// scanDTO is the JSON shape returned for one scan report. The finding
// fields are re-emitted as raw JSON (rather than re-marshaled Go structs)
// since store.Scan already holds them pre-serialized.
//
// TextOnlyFailures is only populated when a scanDTO is built directly from
// a freshly-run scan.Report (POST /api/v1/scan/{id} and the admin rescan
// endpoint); it is omitted when built from a store.Scan reloaded from the
// database (GET /api/v1/scan/{id}, the versions endpoints), since the
// scans table -- per the design -- persists only the TextOnlyOK bool, not
// the specific file list. See scan.Report's doc comment for the rationale.
type scanDTO struct {
	ID                    int64           `json:"id"`
	TargetType            string          `json:"target_type"`
	TargetID              string          `json:"target_id"`
	Trigger               string          `json:"trigger"`
	Verdict               string          `json:"verdict"`
	TextOnlyOK            bool            `json:"text_only_ok"`
	TextOnlyFailures      []string        `json:"text_only_failures,omitempty"`
	HiddenCharsFindings   json.RawMessage `json:"hidden_chars_findings"`
	StaticPatternFindings json.RawMessage `json:"static_pattern_findings"`
	LLMAssessment         json.RawMessage `json:"llm_assessment"`
	ScannedAt             string          `json:"scanned_at"`
}

func toScanDTO(sc store.Scan) scanDTO {
	dto := scanDTO{
		ID:                    sc.ID,
		TargetType:            string(sc.TargetType),
		TargetID:              sc.TargetID,
		Trigger:               string(sc.Trigger),
		Verdict:               string(sc.Verdict),
		TextOnlyOK:            sc.TextOnlyOK,
		HiddenCharsFindings:   json.RawMessage(sc.HiddenCharsFindingsJSON),
		StaticPatternFindings: json.RawMessage(sc.StaticPatternFindingsJSON),
		ScannedAt:             sc.ScannedAt.UTC().Format(time.RFC3339),
	}
	if sc.LLMAssessmentJSON != nil {
		dto.LLMAssessment = json.RawMessage(*sc.LLMAssessmentJSON)
	}
	return dto
}

// toScanDTOFromReport builds the richer, live-report shape (including
// TextOnlyFailures) for the scan-preview/rescan endpoints, which have
// access to the freshly-computed scan.Report as well as the row it was
// persisted as.
func toScanDTOFromReport(report scan.Report, sc store.Scan) scanDTO {
	dto := toScanDTO(sc)
	dto.TextOnlyFailures = report.TextOnlyFailures
	return dto
}

// ScanIDString formats a skill_versions row id as the string form used as
// scans.target_id for ScanTargetSkillVersion rows. Exported so
// internal/web can look up the same scan row this package already reads
// for the JSON API's GET /api/v1/skills/{id}/versions/{version}.
func ScanIDString(id int64) string {
	return strconv.FormatInt(id, 10)
}
