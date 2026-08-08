package api

import (
	"encoding/json"
	"net/http"
	"time"

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
	}
	if s.DecidedAt != nil {
		formatted := s.DecidedAt.UTC().Format(time.RFC3339)
		dto.DecidedAt = &formatted
	}
	return dto
}

// skillDTO is the JSON shape returned for a published skill.
type skillDTO struct {
	SkillID     string `json:"skill_id"`
	DisplayName string `json:"display_name"`
	Description string `json:"description"`
	Version     int64  `json:"version"`
	Submitter   string `json:"submitter"`
	PublishedAt string `json:"published_at"`
	GitHubPath  string `json:"github_path"`
	Downloads   int64  `json:"downloads"`
}

func toSkillDTO(s store.Skill) skillDTO {
	return skillDTO{
		SkillID:     s.SkillID,
		DisplayName: s.DisplayName,
		Description: s.Description,
		Version:     s.Version,
		Submitter:   s.Submitter,
		PublishedAt: s.PublishedAt.UTC().Format(time.RFC3339),
		GitHubPath:  s.GitHubPath,
		Downloads:   s.Downloads,
	}
}

func toSkillDTOs(skills []store.Skill) []skillDTO {
	out := make([]skillDTO, 0, len(skills))
	for _, s := range skills {
		out = append(out, toSkillDTO(s))
	}
	return out
}
