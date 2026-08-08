package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/nanoinfraorg/skills-server/internal/github"
	"github.com/nanoinfraorg/skills-server/internal/pipeline"
	"github.com/nanoinfraorg/skills-server/internal/store"
)

// ListSubmissions returns submissions, optionally filtered by
// ?status=pending|approved|rejected.
func (h *Handler) ListSubmissions(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	switch status {
	case "", string(store.StatusPending), string(store.StatusApproved), string(store.StatusRejected):
	default:
		writeError(w, http.StatusBadRequest, "status must be one of: pending, approved, rejected")
		return
	}

	submissions, err := h.Store.ListSubmissions(r.Context(), status)
	if err != nil {
		h.Logger.Error("list submissions", "error", err)
		writeError(w, http.StatusInternalServerError, "could not list submissions")
		return
	}

	dtos := make([]submissionDTO, 0, len(submissions))
	for _, s := range submissions {
		dtos = append(dtos, toSubmissionDTO(s))
	}
	writeJSON(w, http.StatusOK, map[string]any{"submissions": dtos})
}

// ApproveSubmission runs the validation pipeline synchronously against the
// submission's archive and, if it passes, publishes the skill to GitHub and
// records it in the public catalog. If the pipeline fails, the submission
// is auto-rejected with the pipeline's failure reason.
//
// The pipeline runs inline in the request rather than via a background job
// queue: v1 is a single-operator service, archives are small, and a
// synchronous approve keeps the state machine trivial to reason about (no
// "approved but not yet published" limbo state to track). See the README.
func (h *Handler) ApproveSubmission(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ctx := r.Context()

	sub, err := h.Store.GetSubmission(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "submission not found")
		return
	}
	if err != nil {
		h.Logger.Error("get submission", "error", err)
		writeError(w, http.StatusInternalServerError, "could not load submission")
		return
	}
	if sub.Status != store.StatusPending {
		writeError(w, http.StatusConflict, fmt.Sprintf("submission is already %s", sub.Status))
		return
	}

	result, err := pipeline.ValidateArchive(sub.ArchivePath, sub.SkillID)
	if err != nil {
		reason := err.Error()
		if decideErr := h.Store.DecideSubmission(ctx, id, store.StatusRejected, &reason, h.now()); decideErr != nil {
			h.Logger.Error("record auto-rejection", "error", decideErr)
			writeError(w, http.StatusInternalServerError, "pipeline failed and rejection could not be recorded")
			return
		}
		h.Logger.Info("submission auto-rejected by pipeline", "id", id, "skill_id", sub.SkillID, "reason", reason)
		writeJSON(w, http.StatusOK, map[string]string{"outcome": "rejected", "reason": reason})
		return
	}

	files, err := pipeline.ReadFiles(sub.ArchivePath, result.Entries)
	if err != nil {
		h.Logger.Error("read validated archive", "error", err)
		writeError(w, http.StatusInternalServerError, "could not read the validated archive")
		return
	}

	version, err := h.Store.NextVersion(ctx, sub.SkillID)
	if err != nil {
		h.Logger.Error("compute next version", "error", err)
		writeError(w, http.StatusInternalServerError, "could not determine the next version")
		return
	}

	ghFiles := make([]github.File, 0, len(files))
	for _, f := range files {
		ghFiles = append(ghFiles, github.File{Path: f.Path, Content: f.Content})
	}
	commitMessage := fmt.Sprintf("Publish %s v%d via skills-server", sub.SkillID, version)
	if err := h.Publisher.PublishFiles(ctx, sub.SkillID, ghFiles, commitMessage); err != nil {
		// A GitHub/infra failure is not the submitter's fault: leave the
		// submission pending so an admin can retry the approval later,
		// rather than auto-rejecting a skill that actually passed the
		// pipeline.
		h.Logger.Error("publish to github", "error", err, "skill_id", sub.SkillID)
		writeError(w, http.StatusBadGateway, "publish to GitHub failed; submission remains pending for retry")
		return
	}

	if err := copyFile(sub.ArchivePath, filepath.Join(h.PublishedDir, sub.SkillID+".zip")); err != nil {
		h.Logger.Error("archive published copy", "error", err)
		writeError(w, http.StatusInternalServerError, "published to GitHub but could not archive the local download copy")
		return
	}

	skill := store.Skill{
		SkillID:     sub.SkillID,
		DisplayName: sub.DisplayName,
		Description: result.Metadata.Description,
		Version:     version,
		Submitter:   sub.Submitter,
		PublishedAt: h.now(),
		GitHubPath:  sub.SkillID + "/",
	}
	if err := h.Store.UpsertSkill(ctx, skill); err != nil {
		h.Logger.Error("upsert skill", "error", err)
		writeError(w, http.StatusInternalServerError, "published to GitHub but could not update the catalog")
		return
	}
	if err := h.Store.DecideSubmission(ctx, id, store.StatusApproved, nil, h.now()); err != nil {
		h.Logger.Error("record approval", "error", err)
		writeError(w, http.StatusInternalServerError, "published but could not record the decision")
		return
	}

	h.Logger.Info("submission published", "id", id, "skill_id", sub.SkillID, "version", version)
	writeJSON(w, http.StatusOK, map[string]any{
		"outcome":  "published",
		"skill_id": sub.SkillID,
		"version":  version,
	})
}

// RejectSubmission rejects a pending submission with an admin-supplied
// reason. No pipeline run is triggered.
func (h *Handler) RejectSubmission(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ctx := r.Context()

	var body struct {
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "request body must be JSON: {\"reason\": \"...\"}")
		return
	}
	reason := strings.TrimSpace(body.Reason)
	if reason == "" {
		writeError(w, http.StatusBadRequest, "reason is required")
		return
	}

	sub, err := h.Store.GetSubmission(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "submission not found")
		return
	}
	if err != nil {
		h.Logger.Error("get submission", "error", err)
		writeError(w, http.StatusInternalServerError, "could not load submission")
		return
	}
	if sub.Status != store.StatusPending {
		writeError(w, http.StatusConflict, fmt.Sprintf("submission is already %s", sub.Status))
		return
	}

	if err := h.Store.DecideSubmission(ctx, id, store.StatusRejected, &reason, h.now()); err != nil {
		h.Logger.Error("record rejection", "error", err)
		writeError(w, http.StatusInternalServerError, "could not record the rejection")
		return
	}

	h.Logger.Info("submission rejected", "id", id, "skill_id", sub.SkillID, "reason", reason)
	writeJSON(w, http.StatusOK, map[string]string{"outcome": "rejected", "reason": reason})
}

func copyFile(srcPath, destPath string) error {
	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return err
	}
	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer dst.Close()

	_, err = io.Copy(dst, src)
	return err
}
