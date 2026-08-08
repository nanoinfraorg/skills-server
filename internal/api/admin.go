package api

import (
	"context"
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
	"github.com/nanoinfraorg/skills-server/internal/scan"
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
// submission's archive and, if it passes, runs the security scan shield
// (internal/scan) against the same validated files. A "blocked" verdict
// auto-rejects the submission via the same path a pipeline-validation
// failure already uses, with the scan's findings summarized in the
// rejection reason. A "flagged" or "pass" verdict proceeds to publish the
// skill to GitHub and record it (as a new version) in the public catalog;
// either way, the scan result is stored, attached to the submission, and
// -- once published -- also attached to the skill version it produced, so
// it's queryable via the versions endpoints.
//
// If skill_id already has a published skill, this is a version update, not
// a create -- the same submission -> pending -> admin approve -> publish
// flow handles both; no separate "update" endpoint exists.
//
// The pipeline and scan both run inline in the request rather than via a
// background job queue: v1 is a single-operator service, archives are
// small, and a synchronous approve keeps the state machine trivial to
// reason about (no "approved but not yet published" limbo state to track).
// See the README.
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
		h.autoReject(w, ctx, id, sub, err.Error())
		return
	}

	files, err := pipeline.ReadFiles(sub.ArchivePath, result.Entries)
	if err != nil {
		h.Logger.Error("read validated archive", "error", err)
		writeError(w, http.StatusInternalServerError, "could not read the validated archive")
		return
	}

	_, err = h.Store.GetSkill(ctx, sub.SkillID)
	isUpdate := err == nil
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		h.Logger.Error("check for existing skill", "error", err)
		writeError(w, http.StatusInternalServerError, "could not check for an existing published skill")
		return
	}
	trigger := store.ScanTriggerPipeline
	if isUpdate {
		trigger = store.ScanTriggerOnUpdate
	}

	report := scan.Run(ctx, files, h.ScanConfig)
	scanRow, err := scan.BuildScanRow(report, store.ScanTargetSubmission, sub.ID, trigger, h.now())
	if err != nil {
		h.Logger.Error("build scan row", "error", err)
		writeError(w, http.StatusInternalServerError, "scan completed but could not be recorded")
		return
	}
	if _, err := h.Store.CreateScan(ctx, scanRow); err != nil {
		h.Logger.Error("record scan", "error", err)
		writeError(w, http.StatusInternalServerError, "scan completed but could not be recorded")
		return
	}

	if report.Verdict == scan.VerdictBlocked {
		h.autoReject(w, ctx, id, sub, summarizeBlockedScan(report))
		return
	}

	version, err := h.Store.MaxVersion(ctx, sub.SkillID)
	if err != nil {
		h.Logger.Error("compute max version", "error", err)
		writeError(w, http.StatusInternalServerError, "could not determine the next version")
		return
	}
	version++

	ghFiles := make([]github.File, 0, len(files))
	for _, f := range files {
		ghFiles = append(ghFiles, github.File{Path: f.Path, Content: f.Content})
	}
	commitMessage := fmt.Sprintf("Publish %s v%d via skills-server", sub.SkillID, version)
	if err := h.Publisher.PublishFiles(ctx, sub.SkillID, ghFiles, commitMessage); err != nil {
		// A GitHub/infra failure is not the submitter's fault: leave the
		// submission pending so an admin can retry the approval later,
		// rather than auto-rejecting a skill that actually passed the
		// pipeline and the scan shield.
		h.Logger.Error("publish to github", "error", err, "skill_id", sub.SkillID)
		writeError(w, http.StatusBadGateway, "publish to GitHub failed; submission remains pending for retry")
		return
	}

	if err := copyFile(sub.ArchivePath, filepath.Join(h.PublishedDir, sub.SkillID+".zip")); err != nil {
		h.Logger.Error("archive published copy", "error", err)
		writeError(w, http.StatusInternalServerError, "published to GitHub but could not archive the local download copy")
		return
	}

	skillVersion := store.SkillVersion{
		SkillID:      sub.SkillID,
		Version:      version,
		SubmissionID: sub.ID,
		DisplayName:  sub.DisplayName,
		Description:  result.Metadata.Description,
		GitHubPath:   sub.SkillID + "/",
		PublishedAt:  h.now(),
		Status:       store.SkillVersionPublished,
	}
	skillVersionID, err := h.Store.CreateSkillVersion(ctx, skillVersion)
	if err != nil {
		h.Logger.Error("create skill version", "error", err)
		writeError(w, http.StatusInternalServerError, "published to GitHub but could not record the new version")
		return
	}
	if err := h.Store.SetSkillPointer(ctx, sub.SkillID, version, h.now()); err != nil {
		h.Logger.Error("set skill pointer", "error", err)
		writeError(w, http.StatusInternalServerError, "published to GitHub but could not update the catalog")
		return
	}
	if err := h.Store.DecideSubmission(ctx, id, store.StatusApproved, nil, h.now()); err != nil {
		h.Logger.Error("record approval", "error", err)
		writeError(w, http.StatusInternalServerError, "published but could not record the decision")
		return
	}

	// Attach the same scan result to the new skill version, so it's
	// queryable via GET /api/v1/skills/{id}/versions/{version} without a
	// second scan run.
	versionScanRow, err := scan.BuildScanRow(report, store.ScanTargetSkillVersion, scanIDString(skillVersionID), trigger, h.now())
	if err != nil {
		h.Logger.Error("build skill-version scan row", "error", err)
	} else if _, err := h.Store.CreateScan(ctx, versionScanRow); err != nil {
		h.Logger.Error("attach scan to skill version", "error", err)
	}

	h.Logger.Info("submission published", "id", id, "skill_id", sub.SkillID, "version", version, "scan_verdict", report.Verdict)
	writeJSON(w, http.StatusOK, map[string]any{
		"outcome":      "published",
		"skill_id":     sub.SkillID,
		"version":      version,
		"scan_verdict": report.Verdict,
	})
}

// autoReject records a submission as auto-rejected with reason and writes
// the standard in-band rejection response. Both a pipeline-validation
// failure and a "blocked" scan verdict funnel through this single path.
func (h *Handler) autoReject(w http.ResponseWriter, ctx context.Context, id string, sub *store.Submission, reason string) {
	if decideErr := h.Store.DecideSubmission(ctx, id, store.StatusRejected, &reason, h.now()); decideErr != nil {
		h.Logger.Error("record auto-rejection", "error", decideErr)
		writeError(w, http.StatusInternalServerError, "validation failed and rejection could not be recorded")
		return
	}
	h.Logger.Info("submission auto-rejected", "id", id, "skill_id", sub.SkillID, "reason", reason)
	writeJSON(w, http.StatusOK, map[string]string{"outcome": "rejected", "reason": reason})
}

// summarizeBlockedScan builds a concise, human-readable rejection reason
// from a "blocked" scan.Report, for use as the auto-rejection reason.
func summarizeBlockedScan(report scan.Report) string {
	var parts []string
	parts = append(parts, "security scan blocked this submission:")
	if !report.TextOnlyOK {
		parts = append(parts, fmt.Sprintf("%d file(s) failed the text-only check (%s);", len(report.TextOnlyFailures), strings.Join(report.TextOnlyFailures, ", ")))
	}
	if n := len(report.HiddenCharFindings); n > 0 {
		parts = append(parts, fmt.Sprintf("%d hidden/invisible-character finding(s);", n))
	}
	if n := len(report.StaticPatternFindings); n > 0 {
		parts = append(parts, fmt.Sprintf("%d suspicious static-pattern finding(s);", n))
	}
	return strings.TrimSuffix(strings.Join(parts, " "), ";")
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
