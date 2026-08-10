package api

import (
	"archive/zip"
	"bytes"
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
	"github.com/nanoinfraorg/skills-server/internal/virustotal"
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

// ApproveOutcome is the shared result of approving a pending submission --
// either published (SkillID/Version/ScanVerdict populated) or auto-rejected
// (Reason populated) -- returned by ApproveSubmissionCore and used by both
// the JSON API (ApproveSubmission) and the HTML admin dashboard
// (internal/web) to render the exact same outcome for the exact same call.
type ApproveOutcome struct {
	Published   bool
	SkillID     string
	Version     int64
	ScanVerdict scan.Verdict
	// Reason is populated when Published is false: either a pipeline
	// validation error or a summarized "blocked" scan verdict.
	Reason string
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
	outcome, subErr := h.ApproveSubmissionCore(r.Context(), r.PathValue("id"))
	if subErr != nil {
		writeError(w, subErr.Status, subErr.Message)
		return
	}
	if !outcome.Published {
		writeJSON(w, http.StatusOK, map[string]string{"outcome": "rejected", "reason": outcome.Reason})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"outcome":      "published",
		"skill_id":     outcome.SkillID,
		"version":      outcome.Version,
		"scan_verdict": outcome.ScanVerdict,
	})
}

// ApproveSubmissionCore is the implementation shared by ApproveSubmission
// (the JSON API) and the HTML admin dashboard's approve action
// (internal/web); see ApproveSubmission's doc comment for the full
// description of what it does and why it runs synchronously.
func (h *Handler) ApproveSubmissionCore(ctx context.Context, id string) (*ApproveOutcome, *SubmissionError) {
	sub, err := h.Store.GetSubmission(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, &SubmissionError{http.StatusNotFound, "submission not found"}
	}
	if err != nil {
		h.Logger.Error("get submission", "error", err)
		return nil, &SubmissionError{http.StatusInternalServerError, "could not load submission"}
	}
	if sub.Status != store.StatusPending {
		return nil, &SubmissionError{http.StatusConflict, fmt.Sprintf("submission is already %s", sub.Status)}
	}

	result, err := pipeline.ValidateArchive(sub.ArchivePath, sub.SkillID)
	if err != nil {
		return h.autoReject(ctx, id, sub, err.Error())
	}

	files, err := pipeline.ReadFiles(sub.ArchivePath, result.Entries)
	if err != nil {
		h.Logger.Error("read validated archive", "error", err)
		return nil, &SubmissionError{http.StatusInternalServerError, "could not read the validated archive"}
	}

	_, err = h.Store.GetSkill(ctx, sub.SkillID)
	isUpdate := err == nil
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		h.Logger.Error("check for existing skill", "error", err)
		return nil, &SubmissionError{http.StatusInternalServerError, "could not check for an existing published skill"}
	}
	trigger := store.ScanTriggerPipeline
	if isUpdate {
		trigger = store.ScanTriggerOnUpdate
	}

	report := scan.Run(ctx, files, h.ScanConfig)
	scanRow, err := scan.BuildScanRow(report, store.ScanTargetSubmission, sub.ID, trigger, h.now())
	if err != nil {
		h.Logger.Error("build scan row", "error", err)
		return nil, &SubmissionError{http.StatusInternalServerError, "scan completed but could not be recorded"}
	}
	if _, err := h.Store.CreateScan(ctx, scanRow); err != nil {
		h.Logger.Error("record scan", "error", err)
		return nil, &SubmissionError{http.StatusInternalServerError, "scan completed but could not be recorded"}
	}

	if report.Verdict == scan.VerdictBlocked {
		return h.autoReject(ctx, id, sub, summarizeBlockedScan(report))
	}

	version, err := h.Store.MaxVersion(ctx, sub.SkillID)
	if err != nil {
		h.Logger.Error("compute max version", "error", err)
		return nil, &SubmissionError{http.StatusInternalServerError, "could not determine the next version"}
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
		return nil, &SubmissionError{http.StatusBadGateway, "publish to GitHub failed; submission remains pending for retry"}
	}

	if err := copyFile(sub.ArchivePath, filepath.Join(h.PublishedDir, sub.SkillID+".zip")); err != nil {
		h.Logger.Error("archive published copy", "error", err)
		return nil, &SubmissionError{http.StatusInternalServerError, "published to GitHub but could not archive the local download copy"}
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
		Owner:        sub.Owner,
		Risks:        sub.Risks,
	}
	skillVersionID, err := h.Store.CreateSkillVersion(ctx, skillVersion)
	if err != nil {
		h.Logger.Error("create skill version", "error", err)
		return nil, &SubmissionError{http.StatusInternalServerError, "published to GitHub but could not record the new version"}
	}
	if err := h.Store.SetSkillPointer(ctx, sub.SkillID, version, h.now()); err != nil {
		h.Logger.Error("set skill pointer", "error", err)
		return nil, &SubmissionError{http.StatusInternalServerError, "published to GitHub but could not update the catalog"}
	}
	if err := h.Store.DecideSubmission(ctx, id, store.StatusApproved, nil, h.now()); err != nil {
		h.Logger.Error("record approval", "error", err)
		return nil, &SubmissionError{http.StatusInternalServerError, "published but could not record the decision"}
	}

	// Attach the same scan result to the new skill version, so it's
	// queryable via GET /api/v1/skills/{id}/versions/{version} without a
	// second scan run.
	versionScanRow, err := scan.BuildScanRow(report, store.ScanTargetSkillVersion, ScanIDString(skillVersionID), trigger, h.now())
	if err != nil {
		h.Logger.Error("build skill-version scan row", "error", err)
	} else if _, err := h.Store.CreateScan(ctx, versionScanRow); err != nil {
		h.Logger.Error("attach scan to skill version", "error", err)
	}

	h.triggerVirusTotalUpload(sub.SkillID, files, skillVersionID)

	h.Logger.Info("submission published", "id", id, "skill_id", sub.SkillID, "version", version, "scan_verdict", report.Verdict)
	return &ApproveOutcome{Published: true, SkillID: sub.SkillID, Version: version, ScanVerdict: report.Verdict}, nil
}

// triggerVirusTotalUpload fires off a background VirusTotal upload for a
// just-published skill version, if VirusTotal is configured
// (h.VirusTotalClient is non-nil). It builds the archive to upload from
// files -- the exact same already-validated, already-in-memory file
// contents this same call to ApproveSubmissionCore already read via
// pipeline.ReadFiles and just committed to GitHub -- rather than re-reading
// sub.ArchivePath or the freshly-written PublishedDir copy from disk.
//
// The upload itself, and recording its result, happen entirely inside the
// spawned goroutine (internal/virustotal.UploadAndRecord), using
// context.Background() rather than the request's own context: the HTTP
// request's context is canceled the moment the approve response is
// written, but VirusTotal's upload (and the analysis it kicks off) has no
// reason to be tied to how long that response took to send. This is what
// keeps VirusTotal's latency -- or a full VirusTotal outage -- from ever
// adding to the approve request's response time or from failing/rolling
// back a publish that has already fully succeeded.
func (h *Handler) triggerVirusTotalUpload(skillID string, files []pipeline.FileContent, skillVersionID int64) {
	if h.VirusTotalClient == nil {
		return
	}
	archive, err := buildArchiveZip(files)
	if err != nil {
		h.Logger.Warn("virustotal: build archive for upload", "error", err, "skill_id", skillID)
		return
	}
	go virustotal.UploadAndRecord(context.Background(), h.VirusTotalClient, h.Store, h.Logger, h.now, skillVersionID, archive, skillID+".zip")
}

// buildArchiveZip re-zips already-read file contents into an in-memory
// archive, entirely in a bytes.Buffer -- no temp file, no second disk read
// of anything ApproveSubmissionCore already has in hand. Used only to build
// the payload for a VirusTotal upload; the durable published archive copy
// (PublishedDir/<skill_id>.zip) is still the original uploaded zip, written
// by copyFile as it always was.
func buildArchiveZip(files []pipeline.FileContent) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range files {
		w, err := zw.Create(f.Path)
		if err != nil {
			return nil, fmt.Errorf("create zip entry %s: %w", f.Path, err)
		}
		if _, err := w.Write(f.Content); err != nil {
			return nil, fmt.Errorf("write zip entry %s: %w", f.Path, err)
		}
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("close zip writer: %w", err)
	}
	return buf.Bytes(), nil
}

// autoReject records a submission as auto-rejected with reason, returning
// the shared ApproveOutcome shape. Both a pipeline-validation failure and a
// "blocked" scan verdict funnel through this single path.
func (h *Handler) autoReject(ctx context.Context, id string, sub *store.Submission, reason string) (*ApproveOutcome, *SubmissionError) {
	if decideErr := h.Store.DecideSubmission(ctx, id, store.StatusRejected, &reason, h.now()); decideErr != nil {
		h.Logger.Error("record auto-rejection", "error", decideErr)
		return nil, &SubmissionError{http.StatusInternalServerError, "validation failed and rejection could not be recorded"}
	}
	h.Logger.Info("submission auto-rejected", "id", id, "skill_id", sub.SkillID, "reason", reason)
	return &ApproveOutcome{Published: false, Reason: reason}, nil
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
	var body struct {
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "request body must be JSON: {\"reason\": \"...\"}")
		return
	}

	reason, subErr := h.RejectSubmissionCore(r.Context(), r.PathValue("id"), body.Reason)
	if subErr != nil {
		writeError(w, subErr.Status, subErr.Message)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"outcome": "rejected", "reason": reason})
}

// RejectSubmissionCore is the implementation shared by RejectSubmission
// (the JSON API, which reads reason from a JSON body) and the HTML admin
// dashboard's reject action (internal/web, which reads it from a form
// field) -- rejects a pending submission with reason and returns it
// trimmed, or an error if the submission is missing, not pending, or reason
// is blank.
func (h *Handler) RejectSubmissionCore(ctx context.Context, id, reason string) (string, *SubmissionError) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return "", &SubmissionError{http.StatusBadRequest, "reason is required"}
	}

	sub, err := h.Store.GetSubmission(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return "", &SubmissionError{http.StatusNotFound, "submission not found"}
	}
	if err != nil {
		h.Logger.Error("get submission", "error", err)
		return "", &SubmissionError{http.StatusInternalServerError, "could not load submission"}
	}
	if sub.Status != store.StatusPending {
		return "", &SubmissionError{http.StatusConflict, fmt.Sprintf("submission is already %s", sub.Status)}
	}

	if err := h.Store.DecideSubmission(ctx, id, store.StatusRejected, &reason, h.now()); err != nil {
		h.Logger.Error("record rejection", "error", err)
		return "", &SubmissionError{http.StatusInternalServerError, "could not record the rejection"}
	}

	h.Logger.Info("submission rejected", "id", id, "skill_id", sub.SkillID, "reason", reason)
	return reason, nil
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
