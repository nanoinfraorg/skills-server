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
	"time"

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

// scanForApproval returns the verdict to publish under, reusing a scan already
// recorded against this submission when there is one.
//
// Returns a non-empty reason when the verdict blocks. The reason comes from a
// freshly-run report when this call ran one, and from the stored row otherwise --
// a stored row holds the findings that produced its verdict, so the rejection
// still says why rather than just "blocked".
func (h *Handler) scanForApproval(
	ctx context.Context,
	id string,
	sub *store.Submission,
	files []pipeline.FileContent,
	trigger store.ScanTrigger,
) (scan.Verdict, string, *SubmissionError) {
	if existing, err := h.Store.GetLatestScan(ctx, store.ScanTargetSubmission, sub.ID); err == nil {
		h.Logger.Info("reusing the scan already recorded for this submission",
			"id", id, "skill_id", sub.SkillID, "verdict", existing.Verdict)
		reused := scan.Verdict(existing.Verdict)
		if reused == scan.VerdictBlocked {
			return reused, "security scan blocked this submission (see its scan report)", nil
		}
		return reused, "", nil
	} else if !errors.Is(err, store.ErrNotFound) {
		h.Logger.Error("look for an existing scan", "error", err)
		return "", "", &SubmissionError{http.StatusInternalServerError, "could not read this submission's scan"}
	}

	report := scan.Run(ctx, files, h.ScanConfig)
	scanRow, err := scan.BuildScanRow(report, store.ScanTargetSubmission, sub.ID, trigger, h.now())
	if err != nil {
		h.Logger.Error("build scan row", "error", err)
		return "", "", &SubmissionError{http.StatusInternalServerError, "scan completed but could not be recorded"}
	}
	if _, err := h.Store.CreateScan(ctx, scanRow); err != nil {
		h.Logger.Error("record scan", "error", err)
		return "", "", &SubmissionError{http.StatusInternalServerError, "scan completed but could not be recorded"}
	}
	if report.Verdict == scan.VerdictBlocked {
		return report.Verdict, summarizeBlockedScan(report), nil
	}
	return report.Verdict, "", nil
}

// publishTimeout bounds one background publish. Generous rather than absent: a
// hung LLM or GitHub call would otherwise leave the row in `publishing` until a
// restart, and the LLM client alone allows 30 seconds.
const publishTimeout = 5 * time.Minute

// ApproveSubmissionAsync claims a pending submission and does the work in the
// background, so the caller's request returns at once.
//
// Approving used to hold the request open for the whole pipeline: an LLM
// classification with a 30-second client timeout, then a GitHub publish.
// Approving ten submissions meant watching that ten times, which is the reason
// this exists.
//
// The claim is a conditional UPDATE from `pending`, so it is also the lock: two
// clicks produce one publish. A caller that does not get the claim is told the
// submission is already being published rather than being handed a second one.
//
// Errors during the work are not lost. Every failure path inside
// ApproveSubmissionCore already ends in a rejection with a reason or a logged
// server error, and the row leaves `publishing` either way -- the one case that
// does not is a crash mid-publish, which ReconcilePublishing recovers at
// startup.
func (h *Handler) ApproveSubmissionAsync(ctx context.Context, id string) (bool, *SubmissionError) {
	sub, err := h.Store.GetSubmission(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return false, &SubmissionError{http.StatusNotFound, "submission not found"}
	}
	if err != nil {
		h.Logger.Error("get submission", "error", err)
		return false, &SubmissionError{http.StatusInternalServerError, "could not load submission"}
	}
	if sub.Status != store.StatusPending {
		return false, &SubmissionError{
			http.StatusConflict,
			fmt.Sprintf("submission is already %s", sub.Status),
		}
	}

	claimed, err := h.Store.ClaimSubmissionForPublish(ctx, id)
	if err != nil {
		h.Logger.Error("claim submission for publish", "error", err)
		return false, &SubmissionError{http.StatusInternalServerError, "could not start publishing"}
	}
	if !claimed {
		return false, &SubmissionError{
			http.StatusConflict,
			"this submission is already being published",
		}
	}

	h.publishInBackground(id, sub.SkillID)
	return true, nil
}

// publishInBackground runs one claimed publish and records what happened.
//
// A background context, not the request's: the caller's connection closing must
// not cancel a GitHub publish halfway. The deadline is generous rather than
// absent, because a hung LLM or GitHub call would otherwise leave the row in
// `publishing` until a restart.
func (h *Handler) publishInBackground(id, skillID string) {
	if h.publishWaitGroup != nil {
		h.publishWaitGroup.Add(1)
	}
	go func() {
		if h.publishWaitGroup != nil {
			defer h.publishWaitGroup.Done()
		}
		ctx, cancel := context.WithTimeout(context.WithoutCancel(context.Background()), publishTimeout)
		defer cancel()

		outcome, subErr := h.ApproveSubmissionCore(ctx, id)
		switch {
		case subErr != nil:
			h.Logger.Error("background publish failed", "id", id, "skill_id", skillID,
				"status", subErr.Status, "message", subErr.Message)
			// Nothing was published, so the row goes back to pending: that is the
			// truthful state, and an admin can try again once the cause is fixed.
			// Left in `publishing` it would need a restart to become actionable.
			if err := h.Store.ReleaseSubmissionClaim(ctx, id); err != nil {
				h.Logger.Error("return a failed publish to pending", "error", err, "id", id)
			}
		case !outcome.Published:
			h.Logger.Info("background publish rejected the submission", "id", id,
				"skill_id", skillID, "reason", outcome.Reason)
		default:
			h.Logger.Info("background publish complete", "id", id, "skill_id", skillID,
				"version", outcome.Version, "scan_verdict", outcome.ScanVerdict)
		}
	}()
}

// ReconcilePublishing puts every submission left mid-publish back where it
// belongs, at startup.
//
// A crash between the claim and the outcome leaves a row in `publishing` with
// nobody working on it, and such a row would sit in the dashboard forever. The
// version row is the commit point: if one exists for this submission the publish
// finished and the row is approved, and if it does not, nothing was published
// and the row goes back to pending.
func (h *Handler) ReconcilePublishing(ctx context.Context) {
	stuck, err := h.Store.ListPublishingSubmissions(ctx)
	if err != nil {
		h.Logger.Error("list submissions left mid-publish", "error", err)
		return
	}
	for _, sub := range stuck {
		version, err := h.Store.GetSkillVersionBySubmission(ctx, sub.ID)
		if err == nil && version != nil {
			reason := ""
			if decideErr := h.Store.DecideSubmission(ctx, sub.ID, store.StatusApproved, &reason, h.now()); decideErr != nil {
				h.Logger.Error("recover a finished publish", "error", decideErr, "id", sub.ID)
				continue
			}
			h.Logger.Warn("recovered a publish that finished before a restart",
				"id", sub.ID, "skill_id", sub.SkillID, "version", version.Version)
			continue
		}
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			h.Logger.Error("check for a published version", "error", err, "id", sub.ID)
			continue
		}
		if err := h.Store.ReleaseSubmissionClaim(ctx, sub.ID); err != nil {
			h.Logger.Error("return a stuck submission to pending", "error", err, "id", sub.ID)
			continue
		}
		h.Logger.Warn("returned a submission left mid-publish to pending",
			"id", sub.ID, "skill_id", sub.SkillID)
	}
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
	// `publishing` is accepted as well as `pending`, because the async path claims
	// the row *before* calling this and must not let go of it.
	//
	// An earlier version released the claim here so this shared check would pass,
	// and a concurrency test caught what that opened: goroutine A claimed,
	// released, and goroutine B claimed the same row -- two publishes from two
	// clicks, which is the exact thing the claim exists to prevent. The claim is
	// a lock, so it is held until the outcome.
	if sub.Status != store.StatusPending && sub.Status != store.StatusPublishing {
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

	// A submission's archive is written once and never modified, so a scan
	// already recorded against it describes these exact bytes. Re-running it
	// here paid for a second LLM call over the same content -- and the verdict
	// an admin reads in the dashboard's Scan column, immediately before
	// clicking approve, came from that first scan. So the second one told
	// nobody anything and cost the wait.
	//
	// A blocked verdict still blocks, whichever scan produced it. With no
	// recorded scan the pipeline runs one, so "nothing publishes unscanned"
	// holds either way.
	verdict, blockedReason, subErr := h.scanForApproval(ctx, id, sub, files, trigger)
	if subErr != nil {
		return nil, subErr
	}
	if blockedReason != "" {
		return h.autoReject(ctx, id, sub, blockedReason)
	}
	report := scan.Report{Verdict: verdict}

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
		// Read from the archive that was just validated, so the listing can say what a reader
		// is installing rather than making every search open a zip.
		Kind: result.Kind,
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
