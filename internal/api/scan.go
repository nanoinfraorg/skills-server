package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"

	"github.com/nanoinfraorg/skills-server/internal/pipeline"
	"github.com/nanoinfraorg/skills-server/internal/scan"
	"github.com/nanoinfraorg/skills-server/internal/store"
)

// TriggerScan re-runs the security scan shield against a pending
// submission's already-uploaded archive on demand, letting a submitter or
// admin preview the shield's verdict before an admin decides whether to
// approve. It does not itself approve, reject, or publish anything.
func (h *Handler) TriggerScan(w http.ResponseWriter, r *http.Request) {
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
		writeError(w, http.StatusConflict, fmt.Sprintf("submission is already %s; scan preview is only available for pending submissions", sub.Status))
		return
	}

	result, err := pipeline.ValidateArchive(sub.ArchivePath, sub.SkillID)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "archive failed pipeline validation, so it cannot be scanned: "+err.Error())
		return
	}
	files, err := pipeline.ReadFiles(sub.ArchivePath, result.Entries)
	if err != nil {
		h.Logger.Error("read validated archive for scan preview", "error", err)
		writeError(w, http.StatusInternalServerError, "could not read the archive")
		return
	}

	report := scan.Run(ctx, files, h.ScanConfig)
	dto, err := h.recordScan(ctx, report, store.ScanTargetSubmission, sub.ID, store.ScanTriggerManual)
	if err != nil {
		h.Logger.Error("record scan preview", "error", err)
		writeError(w, http.StatusInternalServerError, "scan completed but could not be recorded")
		return
	}

	h.Logger.Info("scan preview run", "submission_id", sub.ID, "verdict", report.Verdict)
	writeJSON(w, http.StatusOK, dto)
}

// GetScan returns the most recent scan report recorded for a submission, or
// 404 if none has run yet.
func (h *Handler) GetScan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	sc, err := h.Store.GetLatestScan(r.Context(), store.ScanTargetSubmission, id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "no scan has run for this submission yet")
		return
	}
	if err != nil {
		h.Logger.Error("get latest scan", "error", err)
		writeError(w, http.StatusInternalServerError, "could not load the scan report")
		return
	}
	writeJSON(w, http.StatusOK, toScanDTO(*sc))
}

// RescanSkill re-runs the security scan shield (trigger=manual) against a
// published skill's current version, using the already-archived local zip
// copy (the same one downloads are served from -- no need to refetch from
// GitHub). If the result is "blocked", the current version is immediately
// quarantined, which removes it from search/trending and the download
// endpoint. Returns the report either way.
func (h *Handler) RescanSkill(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ctx := r.Context()

	skill, err := h.Store.GetSkill(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "skill not found")
		return
	}
	if err != nil {
		h.Logger.Error("get skill", "error", err)
		writeError(w, http.StatusInternalServerError, "could not load skill")
		return
	}

	sv, err := h.Store.GetSkillVersion(ctx, id, skill.CurrentVersion)
	if err != nil {
		h.Logger.Error("get current skill version", "error", err)
		writeError(w, http.StatusInternalServerError, "could not load the skill's current version")
		return
	}

	archivePath := filepath.Join(h.PublishedDir, id+".zip")
	report, err := scan.RunOnArchive(ctx, archivePath, id, h.ScanConfig)
	if err != nil {
		h.Logger.Error("rescan published archive", "error", err, "skill_id", id)
		writeError(w, http.StatusInternalServerError, "could not re-validate the published archive: "+err.Error())
		return
	}

	dto, err := h.recordScan(ctx, report, store.ScanTargetSkillVersion, scanIDString(sv.ID), store.ScanTriggerManual)
	if err != nil {
		h.Logger.Error("record rescan", "error", err)
		writeError(w, http.StatusInternalServerError, "scan completed but could not be recorded")
		return
	}

	quarantined := false
	if report.Verdict == scan.VerdictBlocked {
		if err := h.Store.SetSkillVersionStatus(ctx, id, skill.CurrentVersion, store.SkillVersionQuarantined); err != nil {
			h.Logger.Error("quarantine skill version", "error", err, "skill_id", id, "version", skill.CurrentVersion)
			writeError(w, http.StatusInternalServerError, "scan blocked this version but it could not be quarantined")
			return
		}
		quarantined = true
	}

	h.Logger.Info("skill rescanned", "skill_id", id, "version", skill.CurrentVersion, "verdict", report.Verdict, "quarantined", quarantined)
	writeJSON(w, http.StatusOK, map[string]any{
		"scan":        dto,
		"quarantined": quarantined,
	})
}

// recordScan serializes report and persists it against the given target,
// returning the richer live-report DTO (including TextOnlyFailures) ready
// to write back to the caller.
func (h *Handler) recordScan(ctx context.Context, report scan.Report, targetType store.ScanTargetType, targetID string, trigger store.ScanTrigger) (scanDTO, error) {
	row, err := scan.BuildScanRow(report, targetType, targetID, trigger, h.now())
	if err != nil {
		return scanDTO{}, fmt.Errorf("build scan row: %w", err)
	}
	scanID, err := h.Store.CreateScan(ctx, row)
	if err != nil {
		return scanDTO{}, fmt.Errorf("create scan: %w", err)
	}
	row.ID = scanID
	return toScanDTOFromReport(report, row), nil
}
