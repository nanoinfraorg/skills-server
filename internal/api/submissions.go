package api

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/nanoinfraorg/skills-server/internal/pipeline"
	"github.com/nanoinfraorg/skills-server/internal/store"
)

// maxUploadBytes caps the whole multipart request body: the archive itself
// (pipeline.MaxArchiveBytes) plus generous slack for multipart framing and
// form fields.
var maxUploadBytes = pipeline.MaxArchiveBytes + 1<<20

// CreateSubmission accepts a new skill submission: a multipart form with a
// zip archive plus skill_id / display_name / submitter fields. The archive
// is validated immediately with the same pipeline logic the admin-approval
// step re-runs later; this rejects obviously-broken uploads (missing
// SKILL.md, unsafe paths, oversized archives) before they ever sit in the
// pending queue, while approval still re-validates from scratch as the
// authoritative, tamper-resistant gate.
func (h *Handler) CreateSubmission(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	if err := r.ParseMultipartForm(maxUploadBytes); err != nil {
		writeError(w, http.StatusBadRequest, "request body is not a valid multipart form or exceeds the size limit")
		return
	}
	defer func() {
		if r.MultipartForm != nil {
			_ = r.MultipartForm.RemoveAll()
		}
	}()

	skillID := strings.TrimSpace(r.FormValue("skill_id"))
	displayName := strings.TrimSpace(r.FormValue("display_name"))
	submitter := strings.TrimSpace(r.FormValue("submitter"))

	// A request authenticated via a Google OAuth session (rather than the
	// shared X-Submitter-Token) has a real, verified identity -- it always
	// wins over whatever the client put in the submitter form field, so
	// that field can't be spoofed once we actually know who's submitting.
	if email, ok := sessionEmailFromContext(r.Context()); ok {
		submitter = email
	}

	if !pipeline.ValidSkillID(skillID) {
		writeError(w, http.StatusBadRequest, "invalid skill_id: must be lowercase letters, digits, and hyphens, max 64 chars")
		return
	}
	if displayName == "" {
		writeError(w, http.StatusBadRequest, "display_name is required")
		return
	}
	if submitter == "" {
		writeError(w, http.StatusBadRequest, "submitter is required")
		return
	}

	file, _, err := r.FormFile("archive")
	if err != nil {
		writeError(w, http.StatusBadRequest, "archive file field is required (multipart field name: archive)")
		return
	}
	defer file.Close()

	id := uuid.NewString()
	archivePath := filepath.Join(h.SubmissionsDir, id+".zip")
	if err := saveUpload(archivePath, file); err != nil {
		h.Logger.Error("save submission archive", "error", err)
		writeError(w, http.StatusInternalServerError, "could not store the uploaded archive")
		return
	}

	if _, err := pipeline.ValidateArchive(archivePath, skillID); err != nil {
		_ = os.Remove(archivePath)
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}

	sub := store.Submission{
		ID:          id,
		SkillID:     skillID,
		DisplayName: displayName,
		Submitter:   submitter,
		Status:      store.StatusPending,
		ArchivePath: archivePath,
		CreatedAt:   h.now(),
	}
	if err := h.Store.CreateSubmission(r.Context(), sub); err != nil {
		_ = os.Remove(archivePath)
		h.Logger.Error("create submission", "error", err)
		writeError(w, http.StatusInternalServerError, "could not record the submission")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{"id": id, "status": string(store.StatusPending)})
}

func saveUpload(destPath string, src io.Reader) error {
	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return err
	}
	dst, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer dst.Close()
	_, err = io.Copy(dst, src)
	return err
}
