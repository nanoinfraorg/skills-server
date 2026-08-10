package api

import (
	"context"
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

// SubmissionError is a safe, user-facing HTTP status + message describing
// why CreateSubmissionCore (or one of the other *Core functions in this
// package) rejected a request. It is the shared error shape both the JSON
// API (which writes it via writeError) and the HTML UI (internal/web,
// which renders it inline on the form) report to the caller, so both
// surfaces show the exact same validation text for the exact same failure.
type SubmissionError struct {
	Status  int
	Message string
}

func (e *SubmissionError) Error() string { return e.Message }

// SubmissionInput is the shared, transport-agnostic input for creating a
// submission: both the JSON API's multipart POST (CreateSubmission) and the
// HTML submit form (internal/web) parse a multipart request down to this
// same shape and hand it to CreateSubmissionCore, so the actual
// validate-then-store logic is never duplicated between the two.
type SubmissionInput struct {
	SkillID     string
	DisplayName string
	Submitter   string
	// Owner and Risks are optional, submitter-provided free text for the
	// "Skill Card" governance fields (who's accountable for this skill, and
	// what could go wrong plus how that's mitigated). Empty means "not
	// provided" -- neither is validated as required.
	Owner   string
	Risks   string
	Archive io.Reader
}

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
	owner := strings.TrimSpace(r.FormValue("owner"))
	risks := strings.TrimSpace(r.FormValue("risks"))

	// A request authenticated via a Google OAuth session (rather than the
	// shared X-Submitter-Token) has a real, verified identity -- it always
	// wins over whatever the client put in the submitter form field, so
	// that field can't be spoofed once we actually know who's submitting.
	if email, ok := sessionEmailFromContext(r.Context()); ok {
		submitter = email
	}

	file, _, err := r.FormFile("archive")
	if err != nil {
		writeError(w, http.StatusBadRequest, "archive file field is required (multipart field name: archive)")
		return
	}
	defer file.Close()

	id, subErr := h.CreateSubmissionCore(r.Context(), SubmissionInput{
		SkillID:     skillID,
		DisplayName: displayName,
		Submitter:   submitter,
		Owner:       owner,
		Risks:       risks,
		Archive:     file,
	})
	if subErr != nil {
		writeError(w, subErr.Status, subErr.Message)
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{"id": id, "status": string(store.StatusPending)})
}

// CreateSubmissionCore validates in and, if it passes, stores the uploaded
// archive and records a new pending submission row. It is the single
// implementation shared by CreateSubmission (the JSON API) and the HTML
// submit form (internal/web) -- both parse their respective multipart
// request down to a SubmissionInput and call this.
func (h *Handler) CreateSubmissionCore(ctx context.Context, in SubmissionInput) (string, *SubmissionError) {
	if !pipeline.ValidSkillID(in.SkillID) {
		return "", &SubmissionError{http.StatusBadRequest, "invalid skill_id: must be lowercase letters, digits, and hyphens, max 64 chars"}
	}
	if in.DisplayName == "" {
		return "", &SubmissionError{http.StatusBadRequest, "display_name is required"}
	}
	if in.Submitter == "" {
		return "", &SubmissionError{http.StatusBadRequest, "submitter is required"}
	}

	id := uuid.NewString()
	archivePath := filepath.Join(h.SubmissionsDir, id+".zip")
	if err := saveUpload(archivePath, in.Archive); err != nil {
		h.Logger.Error("save submission archive", "error", err)
		return "", &SubmissionError{http.StatusInternalServerError, "could not store the uploaded archive"}
	}

	if _, err := pipeline.ValidateArchive(archivePath, in.SkillID); err != nil {
		_ = os.Remove(archivePath)
		return "", &SubmissionError{http.StatusUnprocessableEntity, err.Error()}
	}

	sub := store.Submission{
		ID:          id,
		SkillID:     in.SkillID,
		DisplayName: in.DisplayName,
		Submitter:   in.Submitter,
		Status:      store.StatusPending,
		ArchivePath: archivePath,
		CreatedAt:   h.now(),
		Owner:       in.Owner,
		Risks:       in.Risks,
	}
	if err := h.Store.CreateSubmission(ctx, sub); err != nil {
		_ = os.Remove(archivePath)
		h.Logger.Error("create submission", "error", err)
		return "", &SubmissionError{http.StatusInternalServerError, "could not record the submission"}
	}

	return id, nil
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
