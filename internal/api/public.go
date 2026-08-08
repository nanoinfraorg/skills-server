package api

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/nanoinfraorg/skills-server/internal/store"
)

const trendingLimit = 20

// SearchSkills performs a case-insensitive substring search over published
// skills' denormalized name+description+skill_id text.
func (h *Handler) SearchSkills(w http.ResponseWriter, r *http.Request) {
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	if query == "" {
		writeError(w, http.StatusBadRequest, "q is required")
		return
	}

	skills, err := h.Store.SearchSkills(r.Context(), query, trendingLimit)
	if err != nil {
		h.Logger.Error("search skills", "error", err)
		writeError(w, http.StatusInternalServerError, "search failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"query": query, "skills": toSkillDTOs(skills)})
}

// TrendingSkills returns published skills ordered by downloads descending.
func (h *Handler) TrendingSkills(w http.ResponseWriter, r *http.Request) {
	skills, err := h.Store.TrendingSkills(r.Context(), trendingLimit)
	if err != nil {
		h.Logger.Error("trending skills", "error", err)
		writeError(w, http.StatusInternalServerError, "could not load trending skills")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"skills": toSkillDTOs(skills)})
}

// GetSkill returns catalog details for a single published skill.
func (h *Handler) GetSkill(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	skill, err := h.Store.GetSkill(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "skill not found")
		return
	}
	if err != nil {
		h.Logger.Error("get skill", "error", err)
		writeError(w, http.StatusInternalServerError, "could not load skill")
		return
	}
	writeJSON(w, http.StatusOK, toSkillDTO(*skill))
}

// DownloadSkill streams a published skill's zip archive.
//
// The archive is served from the local PublishedDir copy rather than
// fetched live from GitHub on each request: the private nanoinfraorg/skills
// repo is treated as the durable source-of-truth / audit trail, while the
// locally-archived, pipeline-validated zip (written at publish time) is the
// actual read path. This avoids re-fetching and re-zipping files from the
// GitHub API on every download and avoids a live dependency between the
// public download endpoint and GitHub's availability. See the README.
func (h *Handler) DownloadSkill(w http.ResponseWriter, r *http.Request) {
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

	archivePath := filepath.Join(h.PublishedDir, skill.SkillID+".zip")
	f, err := os.Open(archivePath)
	if err != nil {
		h.Logger.Error("open published archive", "error", err, "skill_id", skill.SkillID)
		writeError(w, http.StatusInternalServerError, "published archive is missing")
		return
	}
	defer f.Close()

	if err := h.Store.IncrementDownloads(ctx, skill.SkillID); err != nil {
		h.Logger.Warn("increment downloads", "error", err, "skill_id", skill.SkillID)
	}

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+skill.SkillID+".zip\"")
	http.ServeContent(w, r, skill.SkillID+".zip", skill.PublishedAt, f)
}
