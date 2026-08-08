package api

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/nanoinfraorg/skills-server/internal/store"
)

const trendingLimit = 20

// SearchSkills performs a case-insensitive substring search over published
// skills' denormalized current-version name+description+skill_id text.
// Skills whose current version is quarantined are excluded.
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

// TrendingSkills returns published skills ordered by downloads descending,
// excluding any whose current version is quarantined.
func (h *Handler) TrendingSkills(w http.ResponseWriter, r *http.Request) {
	skills, err := h.Store.TrendingSkills(r.Context(), trendingLimit)
	if err != nil {
		h.Logger.Error("trending skills", "error", err)
		writeError(w, http.StatusInternalServerError, "could not load trending skills")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"skills": toSkillDTOs(skills)})
}

// GetSkill returns catalog details for a single published skill's current
// version. Unlike search/trending, a quarantined current version is still
// returned here (clearly marked via its status field) rather than hidden,
// so an admin or the submitter can see why it was pulled.
func (h *Handler) GetSkill(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	skill, err := h.Store.GetSkillDetail(r.Context(), id)
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

// ListSkillVersions returns every version of one skill's history, newest
// first.
func (h *Handler) ListSkillVersions(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ctx := r.Context()

	if _, err := h.Store.GetSkill(ctx, id); errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "skill not found")
		return
	} else if err != nil {
		h.Logger.Error("get skill", "error", err)
		writeError(w, http.StatusInternalServerError, "could not load skill")
		return
	}

	versions, err := h.Store.ListSkillVersions(ctx, id)
	if err != nil {
		h.Logger.Error("list skill versions", "error", err)
		writeError(w, http.StatusInternalServerError, "could not list skill versions")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"skill_id": id, "versions": toSkillVersionSummaryDTOs(versions)})
}

// GetSkillVersion returns one specific version's full detail, plus its
// latest scan report if one has run. Like GetSkill, a quarantined version
// is still returned (clearly marked), not hidden.
func (h *Handler) GetSkillVersion(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ctx := r.Context()

	version, err := strconv.ParseInt(r.PathValue("version"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "version must be an integer")
		return
	}

	sv, err := h.Store.GetSkillVersion(ctx, id, version)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "skill version not found")
		return
	}
	if err != nil {
		h.Logger.Error("get skill version", "error", err)
		writeError(w, http.StatusInternalServerError, "could not load skill version")
		return
	}

	var scanDTOPtr *scanDTO
	latestScan, err := h.Store.GetLatestScan(ctx, store.ScanTargetSkillVersion, scanIDString(sv.ID))
	if err == nil {
		dto := toScanDTO(*latestScan)
		scanDTOPtr = &dto
	} else if !errors.Is(err, store.ErrNotFound) {
		h.Logger.Error("get latest scan for skill version", "error", err)
		writeError(w, http.StatusInternalServerError, "could not load the version's scan report")
		return
	}

	writeJSON(w, http.StatusOK, toSkillVersionDetailDTO(*sv, scanDTOPtr))
}

// DownloadSkill streams a published skill's current-version zip archive.
//
// The archive is served from the local PublishedDir copy rather than
// fetched live from GitHub on each request: the private nanoinfraorg/skills
// repo is treated as the durable source-of-truth / audit trail, while the
// locally-archived, pipeline-validated zip (written at publish time) is the
// actual read path. This avoids re-fetching and re-zipping files from the
// GitHub API on every download and avoids a live dependency between the
// public download endpoint and GitHub's availability. See the README.
//
// A skill whose current version has been quarantined by the scan shield is
// treated as not found: the whole point of quarantining a blocked version
// is to stop it circulating, so serving its archive for download even
// while search/trending hide it would defeat the shield's purpose. This is
// a deliberate extension beyond the versioning design's literal wording
// (which only calls out search/trending as excluding quarantined skills);
// see the README's design-choices section.
func (h *Handler) DownloadSkill(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ctx := r.Context()

	skill, err := h.Store.GetSkillDetail(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "skill not found")
		return
	}
	if err != nil {
		h.Logger.Error("get skill", "error", err)
		writeError(w, http.StatusInternalServerError, "could not load skill")
		return
	}
	if skill.Status == store.SkillVersionQuarantined {
		writeError(w, http.StatusNotFound, "skill not found")
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
