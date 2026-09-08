package api

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/nanoinfraorg/skills-server/internal/pipeline"
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

	// A client browsing for one kind asks for that kind, rather than fetching the catalog and
	// filtering what it did not want -- which is what a page showing only connectors would
	// otherwise do, one archive of bandwidth at a time (#207).
	kind := strings.TrimSpace(r.URL.Query().Get("kind"))
	if kind != "" {
		page, err := h.Store.ListPublishedSkillsOfKind(
			r.Context(), query, kind, store.SkillSortDownloads, true, trendingLimit, 0,
		)
		if err != nil {
			h.Logger.Error("search skills of kind", "error", err, "kind", kind)
			writeError(w, http.StatusInternalServerError, "search failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"query":  query,
			"kind":   kind,
			"skills": toSkillDTOs(page.Skills),
		})
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

// maxPageLimit bounds ListSkills. Every value in that request came from a browser, and a page
// size is the one that decides how much work one call does.
const maxPageLimit = 100

// ListSkills is the paginated directory of everything published (#3).
//
// Until this existed no endpoint answered *what the catalog publishes*: `/api/v1/trending` returns
// a page of 20 and calls it a ranking, and `/api/v1/search` refuses an empty `q`. A client that
// wanted to browse had nowhere to go, so nanoinfra's WebUI sent people to this site instead of
// listing it in the app.
//
// The query behind it is the one the HTML directory already uses, so this is a handler and a JSON
// shape rather than new logic -- including the total, without which a client cannot draw a pager.
func (h *Handler) ListSkills(w http.ResponseWriter, r *http.Request) {
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	// Passed through rather than validated against a list of kinds, which is what search does:
	// the store compares the value instead of interpolating it, and a kind nobody has published
	// is an empty page rather than an error.
	kind := strings.TrimSpace(r.URL.Query().Get("kind"))

	sort := store.SkillSortDownloads
	switch strings.TrimSpace(r.URL.Query().Get("sort")) {
	case "recent":
		sort = store.SkillSortRecent
	case "name":
		sort = store.SkillSortName
	}
	// Descending by default, because the default sort is downloads and nobody browses a catalog
	// from its least-installed entry. `desc=false` asks for the other direction.
	desc := strings.TrimSpace(r.URL.Query().Get("desc")) != "false"

	limit := trendingLimit
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			writeError(w, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		limit = min(parsed, maxPageLimit)
	}

	offset := 0
	if raw := strings.TrimSpace(r.URL.Query().Get("offset")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 {
			writeError(w, http.StatusBadRequest, "offset must be a non-negative integer")
			return
		}
		offset = parsed
	}

	page, err := h.Store.ListPublishedSkillsOfKind(
		r.Context(), query, kind, sort, desc, limit, offset,
	)
	if err != nil {
		h.Logger.Error("list published skills", "error", err, "kind", kind)
		writeError(w, http.StatusInternalServerError, "could not list skills")
		return
	}

	payload := map[string]any{
		"skills": toSkillDTOs(page.Skills),
		"total":  page.Total,
		"limit":  limit,
		"offset": offset,
	}
	if query != "" {
		payload["query"] = query
	}
	if kind != "" {
		payload["kind"] = kind
	}
	writeJSON(w, http.StatusOK, payload)
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
	dto := toSkillDTO(*skill)
	// Read from the archive here and nowhere else: this is the endpoint a client calls when it is
	// about to decide, and `credential.allowedHosts` is the field that decides whether a hostile
	// manifest gets a live token. A catalog listing is not yet deciding anything (#207).
	dto.Grants = toGrantsDTO(h.PublishedGrants(skill.SkillID))
	writeJSON(w, http.StatusOK, dto)
}

// PublishedGrants reads what a published package would allow from its archived copy. Nil when the
// archive cannot be read, which a client renders as nothing rather than as an empty table: an
// absent answer and "grants nothing" are different statements.
//
// Exported because the HTML detail page needs the same answer, and the archive path belongs to
// whoever owns PublishedDir.
func (h *Handler) PublishedGrants(skillID string) *pipeline.Grants {
	result, err := pipeline.ValidateArchive(filepath.Join(h.PublishedDir, skillID+".zip"), "")
	if err != nil {
		h.Logger.Warn("describe published archive", "error", err, "skill_id", skillID)
		return nil
	}
	grants := result.Describe()
	return &grants
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
	latestScan, err := h.Store.GetLatestScan(ctx, store.ScanTargetSkillVersion, ScanIDString(sv.ID))
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
