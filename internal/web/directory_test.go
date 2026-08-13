package web

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nanoinfraorg/skills-server/internal/api"
	"github.com/nanoinfraorg/skills-server/internal/store"
)

// seedDirectorySkill publishes one skill with a chosen display name, publish
// time and download count, which is what the directory orders by.
func seedDirectorySkill(
	t *testing.T, apiHandler *api.Handler, skillID, displayName string, publishedAt time.Time, downloads int,
) {
	t.Helper()
	ctx := context.Background()
	if _, err := apiHandler.Store.CreateSkillVersion(ctx, store.SkillVersion{
		SkillID: skillID, Version: 1, SubmissionID: "seed-" + skillID, DisplayName: displayName,
		Description: "fixture for " + skillID, GitHubPath: skillID + "/", PublishedAt: publishedAt,
		Status: store.SkillVersionPublished,
	}); err != nil {
		t.Fatalf("seed skill version %s: %v", skillID, err)
	}
	if err := apiHandler.Store.SetSkillPointer(ctx, skillID, 1, publishedAt); err != nil {
		t.Fatalf("seed skill pointer %s: %v", skillID, err)
	}
	for i := 0; i < downloads; i++ {
		if err := apiHandler.Store.IncrementDownloads(ctx, skillID); err != nil {
			t.Fatalf("seed downloads %s: %v", skillID, err)
		}
	}
}

// orderOf returns the positions of each name in the rendered body, so a test
// can assert relative order without depending on the surrounding markup.
func orderOf(t *testing.T, body string, names ...string) []int {
	t.Helper()
	positions := make([]int, len(names))
	for i, name := range names {
		positions[i] = strings.Index(body, name)
		if positions[i] < 0 {
			t.Fatalf("%q missing from the directory body", name)
		}
	}
	return positions
}

func TestDirectory_SortOrders(t *testing.T) {
	h, apiHandler, _ := testHandler(t)
	mux := newMux(h)
	now := time.Now()

	// Chosen so no two orderings agree: Zulu is the most downloaded but the
	// oldest and last alphabetically; Alpha is the newest with no downloads.
	seedDirectorySkill(t, apiHandler, "zulu", "Zulu", now.Add(-72*time.Hour), 30)
	seedDirectorySkill(t, apiHandler, "mike", "Mike", now.Add(-48*time.Hour), 10)
	seedDirectorySkill(t, apiHandler, "alpha", "Alpha", now.Add(-1*time.Hour), 0)

	cases := []struct {
		name  string
		path  string
		order []string
	}{
		{"downloads is the default", "/skills", []string{"Zulu", "Mike", "Alpha"}},
		{"downloads ascending", "/skills?sort=downloads&dir=asc", []string{"Alpha", "Mike", "Zulu"}},
		{"most recently published", "/skills?sort=recent", []string{"Alpha", "Mike", "Zulu"}},
		{"oldest published", "/skills?sort=recent&dir=asc", []string{"Zulu", "Mike", "Alpha"}},
		{"name A to Z", "/skills?sort=name&dir=asc", []string{"Alpha", "Mike", "Zulu"}},
		{"name Z to A", "/skills?sort=name&dir=desc", []string{"Zulu", "Mike", "Alpha"}},
		// A hand-edited query string must not error or leak: it falls back to
		// the default ordering, because the store maps the value to a fixed
		// ORDER BY rather than interpolating it.
		{"unknown sort falls back to downloads", "/skills?sort=%27%3B+DROP+TABLE+skills--", []string{"Zulu", "Mike", "Alpha"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}
			positions := orderOf(t, rec.Body.String(), tc.order...)
			for i := 1; i < len(positions); i++ {
				if positions[i-1] > positions[i] {
					t.Fatalf("expected %v in order, got positions %v", tc.order, positions)
				}
			}
		})
	}

	// The table must still be there after the injection attempt.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/skills", nil))
	if !strings.Contains(rec.Body.String(), "Zulu") {
		t.Fatal("the skills table did not survive the malformed sort request")
	}
}

func TestDirectory_Pagination(t *testing.T) {
	h, apiHandler, _ := testHandler(t)
	mux := newMux(h)
	now := time.Now()

	// One more than a page, so page 2 holds exactly one row. Downloads descend
	// with the index so the ordering across the page boundary is predictable.
	const total = directoryPageSize + 1
	for i := 0; i < total; i++ {
		seedDirectorySkill(t, apiHandler,
			fmt.Sprintf("skill-%03d", i), fmt.Sprintf("Skill %03d", i),
			now.Add(-time.Duration(i)*time.Minute), total-i)
	}

	get := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec
	}

	first := get("/skills")
	if first.Code != http.StatusOK {
		t.Fatalf("page 1 status = %d, want 200", first.Code)
	}
	body := first.Body.String()
	if got := strings.Count(body, `<tr>`) - 1; got != directoryPageSize { // -1 for the header row
		t.Errorf("page 1 rows = %d, want %d", got, directoryPageSize)
	}
	if !strings.Contains(body, "Page 1 of 2") {
		t.Error("expected a pager reading 'Page 1 of 2' on page 1")
	}
	// The 51st skill (least downloaded) belongs on page 2, not page 1.
	if strings.Contains(body, fmt.Sprintf("Skill %03d", total-1)) {
		t.Error("the last skill by downloads should not appear on page 1")
	}

	second := get("/skills?page=2")
	if second.Code != http.StatusOK {
		t.Fatalf("page 2 status = %d, want 200", second.Code)
	}
	body = second.Body.String()
	if got := strings.Count(body, `<tr>`) - 1; got != 1 {
		t.Errorf("page 2 rows = %d, want 1", got)
	}
	if !strings.Contains(body, fmt.Sprintf("Skill %03d", total-1)) {
		t.Error("page 2 should hold the last skill by downloads")
	}

	// A page past the end would render an empty table with a working pager,
	// which reads as an empty catalog.
	past := get("/skills?page=99")
	if past.Code != http.StatusSeeOther {
		t.Fatalf("out-of-range page status = %d, want 303", past.Code)
	}
	if loc := past.Header().Get("Location"); !strings.Contains(loc, "page=2") {
		t.Errorf("out-of-range page redirected to %q, want the last page", loc)
	}

	// Page 0 and garbage both mean page 1 rather than an error.
	for _, path := range []string{"/skills?page=0", "/skills?page=-3", "/skills?page=abc"} {
		if rec := get(path); rec.Code != http.StatusOK {
			t.Errorf("%s status = %d, want 200", path, rec.Code)
		}
	}
}

func TestDirectory_PaginationKeepsTheSearchAndSort(t *testing.T) {
	h, apiHandler, _ := testHandler(t)
	mux := newMux(h)
	now := time.Now()
	for i := 0; i < directoryPageSize+1; i++ {
		seedDirectorySkill(t, apiHandler,
			fmt.Sprintf("fixture-%03d", i), fmt.Sprintf("Fixture %03d", i),
			now.Add(-time.Duration(i)*time.Minute), i)
	}

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/skills?q=fixture&sort=name&dir=asc", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	// The "next page" link has to carry the query and the ordering, or paging
	// through a search silently drops back to the unfiltered default listing.
	for _, want := range []string{"q=fixture", "sort=name", "dir=asc", "page=2"} {
		if !strings.Contains(body, want) {
			t.Errorf("the pager lost %q; body: %s", want, body)
		}
	}
}

func TestDirectory_ExcludesQuarantinedAndCountsTotal(t *testing.T) {
	h, apiHandler, _ := testHandler(t)
	mux := newMux(h)
	ctx := context.Background()
	now := time.Now()

	seedDirectorySkill(t, apiHandler, "good", "Good Skill", now, 5)
	seedDirectorySkill(t, apiHandler, "bad", "Bad Skill", now, 99)
	if err := apiHandler.Store.SetSkillVersionStatus(ctx, "bad", 1, store.SkillVersionQuarantined); err != nil {
		t.Fatalf("quarantine: %v", err)
	}

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/skills", nil))
	body := rec.Body.String()
	if strings.Contains(body, "Bad Skill") {
		t.Error("a quarantined skill must not appear in the public directory")
	}
	if !strings.Contains(body, "Good Skill") {
		t.Error("expected the published skill to appear")
	}
	// The count has to match what is listed, not what is stored: an inflated
	// total would render a pager to a page that does not exist.
	if !strings.Contains(body, "of <strong>1</strong>") {
		t.Errorf("expected a total of 1 published skill; body: %s", body)
	}
}
