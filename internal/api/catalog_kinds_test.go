package api

import (
	"archive/zip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nanoinfraorg/skills-server/internal/pipeline"
	"github.com/nanoinfraorg/skills-server/internal/store"
)

// A client installing from this catalog has to be able to answer two questions before it writes
// anything: *what kind of package is this* -- a skill is text, a connector is requests made with a
// live credential -- and *what would it be allowed to do*. Both were answerable on the HTML pages
// and neither was in the JSON API, so nanoinfra's marketplace client treated every row as a skill
// and would have installed a connector into the skills directory (#207).

func seedKind(t *testing.T, db *store.Store, id, name, kind string, downloads int64) {
	t.Helper()
	ctx := context.Background()
	if _, err := db.CreateSkillVersion(ctx, store.SkillVersion{
		SkillID: id, Version: 1, SubmissionID: "seed-" + id, DisplayName: name,
		Description: name + " description", GitHubPath: id + "/",
		PublishedAt: time.Now(), Status: store.SkillVersionPublished, Kind: kind,
	}); err != nil {
		t.Fatalf("seed version: %v", err)
	}
	if err := db.SetSkillPointer(ctx, id, 1, time.Now()); err != nil {
		t.Fatalf("seed pointer: %v", err)
	}
	for range downloads {
		if err := db.IncrementDownloads(ctx, id); err != nil {
			t.Fatalf("increment downloads: %v", err)
		}
	}
}

func writePublishedArchive(t *testing.T, dir, id string, files map[string]string) {
	t.Helper()
	f, err := os.Create(filepath.Join(dir, id+".zip"))
	if err != nil {
		t.Fatalf("create archive: %v", err)
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	for path, content := range files {
		w, err := zw.Create(path)
		if err != nil {
			t.Fatalf("create entry %s: %v", path, err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatalf("write entry %s: %v", path, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close archive: %v", err)
	}
}

func connectorArchive(t *testing.T, dir, id string) {
	t.Helper()
	manifest := map[string]any{
		"$schema":     pipeline.ConnectorSchema,
		"name":        id,
		"displayName": "Acme CRM",
		"description": "Read and write Acme contacts.",
		"baseUrl":     "https://api.acme.example",
		"credential": map[string]any{
			"kind":         "oauth2",
			"tokenUrl":     "https://api.acme.example/oauth/token",
			"allowedHosts": []string{"api.acme.example"},
			"scopes":       map[string][]string{"read": {"crm.read"}, "mutate.remote": {"crm.write"}},
		},
		"operations": []map[string]any{
			{"name": "list_contacts", "class": "read", "method": "GET", "path": "/v1/contacts"},
			{"name": "create_contact", "class": "mutate.remote", "method": "POST", "path": "/v1/contacts"},
		},
		"dependencies": []string{},
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	writePublishedArchive(t, dir, id, map[string]string{
		"connector.json": string(raw),
		"SKILL.md":       "# Acme CRM\n\nWhat it does.\n",
	})
}

func getJSON(t *testing.T, h *Handler, path string) map[string]any {
	t.Helper()
	recorder := httptest.NewRecorder()
	NewMux(h).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET %s = %d, body: %s", path, recorder.Code, recorder.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode %s: %v, body: %s", path, err, recorder.Body.String())
	}
	return payload
}

// --- the kind ------------------------------------------------------------------------------

func TestTheDetailPayloadNamesTheKind(t *testing.T) {
	h, _ := testHandler(t)
	seedKind(t, h.Store, "acme-crm", "Acme CRM", pipeline.KindConnector, 0)
	connectorArchive(t, h.PublishedDir, "acme-crm")

	payload := getJSON(t, h, "/api/v1/skills/acme-crm")

	if payload["kind"] != pipeline.KindConnector {
		t.Fatalf("kind = %v, want %q", payload["kind"], pipeline.KindConnector)
	}
}

func TestSearchNarrowsToOneKind(t *testing.T) {
	h, _ := testHandler(t)
	seedKind(t, h.Store, "acme-crm", "Acme CRM connector", pipeline.KindConnector, 3)
	seedKind(t, h.Store, "acme-notes", "Acme notes skill", pipeline.KindSkill, 9)

	payload := getJSON(t, h, "/api/v1/search?q=acme&kind=connector")

	skills, _ := payload["skills"].([]any)
	if len(skills) != 1 {
		t.Fatalf("want one connector, got %d: %v", len(skills), skills)
	}
	row, _ := skills[0].(map[string]any)
	if row["skill_id"] != "acme-crm" {
		t.Fatalf("wrong row: %v", row)
	}
}

func TestSearchWithoutAKindStillReturnsEverything(t *testing.T) {
	// The parameter narrows; its absence must not start filtering, or every client that predates
	// it loses half the catalog.
	h, _ := testHandler(t)
	seedKind(t, h.Store, "acme-crm", "Acme CRM connector", pipeline.KindConnector, 3)
	seedKind(t, h.Store, "acme-notes", "Acme notes skill", pipeline.KindSkill, 9)

	payload := getJSON(t, h, "/api/v1/search?q=acme")

	skills, _ := payload["skills"].([]any)
	if len(skills) != 2 {
		t.Fatalf("want both rows, got %d: %v", len(skills), skills)
	}
}

// --- what installing it would allow --------------------------------------------------------

func TestTheDetailPayloadSaysWhatAConnectorWouldBeAllowedToDo(t *testing.T) {
	h, _ := testHandler(t)
	seedKind(t, h.Store, "acme-crm", "Acme CRM", pipeline.KindConnector, 0)
	connectorArchive(t, h.PublishedDir, "acme-crm")

	payload := getJSON(t, h, "/api/v1/skills/acme-crm")

	grants, ok := payload["grants"].(map[string]any)
	if !ok {
		t.Fatalf("no grants in payload: %v", payload)
	}
	operations, _ := grants["operations"].([]any)
	if len(operations) != 2 {
		t.Fatalf("want two operations, got %v", operations)
	}
	// Keyed by name rather than by position: `Describe()` sorts, which is what a rendered table
	// wants, so asserting manifest order would be asserting the wrong thing.
	classes := map[string]string{}
	methods := map[string]string{}
	for _, entry := range operations {
		row, _ := entry.(map[string]any)
		name, _ := row["name"].(string)
		classes[name], _ = row["class"].(string)
		methods[name], _ = row["method"].(string)
	}
	if classes["list_contacts"] != "read" || methods["list_contacts"] != "GET" {
		t.Fatalf("the read operation is wrong: %v", operations)
	}
	if classes["create_contact"] != "mutate.remote" || methods["create_contact"] != "POST" {
		t.Fatalf("the write operation is wrong -- this is the row an approver reads: %v", operations)
	}
	hosts, _ := grants["hosts"].([]any)
	if len(hosts) != 1 || hosts[0] != "api.acme.example" {
		t.Fatalf("hosts = %v; this is the field that decides whether a token can leave", hosts)
	}
	scopes, _ := grants["scopes"].([]any)
	if len(scopes) == 0 {
		t.Fatalf("a token's scopes are part of what installing this allows: %v", grants)
	}
}

func TestGrantsAreAbsentRatherThanEmptyWhenTheArchiveCannotBeRead(t *testing.T) {
	// An absent answer and "grants nothing" are different statements. A client must not render an
	// unreadable archive as a package that asked for nothing.
	h, _ := testHandler(t)
	seedKind(t, h.Store, "acme-crm", "Acme CRM", pipeline.KindConnector, 0)

	payload := getJSON(t, h, "/api/v1/skills/acme-crm")

	if _, present := payload["grants"]; present {
		t.Fatalf("grants should be omitted with no archive, got: %v", payload["grants"])
	}
}

func TestSearchDoesNotPayForGrants(t *testing.T) {
	// One archive read per row would put the whole catalog's zip files on the path of a keystroke,
	// and a client listing a catalog is not yet deciding anything.
	h, _ := testHandler(t)
	seedKind(t, h.Store, "acme-crm", "Acme CRM connector", pipeline.KindConnector, 0)
	connectorArchive(t, h.PublishedDir, "acme-crm")

	payload := getJSON(t, h, "/api/v1/search?q=acme")

	skills, _ := payload["skills"].([]any)
	row, _ := skills[0].(map[string]any)
	if _, present := row["grants"]; present {
		t.Fatalf("search rows should carry no grants: %v", row)
	}
	if row["kind"] != pipeline.KindConnector {
		t.Fatalf("but the kind is cheap and belongs there: %v", row)
	}
}
