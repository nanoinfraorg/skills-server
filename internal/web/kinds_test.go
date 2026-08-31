package web

import (
	"archive/zip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nanoinfraorg/skills-server/internal/pipeline"
	"github.com/nanoinfraorg/skills-server/internal/store"
)

// A connector manifest, as a map so a test can break exactly one field.
func connectorManifest(id string, credential map[string]any) map[string]any {
	return map[string]any{
		"$schema":     pipeline.ConnectorSchema,
		"name":        id,
		"displayName": "Acme CRM",
		"description": "Read and write Acme contacts.",
		"baseUrl":     "https://api.acme.example",
		"credential":  credential,
		"operations": []map[string]any{
			{"name": "list_contacts", "class": "read", "method": "GET", "path": "/v1/contacts"},
			{"name": "create_contact", "class": "mutate.remote", "method": "POST", "path": "/v1/contacts"},
		},
		"dependencies": []string{},
	}
}

func oauthCredential() map[string]any {
	return map[string]any{
		"kind":         "oauth2",
		"tokenUrl":     "https://api.acme.example/oauth/token",
		"allowedHosts": []string{"api.acme.example"},
		"scopes":       map[string][]string{"read": {"crm.read"}, "mutate.remote": {"crm.write"}},
	}
}

// publishPackage writes a published archive plus its rows, so a page has
// something real to read rather than a row with no archive behind it.
func publishPackage(t *testing.T, dir, id, name, kind string, files map[string]string) {
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

func seedPublished(t *testing.T, db *store.Store, id, name, kind string) {
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
}

func jsonString(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(raw)
}

// --- the directory ---------------------------------------------------------

func TestDirectoryFiltersByKind(t *testing.T) {
	h, apiHandler, _ := testHandler(t)
	mux := newMux(h)
	seedPublished(t, apiHandler.Store, "linux-commands", "Linux Commands", "skill")
	seedPublished(t, apiHandler.Store, "acme-crm", "Acme CRM", pipeline.KindConnector)

	body := get(t, mux, "/skills?kind=connector")

	if !strings.Contains(body, "Acme CRM") {
		t.Fatalf("connector filter should list the connector, body: %s", body)
	}
	if strings.Contains(body, "Linux Commands") {
		t.Fatalf("connector filter should not list a skill, body: %s", body)
	}
	if !strings.Contains(body, "Browse connectors") {
		t.Fatalf("a filtered page should be titled after what it shows, body: %s", body)
	}
}

func TestDirectoryShowsSkillsPublishedBeforeTheKindsExisted(t *testing.T) {
	// The column defaults to "skill", but a row written by an older binary has
	// the empty string. Filtering for skills has to accept both spellings or it
	// hides everything published before the third kind existed.
	h, apiHandler, _ := testHandler(t)
	mux := newMux(h)
	seedPublished(t, apiHandler.Store, "legacy", "Legacy Skill", "")

	body := get(t, mux, "/skills?kind=skill")

	if !strings.Contains(body, "Legacy Skill") {
		t.Fatalf("a pre-kinds row is a skill, body: %s", body)
	}
}

func TestAnUnknownKindShowsTheWholeCatalog(t *testing.T) {
	h, apiHandler, _ := testHandler(t)
	mux := newMux(h)
	seedPublished(t, apiHandler.Store, "acme-crm", "Acme CRM", pipeline.KindConnector)

	body := get(t, mux, "/skills?kind=nonsense")

	if !strings.Contains(body, "Acme CRM") {
		t.Fatalf("a bogus filter should show the catalog rather than nothing, body: %s", body)
	}
}

func TestTheKindBadgeAppearsOnlyForNonSkills(t *testing.T) {
	h, apiHandler, _ := testHandler(t)
	mux := newMux(h)
	seedPublished(t, apiHandler.Store, "linux-commands", "Linux Commands", "skill")
	seedPublished(t, apiHandler.Store, "acme-crm", "Acme CRM", pipeline.KindConnector)

	body := get(t, mux, "/skills")

	if !strings.Contains(body, "directory__kind--connector") {
		t.Fatalf("a connector row needs its badge, body: %s", body)
	}
	if strings.Contains(body, "directory__kind--skill") {
		t.Fatalf("a plain skill is the default and takes no badge, body: %s", body)
	}
}

func TestAnEmptyFilterSaysWhichKindIsEmpty(t *testing.T) {
	h, apiHandler, _ := testHandler(t)
	mux := newMux(h)
	seedPublished(t, apiHandler.Store, "linux-commands", "Linux Commands", "skill")

	body := get(t, mux, "/skills?kind=connector")

	if !strings.Contains(body, "No connectors") {
		t.Fatalf("an empty filter should name the empty kind, body: %s", body)
	}
}

// --- the detail page -------------------------------------------------------

func TestAConnectorDetailPageShowsWhatItGrants(t *testing.T) {
	h, apiHandler, _ := testHandler(t)
	mux := newMux(h)
	publishPackage(t, apiHandler.PublishedDir, "acme-crm", "Acme CRM", pipeline.KindConnector,
		map[string]string{
			"connector.json": jsonString(t, connectorManifest("acme-crm", oauthCredential())),
		})
	seedPublished(t, apiHandler.Store, "acme-crm", "Acme CRM", pipeline.KindConnector)

	body := get(t, mux, "/skills/acme-crm")

	for _, want := range []string{
		"What this grants",
		"list_contacts",
		"create_contact",
		"mutate.remote",
		"GET /v1/contacts",
		"api.acme.example",
		"crm.write",
		"This is a connector",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("connector page is missing %q, body: %s", want, body)
		}
	}
}

func TestACredentialFreeConnectorSaysSo(t *testing.T) {
	h, apiHandler, _ := testHandler(t)
	mux := newMux(h)
	publishPackage(t, apiHandler.PublishedDir, "hello-world", "Hello World", pipeline.KindConnector,
		map[string]string{
			"connector.json": jsonString(t, connectorManifest("hello-world", map[string]any{"kind": "none"})),
		})
	seedPublished(t, apiHandler.Store, "hello-world", "Hello World", pipeline.KindConnector)

	body := get(t, mux, "/skills/hello-world")

	if !strings.Contains(body, "No credential") {
		t.Fatalf("a credential-free connector should say so, body: %s", body)
	}
}

func TestAPluginDetailPageMarksCodeExecution(t *testing.T) {
	h, apiHandler, _ := testHandler(t)
	mux := newMux(h)
	publishPackage(t, apiHandler.PublishedDir, "acme-toolkit", "Acme Toolkit", pipeline.KindAgentPlugin,
		map[string]string{
			"plugin.json": jsonString(t, map[string]any{
				"$schema": pipeline.AgentPluginSchema, "name": "acme-toolkit",
				"description": "Acme's toolkit.", "version": "1.0.0",
			}),
			"mcp.json": jsonString(t, map[string]any{
				"$schema":    pipeline.AgentPluginMCPSchema,
				"mcpServers": map[string]any{"acme-mcp": map[string]any{"command": "npx"}},
			}),
			"skills/deploy-check/SKILL.md": "---\nname: deploy-check\ndescription: Checks a deploy. Use before releasing.\n---\n\n# Deploy check\n",
		})
	seedPublished(t, apiHandler.Store, "acme-toolkit", "Acme Toolkit", pipeline.KindAgentPlugin)

	body := get(t, mux, "/skills/acme-toolkit")

	if !strings.Contains(body, "Runs code") || !strings.Contains(body, "acme-mcp") {
		t.Fatalf("a plugin declaring an MCP server has to say it runs code, body: %s", body)
	}
}

func TestASkillDetailPageStaysASkill(t *testing.T) {
	h, apiHandler, _ := testHandler(t)
	mux := newMux(h)
	publishPackage(t, apiHandler.PublishedDir, "linux-commands", "Linux Commands", "skill",
		map[string]string{
			"SKILL.md": "---\nname: linux-commands\ndescription: Reference for common Linux shell commands.\n---\n\n# Linux Commands\n",
		})
	seedPublished(t, apiHandler.Store, "linux-commands", "Linux Commands", "skill")

	body := get(t, mux, "/skills/linux-commands")

	if strings.Contains(body, "This is a connector") {
		t.Fatalf("a skill page must not claim to be a connector, body: %s", body)
	}
	if !strings.Contains(body, ">Skill<") {
		t.Fatalf("a skill page keeps its eyebrow, body: %s", body)
	}
}

func get(t *testing.T, mux http.Handler, path string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200", path, rec.Code)
	}
	return rec.Body.String()
}
