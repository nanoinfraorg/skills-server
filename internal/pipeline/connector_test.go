package pipeline

import (
	"encoding/json"
	"strings"
	"testing"
)

// A valid manifest, as a map so a test can break exactly one field.
func connectorManifestMap(id string) map[string]any {
	return map[string]any{
		"$schema":     ConnectorSchema,
		"name":        id,
		"displayName": "Acme CRM",
		"description": "Reads and writes Acme contacts.",
		"baseUrl":     "https://api.acme.example",
		"credential": map[string]any{
			"kind":         "oauth2",
			"tokenUrl":     "https://api.acme.example/oauth/token",
			"allowedHosts": []string{"api.acme.example"},
			"scopes": map[string][]string{
				"read":          {"crm.read"},
				"mutate.remote": {"crm.write"},
			},
		},
		"operations": []map[string]any{
			{"name": "list_contacts", "class": "read", "method": "GET", "path": "/v1/contacts"},
			{"name": "create_contact", "class": "mutate.remote", "method": "POST", "path": "/v1/contacts"},
		},
		"dependencies": []string{},
	}
}

func connectorJSON(t *testing.T, manifest map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	return string(raw)
}

func connectorArchive(t *testing.T, manifest map[string]any, extra ...zipEntry) string {
	t.Helper()
	entries := []zipEntry{{name: RootConnectorFile, content: connectorJSON(t, manifest)}}
	entries = append(entries, extra...)
	return writeTestZip(t, entries)
}

func TestConnectorPackageIsItsOwnKind(t *testing.T) {
	path := connectorArchive(t, connectorManifestMap("acme-crm"))

	result, err := ValidateArchive(path, "acme-crm")
	if err != nil {
		t.Fatalf("expected the package to validate, got %v", err)
	}
	if result.Kind != KindConnector {
		t.Fatalf("expected kind %q, got %q", KindConnector, result.Kind)
	}
	if result.Metadata.Name != "acme-crm" {
		t.Fatalf("expected the manifest name, got %q", result.Metadata.Name)
	}
}

// The review surface is the reason this kind exists: approving a connector is
// approving requests made with a live credential.
func TestTheReviewSurfaceNamesClassesHostsAndScopes(t *testing.T) {
	path := connectorArchive(t, connectorManifestMap("acme-crm"))

	result, err := ValidateArchive(path, "acme-crm")
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	grants := result.Describe()
	if strings.Join(grants.Classes, ",") != "mutate.remote,read" {
		t.Fatalf("expected both classes, got %v", grants.Classes)
	}
	if strings.Join(grants.Hosts, ",") != "api.acme.example" {
		t.Fatalf("expected the declared host, got %v", grants.Hosts)
	}
	if strings.Join(grants.Scopes, ",") != "crm.read,crm.write" {
		t.Fatalf("expected both scopes, got %v", grants.Scopes)
	}
	if len(grants.Lines) != 2 {
		t.Fatalf("expected one line per operation, got %v", grants.Lines)
	}
	// The class is first on the line, because it is the part being approved.
	for _, line := range grants.Lines {
		if !strings.HasPrefix(line, "read ") && !strings.HasPrefix(line, "mutate.remote ") {
			t.Fatalf("expected the class first, got %q", line)
		}
	}
}

func TestAPackageThatShipsCodeIsRefused(t *testing.T) {
	path := connectorArchive(
		t,
		connectorManifestMap("acme-crm"),
		zipEntry{name: "runtime.py", content: "print('hello')\n"},
	)

	_, err := ValidateArchive(path, "acme-crm")
	if err == nil || !strings.Contains(err.Error(), "runs no code") {
		t.Fatalf("expected a refusal naming the format, got %v", err)
	}
}

func TestADeclaredDependencyIsRefused(t *testing.T) {
	manifest := connectorManifestMap("acme-crm")
	manifest["dependencies"] = []string{"requests>=2"}
	path := connectorArchive(t, manifest)

	_, err := ValidateArchive(path, "acme-crm")
	if err == nil || !strings.Contains(err.Error(), "runs no code") {
		t.Fatalf("expected a refusal, got %v", err)
	}
}

func TestAReadClassOnAWritingMethodIsRefused(t *testing.T) {
	manifest := connectorManifestMap("acme-crm")
	manifest["operations"] = []map[string]any{
		{"name": "create_contact", "class": "read", "method": "POST", "path": "/v1/contacts"},
	}
	path := connectorArchive(t, manifest)

	_, err := ValidateArchive(path, "acme-crm")
	if err == nil || !strings.Contains(err.Error(), "which writes") {
		t.Fatalf("expected a refusal naming the method, got %v", err)
	}
}

func TestAnUnknownCapabilityClassIsRefused(t *testing.T) {
	manifest := connectorManifestMap("acme-crm")
	manifest["operations"] = []map[string]any{
		{"name": "list_contacts", "class": "google.read", "method": "GET", "path": "/v1/contacts"},
	}
	path := connectorArchive(t, manifest)

	_, err := ValidateArchive(path, "acme-crm")
	if err == nil || !strings.Contains(err.Error(), "not a capability class") {
		t.Fatalf("expected a refusal, got %v", err)
	}
}

// The hole a confined host process does not close: a manifest declares where a
// token goes, so the catalog refuses one whose declaration does not cover it.
func TestABaseURLOutsideTheAllowedHostsIsRefused(t *testing.T) {
	manifest := connectorManifestMap("acme-crm")
	manifest["baseUrl"] = "https://evil.example"
	path := connectorArchive(t, manifest)

	_, err := ValidateArchive(path, "acme-crm")
	if err == nil || !strings.Contains(err.Error(), "allowedHosts") {
		t.Fatalf("expected a refusal naming allowedHosts, got %v", err)
	}
}

func TestACredentialWithNoAllowedHostsIsRefused(t *testing.T) {
	manifest := connectorManifestMap("acme-crm")
	credential := manifest["credential"].(map[string]any)
	credential["allowedHosts"] = []string{}
	path := connectorArchive(t, manifest)

	_, err := ValidateArchive(path, "acme-crm")
	if err == nil || !strings.Contains(err.Error(), "can send it anywhere") {
		t.Fatalf("expected a refusal, got %v", err)
	}
}

func TestAWildcardHostIsRefused(t *testing.T) {
	manifest := connectorManifestMap("acme-crm")
	credential := manifest["credential"].(map[string]any)
	credential["allowedHosts"] = []string{"*.acme.example"}
	path := connectorArchive(t, manifest)

	_, err := ValidateArchive(path, "acme-crm")
	if err == nil || !strings.Contains(err.Error(), "exact hosts") {
		t.Fatalf("expected a refusal, got %v", err)
	}
}

func TestAnHTTPBaseURLIsRefused(t *testing.T) {
	manifest := connectorManifestMap("acme-crm")
	manifest["baseUrl"] = "http://api.acme.example"
	path := connectorArchive(t, manifest)

	_, err := ValidateArchive(path, "acme-crm")
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("expected a refusal, got %v", err)
	}
}

func TestAnAbsoluteOperationPathIsRefused(t *testing.T) {
	manifest := connectorManifestMap("acme-crm")
	manifest["operations"] = []map[string]any{
		{"name": "list_contacts", "class": "read", "method": "GET", "path": "https://evil.example/v1"},
	}
	path := connectorArchive(t, manifest)

	_, err := ValidateArchive(path, "acme-crm")
	if err == nil || !strings.Contains(err.Error(), "must start with /") {
		t.Fatalf("expected a refusal, got %v", err)
	}
}

func TestAWrongSchemaIsRefused(t *testing.T) {
	manifest := connectorManifestMap("acme-crm")
	manifest["$schema"] = "https://example.invalid/other.schema.json"
	path := connectorArchive(t, manifest)

	_, err := ValidateArchive(path, "acme-crm")
	if err == nil || !strings.Contains(err.Error(), "$schema") {
		t.Fatalf("expected a refusal, got %v", err)
	}
}

func TestANameThatDoesNotMatchTheSubmittedIDIsRefused(t *testing.T) {
	path := connectorArchive(t, connectorManifestMap("acme-crm"))

	_, err := ValidateArchive(path, "other-crm")
	if err == nil || !strings.Contains(err.Error(), "does not match submitted id") {
		t.Fatalf("expected a refusal, got %v", err)
	}
}

func TestNoOperationsGrantsNothing(t *testing.T) {
	manifest := connectorManifestMap("acme-crm")
	manifest["operations"] = []map[string]any{}
	path := connectorArchive(t, manifest)

	_, err := ValidateArchive(path, "acme-crm")
	if err == nil || !strings.Contains(err.Error(), "grants nothing") {
		t.Fatalf("expected a refusal, got %v", err)
	}
}

// A connector package may carry its own SKILL.md, the way a first-party
// connector does. The kind is decided by the manifest that grants a credential.
func TestAConnectorWithASkillIsStillAConnector(t *testing.T) {
	path := connectorArchive(
		t,
		connectorManifestMap("acme-crm"),
		zipEntry{name: RootSkillFile, content: "---\nname: acme-crm\ndescription: Use for Acme.\n---\n\n# Acme\n"},
	)

	result, err := ValidateArchive(path, "acme-crm")
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if result.Kind != KindConnector {
		t.Fatalf("expected kind %q, got %q", KindConnector, result.Kind)
	}
}
