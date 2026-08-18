package pipeline

import (
	"strings"
	"testing"
)

const pluginSkillMD = "---\nname: deploy-check\ndescription: Checks a deploy. Use before releasing.\n---\n\n# Deploy check\n"

func manifestJSON(name string) string {
	return `{"$schema":"` + AgentPluginSchema + `","name":"` + name + `","description":"Deploy helpers."}`
}

func mcpJSON(servers string) string {
	return `{"$schema":"` + AgentPluginMCPSchema + `","mcpServers":{` + servers + `}}`
}

func TestValidateArchive_PluginPackagePasses(t *testing.T) {
	path := writeTestZip(t, []zipEntry{
		{name: "plugin.json", content: manifestJSON("acme.toolkit")},
		{name: "skills/deploy-check/SKILL.md", content: pluginSkillMD},
	})

	result, err := ValidateArchive(path, "acme.toolkit")
	if err != nil {
		t.Fatalf("expected the package to validate, got: %v", err)
	}
	if result.Kind != KindAgentPlugin {
		t.Fatalf("expected kind %q, got %q", KindAgentPlugin, result.Kind)
	}
	if result.Metadata.Name != "acme.toolkit" {
		t.Fatalf("expected identity from plugin.json, got %q", result.Metadata.Name)
	}
	if len(result.Skills) != 1 || result.Skills[0] != "deploy-check" {
		t.Fatalf("expected one declared skill, got %v", result.Skills)
	}
	if len(result.MCPServers) != 0 {
		t.Fatalf("expected no MCP servers, got %v", result.MCPServers)
	}
}

// A reviewer approving a package that declares an MCP server is approving code
// execution, so the names must reach the review surface.
func TestValidateArchive_PluginReportsMCPServersForReview(t *testing.T) {
	path := writeTestZip(t, []zipEntry{
		{name: "plugin.json", content: manifestJSON("acme.toolkit")},
		{name: "skills/deploy-check/SKILL.md", content: pluginSkillMD},
		{name: "mcp.json", content: mcpJSON(`"api":{"type":"stdio","command":"echo"},"other":{"type":"stdio","command":"echo"}`)},
	})

	result, err := ValidateArchive(path, "acme.toolkit")
	if err != nil {
		t.Fatalf("expected the package to validate, got: %v", err)
	}
	if len(result.MCPServers) != 2 {
		t.Fatalf("expected two MCP servers, got %v", result.MCPServers)
	}
	if result.MCPServers[0] != "api" || result.MCPServers[1] != "other" {
		t.Fatalf("expected sorted server names, got %v", result.MCPServers)
	}
}

func TestValidateArchive_PluginWithOnlyMCPPasses(t *testing.T) {
	path := writeTestZip(t, []zipEntry{
		{name: "plugin.json", content: manifestJSON("acme.api")},
		{name: "mcp.json", content: mcpJSON(`"api":{"type":"stdio","command":"echo"}`)},
	})

	result, err := ValidateArchive(path, "acme.api")
	if err != nil {
		t.Fatalf("a package may ship only an MCP component: %v", err)
	}
	if len(result.Skills) != 0 {
		t.Fatalf("expected no skills, got %v", result.Skills)
	}
}

func TestValidateArchive_PluginIdentityMustMatchSubmission(t *testing.T) {
	path := writeTestZip(t, []zipEntry{
		{name: "plugin.json", content: manifestJSON("acme.toolkit")},
		{name: "skills/deploy-check/SKILL.md", content: pluginSkillMD},
	})

	_, err := ValidateArchive(path, "someone.else")
	if err == nil {
		t.Fatal("expected a mismatched identity to be rejected")
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("expected an identity mismatch reason, got %q", err.Error())
	}
}

func TestValidateArchive_PluginRejections(t *testing.T) {
	cases := []struct {
		name    string
		entries []zipEntry
		reason  string
	}{
		{
			name: "wrong manifest schema",
			entries: []zipEntry{
				{name: "plugin.json", content: `{"$schema":"https://example.com/other","name":"acme.toolkit"}`},
			},
			reason: "$schema",
		},
		{
			name: "manifest is not an object",
			entries: []zipEntry{
				{name: "plugin.json", content: `["nope"]`},
			},
			reason: "plugin.json",
		},
		{
			name: "manifest is malformed json",
			entries: []zipEntry{
				{name: "plugin.json", content: `{"name":`},
			},
			reason: "plugin.json",
		},
		{
			name: "identity has consecutive hyphens",
			entries: []zipEntry{
				{name: "plugin.json", content: manifestJSON("acme--toolkit")},
			},
			reason: "name",
		},
		{
			name: "identity contains traversal",
			entries: []zipEntry{
				{name: "plugin.json", content: manifestJSON("../escape")},
			},
			reason: "name",
		},
		{
			name: "identity is uppercase",
			entries: []zipEntry{
				{name: "plugin.json", content: manifestJSON("Acme.Toolkit")},
			},
			reason: "name",
		},
		{
			name: "package declares nothing",
			entries: []zipEntry{
				{name: "plugin.json", content: manifestJSON("acme.empty")},
			},
			reason: "declares neither",
		},
		{
			name: "skill directory name disagrees with its frontmatter",
			entries: []zipEntry{
				{name: "plugin.json", content: manifestJSON("acme.toolkit")},
				{name: "skills/other-name/SKILL.md", content: pluginSkillMD},
			},
			reason: "does not match",
		},
		{
			name: "skill frontmatter is invalid",
			entries: []zipEntry{
				{name: "plugin.json", content: manifestJSON("acme.toolkit")},
				{name: "skills/deploy-check/SKILL.md", content: "no frontmatter here\n"},
			},
			reason: "frontmatter",
		},
		{
			name: "skill directory has no SKILL.md",
			entries: []zipEntry{
				{name: "plugin.json", content: manifestJSON("acme.toolkit")},
				{name: "skills/deploy-check/notes.md", content: "hi\n"},
			},
			reason: "SKILL.md",
		},
		{
			name: "mcp component has the wrong schema",
			entries: []zipEntry{
				{name: "plugin.json", content: manifestJSON("acme.toolkit")},
				{name: "skills/deploy-check/SKILL.md", content: pluginSkillMD},
				{name: "mcp.json", content: `{"$schema":"https://example.com/other","mcpServers":{}}`},
			},
			reason: "mcp.json",
		},
		{
			name: "mcp component carries an unexpected key",
			entries: []zipEntry{
				{name: "plugin.json", content: manifestJSON("acme.toolkit")},
				{name: "skills/deploy-check/SKILL.md", content: pluginSkillMD},
				{name: "mcp.json", content: `{"$schema":"` + AgentPluginMCPSchema + `","mcpServers":{},"extra":1}`},
			},
			reason: "mcp.json",
		},
		{
			name: "mcp server is not an object",
			entries: []zipEntry{
				{name: "plugin.json", content: manifestJSON("acme.toolkit")},
				{name: "mcp.json", content: mcpJSON(`"api":"echo"`)},
			},
			reason: "mcp.json",
		},
		{
			name: "mcp server name is empty",
			entries: []zipEntry{
				{name: "plugin.json", content: manifestJSON("acme.toolkit")},
				{name: "mcp.json", content: mcpJSON(`"":{"type":"stdio","command":"echo"}`)},
			},
			reason: "mcp server name",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTestZip(t, tc.entries)
			_, err := ValidateArchive(path, "")
			if err == nil {
				t.Fatal("expected rejection")
			}
			if !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("expected reason containing %q, got %q", tc.reason, err.Error())
			}
		})
	}
}

// A plain skill archive must keep working exactly as before: plugin.json is what
// selects the new shape, and its absence changes nothing.
func TestValidateArchive_SkillArchiveStillReportsItsKind(t *testing.T) {
	path := writeTestZip(t, []zipEntry{
		{name: "SKILL.md", content: validSkillMD},
	})

	result, err := ValidateArchive(path, "my-skill")
	if err != nil {
		t.Fatalf("expected the skill archive to validate, got: %v", err)
	}
	if result.Kind != KindSkill {
		t.Fatalf("expected kind %q, got %q", KindSkill, result.Kind)
	}
	if len(result.Skills) != 0 || len(result.MCPServers) != 0 {
		t.Fatal("a skill archive declares no plugin components")
	}
}

// Path safety is applied to every archive before the shape is even considered,
// so a plugin package gets the same treatment a skill archive does.
func TestValidateArchive_PluginPathSafetyStillApplies(t *testing.T) {
	path := writeTestZip(t, []zipEntry{
		{name: "plugin.json", content: manifestJSON("acme.toolkit")},
		{name: "skills/deploy-check/SKILL.md", content: pluginSkillMD},
		{name: "../escape.txt", content: "nope\n"},
	})

	if _, err := ValidateArchive(path, "acme.toolkit"); err == nil {
		t.Fatal("expected the traversal entry to be rejected")
	}
}

func TestValidPluginID(t *testing.T) {
	valid := []string{"acme", "acme.toolkit", "a1", "acme-tools", "a.b.c", "acme-tools.v2"}
	for _, id := range valid {
		if !ValidPluginID(id) {
			t.Errorf("expected %q to be a valid plugin identity", id)
		}
	}
	invalid := []string{
		"", "Acme", "acme--tools", "../x", "acme..tools", "-acme", "acme-",
		".acme", "acme.", strings.Repeat("a", 65),
	}
	for _, id := range invalid {
		if ValidPluginID(id) {
			t.Errorf("expected %q to be rejected", id)
		}
	}
}
