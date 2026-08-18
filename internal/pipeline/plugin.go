package pipeline

import (
	"archive/zip"
	"encoding/json"
	"path"
	"regexp"
	"sort"
	"strings"
)

// The Agent Plugins v1.0.0 component schemas. A package that names a different
// schema expects semantics this server does not validate, so it is rejected
// rather than accepted on the assumption that the shapes happen to line up.
const (
	AgentPluginSchema    = "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json"
	AgentPluginMCPSchema = "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json"
)

// RootPluginFile is the file whose presence marks an archive as an Agent
// Plugins package rather than a bare skill.
const RootPluginFile = "plugin.json"

// RootPluginMCPFile is the optional MCP component of a package.
const RootPluginMCPFile = "mcp.json"

// PluginSkillsDir is where a package's skills live.
const PluginSkillsDir = "skills"

// MaxMCPServerNameLength mirrors the client's own cap.
const MaxMCPServerNameLength = 128

// Archive kinds this pipeline can validate.
const (
	KindSkill       = "skill"
	KindAgentPlugin = "agent-plugin"
)

// pluginIDPattern mirrors the client's `_PLUGIN_NAME` in
// nanoinfra/agent/plugins.py: lowercase alphanumeric segments joined by single
// hyphens or single dots, and never `--` or `..`. The first keeps a namespaced
// multi-server name (`<plugin>--<server>`) unambiguous; the second keeps an
// identity from being a path traversal.
var pluginIDPattern = regexp.MustCompile(`^(?:[a-z0-9]+(?:[.-][a-z0-9]+)*)$`)

// ValidPluginID reports whether id is an acceptable Agent Plugin identity.
func ValidPluginID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	if strings.Contains(id, "--") || strings.Contains(id, "..") {
		return false
	}
	return pluginIDPattern.MatchString(id)
}

// pluginManifest is the subset of plugin.json this server validates.
type pluginManifest struct {
	Schema      string `json:"$schema"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Version     string `json:"version"`
}

// mcpComponent is the subset of mcp.json this server validates.
type mcpComponent struct {
	Schema     string                     `json:"$schema"`
	MCPServers map[string]json.RawMessage `json:"mcpServers"`
}

// validatePluginPackage validates an Agent Plugins v1 package and reports what
// it would grant.
//
// The point of the MCP half is the review surface, not the runtime: the client
// validates a server's shape again before ever launching it. What an approver
// needs from here is the *names*, because approving a package that declares an
// MCP server is approving code execution, and a review screen that only listed
// skills would hide that.
func validatePluginPackage(reader *zip.Reader, expectedID string) (*Result, error) {
	manifestFile, err := findFile(reader, RootPluginFile)
	if err != nil {
		return nil, err
	}
	raw, err := readEntryLimited(manifestFile, MaxUnpackedBytes)
	if err != nil {
		return nil, fail("%s could not be read: %v", RootPluginFile, err)
	}

	// Decoded twice: once to reject a non-object root, once for the fields.
	// json.Unmarshal into a struct accepts a JSON array as "no fields set".
	var root any
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, fail("%s is not valid JSON: %v", RootPluginFile, err)
	}
	if _, ok := root.(map[string]any); !ok {
		return nil, fail("%s must contain a JSON object", RootPluginFile)
	}
	var manifest pluginManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fail("%s is not a valid manifest: %v", RootPluginFile, err)
	}

	if manifest.Schema != AgentPluginSchema {
		return nil, fail(
			"%s must declare $schema %q", RootPluginFile, AgentPluginSchema,
		)
	}
	if !ValidPluginID(manifest.Name) {
		return nil, fail(
			"%s name %q is not a valid Agent Plugin identity: use lowercase letters, digits, "+
				"and single dots or hyphens between segments",
			RootPluginFile, manifest.Name,
		)
	}
	if expectedID != "" && manifest.Name != expectedID {
		return nil, fail(
			"%s name %q does not match submitted id %q",
			RootPluginFile, manifest.Name, expectedID,
		)
	}

	skills, err := validatePluginSkills(reader)
	if err != nil {
		return nil, err
	}
	servers, err := validatePluginMCP(reader)
	if err != nil {
		return nil, err
	}
	if len(skills) == 0 && len(servers) == 0 {
		return nil, fail(
			"package declares neither a skill under %s/ nor an MCP server in %s, so it grants nothing",
			PluginSkillsDir, RootPluginMCPFile,
		)
	}

	return &Result{
		Kind: KindAgentPlugin,
		Metadata: Metadata{
			Name:        manifest.Name,
			Description: manifest.Description,
		},
		Skills:     skills,
		MCPServers: servers,
	}, nil
}

// validatePluginSkills checks every `skills/<name>/SKILL.md` in the package and
// returns the declared skill names, sorted.
//
// The directory name is the identity, so a SKILL.md whose frontmatter names
// something else is rejected: otherwise a package could ship a skill that
// shadows another by name once installed.
func validatePluginSkills(reader *zip.Reader) ([]string, error) {
	prefix := PluginSkillsDir + "/"
	// Every directory seen under skills/, so a directory with no SKILL.md is a
	// rejection rather than a silent omission.
	dirs := map[string]bool{}
	for _, f := range reader.File {
		normalized, err := normalizeEntryName(f.Name)
		if err != nil || !strings.HasPrefix(normalized, prefix) {
			continue
		}
		rest := strings.TrimPrefix(normalized, prefix)
		segments := strings.SplitN(rest, "/", 2)
		if len(segments) != 2 || segments[0] == "" {
			continue
		}
		if _, seen := dirs[segments[0]]; !seen {
			dirs[segments[0]] = false
		}
		if segments[1] == RootSkillFile {
			dirs[segments[0]] = true
		}
	}

	names := make([]string, 0, len(dirs))
	for name, hasSkillMD := range dirs {
		if !hasSkillMD {
			return nil, fail("%s%s/ has no %s", prefix, name, RootSkillFile)
		}
		if !ValidSkillID(name) {
			return nil, fail("%s%s/ is not a valid skill name", prefix, name)
		}
		file, err := findFile(reader, path.Join(PluginSkillsDir, name, RootSkillFile))
		if err != nil {
			return nil, err
		}
		content, err := readEntryLimited(file, MaxUnpackedBytes)
		if err != nil {
			return nil, fail("%s%s/%s could not be read: %v", prefix, name, RootSkillFile, err)
		}
		meta, err := ParseFrontmatter(content)
		if err != nil {
			return nil, fail("%s%s/%s frontmatter is invalid: %v", prefix, name, RootSkillFile, err)
		}
		if meta.Name != name {
			return nil, fail(
				"%s%s/%s frontmatter name %q does not match its directory %q",
				prefix, name, RootSkillFile, meta.Name, name,
			)
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

// validatePluginMCP checks an optional mcp.json and returns the declared server
// names, sorted. A package without one is valid.
func validatePluginMCP(reader *zip.Reader) ([]string, error) {
	file, err := findFile(reader, RootPluginMCPFile)
	if err != nil {
		// Absent is fine; a package may ship skills only.
		return nil, nil
	}
	raw, err := readEntryLimited(file, MaxUnpackedBytes)
	if err != nil {
		return nil, fail("%s could not be read: %v", RootPluginMCPFile, err)
	}

	// Exactly these two keys, matching the client. An unexpected key means a
	// package written against semantics this server does not check.
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(raw, &keys); err != nil {
		return nil, fail("%s is not a valid JSON object: %v", RootPluginMCPFile, err)
	}
	if len(keys) != 2 {
		return nil, fail("%s must contain exactly $schema and mcpServers", RootPluginMCPFile)
	}
	if _, ok := keys["$schema"]; !ok {
		return nil, fail("%s must declare $schema", RootPluginMCPFile)
	}
	if _, ok := keys["mcpServers"]; !ok {
		return nil, fail("%s must contain mcpServers", RootPluginMCPFile)
	}

	var component mcpComponent
	if err := json.Unmarshal(raw, &component); err != nil {
		return nil, fail("%s is not a valid MCP component: %v", RootPluginMCPFile, err)
	}
	if component.Schema != AgentPluginMCPSchema {
		return nil, fail("%s must declare $schema %q", RootPluginMCPFile, AgentPluginMCPSchema)
	}

	names := make([]string, 0, len(component.MCPServers))
	for name, rawServer := range component.MCPServers {
		if name == "" || len(name) > MaxMCPServerNameLength {
			return nil, fail("%s has an invalid mcp server name", RootPluginMCPFile)
		}
		for _, r := range name {
			if r < 0x20 {
				return nil, fail("%s has an invalid mcp server name", RootPluginMCPFile)
			}
		}
		var server map[string]any
		if err := json.Unmarshal(rawServer, &server); err != nil {
			return nil, fail("%s server %q must be a JSON object", RootPluginMCPFile, name)
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}
