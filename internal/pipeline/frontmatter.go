package pipeline

import (
	"fmt"
	"strings"
)

// maxDescriptionLen mirrors the description length cap in the public Agent
// Skills format specification (https://agentskills.io/specification), which
// nanoinfra's own skill-creator documentation follows in spirit.
const maxDescriptionLen = 1024

// ParseFrontmatter extracts the `name` and `description` scalar fields from a
// SKILL.md file's leading YAML frontmatter block (delimited by "---" lines),
// per the Agent Skill format documented both in nanoinfra's skill-creator
// skill and in the public spec at https://agentskills.io/specification (the
// two describe the same format; nanoinfra's docs are the project-local
// paraphrase). `name` and `description` are the only fields this server
// validates for v1 — optional spec fields like `license`, `compatibility`,
// `metadata`, and `allowed-tools` are read by clients, not enforced here.
//
// This is intentionally a minimal, dependency-free scanner rather than a
// full YAML parser: v1's frontmatter contract only requires two top-level
// scalar string fields, and pulling in a YAML library for that would be
// disproportionate. Nested structures, lists, and multi-line scalars in the
// frontmatter are not needed for validation and are ignored.
func ParseFrontmatter(content []byte) (Metadata, error) {
	text := strings.ReplaceAll(string(content), "\r\n", "\n")
	lines := strings.Split(text, "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) != "---" {
		return Metadata{}, fmt.Errorf("SKILL.md must start with a YAML frontmatter block (---)")
	}

	end := -1
	for i := 1; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == "---" {
			end = i
			break
		}
	}
	if end == -1 {
		return Metadata{}, fmt.Errorf("frontmatter block is not terminated with a closing ---")
	}

	fields := make(map[string]string)
	for _, line := range lines[1:end] {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// Only consider top-level (non-indented) "key: value" scalar pairs;
		// indented lines belong to nested structures we don't need here.
		if line != trimmed {
			continue
		}
		key, value, ok := strings.Cut(trimmed, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = unquote(strings.TrimSpace(value))
		if key != "" {
			fields[key] = value
		}
	}

	name := fields["name"]
	description := fields["description"]
	if name == "" {
		return Metadata{}, fmt.Errorf("frontmatter is missing required field %q", "name")
	}
	if description == "" {
		return Metadata{}, fmt.Errorf("frontmatter is missing required field %q", "description")
	}
	if len(description) > maxDescriptionLen {
		return Metadata{}, fmt.Errorf("frontmatter description exceeds %d characters", maxDescriptionLen)
	}
	if !ValidSkillID(name) {
		return Metadata{}, fmt.Errorf("frontmatter name %q is not a valid skill id", name)
	}

	return Metadata{Name: name, Description: description}, nil
}

// unquote strips a single layer of matching single or double quotes from a
// YAML scalar, e.g. `"foo"` -> `foo`. It does not process YAML escape
// sequences since skill names/descriptions are plain text in practice.
func unquote(value string) string {
	if len(value) >= 2 {
		first, last := value[0], value[len(value)-1]
		if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
			return value[1 : len(value)-1]
		}
	}
	return value
}
