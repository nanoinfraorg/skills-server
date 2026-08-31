// Package pipeline implements the publish-time validation pipeline: it
// re-checks an uploaded skill archive for path-safety issues and re-validates
// the SKILL.md frontmatter, mirroring (in spirit, not by transliteration) the
// zip-safety checks nanoinfra's Python client already applies to skillhub.cn
// archives before extracting them locally.
package pipeline

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"strings"
)

// These limits are vars, not consts, so tests can temporarily shrink them
// (e.g. to exercise the size/file-count caps without generating enormous
// fixture archives) and restore the defaults afterward.
var (
	// MaxArchiveBytes caps the on-disk size of an accepted zip archive.
	MaxArchiveBytes int64 = 25 * 1024 * 1024
	// MaxUnpackedBytes caps the total decompressed size across all entries,
	// guarding against zip bombs that lie about compression ratios.
	MaxUnpackedBytes int64 = 100 * 1024 * 1024
	// MaxFiles caps the number of entries an archive may contain.
	MaxFiles = 1000
)

// RootSkillFile is the file every skill archive must contain at its root.
const RootSkillFile = "SKILL.md"

// skillIDPattern mirrors nanoinfra's `_SKILL_RE` and, equivalently, the
// `name` field rules in the public Agent Skills spec
// (https://agentskills.io/specification): lowercase letters and digits,
// segments joined by single hyphens (so no leading/trailing/consecutive
// hyphens are possible).
var skillIDPattern = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// ValidSkillID reports whether id is an acceptable skill slug: lowercase
// letters, digits, and hyphens (no leading/trailing/consecutive hyphens),
// 1-64 characters.
func ValidSkillID(id string) bool {
	return len(id) > 0 && len(id) <= 64 && skillIDPattern.MatchString(id)
}

// Entry describes one validated, path-safe file inside a skill archive.
type Entry struct {
	// Name is the normalized, forward-slash, non-empty relative path.
	Name string
	// Size is the entry's declared (uncompressed) size in bytes.
	Size int64
}

// Metadata is the subset of SKILL.md YAML frontmatter this server cares
// about.
type Metadata struct {
	Name        string
	Description string
}

// Result is the outcome of successfully validating an archive.
type Result struct {
	Entries            []Entry
	Metadata           Metadata
	TotalUnpackedBytes int64
	// Kind is KindSkill for a bare SKILL.md archive or KindAgentPlugin for an
	// Agent Plugins v1 package. Presence of a root plugin.json selects it.
	Kind string
	// Skills names the skills an Agent Plugin package declares. Empty for a
	// plain skill archive, whose single skill is Metadata.Name.
	Skills []string
	// MCPServers names the MCP servers an Agent Plugin package declares.
	// Non-empty means approving this package approves code execution, so the
	// review surface has to show it.
	MCPServers []string
	// The four connector fields, empty for every other kind. Approving a
	// connector is approving requests a deployment will make with a live
	// credential, so all four belong on the review screen: what the operations
	// are allowed to do, where a token could go, and what it would carry.
	ConnectorOperations []string
	ConnectorClasses    []string
	ConnectorHosts      []string
	ConnectorScopes     []string
}

// Grants describes what approving one archive would allow, for the review
// screen. It is derived from a Result rather than stored, because the archive is
// the authority and a stored summary can drift from it.
//
// A skill grants text the agent reads. An Agent Plugin may also declare MCP
// servers, which is code execution. A connector declares *requests a deployment
// will make with a live credential* -- so its operations carry a capability
// class each, its hosts say where a token could go, and its scopes say what that
// token would carry. An approver who sees only a name sees none of that.
type Grants struct {
	Kind  string
	Lines []string
	// Operations is the same information as Lines, split into fields, because
	// the public detail page renders a table and a template should not be
	// parsing a string back apart to do it.
	Operations []GrantOperation
	Classes    []string
	Hosts      []string
	Scopes     []string
	MCPServers []string
}

// GrantOperation is one row of a connector's "what this grants" table.
type GrantOperation struct {
	Name   string
	Class  string
	Method string
	Path   string
}

// ClassSlug is Class with the dot replaced, for a CSS class name. A template
// cannot do this, and a second field on the pipeline result would be a
// presentation detail stored twice.
func (o GrantOperation) ClassSlug() string {
	return strings.ReplaceAll(o.Class, ".", "-")
}

// Describe reports what approving this archive would allow.
func (r *Result) Describe() Grants {
	switch r.Kind {
	case KindConnector:
		return Grants{
			Kind:       KindConnector,
			Lines:      r.ConnectorOperations,
			Operations: grantOperations(r.ConnectorOperations),
			Classes:    r.ConnectorClasses,
			Hosts:      r.ConnectorHosts,
			Scopes:     r.ConnectorScopes,
		}
	case KindAgentPlugin:
		lines := make([]string, 0, len(r.Skills))
		for _, name := range r.Skills {
			lines = append(lines, "skill "+name)
		}
		return Grants{Kind: KindAgentPlugin, Lines: lines, MCPServers: r.MCPServers}
	default:
		return Grants{Kind: KindSkill, Lines: []string{"skill " + r.Metadata.Name}}
	}
}

// grantOperations splits the review lines validateConnectorOperations wrote --
// "<class> <METHOD> <path> <name>" -- back into fields. One producer, one
// consumer, and the format is asserted by the tests either side of it.
func grantOperations(lines []string) []GrantOperation {
	out := make([]GrantOperation, 0, len(lines))
	for _, line := range lines {
		parts := strings.SplitN(line, " ", 4)
		if len(parts) != 4 {
			continue
		}
		out = append(out, GrantOperation{
			Class:  parts[0],
			Method: parts[1],
			Path:   parts[2],
			Name:   parts[3],
		})
	}
	return out
}

// ValidationError is a safe, user-facing description of why an archive was
// rejected. Approval handlers surface Error() verbatim as the auto-rejection
// reason, so it must never leak internal paths or stack traces.
type ValidationError struct {
	Reason string
}

func (e *ValidationError) Error() string { return e.Reason }

func fail(format string, args ...any) error {
	return &ValidationError{Reason: fmt.Sprintf(format, args...)}
}

// ValidateArchive opens the zip file at archivePath, applies path-safety
// checks to every entry, confirms a root SKILL.md is present with valid
// frontmatter, and returns the validated entry list plus parsed metadata.
//
// expectedSkillID, when non-empty, must match the SKILL.md frontmatter
// `name` field; this keeps the published slug and the skill's declared
// identity in sync.
func ValidateArchive(archivePath string, expectedSkillID string) (*Result, error) {
	info, err := os.Stat(archivePath)
	if err != nil {
		return nil, fail("archive could not be read")
	}
	if info.Size() > MaxArchiveBytes {
		return nil, fail("archive exceeds the maximum size of %d bytes", MaxArchiveBytes)
	}

	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return nil, fail("archive is not a valid zip file")
	}
	defer reader.Close()

	entries, total, err := validatedEntries(&reader.Reader)
	if err != nil {
		return nil, err
	}

	// Path safety above applies to every archive before the shape is considered,
	// so a package gets the same treatment a bare skill does. A root
	// connector.json selects the connector path and a root plugin.json selects
	// the Agent Plugins one; the absence of both changes nothing.
	//
	// Connector first, because a connector package may also ship a SKILL.md --
	// its own skill lives inside the package the way a first-party connector's
	// does -- and the kind a reader is installing is decided by the manifest
	// that grants a credential, not by the text beside it.
	if _, connectorErr := findFile(&reader.Reader, RootConnectorFile); connectorErr == nil {
		result, err := validateConnectorPackage(&reader.Reader, expectedSkillID)
		if err != nil {
			return nil, err
		}
		result.Entries = entries
		result.TotalUnpackedBytes = total
		return result, nil
	}

	if _, pluginErr := findFile(&reader.Reader, RootPluginFile); pluginErr == nil {
		result, err := validatePluginPackage(&reader.Reader, expectedSkillID)
		if err != nil {
			return nil, err
		}
		result.Entries = entries
		result.TotalUnpackedBytes = total
		return result, nil
	}

	skillMDFile, err := findFile(&reader.Reader, RootSkillFile)
	if err != nil {
		return nil, err
	}
	content, err := readEntryLimited(skillMDFile, MaxUnpackedBytes)
	if err != nil {
		return nil, fail("SKILL.md could not be read: %v", err)
	}

	meta, err := ParseFrontmatter(content)
	if err != nil {
		return nil, fail("SKILL.md frontmatter is invalid: %v", err)
	}
	if expectedSkillID != "" && meta.Name != expectedSkillID {
		return nil, fail(
			"SKILL.md frontmatter name %q does not match submitted skill id %q",
			meta.Name, expectedSkillID,
		)
	}

	return &Result{
		Entries:            entries,
		Metadata:           meta,
		TotalUnpackedBytes: total,
		Kind:               KindSkill,
	}, nil
}

// validatedEntries walks every entry in the archive and rejects it outright
// on the first path-safety violation: zip-slip / absolute paths / symlinks /
// ".." traversal / duplicate entries / a size cap. It mirrors the intent of
// nanoinfra's Python `_validated_skillhub_entries`.
func validatedEntries(reader *zip.Reader) ([]Entry, int64, error) {
	seen := make(map[string]struct{}, len(reader.File))
	entries := make([]Entry, 0, len(reader.File))
	var total int64
	fileCount := 0

	for _, f := range reader.File {
		normalized, err := normalizeEntryName(f.Name)
		if err != nil {
			return nil, 0, fail("archive contains an unsafe path: %s", f.Name)
		}

		mode := f.Mode()
		isDir := f.FileInfo().IsDir() || strings.HasSuffix(f.Name, "/")
		if mode&os.ModeSymlink != 0 {
			return nil, 0, fail("archive contains a symlink, which is not allowed: %s", f.Name)
		}
		if !isDir && !mode.IsRegular() {
			return nil, 0, fail("archive contains an unsupported entry type: %s", f.Name)
		}
		if isDir {
			continue
		}

		if _, dup := seen[normalized]; dup {
			return nil, 0, fail("archive contains a duplicate path: %s", normalized)
		}
		seen[normalized] = struct{}{}

		fileCount++
		if fileCount > MaxFiles {
			return nil, 0, fail("archive contains too many files (limit %d)", MaxFiles)
		}

		size := int64(f.UncompressedSize64)
		total += size
		if total > MaxUnpackedBytes {
			return nil, 0, fail("archive expands beyond the size limit of %d bytes", MaxUnpackedBytes)
		}

		entries = append(entries, Entry{Name: normalized, Size: size})
	}

	// An archive is one of three shapes, and this is the earliest point that can
	// tell them apart: a bare skill has a root SKILL.md, an Agent Plugins package
	// has a root plugin.json, and a connector package has a root connector.json.
	// Requiring SKILL.md unconditionally here rejected every package before the
	// shape was ever considered -- and it did so again when the third kind
	// arrived, which is why the list is spelled out rather than defaulted.
	_, hasSkill := seen[RootSkillFile]
	_, hasPlugin := seen[RootPluginFile]
	_, hasConnector := seen[RootConnectorFile]
	if !hasSkill && !hasPlugin && !hasConnector {
		return nil, 0, fail(
			"archive does not contain a root %s, a root %s or a root %s",
			RootSkillFile, RootPluginFile, RootConnectorFile,
		)
	}
	return entries, total, nil
}

// normalizeEntryName converts a zip entry name to a clean, forward-slash,
// archive-relative path and rejects anything that could escape the
// extraction directory: empty names, NUL bytes, backslash-separated
// (Windows-style) drive-letter paths, absolute paths, and ".." segments.
func normalizeEntryName(raw string) (string, error) {
	if raw == "" || strings.ContainsRune(raw, 0) {
		return "", errors.New("empty or NUL-containing name")
	}
	name := strings.ReplaceAll(raw, "\\", "/")
	if strings.HasPrefix(name, "/") {
		return "", errors.New("absolute path")
	}
	// Reject Windows drive-letter prefixes such as "C:/..." regardless of
	// the host OS's path semantics, since archives are portable data.
	if idx := strings.IndexByte(name, '/'); idx != -1 && strings.Contains(name[:idx], ":") {
		return "", errors.New("drive-letter path")
	} else if idx == -1 && strings.Contains(name, ":") {
		return "", errors.New("drive-letter path")
	}

	trailingSlash := strings.HasSuffix(name, "/")
	cleaned := path.Clean(name)
	if cleaned == "." {
		return "", errors.New("empty path after cleaning")
	}
	for _, part := range strings.Split(cleaned, "/") {
		if part == ".." {
			return "", errors.New("path traversal")
		}
	}
	if trailingSlash {
		cleaned += "/"
	}
	return cleaned, nil
}

// findFile returns the zip.File with the exact given root-relative name, or
// a ValidationError if absent.
func findFile(reader *zip.Reader, name string) (*zip.File, error) {
	for _, f := range reader.File {
		normalized, err := normalizeEntryName(f.Name)
		if err != nil {
			continue
		}
		if normalized == name {
			return f, nil
		}
	}
	return nil, fail("archive does not contain a root %s", name)
}

// FileContent is one validated entry's path plus its full decompressed
// content, ready to hand to a publisher.
type FileContent struct {
	Path    string
	Content []byte
}

// ReadFiles re-opens archivePath and reads the full content of every entry
// named in entries (as returned by a prior, successful ValidateArchive
// call). It is used by the publish step to materialize the file list to
// commit to GitHub.
func ReadFiles(archivePath string, entries []Entry) ([]FileContent, error) {
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return nil, fail("archive could not be reopened for publishing")
	}
	defer reader.Close()

	byName := make(map[string]*zip.File, len(reader.File))
	for _, f := range reader.File {
		normalized, err := normalizeEntryName(f.Name)
		if err != nil {
			continue
		}
		byName[normalized] = f
	}

	out := make([]FileContent, 0, len(entries))
	for _, e := range entries {
		f, ok := byName[e.Name]
		if !ok {
			return nil, fail("archive entry %s disappeared between validation and publish", e.Name)
		}
		data, err := readEntryLimited(f, MaxUnpackedBytes)
		if err != nil {
			return nil, fail("could not read %s: %v", e.Name, err)
		}
		out = append(out, FileContent{Path: e.Name, Content: data})
	}
	return out, nil
}

// readEntryLimited reads a zip entry's contents, refusing to read past
// limit+1 bytes even if the entry's declared size understates the true
// decompressed size (a classic zip-bomb trick).
func readEntryLimited(f *zip.File, limit int64) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	limited := io.LimitReader(rc, limit+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("entry exceeds %d bytes", limit)
	}
	return data, nil
}
