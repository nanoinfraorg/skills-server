package pipeline

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validSkillMD = "---\nname: my-skill\ndescription: Does a useful thing. Use when doing the thing.\n---\n\n# My Skill\n"

// zipEntry describes one entry to write into a test fixture archive.
type zipEntry struct {
	name    string
	content string
	symlink bool // if true, content is the symlink target and mode bits are set accordingly
}

// writeTestZip builds a zip archive from entries and returns its path.
func writeTestZip(t *testing.T, entries []zipEntry) string {
	t.Helper()
	dir := t.TempDir()
	archivePath := filepath.Join(dir, "archive.zip")
	f, err := os.Create(archivePath)
	if err != nil {
		t.Fatalf("create archive: %v", err)
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	for _, e := range entries {
		hdr := &zip.FileHeader{Name: e.name}
		if e.symlink {
			hdr.SetMode(os.ModeSymlink | 0o777)
		} else {
			hdr.SetMode(0o644)
		}
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			t.Fatalf("create header for %s: %v", e.name, err)
		}
		if _, err := w.Write([]byte(e.content)); err != nil {
			t.Fatalf("write entry %s: %v", e.name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip writer: %v", err)
	}
	return archivePath
}

func TestValidateArchive_ValidSkillPasses(t *testing.T) {
	path := writeTestZip(t, []zipEntry{
		{name: "SKILL.md", content: validSkillMD},
		{name: "scripts/run.py", content: "print('hi')\n"},
	})

	result, err := ValidateArchive(path, "my-skill")
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if result.Metadata.Name != "my-skill" {
		t.Errorf("metadata name = %q, want my-skill", result.Metadata.Name)
	}
	if result.Metadata.Description == "" {
		t.Errorf("expected non-empty description")
	}
	if len(result.Entries) != 2 {
		t.Errorf("expected 2 entries, got %d: %+v", len(result.Entries), result.Entries)
	}
}

func TestValidateArchive_SkillIDMismatchRejected(t *testing.T) {
	path := writeTestZip(t, []zipEntry{
		{name: "SKILL.md", content: validSkillMD},
	})

	if _, err := ValidateArchive(path, "different-slug"); err == nil {
		t.Fatal("expected error for skill id mismatch, got nil")
	}
}

func TestValidateArchive_MissingSkillMDRejected(t *testing.T) {
	path := writeTestZip(t, []zipEntry{
		{name: "README.md", content: "hello"},
	})

	_, err := ValidateArchive(path, "")
	if err == nil {
		t.Fatal("expected error for missing SKILL.md, got nil")
	}
	if !strings.Contains(err.Error(), "SKILL.md") {
		t.Errorf("error should mention SKILL.md, got: %v", err)
	}
}

func TestValidateArchive_PathTraversalRejected(t *testing.T) {
	cases := []struct {
		name string
		path string
	}{
		{"dot-dot slash", "../outside.sh"},
		{"nested dot-dot", "scripts/../../outside.sh"},
		{"absolute path", "/etc/passwd"},
		{"backslash traversal", "..\\outside.sh"},
		{"windows drive letter", "C:/Windows/System32/evil.dll"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTestZip(t, []zipEntry{
				{name: "SKILL.md", content: validSkillMD},
				{name: tc.path, content: "malicious"},
			})
			if _, err := ValidateArchive(path, ""); err == nil {
				t.Fatalf("expected rejection for unsafe path %q, got nil", tc.path)
			}
		})
	}
}

func TestValidateArchive_SymlinkRejected(t *testing.T) {
	path := writeTestZip(t, []zipEntry{
		{name: "SKILL.md", content: validSkillMD},
		{name: "link", content: "/etc/passwd", symlink: true},
	})

	_, err := ValidateArchive(path, "")
	if err == nil {
		t.Fatal("expected error for symlink entry, got nil")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("error should mention symlink, got: %v", err)
	}
}

func TestValidateArchive_DuplicatePathRejected(t *testing.T) {
	// zip.Writer permits writing the same name twice; the reader will
	// enumerate both entries in reader.File, which is exactly the ambiguous
	// situation the duplicate check exists to reject.
	path := writeTestZip(t, []zipEntry{
		{name: "SKILL.md", content: validSkillMD},
		{name: "scripts/run.py", content: "v1"},
		{name: "scripts/run.py", content: "v2 - shadows v1"},
	})

	_, err := ValidateArchive(path, "")
	if err == nil {
		t.Fatal("expected error for duplicate path, got nil")
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("error should mention duplicate, got: %v", err)
	}
}

func TestValidateArchive_TooManyFilesRejected(t *testing.T) {
	original := MaxFiles
	MaxFiles = 2
	t.Cleanup(func() { MaxFiles = original })

	path := writeTestZip(t, []zipEntry{
		{name: "SKILL.md", content: validSkillMD},
		{name: "a.txt", content: "a"},
		{name: "b.txt", content: "b"},
	})

	_, err := ValidateArchive(path, "")
	if err == nil {
		t.Fatal("expected error for too many files, got nil")
	}
	if !strings.Contains(err.Error(), "too many files") {
		t.Errorf("error should mention file count limit, got: %v", err)
	}
}

func TestValidateArchive_UnpackedSizeCapRejected(t *testing.T) {
	original := MaxUnpackedBytes
	MaxUnpackedBytes = 16
	t.Cleanup(func() { MaxUnpackedBytes = original })

	path := writeTestZip(t, []zipEntry{
		{name: "SKILL.md", content: validSkillMD},
		{name: "big.txt", content: strings.Repeat("x", 64)},
	})

	_, err := ValidateArchive(path, "")
	if err == nil {
		t.Fatal("expected error for exceeding unpacked size cap, got nil")
	}
	if !strings.Contains(err.Error(), "size limit") {
		t.Errorf("error should mention the size limit, got: %v", err)
	}
}

func TestValidateArchive_ArchiveTooLargeOnDiskRejected(t *testing.T) {
	original := MaxArchiveBytes
	MaxArchiveBytes = 8
	t.Cleanup(func() { MaxArchiveBytes = original })

	path := writeTestZip(t, []zipEntry{
		{name: "SKILL.md", content: validSkillMD},
	})

	_, err := ValidateArchive(path, "")
	if err == nil {
		t.Fatal("expected error for oversized archive on disk, got nil")
	}
	if !strings.Contains(err.Error(), "maximum size") {
		t.Errorf("error should mention the maximum size, got: %v", err)
	}
}

func TestValidateArchive_NotAZipFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "not-a-zip.zip")
	if err := os.WriteFile(path, []byte("this is not a zip file"), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	if _, err := ValidateArchive(path, ""); err == nil {
		t.Fatal("expected error for non-zip file, got nil")
	}
}

func TestValidateArchive_DirectoryEntriesAllowedAndSkipped(t *testing.T) {
	path := writeTestZip(t, []zipEntry{
		{name: "scripts/", content: ""},
		{name: "SKILL.md", content: validSkillMD},
	})

	result, err := ValidateArchive(path, "")
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	for _, e := range result.Entries {
		if strings.HasSuffix(e.Name, "/") {
			t.Errorf("directory entry %q should not appear in validated file entries", e.Name)
		}
	}
}

func TestParseFrontmatter(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr bool
	}{
		{"valid", validSkillMD, false},
		{"missing opening delimiter", "# no frontmatter here\n", true},
		{"unterminated block", "---\nname: foo\ndescription: bar\n", true},
		{"missing name", "---\ndescription: bar\n---\n", true},
		{"missing description", "---\nname: foo\n---\n", true},
		{"invalid name format", "---\nname: Not_Valid_Name\ndescription: bar\n---\n", true},
		{"quoted values", "---\nname: \"my-skill\"\ndescription: 'quoted description'\n---\n", false},
		{
			"description too long",
			"---\nname: foo\ndescription: " + strings.Repeat("x", maxDescriptionLen+1) + "\n---\n",
			true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseFrontmatter([]byte(tc.content))
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected no error, got: %v", err)
			}
		})
	}
}

func TestValidSkillID(t *testing.T) {
	valid := []string{"a", "my-skill", "skill-2", "a1-b2-c3"}
	invalid := []string{"", "My-Skill", "my_skill", "-leading", "trailing-", "has space", strings.Repeat("a", 65)}

	for _, id := range valid {
		if !ValidSkillID(id) {
			t.Errorf("expected %q to be valid", id)
		}
	}
	for _, id := range invalid {
		if ValidSkillID(id) {
			t.Errorf("expected %q to be invalid", id)
		}
	}
}

func TestReadFiles_RoundTrip(t *testing.T) {
	path := writeTestZip(t, []zipEntry{
		{name: "SKILL.md", content: validSkillMD},
		{name: "scripts/run.py", content: "print(1)\n"},
	})

	result, err := ValidateArchive(path, "")
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	files, err := ReadFiles(path, result.Entries)
	if err != nil {
		t.Fatalf("read files: %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("expected 2 files, got %d", len(files))
	}
	contents := map[string]string{}
	for _, f := range files {
		contents[f.Path] = string(f.Content)
	}
	if contents["SKILL.md"] != validSkillMD {
		t.Errorf("SKILL.md content mismatch")
	}
	if contents["scripts/run.py"] != "print(1)\n" {
		t.Errorf("scripts/run.py content mismatch")
	}
}
