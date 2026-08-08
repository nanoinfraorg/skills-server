package scan

import (
	"fmt"
	"regexp"
	"strings"
)

// suspiciousPattern is one high-signal, regexp-based static check.
//
// This list is deliberately short and documented as v1/best-effort -- not a
// comprehensive malware-signature database. Extend it as new high-signal,
// low-false-positive patterns are identified; resist the urge to grow it
// into a general-purpose antivirus engine.
type suspiciousPattern struct {
	name string
	re   *regexp.Regexp
}

var suspiciousPatterns = []suspiciousPattern{
	// Piping a remote download straight into a shell is a classic
	// "curl | bash" / "wget | sh" one-liner technique for arbitrary remote
	// code execution; a skill's own bundled files have no legitimate reason
	// to contain one.
	{"pipe-to-shell (curl)", regexp.MustCompile(`(?i)curl\s+[^|\n]*\|\s*(sudo\s+)?(sh|bash)\b`)},
	{"pipe-to-shell (wget)", regexp.MustCompile(`(?i)wget\s+[^|\n]*\|\s*(sudo\s+)?(sh|bash)\b`)},
	// A long run of base64-alphabet characters is a reasonable proxy for an
	// obfuscated/encoded payload hiding inside an otherwise-text file.
	{"long base64-like blob", regexp.MustCompile(`[A-Za-z0-9+/]{200,}={0,2}`)},
}

// scanStaticPatterns scans one text file's content against every pattern in
// suspiciousPatterns, returning one finding per match with its line number
// and a short, size-capped excerpt.
func scanStaticPatterns(path string, content []byte) []StaticPatternFinding {
	var findings []StaticPatternFinding
	text := string(content)
	for _, p := range suspiciousPatterns {
		for _, loc := range p.re.FindAllStringIndex(text, -1) {
			findings = append(findings, StaticPatternFinding{
				File:    path,
				Pattern: p.name,
				Line:    lineAt(text, loc[0]),
				Excerpt: excerpt(text, loc[0], loc[1]),
			})
		}
	}
	return findings
}

// lineAt returns the 1-based line number containing byte offset pos.
func lineAt(text string, pos int) int {
	return 1 + strings.Count(text[:pos], "\n")
}

// excerpt returns a short, size-capped snippet of text spanning [start,
// end), so a finding never carries an unbounded amount of matched content
// (relevant in particular for the base64-blob pattern, which can match
// arbitrarily long runs).
func excerpt(text string, start, end int) string {
	const maxLen = 80
	truncated := end-start > maxLen
	if truncated {
		end = start + maxLen
	}
	snippet := text[start:end]
	if truncated {
		snippet += "..."
	}
	return fmt.Sprintf("%q", snippet)
}
