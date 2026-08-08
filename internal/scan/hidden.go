package scan

import "fmt"

// Constants are spelled with explicit \u/\U escapes rather than literal
// characters, deliberately: this file's whole job is detecting invisible
// characters, so the invisible characters themselves must never appear
// unescaped in the source, where they'd be impossible to review or diff.
const (
	zwsp   = '\u200B' // ZWSP: zero width space
	zwnj   = '\u200C' // ZWNJ: zero width non-joiner
	zwj    = '\u200D' // ZWJ: zero width joiner
	zwnbsp = '\uFEFF' // ZWNBSP / BOM: zero width no-break space

	// bidiControlLow1..High1 and Low2..High2 together are the "Trojan
	// Source" bidi control range: U+202A-U+202E (LRE, RLE, PDF, LRO, RLO)
	// and U+2066-U+2069 (LRI, RLI, FSI, PDI).
	bidiControlLow1  = '\u202A'
	bidiControlHigh1 = '\u202E'
	bidiControlLow2  = '\u2066'
	bidiControlHigh2 = '\u2069'

	// tagsBlockLow..High is the Unicode Tags block, the 2024-disclosed
	// "ASCII smuggling" technique for hiding LLM-readable,
	// human-invisible instructions in ordinary-looking text.
	tagsBlockLow  = '\U000E0000'
	tagsBlockHigh = '\U000E007F'
)

// isHiddenChar reports whether r falls in one of the hidden/invisible
// Unicode ranges this scanner flags:
//   - zero-width characters, which can hide extra tokens an LLM will read
//     but a human reviewing the raw file will not see rendered;
//   - bidi control characters (the "Trojan Source" range), which can
//     visually reorder code/text to disguise its real meaning;
//   - the Unicode Tags block (see the const doc above).
func isHiddenChar(r rune) bool {
	switch r {
	case zwsp, zwnj, zwj, zwnbsp:
		return true
	}
	if r >= bidiControlLow1 && r <= bidiControlHigh1 {
		return true
	}
	if r >= bidiControlLow2 && r <= bidiControlHigh2 {
		return true
	}
	if r >= tagsBlockLow && r <= tagsBlockHigh {
		return true
	}
	return false
}

// scanHiddenChars scans one text file's decoded runes for hidden/invisible
// Unicode characters, returning one finding per occurrence with its
// codepoint and 1-based line number.
//
// isFirstFile marks whether path is the very first file in the scan's
// processing order. Per the design doc, "a legitimate leading BOM on the
// very first file read" is ignored -- i.e. a U+FEFF at byte offset 0 of
// that one file is not flagged. Every other occurrence of U+FEFF --
// including a leading BOM on any file *other* than the first, and any
// non-leading occurrence in any file -- is flagged: a real editor-written
// BOM would ordinarily appear at most once, at the very start of the
// archive's first (conventionally SKILL.md) file, so any other occurrence
// is unexpected and worth a human's attention.
func scanHiddenChars(path string, content []byte, isFirstFile bool) []HiddenCharFinding {
	var findings []HiddenCharFinding
	line := 1
	for i, r := range string(content) {
		if r == zwnbsp && isFirstFile && i == 0 {
			continue // legitimate leading BOM on the very first file read
		}
		if isHiddenChar(r) {
			findings = append(findings, HiddenCharFinding{
				File:      path,
				Rune:      string(r),
				Codepoint: fmt.Sprintf("U+%04X", r),
				Line:      line,
			})
		}
		if r == '\n' {
			line++
		}
	}
	return findings
}
