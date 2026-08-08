package scan

import "unicode/utf8"

// isTextOnly reports whether content passes the scanner's text-only check:
// valid UTF-8 and free of NUL bytes. This intentionally simple heuristic --
// not a full MIME-sniffing pass -- is enough to catch "binary disguised as
// text" for v1; see the design doc section 2a for why a more elaborate
// check was not built here.
func isTextOnly(content []byte) bool {
	if !utf8.Valid(content) {
		return false
	}
	for _, b := range content {
		if b == 0 {
			return false
		}
	}
	return true
}
