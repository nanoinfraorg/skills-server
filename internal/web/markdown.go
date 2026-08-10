package web

import (
	"bytes"
	"fmt"
	"html/template"
	"strings"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/text"
	"github.com/yuin/goldmark/util"
)

// renderMarkdownPreview renders a skill's SKILL.md body (untrusted,
// third-party-submitted, shown unauthenticated -- see skill_detail.html's
// "raw"/"preview" toggle and SkillDetail) as Markdown-to-HTML for the
// opt-in "preview" view, and is deliberately paranoid about it: the
// default "raw" view (a <pre> block html/template auto-escapes) remains
// the only thing every visitor sees unless they explicitly ask for
// "preview", and this function is what stands between that opt-in and a
// stored-XSS hole. Two things make it safe, both explained in detail
// below and both load-bearing: (1) raw HTML in the Markdown source is
// dropped, never passed through, and (2) every link/image URL is checked
// against an explicit scheme allowlist, not merely goldmark's own
// built-in scheme blocklist. Only after both are in effect is the
// rendered output wrapped in template.HTML, which disables
// html/template's auto-escaping for that value -- get either (1) or (2)
// wrong and that line is the whole vulnerability.
func renderMarkdownPreview(source string) (template.HTML, error) {
	// (1) Raw HTML passthrough: WithUnsafe() is the one goldmark renderer
	// option that would make goldmark emit raw HTML blocks/inline HTML
	// (e.g. a literal "<script>...</script>" or "<img onerror=...>" in
	// the Markdown source) verbatim into the output. It is deliberately
	// NOT set anywhere in this file. Confirmed by reading goldmark
	// v1.8.5's renderer/html/html.go directly: renderHTMLBlock and
	// renderRawHTML both check `if r.Unsafe` before writing the actual
	// HTML bytes; when Unsafe is false (goldmark's own default, and this
	// renderer's only configuration, since goldmark.New below is never
	// given a WithUnsafe() option) they instead write the literal comment
	// "<!-- raw HTML omitted -->" and nothing else. So a raw <script>
	// block, a raw <img onerror=...> tag, or any other literal HTML in
	// the submitted SKILL.md never reaches the response at all -- not
	// even escaped, just omitted.
	//
	// No goldmark extensions (GFM tables/autolink/strikethrough/etc.) are
	// enabled either -- default CommonMark parsing already covers
	// headings, lists, blockquotes, and fenced code blocks, which is all
	// this preview needs to render, and every extension is more surface
	// area to have to reason about for this one security-sensitive
	// function.
	md := goldmark.New(
		goldmark.WithParserOptions(
			// (2) Link/image URL schemes: goldmark's default HTML renderer
			// already refuses to emit a handful of specific dangerous
			// schemes on its own (renderer/html/html.go's IsDangerousURL:
			// "javascript:", "vbscript:", "file:", and "data:" other than
			// data:image/{png,gif,jpeg,webp}) by writing an empty href/src
			// instead of the URL. That's a blocklist, though, not the
			// allowlist this needs: it would still pass through, say,
			// "tel:", a bare unknown scheme, or (more subtly) a scheme
			// obfuscated with an embedded tab/newline the way
			// "java\tscript:alert(1)" defeats a naive prefix check, because
			// browsers strip ASCII tab/newline/CR from a URL before
			// resolving its scheme (see the WHATWG URL Standard's basic URL
			// parser, step 1: "Remove all ASCII tab or newline from url"),
			// but a simple hasPrefix("javascript:") check does not.
			//
			// So this registers our own parser.ASTTransformer
			// (schemeAllowlistTransformer below) that walks the parsed AST
			// after parsing and before rendering and, for every ast.Link
			// and ast.Image node, blanks the Destination outright unless
			// its scheme (after stripping those same control characters
			// first) is exactly "http", "https", or "mailto". A blanked
			// Destination renders as href="" / src="" -- present in the
			// markup, but not a URL that navigates or loads anything.
			//
			// This is an AST transformer, not a custom NodeRenderer
			// override or a second post-render sanitization pass, because
			// it's goldmark's own idiomatic extension point for exactly
			// this ("transform the tree between parse and render" --
			// parser.ASTTransformer, wired in the same way goldmark's own
			// bundled extensions register theirs) and it means the URL
			// check runs exactly once, on the actual parsed destination
			// bytes, in one place, rather than duplicating goldmark's own
			// HTML-escaping/URL-writing logic in a rewritten renderer or
			// re-parsing already-rendered HTML with a second library. A
			// bluemonday-style post-render HTML sanitizer was considered
			// (the operator's own suggestion) and rejected: it would be a
			// second non-stdlib dependency in a codebase that has stayed
			// deliberately light on those (see docs/design-choices.md --
			// even the GitHub client was hand-rolled specifically to avoid
			// adding one), where goldmark's own renderer options already
			// hand this function everything it needs to enforce the same
			// property natively.
			parser.WithASTTransformers(
				util.Prioritized(schemeAllowlistTransformer{}, 999),
			),
		),
	)

	var buf bytes.Buffer
	if err := md.Convert([]byte(source), &buf); err != nil {
		return "", fmt.Errorf("render markdown preview: %w", err)
	}
	// Safe to disable auto-escaping for this value now -- but only now,
	// after both (1) and (2) above have already run. template.HTML makes
	// html/template treat the string as pre-vetted HTML instead of
	// escaping it, which is exactly why the two steps above have to be
	// correct on their own; this line does no filtering of its own.
	return template.HTML(buf.String()), nil //nolint:gosec // deliberate: see doc comment above
}

// allowedURLSchemes is the explicit allowlist enforced by
// schemeAllowlistTransformer: only these three schemes are ever allowed
// through as a link href or image src in rendered Markdown preview
// output. Everything else -- javascript:, vbscript:, data:, file:, tel:,
// an unrecognized custom scheme, anything -- is blanked. A URL with no
// scheme at all (a same-page fragment like "#section", a relative path,
// or a protocol-relative "//host/path") is left alone rather than
// blanked: it's exactly as capable as any link a visitor could type into
// their own browser's address bar pointed at this same site or another
// https site, not a new capability this preview grants.
var allowedURLSchemes = map[string]bool{
	"http":   true,
	"https":  true,
	"mailto": true,
}

// schemeAllowlistTransformer is a parser.ASTTransformer that blanks the
// Destination of every ast.Link and ast.Image node whose URL scheme
// isn't in allowedURLSchemes -- see renderMarkdownPreview's doc comment
// for why this exists (goldmark's own default is a narrower blocklist)
// and why an AST transformer is the mechanism.
type schemeAllowlistTransformer struct{}

func (schemeAllowlistTransformer) Transform(doc *ast.Document, _ text.Reader, _ parser.Context) {
	_ = ast.Walk(doc, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		switch link := n.(type) {
		case *ast.Link:
			if !urlSchemeAllowed(link.Destination) {
				link.Destination = nil
			}
		case *ast.Image:
			if !urlSchemeAllowed(link.Destination) {
				link.Destination = nil
			}
		}
		return ast.WalkContinue, nil
	})
}

// urlSchemeAllowed reports whether dest is safe to render as a link
// href or image src: either it names no scheme at all (a relative or
// fragment reference), or its scheme is in allowedURLSchemes.
//
// dest is first stripped of ASCII tab/newline/CR characters -- browsers
// do the same before parsing a URL's scheme (WHATWG URL Standard, basic
// URL parser step 1), which is what makes "java\tscript:alert(1)" a
// working javascript: URL in an actual browser despite not literally
// starting with "javascript:"; skipping this step here would make the
// allowlist below trivially bypassable by anyone who knows that trick.
// Leading/trailing ASCII whitespace and C0 control characters are
// trimmed for the same reason (the same parsing step also strips
// leading/trailing "C0 control or space").
func urlSchemeAllowed(dest []byte) bool {
	cleaned := stripURLControlChars(dest)
	scheme, hasScheme := urlScheme(cleaned)
	if !hasScheme {
		return true // relative/fragment reference -- nothing to allowlist
	}
	return allowedURLSchemes[strings.ToLower(scheme)]
}

// stripURLControlChars removes every ASCII tab (0x09), newline (0x0A),
// and carriage return (0x0D) from s, then trims any remaining
// leading/trailing ASCII whitespace or C0 control byte (0x00-0x20) --
// mirroring the WHATWG URL Standard's basic URL parser's own first
// normalization step, so scheme detection below sees what a browser
// would actually resolve the URL's scheme to, not just its literal
// unmodified bytes.
func stripURLControlChars(s []byte) []byte {
	cleaned := make([]byte, 0, len(s))
	for _, b := range s {
		if b == '\t' || b == '\n' || b == '\r' {
			continue
		}
		cleaned = append(cleaned, b)
	}
	return bytes.TrimFunc(cleaned, func(r rune) bool {
		return r <= 0x20
	})
}

// urlScheme extracts the scheme from a URL per RFC 3986 (a leading ALPHA
// followed by any number of ALPHA / DIGIT / "+" / "-" / "." characters,
// then a ":"), returning ("", false) if s has no such prefix -- e.g. a
// relative path, a fragment ("#foo"), or a protocol-relative URL
// ("//host/path", which has no scheme token before its first ":", if
// any).
func urlScheme(s []byte) (string, bool) {
	colon := bytes.IndexByte(s, ':')
	if colon <= 0 {
		return "", false
	}
	candidate := s[:colon]
	for i, b := range candidate {
		switch {
		case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z':
			continue
		case i > 0 && (b >= '0' && b <= '9' || b == '+' || b == '-' || b == '.'):
			continue
		default:
			return "", false
		}
	}
	return string(candidate), true
}
