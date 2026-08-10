package web

import (
	"embed"
	"io/fs"
)

// static/pico.min.css is Pico CSS v2.1.1 (https://picocss.com), vendored
// in-repo rather than loaded from a CDN -- consistent with this project's
// existing no-outbound-dependency posture (see docs/design-choices.md and
// docs/web-ui.md). static/pico.LICENSE.md is its upstream MIT license text.
//
//go:embed static
var staticFS embed.FS

// staticFiles strips the embedded "static" directory prefix so
// GET /static/pico.min.css serves static/pico.min.css's contents, not
// static/static/pico.min.css.
var staticFiles = mustSub(staticFS, "static")

func mustSub(fsys fs.FS, dir string) fs.FS {
	sub, err := fs.Sub(fsys, dir)
	if err != nil {
		panic(err)
	}
	return sub
}
