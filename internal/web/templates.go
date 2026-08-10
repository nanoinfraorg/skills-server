package web

import (
	"embed"
	"html/template"
)

//go:embed templates/*.html
var templateFiles embed.FS

// pageTemplates lists every page-specific template file (i.e. every
// templates/*.html file except layout.html itself). Each one is parsed
// against its own clone of the shared layout, so that every file's
// `{{define "content"}}` block is scoped to that page alone -- html/template
// associates a given defined-template name with the whole *template.Template
// tree it was parsed into, so without cloning, every page's "content" block
// would silently overwrite the last one parsed instead of staying distinct.
var pageTemplates = []string{
	"home.html",
	"skills.html",
	"skill_detail.html",
	"submit.html",
	"my_submissions.html",
	"admin.html",
	"message.html",
}

// loadTemplates parses templates/layout.html once as the shared base, then
// clones it per page and parses that page's own file into the clone -- see
// pageTemplates' doc comment for why the clone is necessary. The result is
// keyed by page file name (e.g. "home.html"), matching Handler.render's
// page argument.
func loadTemplates() map[string]*template.Template {
	base := template.Must(template.New("layout.html").ParseFS(templateFiles, "templates/layout.html"))

	out := make(map[string]*template.Template, len(pageTemplates))
	for _, name := range pageTemplates {
		clone := template.Must(base.Clone())
		out[name] = template.Must(clone.ParseFS(templateFiles, "templates/"+name))
	}
	return out
}
