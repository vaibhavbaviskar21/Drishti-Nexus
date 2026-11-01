package report

import (
	_ "embed"
	"html/template"
	"io"
	"strings"
)

//go:embed report.html.tmpl
var htmlSource string

// Log content is attacker-controlled: html/template escapes every value, and no
// template.HTML is ever built from data.
var htmlTmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"time":      fmtTime,
	"join":      strings.Join,
	"unchanged": unchanged,
	"lower":     strings.ToLower,
}).Parse(htmlSource))

// WriteHTML writes the report as one self-contained HTML file (inline CSS, no
// scripts, no external resources).
func WriteHTML(w io.Writer, d Data) error {
	return htmlTmpl.Execute(w, d)
}
