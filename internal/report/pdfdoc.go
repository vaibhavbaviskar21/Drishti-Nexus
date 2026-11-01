package report

import (
	"bytes"
	"fmt"
	"io"
	"strings"
)

// pdfDoc is a minimal text-and-rectangles PDF 1.4 writer: A4 pages, the
// standard Helvetica / Helvetica-Bold / Courier fonts (not embedded, WinAnsi
// encoding), no compression. Pure Go, stdlib only, so the binary stays static
// and dependency-free; see docs/REPORTING.md.
type pdfDoc struct {
	pages []*bytes.Buffer
	page  *bytes.Buffer
	y     float64 // baseline of the next line, from the page bottom
}

type font int

const (
	regular font = iota
	bold
	mono
)

const (
	pageW, pageH = 595.28, 841.89
	marginX      = 42.0
	marginTop    = 48.0
	marginBottom = 54.0
	contentW     = pageW - 2*marginX
)

type rgb [3]float64

var (
	black = rgb{0.11, 0.12, 0.14}
	muted = rgb{0.36, 0.39, 0.44}
	panel = rgb{0.93, 0.94, 0.95}
	red   = rgb{0.73, 0.11, 0.11}
	green = rgb{0.09, 0.40, 0.20}
)

func (p *pdfDoc) newPage() {
	p.page = &bytes.Buffer{}
	p.pages = append(p.pages, p.page)
	p.y = pageH - marginTop
}

// need starts a new page unless h points still fit above the bottom margin.
func (p *pdfDoc) need(h float64) {
	if p.page == nil || p.y-h < marginBottom {
		p.newPage()
	}
}

func (p *pdfDoc) text(x, y float64, f font, size float64, c rgb, s string) {
	fmt.Fprintf(p.page, "BT %.2f %.2f %.2f rg /F%d %.1f Tf %.2f %.2f Td (%s) Tj ET\n",
		c[0], c[1], c[2], int(f)+1, size, x, y, pdfEscape(s))
}

func (p *pdfDoc) rect(x, y, w, h float64, c rgb) {
	fmt.Fprintf(p.page, "%.2f %.2f %.2f rg %.2f %.2f %.2f %.2f re f\n", c[0], c[1], c[2], x, y, w, h)
}

// para writes s wrapped to the content width, starting at x.
func (p *pdfDoc) para(x float64, f font, size float64, c rgb, s string) {
	for _, line := range wrap(winAnsi(s), f, size, pageW-marginX-x) {
		p.need(size * 1.35)
		p.text(x, p.y-size, f, size, c, line)
		p.y -= size * 1.35
	}
}

// cell is one column of a table row.
type cell struct {
	w    float64
	f    font
	c    rgb
	text string
}

// row draws cells side by side, each wrapped to its width, optionally on a shaded band.
func (p *pdfDoc) row(size float64, shade bool, cells ...cell) {
	lead := size * 1.3
	lines := make([][]string, len(cells))
	n := 1
	for i, c := range cells {
		lines[i] = wrap(winAnsi(c.text), c.f, size, c.w-6)
		n = max(n, len(lines[i]))
	}
	h := float64(n)*lead + 4
	if h > pageH-marginTop-marginBottom { // a row taller than a page is cut, not looped forever
		n = int((pageH - marginTop - marginBottom - 4) / lead)
		h = float64(n)*lead + 4
	}
	p.need(h)
	if shade {
		p.rect(marginX, p.y-h, contentW, h, panel)
	}
	x := marginX
	for i, c := range cells {
		for j, l := range lines[i] {
			if j == n {
				break
			}
			p.text(x+3, p.y-2-size-float64(j)*lead, c.f, size, c.c, l)
		}
		x += c.w
	}
	p.y -= h
}

func (p *pdfDoc) write(w io.Writer, title string) error {
	var b bytes.Buffer
	var offsets []int
	obj := func(body string) {
		offsets = append(offsets, b.Len())
		fmt.Fprintf(&b, "%d 0 obj\n%s\nendobj\n", len(offsets), body)
	}
	b.WriteString("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")

	kids := make([]string, len(p.pages))
	for i := range p.pages {
		kids[i] = fmt.Sprintf("%d 0 R", 6+2*i)
	}
	obj("<< /Type /Catalog /Pages 2 0 R >>")
	obj(fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", strings.Join(kids, " "), len(p.pages)))
	for _, name := range []string{"Helvetica", "Helvetica-Bold", "Courier"} {
		obj("<< /Type /Font /Subtype /Type1 /BaseFont /" + name + " /Encoding /WinAnsiEncoding >>")
	}
	for i, pg := range p.pages {
		obj(fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %.2f %.2f] /Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> /Contents %d 0 R >>",
			pageW, pageH, 7+2*i))
		obj(fmt.Sprintf("<< /Length %d >>\nstream\n%sendstream", pg.Len(), pg.Bytes()))
	}
	obj(fmt.Sprintf("<< /Title (%s) /Producer (Drishti Nexus) >>", pdfEscape(winAnsi(title))))

	xref := b.Len()
	fmt.Fprintf(&b, "xref\n0 %d\n0000000000 65535 f \n", len(offsets)+1)
	for _, o := range offsets {
		fmt.Fprintf(&b, "%010d 00000 n \n", o)
	}
	fmt.Fprintf(&b, "trailer\n<< /Size %d /Root 1 0 R /Info %d 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(offsets)+1, len(offsets), xref)
	_, err := w.Write(b.Bytes())
	return err
}

// winAnsi maps s to single-byte WinAnsi text. Control characters become spaces
// and characters the standard fonts cannot show become '?', so attacker-controlled
// bytes can never alter the PDF structure (parentheses and backslashes are
// escaped separately by pdfEscape).
func winAnsi(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r < 0x20 || r == 0x7f:
			b.WriteByte(' ')
		case r < 0x7f || (r >= 0xa0 && r <= 0xff):
			b.WriteByte(byte(r))
		case r == '…':
			b.WriteByte(0x85)
		case r == '–':
			b.WriteByte(0x96)
		case r == '—':
			b.WriteByte(0x97)
		case r == '·', r == '•':
			b.WriteByte(0xb7)
		case r == '→':
			b.WriteString("->")
		default:
			b.WriteByte('?')
		}
	}
	return b.String()
}

func pdfEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `(`, `\(`, `)`, `\)`).Replace(s)
}

// wrap breaks WinAnsi text into lines no wider than maxW points; words longer
// than a line (hashes, base64) are split.
func wrap(s string, f font, size, maxW float64) []string {
	var lines []string
	line := ""
	for _, word := range strings.Fields(s) {
		cand := word
		if line != "" {
			cand = line + " " + word
		}
		if width(cand, f, size) <= maxW {
			line = cand
			continue
		}
		if line != "" {
			lines = append(lines, line)
		}
		for width(word, f, size) > maxW {
			i := 1
			for i < len(word) && width(word[:i+1], f, size) <= maxW {
				i++
			}
			lines = append(lines, word[:i])
			word = word[i:]
		}
		line = word
	}
	if line != "" || len(lines) == 0 {
		lines = append(lines, line)
	}
	return lines
}

func width(s string, f font, size float64) float64 {
	units := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case f == mono:
			units += 600
		case c >= 32 && c < 127 && f == bold:
			units += helveticaBold[c-32]
		case c >= 32 && c < 127:
			units += helvetica[c-32]
		default:
			units += 556 // shortcut: average glyph width for WinAnsi 0x80-0xff
		}
	}
	return float64(units) * size / 1000
}

// Glyph widths (1/1000 em) for ASCII 32..126, from the Adobe core font AFMs.
var helvetica = [95]int{
	278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278,
	556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556,
	1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778,
	667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556,
	333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556,
	556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584,
}

var helveticaBold = [95]int{
	278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278,
	556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 333, 333, 584, 584, 584, 611,
	975, 722, 722, 722, 722, 667, 611, 778, 722, 278, 556, 722, 611, 833, 722, 778,
	667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 333, 278, 333, 584, 556,
	333, 556, 611, 556, 611, 556, 333, 611, 611, 278, 278, 556, 278, 889, 611, 611,
	611, 611, 389, 556, 333, 611, 556, 778, 556, 556, 500, 389, 280, 389, 584,
}
