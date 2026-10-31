package pipeline

import (
	"drishti-nexus/internal/parser"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestLineReader_OffsetsAreExactIncludingCRLF(t *testing.T) {
	input := "one\r\ntwo\nthree"
	lr := NewLineReader(strings.NewReader(input))
	want := []struct {
		line     string
		complete bool
		offset   int64
	}{
		{"one\r", true, 5},
		{"two", true, 9},
		{"three", false, 14},
	}
	for _, w := range want {
		line, complete, err := lr.Next()
		if err != nil {
			t.Fatal(err)
		}
		if line != w.line || complete != w.complete || lr.Offset() != w.offset {
			t.Errorf("got (%q,%v,%d), want (%q,%v,%d)", line, complete, lr.Offset(), w.line, w.complete, w.offset)
		}
	}
	if _, _, err := lr.Next(); !errors.Is(err, io.EOF) {
		t.Errorf("want EOF, got %v", err)
	}
}

// bufio.Scanner aborts the whole file on a line > its buffer; LineReader must
// truncate that line and keep going.
func TestLineReader_OversizedLineDoesNotAbortFile(t *testing.T) {
	huge := strings.Repeat("x", parser.MaxLineBytes*3)
	input := "before\n" + huge + "\nafter\n"
	lr := NewLineReader(strings.NewReader(input))

	var lines []string
	for {
		line, _, err := lr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, line)
	}
	if len(lines) != 3 || lines[0] != "before" || lines[2] != "after" {
		t.Fatalf("lines around the oversized one were lost: %d lines", len(lines))
	}
	if len(lines[1]) != parser.MaxLineBytes+1 {
		t.Errorf("oversized line should be cut to MaxLineBytes+1 so the parser flags it, got %d", len(lines[1]))
	}
	if lr.Offset() != int64(len(input)) {
		t.Errorf("offset %d, want %d (skipped bytes must still be counted)", lr.Offset(), len(input))
	}
}
