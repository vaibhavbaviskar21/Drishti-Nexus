package pipeline

import (
	"bufio"
	"drishti-nexus/internal/parser"
	"errors"
	"io"
)

// LineReader reads physical lines of any length with exact byte offsets.
// Lines longer than parser.MaxLineBytes are returned truncated to
// MaxLineBytes+1 bytes (so the parser flags them) and the remainder is skipped
// — unlike bufio.Scanner, which aborts the whole file on one long line.
type LineReader struct {
	r      *bufio.Reader
	offset int64 // bytes consumed, including terminators
}

func NewLineReader(r io.Reader) *LineReader {
	return &LineReader{r: bufio.NewReaderSize(r, 256*1024)}
}

// Offset returns the number of bytes consumed so far.
func (lr *LineReader) Offset() int64 {
	return lr.offset
}

// Next returns the next line without "\n" (a trailing "\r" is left for the
// parser to strip). complete is false when the data ended without a newline —
// a writer may still be appending, so tail callers should re-read it later.
// err is io.EOF only when no bytes remain.
func (lr *LineReader) Next() (line string, complete bool, err error) {
	var buf []byte
	var consumed int64
	for {
		chunk, rerr := lr.r.ReadSlice('\n')
		consumed += int64(len(chunk))
		if room := parser.MaxLineBytes + 1 - len(buf); room > 0 {
			if len(chunk) > room {
				buf = append(buf, chunk[:room]...)
			} else {
				buf = append(buf, chunk...)
			}
		}
		switch {
		case rerr == nil:
			lr.offset += consumed
			return string(trimNewline(buf)), true, nil
		case errors.Is(rerr, bufio.ErrBufferFull):
			continue
		case errors.Is(rerr, io.EOF):
			lr.offset += consumed
			if consumed == 0 {
				return "", false, io.EOF
			}
			return string(buf), false, nil
		default:
			lr.offset += consumed
			return "", false, rerr
		}
	}
}

func trimNewline(b []byte) []byte {
	if n := len(b); n > 0 && b[n-1] == '\n' {
		return b[:n-1]
	}
	return b
}
