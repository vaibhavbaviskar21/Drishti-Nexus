package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// OpenEvidence is the only sanctioned way to open a source log. It opens the file
// strictly read-only (O_RDONLY); no code path in Drishti Nexus opens evidence for
// writing. TestEvidenceOpenedReadOnly enforces this across the codebase.
func OpenEvidence(path string) (*os.File, error) {
	f, err := os.OpenFile(filepath.Clean(path), os.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("open evidence %s: %w", path, err)
	}
	return f, nil
}

// HashFile returns the SHA-256 (hex) and size of a file, read via OpenEvidence.
func HashFile(path string) (string, int64, error) {
	f, err := OpenEvidence(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()

	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", n, fmt.Errorf("hash %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// EvidenceFile describes one source file and proves it was not modified.
type EvidenceFile struct {
	Path         string    `json:"path"`
	Label        string    `json:"label"` // prefix of entry IDs ("<label>:<line>"), unique within a session
	AbsPath      string    `json:"abs_path"`
	SizeBytes    int64     `json:"size_bytes"`
	ModTime      time.Time `json:"mod_time"`
	SHA256Before string    `json:"sha256"`
	// Set when the session finishes: the file is re-hashed after analysis.
	SHA256After string `json:"sha256_after,omitempty"`
	Unchanged   *bool  `json:"unchanged,omitempty"`
	// Only for growing files (tail): bytes analysed, and whether the analysed
	// prefix is byte-identical to what was hashed at start.
	BytesAnalyzed int64 `json:"bytes_analyzed,omitempty"`
}

// NewEvidenceFile stats and hashes path.
func NewEvidenceFile(path string) (*EvidenceFile, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat evidence %s: %w", path, err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("evidence %s is a directory", path)
	}
	sum, size, err := HashFile(path)
	if err != nil {
		return nil, err
	}
	return &EvidenceFile{
		Path:         path,
		AbsPath:      abs,
		SizeBytes:    size,
		ModTime:      info.ModTime().UTC(),
		SHA256Before: sum,
	}, nil
}

// Reverify re-hashes the file and records whether it is unchanged.
func (e *EvidenceFile) Reverify() error {
	sum, _, err := HashFile(e.Path)
	if err != nil {
		return err
	}
	e.SHA256After = sum
	same := sum == e.SHA256Before
	e.Unchanged = &same
	return nil
}

// CheckOutputPath refuses to write an output over any evidence file.
func CheckOutputPath(output string, evidence []*EvidenceFile) error {
	outAbs, err := filepath.Abs(output)
	if err != nil {
		return err
	}
	outInfo, statErr := os.Stat(output)
	for _, ev := range evidence {
		if outAbs == ev.AbsPath {
			return fmt.Errorf("refusing to write output %s: it is an evidence file", output)
		}
		if statErr == nil {
			if evInfo, err := os.Stat(ev.Path); err == nil && os.SameFile(outInfo, evInfo) {
				return fmt.Errorf("refusing to write output %s: it is the same file as evidence %s", output, ev.Path)
			}
		}
	}
	return nil
}
