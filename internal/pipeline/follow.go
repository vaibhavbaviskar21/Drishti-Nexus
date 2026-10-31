package pipeline

import (
	"crypto/sha256"
	"drishti-nexus/internal/audit"
	"drishti-nexus/internal/parser"
	"drishti-nexus/internal/storage"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

// FollowOptions configure a live (tail) session.
type FollowOptions struct {
	Follow          bool          // keep polling for appended data after EOF
	Poll            time.Duration // poll interval when idle (default 1s)
	CheckpointEvery int           // checkpoint after this many lines while catching up (default 50000)
	Stop            <-chan struct{}

	// OnResume is told where processing restarts (offset 0 for a fresh start).
	OnResume func(offset int64, lines int)
}

// headBytes is how much of the file start is hashed to recognise the same file on resume.
const headBytes = 4096

// afterCheckpointHook lets tests simulate a crash right after a checkpoint.
var afterCheckpointHook func()

// Follow processes one growing file, optionally forever, checkpointing to the
// store when it supports it so an interrupted session resumes where it stopped.
//
// Checkpoints are only taken at entry boundaries: the stored offset points at
// the first line of the entry the parser is still assembling, and the engine
// snapshot reflects exactly the entries before it. On resume those lines are
// re-read, so nothing is lost or double-counted.
func Follow(path string, opts Options, fo FollowOptions) (*Result, error) {
	if fo.Poll <= 0 {
		fo.Poll = time.Second
	}
	if fo.CheckpointEvery <= 0 {
		fo.CheckpointEvery = 50000
	}

	res, err := Prepare([]string{path}, &opts)
	if err != nil {
		return nil, err
	}
	ev := res.Session.Evidence[0]
	start := time.Now()
	defer res.finishStats(start)

	f, err := audit.OpenEvidence(path)
	if err != nil {
		return res, err
	}
	defer f.Close()

	cpStore, _ := opts.Store.(storage.Checkpointer)
	reg := parser.NewParserRegistryWithOptions(parser.Options{
		SourceLabel: ev.Label,
		Location:    opts.Location,
		Reference:   ev.ModTime,
	})

	var base int64
	if cpStore != nil {
		base, err = res.resume(cpStore, f, ev, reg)
		if err != nil {
			return res, err
		}
	}
	if fo.OnResume != nil {
		fo.OnResume(base, reg.LinesSeen())
	}

	lr := NewLineReader(f)
	var partial string
	committed := func() int64 { return base + lr.Offset() - int64(len(partial)) }

	// Byte offset where the parser's pending entry starts.
	pendingOffset, pendingLine := base, reg.LinesSeen()
	sinceCheckpoint := 0

	checkpoint := func(offset int64, lines int) error {
		if cpStore == nil {
			return nil
		}
		state, err := res.Engine.Snapshot()
		if err != nil {
			return err
		}
		head, err := headHash(path, offset)
		if err != nil {
			return err
		}
		sinceCheckpoint = 0
		if err := cpStore.SaveCheckpoint(&storage.Checkpoint{
			SourcePath: ev.AbsPath, Offset: offset, Lines: lines,
			HeadSHA256: head, EngineState: state, UpdatedAt: time.Now(),
		}); err != nil {
			return err
		}
		if afterCheckpointHook != nil {
			afterCheckpointHook()
		}
		return nil
	}
	flushAndCheckpoint := func() error {
		if entry, _ := reg.Flush(); entry != nil {
			res.Handle(entry, &opts)
		}
		pendingOffset, pendingLine = committed(), reg.LinesSeen()
		return checkpoint(pendingOffset, pendingLine)
	}

	stopped := func() bool {
		select {
		case <-fo.Stop:
			return true
		default:
			return false
		}
	}

	for {
		before := committed()
		line, complete, rerr := lr.Next()
		if errors.Is(rerr, io.EOF) {
			if !fo.Follow || stopped() {
				break
			}
			if err := flushAndCheckpoint(); err != nil {
				return res, err
			}
			if info, err := os.Stat(path); err == nil && info.Size() < committed() {
				return res, fmt.Errorf("%s shrank from %d to %d bytes (truncated or rotated); start a new session", path, committed(), info.Size())
			}
			select {
			case <-fo.Stop:
			case <-time.After(fo.Poll):
			}
			if stopped() {
				break
			}
			continue
		}
		if rerr != nil {
			return res, fmt.Errorf("read %s: %w", path, rerr)
		}
		if !complete && fo.Follow {
			partial += line // writer mid-line; wait for the rest
			continue
		}
		// committed() excludes buffered partial bytes, so before is where this
		// (possibly re-joined) line starts.
		line, partial = partial+line, ""

		res.Stats.Lines++
		entry, _ := reg.Parse(line)
		if entry != nil {
			res.Handle(entry, &opts)
		}
		if reg.PendingStartLine() == reg.LinesSeen() {
			// This line started a new pending entry: everything before it is emitted.
			pendingOffset, pendingLine = before, reg.LinesSeen()-1
		}

		sinceCheckpoint++
		if sinceCheckpoint >= fo.CheckpointEvery {
			if err := checkpoint(pendingOffset, pendingLine); err != nil {
				return res, err
			}
		}
		if stopped() {
			break
		}
	}

	if err := flushAndCheckpoint(); err != nil {
		return res, err
	}

	// A growing file cannot be re-hashed as a whole; prove instead that the bytes
	// hashed at session start are unchanged (nothing rewritten, only appended).
	ev.BytesAnalyzed = committed()
	prefix, err := prefixHash(path, ev.SizeBytes)
	if err == nil {
		ev.SHA256After = prefix
		same := prefix == ev.SHA256Before
		ev.Unchanged = &same
	}
	return res, nil
}

// resume restores parser position and engine state from a checkpoint.
func (r *Result) resume(cp storage.Checkpointer, f *os.File, ev *audit.EvidenceFile, reg *parser.ParserRegistry) (int64, error) {
	saved, err := cp.LoadCheckpoint(ev.AbsPath)
	if err != nil {
		return 0, fmt.Errorf("load checkpoint: %w", err)
	}
	if saved == nil {
		if logs, alerts := r.Store.Count(); logs > 0 || alerts > 0 {
			return 0, fmt.Errorf("database already holds data but no checkpoint for %s; use a separate -db per evidence file", ev.Path)
		}
		return 0, nil
	}
	if saved.Offset > ev.SizeBytes {
		return 0, fmt.Errorf("checkpoint offset %d is beyond the end of %s (%d bytes): file was truncated or replaced; use a new -db", saved.Offset, ev.Path, ev.SizeBytes)
	}
	head, err := headHash(ev.Path, saved.Offset)
	if err != nil {
		return 0, err
	}
	if head != saved.HeadSHA256 {
		return 0, fmt.Errorf("%s no longer matches the checkpointed file (start of file changed); use a new -db", ev.Path)
	}
	if err := r.Engine.Restore(saved.EngineState); err != nil {
		return 0, err
	}
	if _, err := f.Seek(saved.Offset, io.SeekStart); err != nil {
		return 0, err
	}
	reg.SetLineOffset(saved.Lines)
	r.Session.Config.Warnings = append(r.Session.Config.Warnings,
		fmt.Sprintf("resumed from checkpoint at byte %d (line %d) saved %s", saved.Offset, saved.Lines, saved.UpdatedAt.UTC().Format(time.RFC3339)))
	return saved.Offset, nil
}

// headHash hashes the first min(headBytes, limit) bytes of path.
func headHash(path string, limit int64) (string, error) {
	n := int64(headBytes)
	if limit < n {
		n = limit
	}
	return prefixHash(path, n)
}

// prefixHash returns the SHA-256 of the first n bytes of path.
func prefixHash(path string, n int64) (string, error) {
	f, err := audit.OpenEvidence(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.CopyN(h, f, n); err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
