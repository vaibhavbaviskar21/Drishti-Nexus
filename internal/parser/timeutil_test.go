package parser

import (
	"testing"
	"time"
)

func mustLoad(t *testing.T, name string) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation(name)
	if err != nil {
		t.Skip("tzdata unavailable:", err)
	}
	return loc
}

// US spring-forward 2025-03-09: 02:00 EST jumps to 03:00 EDT, so 02:30 never exists.
func TestResolveLocal_NonexistentSpringForward(t *testing.T) {
	ny := mustLoad(t, "America/New_York")
	got, flag := resolveLocal(2025, time.March, 9, 2, 30, 0, 0, ny, time.Time{})
	if flag != dstNonexistent {
		t.Fatalf("flag = %q, want %q", flag, dstNonexistent)
	}
	// Go normalizes forward by the gap; we keep that and flag it.
	if want := time.Date(2025, 3, 9, 7, 30, 0, 0, time.UTC); !got.Equal(want) {
		t.Errorf("got %v, want %v", got.UTC(), want)
	}
}

// US fall-back 2025-11-02: 01:30 happens at 05:30Z (EDT) and again at 06:30Z (EST).
func TestResolveLocal_AmbiguousFallBack(t *testing.T) {
	ny := mustLoad(t, "America/New_York")
	first := time.Date(2025, 11, 2, 5, 30, 0, 0, time.UTC)
	second := time.Date(2025, 11, 2, 6, 30, 0, 0, time.UTC)

	got, flag := resolveLocal(2025, time.November, 2, 1, 30, 0, 0, ny, time.Time{})
	if flag != dstAmbiguous || !got.Equal(first) {
		t.Errorf("no context: got %v %q, want first occurrence %v ambiguous", got.UTC(), flag, first)
	}

	// After 01:59 EDT has been seen, a later 01:30 must be the second pass (EST),
	// otherwise time would run backwards and window rules would break.
	prev := time.Date(2025, 11, 2, 5, 59, 0, 0, time.UTC)
	got, flag = resolveLocal(2025, time.November, 2, 1, 30, 0, 0, ny, prev)
	if flag != dstAmbiguous || !got.Equal(second) {
		t.Errorf("after 01:59 EDT: got %v %q, want %v", got.UTC(), flag, second)
	}

	// Before the transition, the earlier instant stays the right answer.
	prev = time.Date(2025, 11, 2, 5, 0, 0, 0, time.UTC)
	got, _ = resolveLocal(2025, time.November, 2, 1, 30, 0, 0, ny, prev)
	if !got.Equal(first) {
		t.Errorf("before transition: got %v, want %v", got.UTC(), first)
	}
}

func TestResolveLocal_UnambiguousTimesAroundTransitions(t *testing.T) {
	ny := mustLoad(t, "America/New_York")
	cases := []struct {
		day, hour int
		month     time.Month
		want      time.Time
	}{
		{9, 1, time.March, time.Date(2025, 3, 9, 6, 0, 0, 0, time.UTC)},     // 01:00 EST, just before the gap
		{9, 3, time.March, time.Date(2025, 3, 9, 7, 0, 0, 0, time.UTC)},     // 03:00 EDT, just after
		{2, 0, time.November, time.Date(2025, 11, 2, 4, 0, 0, 0, time.UTC)}, // 00:00 EDT, before the overlap
		{2, 2, time.November, time.Date(2025, 11, 2, 7, 0, 0, 0, time.UTC)}, // 02:00 EST, after
	}
	for _, c := range cases {
		got, flag := resolveLocal(2025, c.month, c.day, c.hour, 0, 0, 0, ny, time.Time{})
		if flag != "" || !got.Equal(c.want) {
			t.Errorf("%s %d %02d:00 → %v %q, want %v unflagged", c.month, c.day, c.hour, got.UTC(), flag, c.want)
		}
	}
}

// Southern hemisphere and half-hour DST shifts are handled by the same probe.
func TestResolveLocal_OtherZones(t *testing.T) {
	syd := mustLoad(t, "Australia/Sydney") // 2025-04-06 03:00 AEDT → 02:00 AEST
	if _, flag := resolveLocal(2025, time.April, 6, 2, 30, 0, 0, syd, time.Time{}); flag != dstAmbiguous {
		t.Errorf("Sydney fall-back: flag %q, want ambiguous", flag)
	}
	lh := mustLoad(t, "Australia/Lord_Howe") // 30-minute DST shift; 2025-10-05 02:00 → 02:30
	if _, flag := resolveLocal(2025, time.October, 5, 2, 15, 0, 0, lh, time.Time{}); flag != dstNonexistent {
		t.Errorf("Lord Howe spring-forward: flag %q, want nonexistent", flag)
	}
	ist := mustLoad(t, "Asia/Kolkata") // no DST
	if _, flag := resolveLocal(2025, time.March, 9, 2, 30, 0, 0, ist, time.Time{}); flag != "" {
		t.Errorf("IST has no DST, got flag %q", flag)
	}
}

func TestRegistry_DSTFlagMarksEntryPartial(t *testing.T) {
	ny := mustLoad(t, "America/New_York")
	reg := NewParserRegistryWithOptions(Options{Location: ny, Reference: time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC)})
	entries := feed(t, reg,
		"Nov  2 01:59:00 h app: before fall-back (EDT)",
		"Nov  2 01:30:00 h app: second pass (EST)",
	)
	if entries[1].Fields["dst"] != dstAmbiguous || entries[1].ParseQuality != "Partial" {
		t.Errorf("ambiguous time not flagged: %v %s", entries[1].Fields, entries[1].ParseQuality)
	}
	if !entries[1].Timestamp.After(entries[0].Timestamp) {
		t.Errorf("second pass resolved backwards: %v then %v", entries[0].Timestamp, entries[1].Timestamp)
	}
}

func TestInferYear(t *testing.T) {
	ref := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)
	if y := inferYear(time.December, 31, ref); y != 2025 {
		t.Errorf("Dec 31 with Jan 2026 reference → %d, want 2025", y)
	}
	if y := inferYear(time.January, 11, ref); y != 2026 {
		t.Errorf("Jan 11 (within 48h) → %d, want 2026", y)
	}
	if y := inferYear(time.January, 13, ref); y != 2025 {
		t.Errorf("Jan 13 (beyond 48h) → %d, want 2025", y)
	}
}

func TestFormatOffset(t *testing.T) {
	for _, c := range []struct {
		off  int
		want string
	}{{0, "+00:00"}, {19800, "+05:30"}, {-28800, "-08:00"}, {-12600, "-03:30"}} {
		tm := time.Date(2025, 1, 1, 0, 0, 0, 0, time.FixedZone("", c.off))
		if got := formatOffset(tm); got != c.want {
			t.Errorf("offset %d → %s, want %s", c.off, got, c.want)
		}
	}
}
