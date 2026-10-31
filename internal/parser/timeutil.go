package parser

import (
	"fmt"
	"time"
)

// DST resolution flags recorded in LogEntry.Fields["dst"].
const (
	dstNonexistent = "nonexistent" // wall-clock time skipped by a spring-forward transition
	dstAmbiguous   = "ambiguous"   // wall-clock time repeated by a fall-back transition
)

// Context carries the per-source assumptions needed to turn zone-less and
// year-less timestamps into absolute UTC instants. One Context is owned by
// one ParserRegistry, i.e. one evidence file.
type Context struct {
	// Location is the zone assumed for timestamps that carry no offset
	// (BSD syslog, "2006-01-02 15:04:05", ...). Defaults to UTC.
	Location *time.Location
	// Reference is "now" from the log's point of view, used to infer the year
	// of RFC 3164 timestamps. Callers should pass the source file's mtime.
	Reference time.Time

	last time.Time // last resolved UTC timestamp, for DST disambiguation and inheritance
}

func (c *Context) loc() *time.Location {
	if c.Location == nil {
		return time.UTC
	}
	return c.Location
}

func (c *Context) ref() time.Time {
	if c.Reference.IsZero() {
		return time.Now()
	}
	return c.Reference
}

// resolveLocal converts a wall-clock time in loc to an absolute instant.
//
// Two DST edge cases are handled explicitly instead of silently:
//   - nonexistent (spring forward, e.g. 02:30 on the US transition day): Go
//     normalizes forward by the gap; we keep that and flag it.
//   - ambiguous (fall back, e.g. 01:30 occurs twice): we pick the earliest
//     candidate that does not move time backwards relative to prev — logs are
//     appended in order, so after the first 01:59 the second pass is the later one.
func resolveLocal(year int, month time.Month, day, hour, min, sec, nsec int, loc *time.Location, prev time.Time) (time.Time, string) {
	t := time.Date(year, month, day, hour, min, sec, nsec, loc)
	if t.Hour() != hour || t.Minute() != min {
		// Go does not guarantee which offset it applies inside a gap. Use the
		// offset in effect before the transition, i.e. shift forward by the gap
		// (02:30 on a US spring-forward day → 03:30 EDT), as java.time and Python do.
		_, before := t.Add(-6 * time.Hour).Zone()
		wall := time.Date(year, month, day, hour, min, sec, nsec, time.UTC)
		return wall.Add(-time.Duration(before) * time.Second).In(loc), dstNonexistent
	}

	// Look for a second instant with the same wall clock. Zone shifts are at most
	// a few hours; checking the zone offset just before and after covers all real zones.
	_, offNow := t.Zone()
	for _, probe := range []time.Duration{-3 * time.Hour, 3 * time.Hour} {
		_, offOther := t.Add(probe).Zone()
		if offOther == offNow {
			continue
		}
		alt := t.Add(time.Duration(offNow-offOther) * time.Second)
		ah, am, as := alt.In(loc).Clock()
		if ah != hour || am != min || as != sec || alt.Equal(t) {
			continue
		}
		early, late := t, alt
		if late.Before(early) {
			early, late = late, early
		}
		if !prev.IsZero() && early.Before(prev) && !late.Before(prev) {
			return late, dstAmbiguous
		}
		return early, dstAmbiguous
	}
	return t, ""
}

// inferYear picks the year for a year-less (RFC 3164) timestamp: the latest year
// that does not place the event more than 48h after the reference time. This
// handles logs that span New Year (Dec entries read in January belong to last
// year) and Feb 29 (walks back to the nearest leap year).
func inferYear(month time.Month, day int, ref time.Time) int {
	year := ref.Year()
	limit := ref.Add(48 * time.Hour)
	for i := 0; i < 8; i++ {
		y := year - i
		t := time.Date(y, month, day, 0, 0, 0, 0, time.UTC)
		if t.Month() != month { // Feb 29 in a non-leap year
			continue
		}
		if !t.After(limit) {
			return y
		}
	}
	return year
}

// formatOffset renders a zone offset as "+05:30".
func formatOffset(t time.Time) string {
	_, off := t.Zone()
	sign := '+'
	if off < 0 {
		sign = '-'
		off = -off
	}
	return fmt.Sprintf("%c%02d:%02d", sign, off/3600, (off%3600)/60)
}

// stampTime records provenance of a timestamp in fields and returns its UTC form.
// assumed reports that the zone came from Context.Location rather than the log.
func stampTime(fields map[string]interface{}, raw string, t time.Time, assumed bool) time.Time {
	fields["timestamp_raw"] = raw
	fields["tz_offset"] = formatOffset(t)
	if assumed {
		fields["tz_assumed"] = true
	}
	return t.UTC()
}

// parseWithZoneFallback parses s with each layout. Layouts carrying an offset are
// used as-is; zone-less layouts are interpreted in ctx's location with DST
// resolution. Returns ok=false if nothing matched.
func parseWithZoneFallback(ctx *Context, s string, fields map[string]interface{}) (time.Time, bool) {
	for _, layout := range zonedLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return stampTime(fields, s, t, false), true
		}
	}
	for _, layout := range zonelessLayouts {
		if t, err := time.ParseInLocation(layout, s, time.UTC); err == nil {
			local, flag := resolveLocal(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), ctx.loc(), ctx.last)
			if flag != "" {
				fields["dst"] = flag
			}
			return stampTime(fields, s, local, true), true
		}
	}
	return time.Time{}, false
}

var zonedLayouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02 15:04:05Z07:00",
	"2006-01-02 15:04:05.999999999Z07:00",
	time.RFC1123Z,
	time.RFC1123,
	"02/Jan/2006:15:04:05 -0700",
}

var zonelessLayouts = []string{
	"2006-01-02T15:04:05.999999999",
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05.999999999",
	"2006-01-02 15:04:05",
	"2006/01/02 15:04:05",
}
