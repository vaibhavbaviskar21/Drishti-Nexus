package ai

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Claim kinds the grounding check extracts. It checks concrete entities only:
// a paraphrased or speculative statement with no identifier, number or time in
// it ("the attacker stole data") is not caught. See docs/AI_SUMMARY.md.
const (
	kindAlert     = "alert"
	kindIncident  = "incident"
	kindTechnique = "technique"
	kindTimestamp = "timestamp"
	kindDate      = "date"
	kindTime      = "time"
	kindIP        = "ip"
	kindName      = "name" // host, user, or other identifier-like token
	kindNumber    = "number"
)

type claim struct{ kind, value string }

var (
	reAlert     = regexp.MustCompile(`\bALERT-\d+\b`)
	reIncident  = regexp.MustCompile(`\bINC-\d+\b`)
	reTechnique = regexp.MustCompile(`\bT\d{4}(?:\.\d{3})?\b`)
	reTimestamp = regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}[T ]\d{1,2}:\d{2}(?::\d{2})?(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?`)
	reDate      = regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}\b`)
	reClock     = regexp.MustCompile(`\b\d{1,2}:\d{2}(?::\d{2})?\b`)
	reIPv4      = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)
	reIPv6      = regexp.MustCompile(`(?i)[0-9a-f]*:[0-9a-f:.]*:[0-9a-f.]*`)
	// "user deploy", "host db01", `"deploy"`: names that carry no digit.
	reNamed   = regexp.MustCompile("(?i)\\b(?:user|username|account|host|hostname|server|machine)\\s+[\"`]?([A-Za-z0-9_.$@-]+)")
	reQuoted  = regexp.MustCompile("[\"`]([A-Za-z0-9_.$@-]{1,64})[\"`]")
	reToken   = regexp.MustCompile(`[A-Za-z0-9_$@-]+(?:\.[A-Za-z0-9_$@-]+)*`)
	reInt     = regexp.MustCompile(`\b\d+\b`)
	reLetter  = regexp.MustCompile(`[A-Za-z]`)
	reDigit   = regexp.MustCompile(`\d`)
	reDigits  = regexp.MustCompile(`\d+`)
	reSplit   = regexp.MustCompile(`[^A-Za-z0-9_.$@-]+`)
	reSeconds = regexp.MustCompile(`T\d{1,2}:\d{2}:\d{2}`)
)

// Words that follow "user"/"host" in ordinary prose and are not names.
var stopwords = map[string]bool{
	"a": true, "an": true, "the": true, "was": true, "is": true, "were": true, "and": true, "or": true,
	"account": true, "accounts": true, "name": true, "that": true, "which": true, "who": true, "with": true,
	"from": true, "on": true, "in": true, "at": true, "to": true, "of": true, "for": true, "by": true,
	"has": true, "had": true, "logged": true, "login": true, "logins": true, "session": true, "then": true,
}

// extract pulls every concrete claim out of text. Each matcher blanks what it
// consumed so, e.g., the digits of an IP are not re-read as counts.
func extract(text string) []claim {
	buf := []byte(text)
	var out []claim
	take := func(re *regexp.Regexp, kind string, norm func(string) (string, bool)) {
		for _, m := range re.FindAllSubmatchIndex(buf, -1) {
			s, e := m[0], m[1]
			if len(m) > 2 && m[2] >= 0 {
				s, e = m[2], m[3]
			}
			v, ok := norm(string(buf[s:e]))
			if !ok {
				continue
			}
			out = append(out, claim{kind, v})
			for i := m[0]; i < m[1]; i++ {
				buf[i] = ' '
			}
		}
	}
	same := func(s string) (string, bool) { return s, true }

	take(reAlert, kindAlert, same)
	take(reIncident, kindIncident, same)
	take(reTechnique, kindTechnique, same)
	take(reTimestamp, kindTimestamp, normTimestamp)
	take(reDate, kindDate, same)
	take(reClock, kindTime, normClock)
	take(reIPv4, kindIP, func(s string) (string, bool) {
		if ip := net.ParseIP(s); ip != nil {
			return ip.String(), true
		}
		return s, true // "999.1.1.1" is still an address claim, and an unsupported one
	})
	take(reIPv6, kindIP, func(s string) (string, bool) {
		ip := net.ParseIP(strings.TrimRight(s, "."))
		if ip == nil {
			return "", false
		}
		return ip.String(), true
	})
	take(reNamed, kindName, func(s string) (string, bool) {
		v := normName(s)
		return v, v != "" && !stopwords[v]
	})
	take(reQuoted, kindName, func(s string) (string, bool) { v := normName(s); return v, v != "" })
	take(reToken, kindName, func(s string) (string, bool) {
		// Only tokens that look like identifiers (web01, 7m26s, mail.example.com);
		// plain words are prose.
		v := normName(s)
		hasDot := strings.Contains(v, ".") && reLetter.MatchString(v)
		return v, (reLetter.MatchString(v) && reDigit.MatchString(v)) || hasDot && len(v) > 4
	})
	take(reInt, kindNumber, func(s string) (string, bool) {
		n, err := strconv.Atoi(s)
		return strconv.Itoa(n), err == nil
	})
	return out
}

func normName(s string) string { return strings.ToLower(strings.Trim(s, ".-")) }

func normTimestamp(s string) (string, bool) {
	s = strings.Replace(s, " ", "T", 1)
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05Z0700", "2006-01-02T15:04:05", "2006-01-02T15:04Z07:00", "2006-01-02T15:04"} {
		if t, err := time.Parse(layout, s); err == nil {
			// Keep the precision the text claimed: minute-only claims are compared by minute.
			if reSeconds.MatchString(s) {
				return t.UTC().Format(time.RFC3339), true
			}
			return t.UTC().Format("2006-01-02T15:04"), true
		}
	}
	return s, true // unparseable: matched only if the facts contain it verbatim
}

func normClock(s string) (string, bool) {
	parts := strings.Split(s, ":")
	h, _ := strconv.Atoi(parts[0])
	m, _ := strconv.Atoi(parts[1])
	if h > 23 || m > 59 {
		return s, true
	}
	if len(parts) == 3 {
		sec, _ := strconv.Atoi(parts[2])
		return fmt.Sprintf("%02d:%02d:%02d", h, m, sec), true
	}
	return fmt.Sprintf("%02d:%02d", h, m), true
}

// grounding is what the facts support, built once per incident.
type grounding struct {
	claims      map[claim]bool
	vocab       map[string]bool
	numbers     map[string]bool
	first, last time.Time
}

func newGrounding(f Facts) *grounding {
	corpus := factsJSON(f)
	g := &grounding{claims: map[claim]bool{}, vocab: map[string]bool{}, numbers: map[string]bool{}, first: f.FirstSeen, last: f.LastSeen}
	for _, c := range extract(corpus) {
		g.claims[c] = true
		if c.kind == kindNumber {
			g.numbers[c.value] = true
		}
		if c.kind == kindName { // "7m26s" supports "7 minutes and 26 seconds"
			for _, d := range reDigits.FindAllString(c.value, -1) {
				n, _ := strconv.Atoi(d)
				g.numbers[strconv.Itoa(n)] = true
			}
		}
	}
	for _, n := range []int{len(f.Alerts), len(f.Evidence) + f.EvidenceOmitted} {
		g.numbers[strconv.Itoa(n)] = true
	}
	for _, tok := range reSplit.Split(corpus, -1) {
		tok = normName(tok)
		g.vocab[tok] = true
		for _, part := range strings.FieldsFunc(tok, func(r rune) bool { return r == '.' || r == '@' }) {
			g.vocab[part] = true
		}
	}
	return g
}

func (g *grounding) supports(c claim) bool {
	if g.claims[c] {
		return true
	}
	switch c.kind {
	case kindName:
		return g.vocab[c.value]
	case kindNumber:
		return g.numbers[c.value]
	case kindTimestamp:
		return g.inWindow(c.value)
	case kindDate:
		d, err := time.Parse("2006-01-02", c.value)
		return err == nil && !d.Before(dayOf(g.first)) && !d.After(dayOf(g.last))
	case kindTime:
		// A bare time of day is supported if it falls in the window on any day the window covers.
		for d := dayOf(g.first); !d.After(g.last) && d.Sub(dayOf(g.first)) <= 366*24*time.Hour; d = d.AddDate(0, 0, 1) {
			if g.inWindow(d.Format("2006-01-02T") + c.value) {
				return true
			}
		}
	}
	return false
}

// inWindow compares at the precision the claim was written in (minute or second).
func (g *grounding) inWindow(ts string) bool {
	if t, err := time.Parse("2006-01-02T15:04", ts); err == nil {
		return !t.Before(g.first.Truncate(time.Minute)) && !t.After(g.last.Truncate(time.Minute))
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, ts); err == nil {
			return !t.Before(g.first) && !t.After(g.last)
		}
	}
	return false
}

func dayOf(t time.Time) time.Time { return t.UTC().Truncate(24 * time.Hour) }

// Check returns every concrete claim in summary that the incident facts do not
// support (empty means verified). It is deterministic and independent of the model.
func Check(summary string, f Facts) []string {
	if strings.TrimSpace(summary) == "" {
		return []string{"empty summary"}
	}
	g := newGrounding(f)
	var unsupported []string
	seen := map[claim]bool{}
	for _, c := range extract(summary) {
		if seen[c] || g.supports(c) {
			continue
		}
		seen[c] = true
		unsupported = append(unsupported, c.kind+" "+c.value)
	}
	return unsupported
}
