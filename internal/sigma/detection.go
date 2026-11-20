package sigma

import (
	"drishti-nexus/internal/models"
	"errors"
	"fmt"
	"net"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type matcher func(*models.LogEntry) bool

// Aggregation is the supported Sigma aggregation, "| count([field]) [by group] > N"
// (or >=) over the rule's timeframe. With a field it counts distinct values of it.
type Aggregation struct {
	Field   string
	By      string
	OrEqual bool
	N       int
	Window  time.Duration
}

var aggRe = regexp.MustCompile(`^count\(\s*([\w.]*)\s*\)\s*(?:by\s+([\w.]+)\s*)?(>=|>)\s*(\d+)$`)

// compileDetection compiles the named searches, the condition and its aggregation.
func compileDetection(det map[string]interface{}) (matcher, *Aggregation, error) {
	searches := map[string]matcher{}
	var conds []string
	timeframe := ""
	for name, body := range det {
		switch name {
		case "condition":
			switch c := body.(type) {
			case string:
				conds = []string{c}
			case []interface{}:
				for _, x := range c {
					s, ok := x.(string)
					if !ok {
						return nil, nil, errors.New("condition list must contain strings")
					}
					conds = append(conds, s)
				}
			default:
				return nil, nil, errors.New("condition must be a string or a list")
			}
		case "timeframe":
			timeframe = scalar(body)
		default:
			m, err := compileSearch(body)
			if err != nil {
				return nil, nil, fmt.Errorf("search %q: %w", name, err)
			}
			searches[name] = m
		}
	}
	if len(conds) == 0 {
		return nil, nil, errors.New("detection has no condition")
	}
	var agg *Aggregation
	if expr, aggText, ok := strings.Cut(conds[0], "|"); ok {
		if len(conds) > 1 {
			return nil, nil, errors.New("unsupported: aggregation in a condition list")
		}
		m := aggRe.FindStringSubmatch(strings.TrimSpace(aggText))
		if m == nil {
			return nil, nil, fmt.Errorf("unsupported: aggregation %q (only count() with > or >=)", strings.TrimSpace(aggText))
		}
		window, err := parseTimeframe(timeframe)
		if err != nil {
			return nil, nil, err
		}
		n, _ := strconv.Atoi(m[4])
		agg = &Aggregation{Field: m[1], By: m[2], OrEqual: m[3] == ">=", N: n, Window: window}
		conds[0] = expr
	} else if timeframe != "" {
		return nil, nil, errors.New("unsupported: timeframe without an aggregation")
	}
	var compiled []matcher
	for _, c := range conds {
		m, err := parseCondition(c, searches)
		if err != nil {
			return nil, nil, fmt.Errorf("condition %q: %w", c, err)
		}
		compiled = append(compiled, m)
	}
	return anyOf(compiled), agg, nil
}

// parseTimeframe reads a Sigma timeframe: a number and s, m, h or d.
func parseTimeframe(s string) (time.Duration, error) {
	if s == "" {
		return 0, errors.New("unsupported: aggregation without a timeframe")
	}
	d, err := time.ParseDuration(s)
	if n, ok := strings.CutSuffix(s, "d"); ok {
		days, cerr := strconv.Atoi(n)
		d, err = time.Duration(days)*24*time.Hour, cerr
	}
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("invalid timeframe %q", s)
	}
	return d, nil
}

// Exceeds reports whether count satisfies the aggregation's comparison.
func (a *Aggregation) Exceeds(count int) bool {
	if a.OrEqual {
		return count >= a.N
	}
	return count > a.N
}

func anyOf(ms []matcher) matcher {
	return func(e *models.LogEntry) bool {
		for _, m := range ms {
			if m(e) {
				return true
			}
		}
		return false
	}
}

func allOf(ms []matcher) matcher {
	return func(e *models.LogEntry) bool {
		for _, m := range ms {
			if !m(e) {
				return false
			}
		}
		return true
	}
}

// compileSearch: a map is an AND of field conditions; a list of maps is an OR of
// them; a list of plain values is a keyword search on the message.
func compileSearch(body interface{}) (matcher, error) {
	switch b := body.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(b))
		for k := range b {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var ms []matcher
		for _, k := range keys {
			m, err := compileField(k, b[k])
			if err != nil {
				return nil, err
			}
			ms = append(ms, m)
		}
		return allOf(ms), nil
	case []interface{}:
		if len(b) == 0 {
			return nil, errors.New("empty search")
		}
		if _, isMap := b[0].(map[string]interface{}); isMap {
			var ms []matcher
			for _, x := range b {
				m, err := compileSearch(x)
				if err != nil {
					return nil, err
				}
				ms = append(ms, m)
			}
			return anyOf(ms), nil
		}
		var vs []func(string) bool
		for _, x := range b {
			f, err := valueMatcher(scalar(x), []string{"contains"})
			if err != nil {
				return nil, err
			}
			vs = append(vs, f)
		}
		return func(e *models.LogEntry) bool {
			for _, f := range vs {
				if f(e.Message) {
					return true
				}
			}
			return false
		}, nil
	}
	return nil, fmt.Errorf("unsupported search of type %T", body)
}

func scalar(x interface{}) string {
	if s, ok := x.(string); ok {
		return s
	}
	return fmt.Sprint(x)
}

var knownModifiers = map[string]bool{"contains": true, "startswith": true, "endswith": true, "re": true, "cidr": true, "all": true, "exists": true}

func compileField(key string, val interface{}) (matcher, error) {
	parts := strings.Split(key, "|")
	field, mods := parts[0], parts[1:]
	all := false
	for _, m := range mods {
		if !knownModifiers[m] {
			return nil, fmt.Errorf("unsupported modifier %q", m)
		}
		all = all || m == "all"
	}

	if len(mods) == 1 && mods[0] == "exists" {
		want, ok := val.(bool)
		if !ok {
			return nil, errors.New("exists needs true or false")
		}
		return func(e *models.LogEntry) bool { _, ok := value(e, field); return ok == want }, nil
	}

	var raw []interface{}
	if list, ok := val.([]interface{}); ok {
		raw = list
	} else {
		raw = []interface{}{val}
	}
	nullOK := false
	var vs []func(string) bool
	for _, x := range raw {
		if x == nil {
			nullOK = true
			continue
		}
		f, err := valueMatcher(scalar(x), mods)
		if err != nil {
			return nil, err
		}
		vs = append(vs, f)
	}
	return func(e *models.LogEntry) bool {
		v, ok := value(e, field)
		if !ok || v == "" {
			return nullOK
		}
		if len(vs) == 0 {
			return false // only "null" was allowed
		}
		for _, f := range vs {
			if f(v) != all {
				return !all // any: first hit wins; all: first miss loses
			}
		}
		return all
	}, nil
}

// valueMatcher compiles one value with the field's modifiers. Comparison is
// case-insensitive (Sigma default) except for re.
func valueMatcher(v string, mods []string) (func(string) bool, error) {
	has := func(m string) bool {
		for _, x := range mods {
			if x == m {
				return true
			}
		}
		return false
	}
	switch {
	case has("re"):
		re, err := regexp.Compile(v)
		if err != nil {
			return nil, err
		}
		return re.MatchString, nil
	case has("cidr"):
		_, n, err := net.ParseCIDR(v)
		if err != nil {
			return nil, err
		}
		return func(s string) bool { ip := net.ParseIP(s); return ip != nil && n.Contains(ip) }, nil
	}
	// Fast path: no wildcard or escape means a plain case-insensitive string test;
	// a (?is)^.*x.*$ regex per value per entry was a third of scan time.
	if !strings.ContainsAny(v, `*?\`) {
		lv := strings.ToLower(v)
		before, after := has("contains") || has("endswith"), has("contains") || has("startswith")
		switch {
		case before && after:
			return func(s string) bool { return containsFold(s, lv) }, nil
		case after:
			return func(s string) bool { return len(s) >= len(lv) && strings.EqualFold(s[:len(lv)], lv) }, nil
		case before:
			return func(s string) bool { return len(s) >= len(lv) && strings.EqualFold(s[len(s)-len(lv):], lv) }, nil
		}
		return func(s string) bool { return strings.EqualFold(s, lv) }, nil
	}
	re, err := regexp.Compile(globRegex(v, has("contains") || has("endswith"), has("contains") || has("startswith")))
	if err != nil {
		return nil, err
	}
	return re.MatchString, nil
}

// containsFold reports whether s contains the lower-case needle, ignoring case.
func containsFold(s, needle string) bool {
	if isASCIILower(s) {
		return strings.Contains(s, needle)
	}
	return strings.Contains(strings.ToLower(s), needle)
}

func isASCIILower(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' || c >= 0x80 {
			return false
		}
	}
	return true
}

// globRegex turns a Sigma value into an anchored, case-insensitive regex: * and ?
// are wildcards, \* \? \\ are literal; any other backslash is literal (Windows paths).
func globRegex(v string, anyBefore, anyAfter bool) string {
	var b strings.Builder
	b.WriteString(`(?is)^`)
	if anyBefore {
		b.WriteString(`.*`)
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c == '\\' && i+1 < len(v) && strings.IndexByte(`*?\`, v[i+1]) >= 0:
			i++
			b.WriteString(regexp.QuoteMeta(string(v[i])))
		case c == '*':
			b.WriteString(`.*`)
		case c == '?':
			b.WriteString(`.`)
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	if anyAfter {
		b.WriteString(`.*`)
	}
	b.WriteString(`$`)
	return b.String()
}

// ---- condition ----

type condParser struct {
	toks     []string
	pos      int
	searches map[string]matcher
}

var tokenRe = regexp.MustCompile(`\(|\)|\|[^\n]*|[^\s()]+`)

func parseCondition(s string, searches map[string]matcher) (matcher, error) {
	p := &condParser{toks: tokenRe.FindAllString(s, -1), searches: searches}
	for _, t := range p.toks {
		if strings.HasPrefix(t, "|") {
			return nil, errors.New("unsupported: aggregation (| count, | near, ...)")
		}
	}
	m, err := p.expr()
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.toks) {
		return nil, fmt.Errorf("unexpected %q", p.toks[p.pos])
	}
	return m, nil
}

func (p *condParser) peek() string {
	if p.pos < len(p.toks) {
		return strings.ToLower(p.toks[p.pos])
	}
	return ""
}

func (p *condParser) next() string { t := p.toks[p.pos]; p.pos++; return t }

func (p *condParser) expr() (matcher, error) {
	var ms []matcher
	for {
		m, err := p.term()
		if err != nil {
			return nil, err
		}
		ms = append(ms, m)
		if p.peek() != "or" {
			return anyOf(ms), nil
		}
		p.next()
	}
}

func (p *condParser) term() (matcher, error) {
	var ms []matcher
	for {
		m, err := p.factor()
		if err != nil {
			return nil, err
		}
		ms = append(ms, m)
		if p.peek() != "and" {
			return allOf(ms), nil
		}
		p.next()
	}
}

func (p *condParser) factor() (matcher, error) {
	switch t := p.peek(); t {
	case "":
		return nil, errors.New("unexpected end of condition")
	case "not":
		p.next()
		m, err := p.factor()
		if err != nil {
			return nil, err
		}
		return func(e *models.LogEntry) bool { return !m(e) }, nil
	case "(":
		p.next()
		m, err := p.expr()
		if err != nil {
			return nil, err
		}
		if p.peek() != ")" {
			return nil, errors.New("missing )")
		}
		p.next()
		return m, nil
	case "1", "any", "all":
		p.next()
		if p.peek() != "of" {
			return nil, fmt.Errorf("expected 'of' after %q", t)
		}
		p.next()
		if p.peek() == "" {
			return nil, errors.New("expected a search pattern after 'of'")
		}
		ms, err := p.matching(p.next())
		if err != nil {
			return nil, err
		}
		if t == "all" {
			return allOf(ms), nil
		}
		return anyOf(ms), nil
	}
	name := p.next()
	m, ok := p.searches[name]
	if !ok {
		return nil, fmt.Errorf("unknown search %q", name)
	}
	return m, nil
}

// matching returns the searches a quantifier pattern names ("selection*", "them").
func (p *condParser) matching(pattern string) ([]matcher, error) {
	var names []string
	for n := range p.searches {
		if ok, _ := path.Match(pattern, n); pattern == "them" || ok {
			names = append(names, n)
		}
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("no search matches %q", pattern)
	}
	sort.Strings(names)
	ms := make([]matcher, len(names))
	for i, n := range names {
		ms[i] = p.searches[n]
	}
	return ms, nil
}
