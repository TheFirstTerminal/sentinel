// Package crs runs the OWASP Core Rule Set (CRS) inside Sentinel.
//
// CRS is written in ModSecurity's rule language (SecLang). This package
// implements the part of SecLang that the CRS request rules use: SecRule,
// SecAction and SecMarker; chains; the TX collection with setvar and macro
// expansion; skipAfter; capture; paranoia levels; and the operators,
// variables and transformations listed in operators.go, variables.go and
// transforms.go. A rule that needs anything else is skipped and counted in
// Stats, never half-applied, so an unsupported feature can cause a missed
// detection but never a false alarm.
//
// Only phases 1 and 2 (the request) are run. Response rules (95x) need the
// app's reply and are out of scope.
package crs

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Rule is one SecRule, SecAction or SecMarker. Chained rules hang off Chain.
type Rule struct {
	ID       int
	Phase    int
	Msg      string
	Severity string
	Tags     []string
	Paranoia int // from the paranoia-level/N tag; 0 = not a detection rule

	vars       []varSpec
	varsKey    string // the variable list as written, for caching its values
	varsStatic bool   // no TX or MATCHED_* variables: values are fixed per request
	op         *operator
	transforms []transform
	tkey       string // the transform chain's names, for caching results
	multiMatch bool
	capture    bool
	setvars    []string
	ctls       []string
	skipAfter  string
	chain      *Rule
	marker     string // SecMarker name
	action     bool   // SecAction: matches without looking at anything

	File string
	Line int
}

// Set is a loaded rule set.
type Set struct {
	phases   [2][]*Rule // phase 1 and phase 2, in file order
	Paranoia int
	Stats    Stats
}

// Stats says how much of CRS is active.
type Stats struct {
	Files       int
	Rules       int            // SecRule/SecAction loaded (chains count once)
	Skipped     int            // rules not loaded because they need unsupported features
	SkipReasons map[string]int // why, e.g. "operator @ipMatchFromFile"
	Detection   int            // loaded rules that add to the anomaly score
	Excluded    int            // rules switched off by Exclude
}

// Exclude removes rules by ID or ID range ("920220", "942100-942199"), the
// way SecRuleRemoveById does. Use it for rules that misfire on your app.
func (s *Set) Exclude(specs []string) error {
	var ranges [][2]int
	for _, sp := range specs {
		lo, hi, isRange := strings.Cut(strings.TrimSpace(sp), "-")
		a, err1 := strconv.Atoi(lo)
		b := a
		var err2 error
		if isRange {
			b, err2 = strconv.Atoi(hi)
		}
		if err1 != nil || err2 != nil || a > b {
			return fmt.Errorf("bad rule ID or range %q", sp)
		}
		ranges = append(ranges, [2]int{a, b})
	}
	for p := range s.phases {
		kept := s.phases[p][:0]
		for _, r := range s.phases[p] {
			drop := false
			for _, rg := range ranges {
				if r.marker == "" && r.ID >= rg[0] && r.ID <= rg[1] {
					drop = true
				}
			}
			if drop {
				s.Stats.Excluded++
				s.Stats.Rules--
				if r.Paranoia > 0 {
					s.Stats.Detection--
				}
				continue
			}
			kept = append(kept, r)
		}
		s.phases[p] = kept
	}
	return nil
}

// Load reads the CRS request rules (REQUEST-9*.conf) from dir, plus any
// crs-setup.conf in dir or its parent. paranoia is 1-4.
func Load(dir string, paranoia int) (*Set, error) {
	if paranoia < 1 || paranoia > 4 {
		return nil, fmt.Errorf("paranoia level must be 1-4")
	}
	files, err := filepath.Glob(filepath.Join(dir, "REQUEST-9*.conf"))
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no REQUEST-9*.conf files in %s (point it at the CRS rules/ folder)", dir)
	}
	sort.Strings(files)
	s := &Set{Paranoia: paranoia, Stats: Stats{SkipReasons: map[string]int{}}}
	for _, f := range files {
		base := filepath.Base(f)
		// 949 turns the score into a block; Sentinel makes that decision itself.
		if strings.HasPrefix(base, "REQUEST-949") {
			continue
		}
		if err := s.parseFile(f, dir); err != nil {
			return nil, err
		}
		s.Stats.Files++
	}
	return s, nil
}

func (s *Set) parseFile(path, dir string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	type parsed struct {
		r   *Rule
		err error
	}
	var ps []parsed
	for _, st := range statements(string(data)) {
		r, err := parseStatement(st.text, dir)
		if r == nil && err == nil {
			continue // a setup directive we ignore
		}
		if r != nil {
			r.File, r.Line = filepath.Base(path), st.line
		}
		ps = append(ps, parsed{r, err})
	}
	for i := 0; i < len(ps); {
		// A group is a rule plus the rules chained to it.
		j := i
		for ps[j].r != nil && ps[j].r.chain == chainPending && j+1 < len(ps) {
			j++
		}
		group := ps[i : j+1]
		i = j + 1
		head := group[0].r
		if head != nil && head.marker != "" {
			s.phases[0] = append(s.phases[0], head)
			s.phases[1] = append(s.phases[1], head)
			continue
		}
		var gerr error
		for _, g := range group {
			if g.err != nil {
				gerr = g.err
				break
			}
		}
		if gerr == nil && group[len(group)-1].r.chain == chainPending {
			gerr = fmt.Errorf("chain without end")
		}
		if gerr != nil {
			s.skip(head, gerr.Error())
			continue
		}
		for k := 0; k < len(group)-1; k++ {
			group[k].r.chain = group[k+1].r
		}
		s.add(head)
	}
	return nil
}

// chainPending marks a rule whose next statement is its chained rule.
var chainPending = &Rule{}

func (s *Set) add(r *Rule) {
	if r.Phase == 0 {
		r.Phase = 2 // ModSecurity's default
	}
	if r.Phase != 1 && r.Phase != 2 {
		return // response phases are not run
	}
	s.phases[r.Phase-1] = append(s.phases[r.Phase-1], r)
	s.Stats.Rules++
	if r.Paranoia > 0 {
		s.Stats.Detection++
	}
}

func (s *Set) skip(r *Rule, why string) {
	if r != nil && r.Phase > 2 {
		return
	}
	s.Stats.Skipped++
	s.Stats.SkipReasons[why]++
}

type statement struct {
	text string
	line int
}

// statements joins backslash-continued lines and drops comments.
func statements(src string) []statement {
	var out []statement
	var cur strings.Builder
	start := 0
	for i, line := range strings.Split(src, "\n") {
		t := strings.TrimRight(line, " \t\r")
		if cur.Len() == 0 {
			lt := strings.TrimSpace(t)
			if lt == "" || strings.HasPrefix(lt, "#") {
				continue
			}
			start = i + 1
		}
		if strings.HasSuffix(t, "\\") {
			cur.WriteString(strings.TrimSuffix(t, "\\"))
			cur.WriteByte(' ')
			continue
		}
		cur.WriteString(t)
		out = append(out, statement{strings.TrimSpace(cur.String()), start})
		cur.Reset()
	}
	return out
}

// fields splits a directive into words, honouring double quotes.
func fields(s string) ([]string, error) {
	var out []string
	for i := 0; i < len(s); {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		if i >= len(s) {
			break
		}
		if s[i] == '"' {
			var b strings.Builder
			i++
			closed := false
			for i < len(s) {
				if s[i] == '\\' && i+1 < len(s) && s[i+1] == '"' {
					b.WriteByte('"')
					i += 2
					continue
				}
				if s[i] == '"' {
					closed = true
					i++
					break
				}
				b.WriteByte(s[i])
				i++
			}
			if !closed {
				return nil, fmt.Errorf("unclosed quote")
			}
			out = append(out, b.String())
			continue
		}
		j := i
		for j < len(s) && s[j] != ' ' && s[j] != '\t' {
			j++
		}
		out = append(out, s[i:j])
		i = j
	}
	return out, nil
}

func parseStatement(text, dir string) (*Rule, error) {
	f, err := fields(text)
	if err != nil || len(f) == 0 {
		return nil, err
	}
	switch f[0] {
	case "SecMarker":
		if len(f) != 2 {
			return nil, fmt.Errorf("bad SecMarker")
		}
		return &Rule{marker: strings.Trim(f[1], "'\"")}, nil
	case "SecAction":
		if len(f) != 2 {
			return nil, fmt.Errorf("bad SecAction")
		}
		r := &Rule{action: true}
		return r, r.parseActions(f[1])
	case "SecRule":
		if len(f) != 4 && len(f) != 3 {
			return nil, fmt.Errorf("bad SecRule")
		}
		r := &Rule{}
		var actErr error
		if len(f) == 4 {
			actErr = r.parseActions(f[3])
		}
		vars, err := parseVars(f[1])
		if err != nil {
			return r, err
		}
		r.vars = vars
		r.varsKey = f[1]
		r.varsStatic = true
		for _, v := range vars {
			if v.name == "TX" || strings.HasPrefix(v.name, "MATCHED_") {
				r.varsStatic = false
			}
		}
		op, err := parseOperator(f[2], dir)
		if err != nil {
			return r, err
		}
		r.op = op
		return r, actErr
	}
	return nil, nil // SecComponentSignature and other setup directives
}

// splitActions splits on commas outside single quotes.
func splitActions(s string) []string {
	var out []string
	var b strings.Builder
	inQ := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s) && s[i+1] == '\'':
			b.WriteByte('\'')
			i++
		case c == '\'':
			inQ = !inQ
			b.WriteByte(c)
		case c == ',' && !inQ:
			out = append(out, strings.TrimSpace(b.String()))
			b.Reset()
		default:
			b.WriteByte(c)
		}
	}
	if t := strings.TrimSpace(b.String()); t != "" {
		out = append(out, t)
	}
	return out
}

var plTag = regexp.MustCompile(`^paranoia-level/(\d)$`)

func (r *Rule) parseActions(s string) error {
	var problem error
	for _, a := range splitActions(s) {
		name, val, _ := strings.Cut(a, ":")
		name = strings.ToLower(strings.TrimSpace(name))
		val = unquote(strings.TrimSpace(val))
		switch name {
		case "id":
			r.ID, _ = strconv.Atoi(val)
		case "phase":
			switch val {
			case "request":
				r.Phase = 2
			case "response":
				r.Phase = 4
			case "logging":
				r.Phase = 5
			default:
				r.Phase, _ = strconv.Atoi(val)
			}
		case "msg":
			r.Msg = val
		case "severity":
			r.Severity = strings.ToUpper(val)
		case "tag":
			r.Tags = append(r.Tags, val)
			if m := plTag.FindStringSubmatch(val); m != nil {
				r.Paranoia, _ = strconv.Atoi(m[1])
			}
		case "t":
			if strings.EqualFold(val, "none") {
				r.transforms, r.tkey = nil, ""
				continue
			}
			t, ok := transforms[strings.ToLower(val)]
			if !ok {
				problem = fmt.Errorf("transform t:%s", val)
				continue
			}
			r.transforms = append(r.transforms, t)
			r.tkey += strings.ToLower(val) + ","
		case "multimatch":
			r.multiMatch = true
		case "capture":
			r.capture = true
		case "chain":
			r.chain = chainPending
		case "setvar":
			r.setvars = append(r.setvars, val)
		case "skipafter":
			r.skipAfter = val
		case "skip":
			problem = fmt.Errorf("action skip")
		case "ctl":
			c, _, _ := strings.Cut(val, "=")
			switch strings.ToLower(c) {
			case "ruleremovetargetbyid", "ruleremovetargetbytag", "ruleremovebyid", "ruleremovebytag",
				"forcerequestbodyvariable", "requestbodyprocessor":
				r.ctls = append(r.ctls, val)
			case "auditengine", "auditlogparts":
			default:
				problem = fmt.Errorf("action ctl:%s", c)
			}
		case "block", "deny", "pass", "drop", "allow", "nolog", "log", "auditlog", "noauditlog",
			"rev", "ver", "maturity", "accuracy", "logdata", "status", "expirevar", "redirect", "initcol":
			// Logging and disruptive actions: Sentinel decides from the score.
		default:
			problem = fmt.Errorf("action %s", name)
		}
	}
	return problem
}

func unquote(s string) string {
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return s[1 : len(s)-1]
	}
	return s
}
