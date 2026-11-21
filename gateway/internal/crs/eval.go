package crs

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Match is one CRS detection rule that fired.
type Match struct {
	ID       int
	Msg      string
	Severity string
	Category string // from the attack-* tag, e.g. "sqli"
	Paranoia int
	Var      string // e.g. "ARGS:q"
	Value    string // what matched (shortened)
}

// Result is the outcome of running CRS on a request.
type Result struct {
	Score   int // CRS inbound anomaly score at the blocking paranoia level
	Matches []Match
	// Incomplete: the request used up Budget and the rest of the rules
	// were not run.
	Incomplete bool
}

// Budget is the most CPU time one request may spend in the Core Rule Set
// (0 = no limit). A large JSON body of many fields once cost seconds, so a
// handful sent at once could stall the gateway.
var Budget = 5 * time.Second

// Evaluate runs the request rules. body must be the complete body.
func (s *Set) Evaluate(r *http.Request, body []byte) Result {
	tx := newTx(r, body)
	if Budget > 0 {
		tx.deadline = time.Now().Add(Budget)
	}
	pl := strconv.Itoa(s.Paranoia)
	// What crs-setup.conf would set; CRS fills in every other default.
	tx.tx["crs_setup_version"] = "480"
	tx.tx["blocking_paranoia_level"] = pl
	tx.tx["detection_paranoia_level"] = pl
	// Inspect XML attribute values too (CRS 4.25 LTS leaves it off unless
	// crs-setup.conf opts in): attacks must not hide in attributes.
	tx.tx["crs_xml_attr_inspect"] = "1"
	// CRS's list plus what browsers send on their own: navigator.sendBeacon
	// and analytics posts use text/plain, and CSP/Reporting API reports
	// have their own types, and Oblivious HTTP (RFC 9458) carries
	// encrypted requests as message/ohttp-req. Rule 920420 blocked ~5% of real traffic without.
	tx.tx["allowed_request_content_type"] = "|application/x-www-form-urlencoded| |multipart/form-data| |text/xml| |application/xml| |application/soap+xml| |application/json| |text/plain| |application/csp-report| |application/reports+json| |message/ohttp-req|"

	for _, phase := range s.phases {
		skipTo := ""
		for _, r := range phase {
			if tx.overBudget {
				break
			}
			if skipTo != "" {
				if r.marker == skipTo {
					skipTo = ""
				}
				continue
			}
			if r.marker != "" || r.Paranoia > s.Paranoia {
				continue // CRS also skips these with its own gates
			}
			if tx.run(r) && r.skipAfter != "" {
				skipTo = r.skipAfter
			}
		}
	}

	res := Result{Matches: tx.matches, Incomplete: tx.overBudget}
	for i := 1; i <= s.Paranoia; i++ {
		res.Score += atoi(tx.tx["inbound_anomaly_score_pl"+strconv.Itoa(i)])
	}
	return res
}

// run evaluates a rule and its chain; it returns whether all of it matched.
func (tx *Tx) run(r *Rule) bool {
	if tx.removed(r) {
		return false
	}
	tx.current = r
	tx.matched = nil
	tx.matchedVar = kv{}
	tx.ruleID = r.ID
	// Like ModSecurity, a link's setvars run as soon as that link matches:
	// later links of the chain may read what earlier ones set.
	for link := r; link != nil; link = link.chain {
		apply := func() {
			for _, sv := range link.setvars {
				tx.setvar(sv)
			}
			for _, c := range link.ctls {
				tx.ctl(c)
			}
		}
		if link.action {
			apply()
			continue
		}
		if !tx.evalLink(link, apply) {
			return false
		}
	}
	if r.Msg != "" && r.Paranoia > 0 {
		m := Match{ID: r.ID, Msg: tx.expand(r.Msg), Severity: r.Severity, Paranoia: r.Paranoia,
			Var: tx.matchedVar.key, Value: shorten(tx.matchedVar.value)}
		for _, t := range r.Tags {
			if c, ok := strings.CutPrefix(t, "attack-"); ok {
				m.Category = c
				break
			}
		}
		tx.matches = append(tx.matches, m)
	}
	return true
}

func shorten(s string) string {
	if len(s) > 120 {
		return s[:120] + "..."
	}
	return s
}

// evalLink runs one link. onMatch runs for every matched value, with
// MATCHED_VAR and the captures of that value (so a rule can set one TX
// variable per matching header, as 920450 does).
func (tx *Tx) evalLink(r *Rule, onMatch func()) bool {
	param := r.op.param
	if strings.Contains(param, "%{") {
		param = tx.expand(param)
	}
	vals := tx.ruleValues(r)
	var found []kv
	var buf [8]string // candidates, without a new slice per value
	for _, v := range vals {
		if !tx.deadline.IsZero() && time.Now().After(tx.deadline) {
			tx.overBudget = true
			return false
		}
		candidates := append(buf[:0], v.value)
		if r.multiMatch {
			cur := v.value
			for _, t := range r.transforms {
				cur = t(cur)
				candidates = append(candidates, cur)
			}
		} else if len(r.transforms) > 0 {
			candidates[0] = tx.transform(r, v.value)
		}
		for _, c := range candidates {
			var ok bool
			var groups []string
			if r.op.pre != nil && !r.op.pre.MayMatch(tx.lowerOf(c)) {
				ok = r.op.negate // the regex cannot match this value
			} else {
				ok, groups = r.op.matchChecked(c, param, r.capture)
			}
			if !ok {
				continue
			}
			if r.capture {
				tx.txSorted = nil
				for i := 0; i < 10; i++ {
					delete(tx.tx, strconv.Itoa(i))
				}
				for i, g := range groups {
					if i < 10 {
						tx.tx[strconv.Itoa(i)] = g
					}
				}
			}
			found = append(found, kv{v.key, c})
			tx.matchedVar = kv{v.key, c}
			onMatch()
			break
		}
		if len(found) > 0 && r.chain == nil {
			break // nothing later needs the other matches
		}
	}
	if len(found) == 0 {
		return false
	}
	tx.matched = found
	tx.matchedVar = found[len(found)-1]
	return true
}

// ruleValues returns the values a rule's variables select. Many CRS rules
// select exactly the same variables, so fixed lists are built once per
// request.
func (tx *Tx) ruleValues(r *Rule) []kv {
	removed := tx.removedTargets(tx.current)
	if !r.varsStatic || len(removed) > 0 {
		return tx.values(append(r.vars[:len(r.vars):len(r.vars)], removed...))
	}
	if tx.vcache == nil {
		tx.vcache = map[string][]kv{}
	}
	if v, ok := tx.vcache[r.varsKey]; ok {
		return v
	}
	v := tx.values(r.vars)
	tx.vcache[r.varsKey] = v
	return v
}

// transform applies a rule's transform chain, caching the result: CRS runs
// the same chain on the same value in dozens of rules.
func (tx *Tx) transform(r *Rule, v string) string {
	if tx.tcache == nil {
		tx.tcache = map[[2]string]string{}
	}
	k := [2]string{r.tkey, v}
	if out, ok := tx.tcache[k]; ok {
		return out
	}
	out := v
	for _, t := range r.transforms {
		out = t(out)
	}
	tx.tcache[k] = out
	return out
}

// expand replaces %{collection.key} macros.
func (tx *Tx) expand(s string) string {
	if !strings.Contains(s, "%{") {
		return s
	}
	var b strings.Builder
	for {
		i := strings.Index(s, "%{")
		if i < 0 {
			b.WriteString(s)
			return b.String()
		}
		j := strings.IndexByte(s[i:], '}')
		if j < 0 {
			b.WriteString(s)
			return b.String()
		}
		b.WriteString(s[:i])
		b.WriteString(tx.lookup(s[i+2 : i+j]))
		s = s[i+j+1:]
	}
}

func (tx *Tx) lookup(name string) string {
	col, key, _ := strings.Cut(name, ".")
	switch strings.ToUpper(col) {
	case "TX":
		return tx.tx[strings.ToLower(key)]
	case "MATCHED_VAR":
		return tx.matchedVar.value
	case "MATCHED_VAR_NAME":
		return tx.matchedVar.key
	case "RULE":
		if strings.EqualFold(key, "id") {
			return strconv.Itoa(tx.ruleID)
		}
	case "REQUEST_HEADERS":
		for _, h := range tx.cols["REQUEST_HEADERS"] {
			if strings.EqualFold(h.key, key) {
				return h.value
			}
		}
	default:
		if v, ok := tx.single[strings.ToUpper(name)]; ok {
			return v
		}
	}
	return ""
}

// setvar handles tx.name=value, =+n, =-n and !tx.name. Other collections
// (ip, session) need persistent storage and are ignored.
func (tx *Tx) setvar(s string) {
	tx.txSorted = nil
	s = strings.Trim(s, "'")
	del := strings.HasPrefix(s, "!")
	s = strings.TrimPrefix(s, "!")
	name, val, hasVal := strings.Cut(s, "=")
	col, key, ok := strings.Cut(tx.expand(name), ".")
	if !ok || !strings.EqualFold(col, "tx") {
		return
	}
	key = strings.ToLower(key)
	if del {
		delete(tx.tx, key)
		return
	}
	if !hasVal {
		tx.tx[key] = "1"
		return
	}
	val = tx.expand(val)
	switch {
	case strings.HasPrefix(val, "+"):
		tx.tx[key] = strconv.Itoa(atoi(tx.tx[key]) + atoi(val[1:]))
	case strings.HasPrefix(val, "-"):
		tx.tx[key] = strconv.Itoa(atoi(tx.tx[key]) - atoi(val[1:]))
	default:
		tx.tx[key] = val
	}
}

// ctl changes how the rest of this request is checked. CRS uses it to
// switch off a rule for a known-safe value (e.g. Facebook click IDs).
func (tx *Tx) ctl(c string) {
	name, val, _ := strings.Cut(c, "=")
	val = tx.expand(val)
	switch strings.ToLower(name) {
	case "ruleremovebyid":
		for _, part := range strings.Fields(strings.ReplaceAll(val, ",", " ")) {
			lo, hi, isRange := strings.Cut(part, "-")
			a := atoi(lo)
			b := a
			if isRange {
				b = atoi(hi)
			}
			tx.removedRanges = append(tx.removedRanges, [2]int{a, b})
		}
	case "ruleremovebytag":
		tx.removedTags = append(tx.removedTags, val)
	case "ruleremovetargetbyid", "ruleremovetargetbytag":
		what, target, ok := strings.Cut(val, ";")
		if !ok {
			return
		}
		specs, err := parseVars("!" + target)
		if err != nil {
			return
		}
		tx.targetRemovals = append(tx.targetRemovals, targetRemoval{byTag: strings.EqualFold(name, "ruleremovetargetbytag"), what: what, spec: specs[0]})
	case "forcerequestbodyvariable":
		if strings.EqualFold(val, "on") {
			tx.vcache = nil
			tx.single["REQUEST_BODY"] = string(tx.body)
		}
	case "requestbodyprocessor":
		if strings.EqualFold(val, "urlencoded") && tx.single["REQBODY_PROCESSOR"] == "" {
			tx.single["REQBODY_PROCESSOR"] = "URLENCODED"
			for _, p := range parseArgs(string(tx.body)) {
				tx.addArg("POST", p.key, p.value)
			}
		}
	}
}

type targetRemoval struct {
	byTag bool
	what  string // rule id or tag
	spec  varSpec
}

func (tx *Tx) removed(r *Rule) bool {
	for _, rg := range tx.removedRanges {
		if r.ID >= rg[0] && r.ID <= rg[1] {
			return true
		}
	}
	for _, tag := range tx.removedTags {
		if hasTag(r, tag) {
			return true
		}
	}
	return false
}

func (tx *Tx) removedTargets(r *Rule) []varSpec {
	if r == nil || len(tx.targetRemovals) == 0 {
		return nil
	}
	var out []varSpec
	for _, tr := range tx.targetRemovals {
		if (tr.byTag && hasTag(r, tr.what)) || (!tr.byTag && strconv.Itoa(r.ID) == tr.what) {
			out = append(out, tr.spec)
		}
	}
	return out
}

func hasTag(r *Rule, tag string) bool {
	for _, t := range r.Tags {
		if strings.EqualFold(t, tag) {
			return true
		}
	}
	return false
}
