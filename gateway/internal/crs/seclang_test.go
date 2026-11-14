package crs

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// A small rule file that exercises the SecLang features CRS relies on.
const miniCRS = `
SecAction "id:900,phase:1,pass,nolog,setvar:'tx.critical_anomaly_score=5',setvar:'tx.allowed=GET POST'"

# Paranoia gate, as CRS writes it.
SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 1" "id:910,phase:2,pass,nolog,skipAfter:END-X"

SecRule ARGS "@rx (?i)union\s+select" \
    "id:1001,phase:2,block,capture,t:none,t:urlDecodeUni,msg:'SQLi',tag:'attack-sqli',tag:'paranoia-level/1',severity:'CRITICAL',\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"

# Chain: the second link reads what the first captured.
SecRule REQUEST_HEADERS_NAMES "@rx ^.*$" \
    "id:1002,phase:2,block,capture,t:lowercase,msg:'bad header',tag:'paranoia-level/1',severity:'CRITICAL',\
    setvar:'tx.h_%{tx.0}=/%{tx.0}/',chain"
    SecRule TX:/^h_/ "@within /x-evil/" "setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"

# Method not in an allowed list (macro in the parameter, negated).
SecRule REQUEST_METHOD "!@within %{tx.allowed}" \
    "id:1003,phase:1,block,msg:'method',tag:'paranoia-level/1',severity:'CRITICAL',\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"

# A rule only for paranoia level 2.
SecRule ARGS "@pm drop" \
    "id:1004,phase:2,block,msg:'pl2 only',tag:'paranoia-level/2',severity:'CRITICAL',\
    setvar:'tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}'"

# ctl removes a known-safe argument from one rule.
SecRule ARGS_GET:token "@rx ^[a-z0-9-]{8}$" "id:1005,phase:1,pass,nolog,ctl:ruleRemoveTargetById=1006;ARGS:token"
SecRule ARGS "@rx --" \
    "id:1006,phase:2,block,msg:'comment',tag:'paranoia-level/1',severity:'CRITICAL',\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"

SecMarker "END-X"
`

func mini(t *testing.T, pl int) *Set {
	t.Helper()
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "REQUEST-920-TEST.conf"), []byte(miniCRS), 0o644)
	s, err := Load(dir, pl)
	if err != nil {
		t.Fatal(err)
	}
	if s.Stats.Skipped != 0 {
		t.Fatalf("skipped rules: %v", s.Stats.SkipReasons)
	}
	return s
}

func ids(res Result) string {
	var out []string
	for _, m := range res.Matches {
		out = append(out, strconv.Itoa(m.ID))
	}
	return strings.Join(out, ",")
}

func TestSecLangFeatures(t *testing.T) {
	s := mini(t, 1)
	cases := []struct {
		name, method, url string
		hdr               string
		want              string
		score             int
	}{
		{"clean", "GET", "/?q=apple", "", "", 0},
		{"sqli (url-decoded)", "GET", "/?q=1%20UNION%20%20SELECT%201", "", "1001", 5},
		{"chained header check", "GET", "/", "X-Evil", "1002", 5},
		{"method not allowed", "DELETE", "/", "", "1003", 5},
		{"pl2 rule is off at pl1", "GET", "/?q=drop", "", "", 0},
		{"ctl exempts the token", "GET", "/?token=ab--cd12", "", "", 0},
		{"same value elsewhere is caught", "GET", "/?other=ab--cd12", "", "1006", 5},
	}
	for _, c := range cases {
		r := httptest.NewRequest(c.method, c.url, nil)
		if c.hdr != "" {
			r.Header.Set(c.hdr, "1")
		}
		res := s.Evaluate(r, nil)
		if ids(res) != c.want || res.Score != c.score {
			t.Errorf("%s: got rules [%s] score %d, want [%s] %d", c.name, ids(res), res.Score, c.want, c.score)
		}
	}
	// Paranoia level 2 turns rule 1004 on.
	if res := mini(t, 2).Evaluate(httptest.NewRequest("GET", "/?q=drop", nil), nil); ids(res) != "1004" || res.Score != 5 {
		t.Errorf("pl2: got [%s] %d", ids(res), res.Score)
	}
}

func TestExclude(t *testing.T) {
	s := mini(t, 1)
	if err := s.Exclude([]string{"1001", "1005-1006"}); err != nil {
		t.Fatal(err)
	}
	if res := s.Evaluate(httptest.NewRequest("GET", "/?q=1%20UNION%20SELECT%201", nil), nil); res.Score != 0 {
		t.Errorf("excluded rule still fired: %s", ids(res))
	}
	if s.Exclude([]string{"abc"}) == nil {
		t.Error("bad ID accepted")
	}
}

// Arabic text must not decode into quotes (see urlDecode).
func TestUnicodeDecodingKeepsCharacters(t *testing.T) {
	if got := urlDecode(utf8ToUnicode("عصير"), true); got != "عصير" {
		t.Errorf("got %q", got)
	}
	if got := urlDecode("%uff07", true); got != "'" { // fullwidth apostrophe
		t.Errorf("fullwidth: got %q", got)
	}
}

// Go rejects ";" in query strings; the checks must still see such values.
func TestSemicolonArgumentsAreInspected(t *testing.T) {
	got := parseArgs("a=1;b=2&c=%zz")
	if len(got) != 2 || got[0].value != "1;b=2" || got[1].value != "%zz" {
		t.Errorf("got %+v", got)
	}
}
