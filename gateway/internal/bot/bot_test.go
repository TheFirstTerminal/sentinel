package bot

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestScannerAndSuspicious(t *testing.T) {
	if Scanner("sqlmap/1.8#stable (https://sqlmap.org)") != "sqlmap" || Scanner("Mozilla/5.0 (Windows NT 10.0) Chrome/120") != "" {
		t.Error("scanner detection")
	}
	r := httptest.NewRequest("GET", "/", nil)
	if Suspicious(r) == "" {
		t.Error("no User-Agent is suspicious")
	}
	r.Header.Set("User-Agent", "Mozilla/5.0 HeadlessChrome/120.0")
	if !strings.Contains(Suspicious(r), "headlesschrome") {
		t.Error("headless")
	}
	r.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0) Chrome/120")
	r.Header.Set("Accept-Language", "ar-IQ,en;q=0.8")
	if Suspicious(r) != "" {
		t.Error("a normal browser is suspicious")
	}
}

func TestChallengeFlow(t *testing.T) {
	c := &Challenger{Key: []byte("k"), Difficulty: 12, PassFor: time.Hour}
	req := func(cookies ...*http.Cookie) *http.Request {
		r := httptest.NewRequest("GET", "/login", nil)
		r.Header.Set("User-Agent", "Mozilla/5.0 Firefox/120")
		for _, ck := range cookies {
			r.AddCookie(ck)
		}
		return r
	}
	page := c.Page(req(), "1.2.3.4")
	work := &http.Cookie{Name: WorkCookie, Value: Solve(page)}
	if !c.Solved(req(work), "1.2.3.4") {
		t.Fatal("a correct solution was refused")
	}
	if c.Solved(req(work), "5.6.7.8") {
		t.Error("a solution worked from another IP")
	}
	bad := &http.Cookie{Name: WorkCookie, Value: work.Value[:strings.LastIndex(work.Value, ".")] + ".0"}
	if c.Solved(req(bad), "1.2.3.4") && leadingZeroBits(strings.Split(work.Value, ".")[0]+"0") < 12 {
		t.Error("no proof of work accepted")
	}
	pass := c.Pass(req(), "1.2.3.4")
	if !c.HasPass(req(pass), "1.2.3.4") {
		t.Fatal("pass refused")
	}
	if c.HasPass(req(pass), "9.9.9.9") {
		t.Error("pass worked from another IP")
	}
	other := req(pass)
	other.Header.Set("User-Agent", "curl/8")
	if c.HasPass(other, "1.2.3.4") {
		t.Error("pass worked with another User-Agent")
	}
	c.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if c.HasPass(req(pass), "1.2.3.4") {
		t.Error("expired pass accepted")
	}
}
