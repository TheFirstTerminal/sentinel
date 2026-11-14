package main

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"sentinel/gateway/internal/bot"
	"sentinel/gateway/internal/config"
)

func TestBotChallengeEndToEnd(t *testing.T) {
	l := newLabWith(t, func(c *config.Config) {
		c.BotBlockScanners, c.BotChallenge, c.BotPaths, c.BotDifficulty = true, "suspicious", []string{"/"}, 10
		c.TrustedProxies = "127.0.0.0/8"
	})
	get := func(ua, accept string, cookies ...*http.Cookie) (*http.Response, string) {
		req, _ := http.NewRequest("GET", l.gw.URL+"/shop", nil)
		req.Header.Set("User-Agent", ua)
		req.Header.Set("Accept", accept)
		req.Header.Set("X-Forwarded-For", "203.0.113.20")
		for _, c := range cookies {
			req.AddCookie(c)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		return res, string(b)
	}
	if res, _ := get("sqlmap/1.8", "*/*"); res.StatusCode != 403 {
		t.Errorf("scanner: %d", res.StatusCode)
	}
	headless := "Mozilla/5.0 HeadlessChrome/120.0"
	res, page := get(headless, "text/html")
	if res.StatusCode != 403 || !strings.Contains(page, "Checking your browser") {
		t.Fatalf("no challenge for a headless browser: %d", res.StatusCode)
	}
	if res, _ := get(headless, "application/json"); res.StatusCode != 200 {
		t.Errorf("API requests must not get a challenge page: %d", res.StatusCode)
	}
	work := &http.Cookie{Name: bot.WorkCookie, Value: bot.Solve(page)}
	res, _ = get(headless, "text/html", work)
	if res.StatusCode != 200 {
		t.Fatalf("solved challenge refused: %d", res.StatusCode)
	}
	var pass *http.Cookie
	for _, c := range res.Cookies() {
		if c.Name == bot.PassCookie {
			pass = c
		}
	}
	if pass == nil || !pass.HttpOnly {
		t.Fatalf("no HttpOnly pass cookie: %+v", res.Cookies())
	}
	if res, _ := get(headless, "text/html", pass); res.StatusCode != 200 {
		t.Errorf("pass refused: %d", res.StatusCode)
	}
	if res, _ := get("Mozilla/5.0 (Windows NT 10.0) Chrome/120", "text/html"); res.StatusCode != 403 {
		// claims a browser without Accept-Language: challenged
		t.Errorf("browser without Accept-Language: %d", res.StatusCode)
	}
}

// A browser's Referer is a URL: on localhost it used to look like SSRF to
// the ML model. An injection hidden in the Referer's query is still caught.
func TestRefererIsNotAFalseAlarm(t *testing.T) {
	l := newLabWith(t, func(c *config.Config) { c.MLMode = "block"; c.MLThreshold = 0.9 })
	for _, ref := range []string{"http://localhost:8120/products", "http://127.0.0.1:3000/cart?item=12", "https://shop.example.com/search?q=apple+juice"} {
		if code, _ := l.do("GET", "/products", "", "", "Referer", ref); code != 200 {
			t.Errorf("Referer %s: %d", ref, code)
		}
	}
	if code, _ := l.do("GET", "/products", "", "", "Referer", "https://x.example/?id=1'+UNION+SELECT+password+FROM+users--"); code != 403 {
		t.Errorf("SQL injection in the Referer's query: %d", code)
	}
}
