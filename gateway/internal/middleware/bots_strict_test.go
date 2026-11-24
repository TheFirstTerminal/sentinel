package middleware

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"sentinel/gateway/internal/bot"
	"sentinel/gateway/internal/reqctx"
)

func TestBotStrictPaths(t *testing.T) {
	ch := &bot.Challenger{Key: []byte("0123456789abcdef0123456789abcdef"), Difficulty: 4, PassFor: time.Hour}
	h := Bots(BotOptions{Challenger: ch, Challenge: "off", Paths: []string{"/"}, StrictPaths: []string{"/login"}},
		slog.New(slog.NewTextHandler(io.Discard, nil)))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("app")) }))
	do := func(method, path string, hdr map[string]string, pass bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader("u=a&p=b"))
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		r = r.WithContext(reqctx.With(r.Context(), &reqctx.Info{ID: "t", ClientIP: "198.51.100.7"}))
		if pass {
			r.AddCookie(ch.Pass(r, "198.51.100.7"))
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	browser := map[string]string{"User-Agent": "Mozilla/5.0 Chrome/126", "Accept": "text/html", "Accept-Language": "en"}
	if w := do("GET", "/login", browser, false); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "<") {
		t.Errorf("browser page load on a strict path: want the check page, got %d %.60q", w.Code, w.Body.String())
	}
	if w := do("GET", "/login", map[string]string{"User-Agent": "curl/8.0"}, false); w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), "app") {
		t.Errorf("curl on a strict path passed: %d", w.Code)
	}
	if w := do("POST", "/login", browser, false); w.Code != http.StatusForbidden {
		t.Errorf("form posted without a pass passed: %d", w.Code)
	}
	if w := do("POST", "/login", browser, true); w.Code != 200 {
		t.Errorf("browser with a pass refused: %d", w.Code)
	}
	if w := do("GET", "/api/items", map[string]string{"User-Agent": "curl/8.0"}, false); w.Code != 200 {
		t.Errorf("other path affected: %d", w.Code)
	}
}
