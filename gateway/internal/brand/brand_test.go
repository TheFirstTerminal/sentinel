package brand

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestServesKit(t *testing.T) {
	h := Handler()
	for path, want := range map[string]string{
		Path + "tft.css":                   "text/css",
		Path + "logo.svg":                  "image/svg+xml",
		Path + "fonts/readex-arabic.woff2": "font/woff2",
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), want) || rec.Body.Len() == 0 {
			t.Errorf("%s: %d %q (%d bytes)", path, rec.Code, rec.Header().Get("Content-Type"), rec.Body.Len())
		}
	}
	// tft.css finds its fonts next to it.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", Path+"tft.css", nil))
	if !strings.Contains(rec.Body.String(), "url(fonts/readex-arabic.woff2)") {
		t.Error("tft.css does not point at fonts/")
	}
	for _, path := range []string{Path, Path + "fonts/", Path + "nope.css", Path + "../brand.go"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: want 404, got %d", path, rec.Code)
		}
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", Path+"tft.css", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: want 405, got %d", rec.Code)
	}
}
