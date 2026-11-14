package watch

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestFormatBlocked(t *testing.T) {
	line := `{"time":"2026-11-05T11:18:05.1+03:00","msg":"request","method":"GET","path":"/rest/products/search","status":403,"outcome":"blocked","rule":"SQLI-001","reason":"UNION-based SQL injection","detail":"field: q  matched: union select"}`
	got := Format([]byte(line), Options{})
	for _, want := range []string{"11:18:05", "✗ BLOCKED", "/rest/products/search", "403", "SQLI-001", "UNION-based", "field: q"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestFormatAllowedWithUser(t *testing.T) {
	line := `{"time":"2026-11-05T11:20:00Z","msg":"request","method":"GET","path":"/staff/api/admin/employees","status":200,"outcome":"allowed","rule":"staff-admin","user":"admin","role":"admin","mfa":true}`
	got := Format([]byte(line), Options{})
	if !strings.Contains(got, "✓ ALLOWED") || !strings.Contains(got, "admin (admin, 2FA)") {
		t.Fatalf("unexpected: %s", got)
	}
	if strings.Contains(got, "staff-admin") {
		t.Errorf("allowed lines should stay short (no rule name): %s", got)
	}
}

func TestNoiseHiddenUnlessAll(t *testing.T) {
	line := []byte(`{"msg":"request","method":"GET","path":"/main.js","status":200,"outcome":"allowed"}`)
	if Format(line, Options{}) != "" {
		t.Error("static files should be hidden by default")
	}
	if Format(line, Options{All: true}) == "" {
		t.Error("--all should show them")
	}
	if Format([]byte(`{"msg":"waf_event"}`), Options{All: true}) != "" {
		t.Error("only request lines are shown")
	}
	if Format([]byte(`not json`), Options{}) != "" {
		t.Error("garbage must be ignored")
	}
}

func TestColor(t *testing.T) {
	line := []byte(`{"msg":"request","method":"GET","path":"/x","status":403,"outcome":"denied","reason":"role 'employee' is not allowed"}`)
	if !strings.Contains(Format(line, Options{Color: true}), red) {
		t.Error("denied should be red")
	}
	if strings.Contains(Format(line, Options{}), "\x1b[") {
		t.Error("no escape codes without colour")
	}
}

func TestFollowPrintsOnlyNewLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sentinel.log")
	os.WriteFile(path, []byte(`{"msg":"request","method":"GET","path":"/old","status":200}`+"\n"), 0o644)

	var out safeBuf
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { Follow(ctx, path, &out, Options{}); close(done) }()
	time.Sleep(400 * time.Millisecond)

	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	f.WriteString(`{"msg":"request","method":"GET","path":"/new","status":403,"outcome":"blocked","rule":"XSS-001"}` + "\n")
	f.Close()
	time.Sleep(600 * time.Millisecond)
	cancel()
	<-done

	s := out.String()
	if strings.Contains(s, "/old") || !strings.Contains(s, "/new") || !strings.Contains(s, "XSS-001") {
		t.Fatalf("follow output wrong:\n%s", s)
	}
}

type safeBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *safeBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *safeBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
