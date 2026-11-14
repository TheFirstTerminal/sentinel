package alert

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"sentinel/gateway/internal/events"
)

type sink struct {
	mu   sync.Mutex
	msgs []map[string]any
}

func (s *sink) server() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		json.NewDecoder(r.Body).Decode(&m)
		s.mu.Lock()
		s.msgs = append(s.msgs, m)
		s.mu.Unlock()
	}))
}

func (s *sink) wait(n int) []map[string]any {
	for i := 0; i < 100; i++ {
		s.mu.Lock()
		if len(s.msgs) >= n {
			out := append([]map[string]any(nil), s.msgs...)
			s.mu.Unlock()
			return out
		}
		s.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.msgs
}

func TestBurstHoneypotAndCooldown(t *testing.T) {
	s := &sink{}
	srv := s.server()
	defer srv.Close()
	hub := events.NewHub(100)
	a := &Alerter{URL: srv.URL, Burst: 5, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Watch(ctx, hub)
	time.Sleep(20 * time.Millisecond)

	for i := 0; i < 12; i++ { // one burst: a single alert, not 12
		hub.Publish(events.Event{ClientIP: "203.0.113.9", Method: "GET", Path: "/", Outcome: "blocked", Rule: "SQLI-001"})
	}
	hub.Publish(events.Event{ClientIP: "198.51.100.4", Path: "/.env", Outcome: "honeypot"})
	hub.Publish(events.Event{ClientIP: "198.51.100.4", Path: "/.git", Outcome: "honeypot"}) // same IP: cooldown
	hub.Publish(events.Event{ClientIP: "10.0.0.1", Path: "/", Outcome: "allowed"})
	msgs := s.wait(2)
	time.Sleep(100 * time.Millisecond)
	if len(s.msgs) != 2 {
		t.Fatalf("want 2 alerts, got %d: %v", len(s.msgs), s.msgs)
	}
	all := ""
	for _, m := range msgs {
		all += m["title"].(string) + " | " + m["text"].(string) + "\n"
	}
	if !strings.Contains(all, "Attack burst") || !strings.Contains(all, "203.0.113.9") || !strings.Contains(all, "Honeypot") {
		t.Errorf("alerts:\n%s", all)
	}
}

func TestFormats(t *testing.T) {
	for url, key := range map[string]string{
		"https://hooks.slack.com/services/x":            "text",
		"https://discord.com/api/webhooks/1/x":          "content",
		"https://api.telegram.org/botTOKEN/sendMessage": "chat_id",
		"https://example.com/hook":                      "event",
	} {
		a := &Alerter{URL: url, ChatID: "42"}
		b, _ := a.payload(Message{Title: "t", Text: "x"})
		var m map[string]any
		json.Unmarshal(b, &m)
		if _, ok := m[key]; !ok {
			t.Errorf("%s: no %q in %s", url, key, b)
		}
	}
}

func TestGlobalCap(t *testing.T) {
	a := &Alerter{URL: "http://127.0.0.1:1", Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	a.init()
	for i := 0; i < 100; i++ {
		a.Send("s"+string(rune('a'+i%26))+string(rune(i)), Message{Title: "x"})
	}
	if len(a.sent) != maxPerMinute {
		t.Errorf("%d alerts allowed in a minute", len(a.sent))
	}
}
