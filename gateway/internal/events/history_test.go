package events

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestHistorySurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	h, err := OpenHistory(dir, 30, nil)
	if err != nil {
		t.Fatal(err)
	}
	hub := NewHub(100)
	hub.Persist(h)
	now := time.Now()
	hub.Publish(Event{Time: now, Outcome: "allowed", Path: "/ok"})
	hub.Publish(Event{Time: now, Outcome: "blocked", Path: "/attack", Rule: "SQLI-001", Site: "shop", ClientIP: "203.0.113.5"})
	hub.Publish(Event{Time: now, Outcome: "detected", Path: "/x", Site: "api"})
	h.Close()

	// A new start: the hub is refilled from disk (allowed requests are not kept).
	h2, _ := OpenHistory(dir, 30, nil)
	defer h2.Close()
	hub2 := NewHub(100)
	hub2.Persist(h2)
	got := hub2.Recent(0)
	if len(got) != 2 || got[0].Path != "/attack" || got[1].Path != "/x" {
		t.Fatalf("after restart: %+v", got)
	}
	if q := h2.Query(Query{Site: "shop"}); len(q) != 1 || q[0].Rule != "SQLI-001" {
		t.Errorf("site filter: %+v", q)
	}
	if q := h2.Query(Query{Text: "203.0.113"}); len(q) != 1 {
		t.Errorf("text search: %+v", q)
	}
	if q := h2.Query(Query{From: now.Add(time.Hour)}); len(q) != 0 {
		t.Errorf("time filter: %+v", q)
	}
}

func TestHistoryDeletesOldDays(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "events-2000-01-01.jsonl")
	recent := filepath.Join(dir, historyPrefix+time.Now().UTC().Format("2006-01-02")+historySuffix)
	os.WriteFile(old, []byte("{}\n"), 0o600)
	os.WriteFile(recent, []byte("{}\n"), 0o600)
	h, _ := OpenHistory(dir, 7, nil)
	defer h.Close()
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Error("a day older than the retention should be deleted")
	}
	if _, err := os.Stat(recent); err != nil {
		t.Error("today's file must be kept")
	}
}

func TestStatsPerSite(t *testing.T) {
	hub := NewHub(10)
	now := time.Now()
	hub.Publish(Event{Time: now, Outcome: "blocked", Site: "a"})
	hub.Publish(Event{Time: now, Outcome: "allowed", Site: "b"})
	if s := hub.Stats(time.Hour, "a"); s.Total != 1 || s.Stopped != 1 {
		t.Errorf("site a: %+v", s)
	}
	if s := hub.Stats(time.Hour); s.Total != 2 {
		t.Errorf("all sites: %+v", s)
	}
}
