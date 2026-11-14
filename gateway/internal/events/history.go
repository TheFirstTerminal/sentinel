package events

import (
	"bufio"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// History keeps every event on disk, one JSON line each, in one file per
// day (events-2026-11-14.jsonl, UTC), so the dashboard's history survives
// restarts. Files older than the retention are deleted. Writing happens in
// the background and never slows a request down: if the disk can't keep
// up, events are dropped and a warning is logged.
type History struct {
	dir  string
	days int
	log  *slog.Logger
	ch   chan Event
	done chan struct{}
	now  func() time.Time

	mu      sync.Mutex // the open day file
	day     string
	file    *os.File
	w       *bufio.Writer
	dropped int
}

const historyPrefix, historySuffix = "events-", ".jsonl"

// OpenHistory starts writing to dir (created if needed) and deletes days
// older than days.
func OpenHistory(dir string, days int, log *slog.Logger) (*History, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	h := &History{dir: dir, days: days, log: log, ch: make(chan Event, 4096), done: make(chan struct{}), now: time.Now}
	h.prune()
	go h.run()
	return h, nil
}

// Append queues an event for writing.
func (h *History) Append(e Event) {
	select {
	case h.ch <- e:
	default:
		h.mu.Lock()
		h.dropped++
		h.mu.Unlock()
	}
}

// Close writes what is queued and closes the file.
func (h *History) Close() {
	close(h.ch)
	<-h.done
}

func (h *History) run() {
	defer close(h.done)
	flush := time.NewTicker(time.Second)
	defer flush.Stop()
	daily := time.NewTicker(time.Hour)
	defer daily.Stop()
	for {
		select {
		case e, ok := <-h.ch:
			if !ok {
				h.closeFile()
				return
			}
			h.write(e)
		case <-flush.C:
			h.mu.Lock()
			if h.w != nil {
				h.w.Flush()
			}
			if h.dropped > 0 && h.log != nil {
				h.log.Warn("history: events dropped, the disk is too slow", "count", h.dropped)
				h.dropped = 0
			}
			h.mu.Unlock()
		case <-daily.C:
			h.prune()
		}
	}
}

func (h *History) write(e Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	day := e.Time.UTC().Format("2006-01-02")
	if day != h.day || h.file == nil {
		h.closeFileLocked()
		f, err := os.OpenFile(filepath.Join(h.dir, historyPrefix+day+historySuffix), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			if h.log != nil {
				h.log.Warn("history: cannot write", "error", err.Error())
			}
			return
		}
		h.file, h.w, h.day = f, bufio.NewWriterSize(f, 64<<10), day
	}
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	h.w.Write(b)
	h.w.WriteByte('\n')
}

func (h *History) closeFile() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closeFileLocked()
}

func (h *History) closeFileLocked() {
	if h.w != nil {
		h.w.Flush()
	}
	if h.file != nil {
		h.file.Close()
	}
	h.file, h.w, h.day = nil, nil, ""
}

// Flush writes buffered events now (tests and shutdown).
func (h *History) Flush() {
	for i := 0; i < 100 && len(h.ch) > 0; i++ {
		time.Sleep(5 * time.Millisecond)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.w != nil {
		h.w.Flush()
	}
}

// days lists the day files, newest first.
func (h *History) dayFiles() []string {
	matches, _ := filepath.Glob(filepath.Join(h.dir, historyPrefix+"*"+historySuffix))
	sort.Sort(sort.Reverse(sort.StringSlice(matches)))
	return matches
}

func (h *History) prune() {
	if h.days <= 0 {
		return
	}
	cutoff := h.now().UTC().AddDate(0, 0, -h.days).Format("2006-01-02")
	for _, f := range h.dayFiles() {
		day := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(f), historyPrefix), historySuffix)
		if day < cutoff {
			if err := os.Remove(f); err == nil && h.log != nil {
				h.log.Info("history: old day deleted", "day", day)
			}
		}
	}
}

// Query selects events from the history.
type Query struct {
	From, To time.Time // zero = no limit
	Site     string    // "" = every site
	Stopped  bool      // only requests Sentinel refused (or would have)
	Text     string    // matched against IP, path, rule, reason and detail
	Limit    int       // newest first; default 500, at most 5000
}

// Query returns matching events, newest first.
func (h *History) Query(q Query) []Event {
	if q.Limit <= 0 {
		q.Limit = 500
	}
	if q.Limit > 5000 {
		q.Limit = 5000
	}
	h.Flush()
	text := strings.ToLower(q.Text)
	var out []Event
	for _, f := range h.dayFiles() {
		day := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(f), historyPrefix), historySuffix)
		if !q.From.IsZero() && day < q.From.UTC().Format("2006-01-02") {
			break // older files only from here on
		}
		if !q.To.IsZero() && day > q.To.UTC().Format("2006-01-02") {
			continue
		}
		events := readDay(f)
		for i := len(events) - 1; i >= 0; i-- {
			e := events[i]
			if !q.From.IsZero() && e.Time.Before(q.From) || !q.To.IsZero() && e.Time.After(q.To) {
				continue
			}
			if q.Site != "" && e.Site != q.Site {
				continue
			}
			if q.Stopped && !(e.Stopped() || e.Outcome == "detected" || e.Outcome == "monitored") {
				continue
			}
			if text != "" && !strings.Contains(strings.ToLower(e.ClientIP+" "+e.Path+" "+e.Rule+" "+e.Reason+" "+e.Detail), text) {
				continue
			}
			out = append(out, e)
			if len(out) >= q.Limit {
				return out
			}
		}
	}
	return out
}

// Last returns the newest n events, oldest first (to refill the dashboard).
func (h *History) Last(n int) []Event {
	evs := h.Query(Query{Limit: n})
	for i, j := 0, len(evs)-1; i < j; i, j = i+1, j-1 {
		evs[i], evs[j] = evs[j], evs[i]
	}
	return evs
}

func readDay(path string) []Event {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		var e Event
		if json.Unmarshal(sc.Bytes(), &e) == nil {
			out = append(out, e)
		}
	}
	return out
}
