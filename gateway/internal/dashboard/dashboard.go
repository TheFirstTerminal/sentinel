// Package dashboard is Sentinel's web dashboard: a page at
// /__sentinel/dashboard and the JSON API behind it under /__sentinel/api/.
//
// The page itself is public (it is just a login form and some JavaScript);
// every API call needs an admin token that passed 2FA, so only verified
// admins see traffic and bans, and change them.
package dashboard

import (
	"sentinel/gateway/internal/exclude"

	_ "embed"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"sentinel/gateway/internal/audit"
	"sentinel/gateway/internal/blocklist"
	"sentinel/gateway/internal/events"
	"sentinel/gateway/internal/reqctx"
)

const (
	PagePath  = "/__sentinel/dashboard"
	APIPrefix = "/__sentinel/api/"
)

//go:embed dashboard.html
var page []byte

type Recorder interface {
	Record(audit.Event) error
}

// Info is the read-only configuration summary shown on the dashboard.
type Info struct {
	Version    string   `json:"version"`
	Mode       string   `json:"mode"`
	WAFMode    string   `json:"waf_mode"`
	Rules      int      `json:"waf_rules"`
	RateLimits []string `json:"rate_limits"`
	Store      string   `json:"store"`
	Geo        string   `json:"geo"`
	PromptPath []string `json:"prompt_guard_paths"`
	ML         string   `json:"ml"`
	Started    string   `json:"started"`
}

type Dashboard struct {
	Hub    *events.Hub
	Bans   *blocklist.List
	Rec    Recorder
	Log    *slog.Logger
	Info   Info
	Excl   *exclude.Set           // false-alarm exclusions (nil = feature off)
	Reload func(why string) error // reloads rules, CRS and exclusions
}

func (d *Dashboard) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == PagePath || r.URL.Path == PagePath+"/" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(page)
		return
	}
	info := reqctx.From(r.Context())
	u := info.User()
	switch {
	case u == nil:
		jsonError(w, http.StatusUnauthorized, "log in as an admin with 2FA", info.ID)
		info.SetOutcome(reqctx.Outcome{Kind: "unauthenticated", Reason: "dashboard API without login", Rule: "dashboard"})
		return
	case u.Role != "admin" || !u.MFA:
		jsonError(w, http.StatusForbidden, "the dashboard is for admins who passed 2FA", info.ID)
		info.SetOutcome(reqctx.Outcome{Kind: "denied", Reason: "dashboard needs admin + 2FA", Rule: "dashboard"})
		return
	}
	w.Header().Set("Cache-Control", "no-store")

	path := strings.TrimPrefix(r.URL.Path, APIPrefix)
	switch {
	case path == "stats" && r.Method == "GET":
		win := 60 * time.Minute
		if m, err := strconv.Atoi(r.URL.Query().Get("minutes")); err == nil && m >= 1 && m <= 24*60 {
			win = time.Duration(m) * time.Minute
		}
		reply(w, d.Hub.Stats(win))
	case path == "events" && r.Method == "GET":
		n, _ := strconv.Atoi(r.URL.Query().Get("n"))
		if n <= 0 || n > 1000 {
			n = 200
		}
		reply(w, d.Hub.Recent(n))
	case path == "stream" && r.Method == "GET":
		d.stream(w, r)
	case path == "bans" && r.Method == "GET":
		reply(w, d.Bans.List())
	case path == "bans" && r.Method == "POST":
		d.ban(w, r, u.Username)
	case strings.HasPrefix(path, "bans/") && r.Method == "DELETE":
		ip := strings.TrimPrefix(path, "bans/")
		if !d.Bans.Unban(ip) {
			jsonError(w, http.StatusNotFound, "no ban for "+ip, info.ID)
			return
		}
		d.audit(r, "dashboard_unban", map[string]any{"ip": ip, "by": u.Username})
		reply(w, map[string]any{"unbanned": ip})
	case path == "info" && r.Method == "GET":
		reply(w, d.Info)
	case path == "reload" && r.Method == "POST" && d.Reload != nil:
		if err := d.Reload("dashboard (" + u.Username + ")"); err != nil {
			jsonError(w, http.StatusUnprocessableEntity, "reload failed, the old rules stay active: "+err.Error(), info.ID)
			return
		}
		d.audit(r, "reload", map[string]any{"by": u.Username})
		reply(w, map[string]any{"reloaded": true})
	case path == "exclusions" && r.Method == "GET" && d.Excl != nil:
		reply(w, map[string]any{"file": d.Excl.File(), "exclusions": d.Excl.List()})
	case path == "exclusions" && r.Method == "POST" && d.Excl != nil:
		var in exclude.Exclusion
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&in); err != nil {
			jsonError(w, http.StatusBadRequest, "send JSON: {rule, path, field, method, note}", info.ID)
			return
		}
		in.By, in.ID = u.Username, ""
		e, err := d.Excl.Add(in)
		if err != nil {
			jsonError(w, http.StatusBadRequest, err.Error(), info.ID)
			return
		}
		d.audit(r, "exclusion_added", map[string]any{"exclusion": e})
		reply(w, e)
	case strings.HasPrefix(path, "exclusions/") && r.Method == "DELETE" && d.Excl != nil:
		id := strings.TrimPrefix(path, "exclusions/")
		ok, err := d.Excl.Remove(id)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, err.Error(), info.ID)
			return
		}
		if !ok {
			jsonError(w, http.StatusNotFound, "no exclusion "+id, info.ID)
			return
		}
		d.audit(r, "exclusion_removed", map[string]any{"id": id, "by": u.Username})
		reply(w, map[string]any{"removed": id})
	default:
		jsonError(w, http.StatusNotFound, "unknown dashboard API path", info.ID)
	}
}

func (d *Dashboard) ban(w http.ResponseWriter, r *http.Request, by string) {
	var in struct {
		IP      string `json:"ip"`
		Minutes int    `json:"minutes"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in); err != nil || net.ParseIP(in.IP) == nil {
		jsonError(w, http.StatusBadRequest, `send {"ip":"1.2.3.4","minutes":60}`, reqctx.From(r.Context()).ID)
		return
	}
	if in.Minutes <= 0 || in.Minutes > 7*24*60 {
		in.Minutes = 60
	}
	d.Bans.Ban(in.IP, time.Duration(in.Minutes)*time.Minute)
	d.audit(r, "dashboard_ban", map[string]any{"ip": in.IP, "minutes": in.Minutes, "by": by})
	reply(w, map[string]any{"banned": in.IP, "minutes": in.Minutes})
}

// stream sends new events as Server-Sent Events until the client leaves.
// The page reads it with fetch() so it can send the token in a header.
func (d *Dashboard) stream(w http.ResponseWriter, r *http.Request) {
	rc := http.NewResponseController(w)
	rc.SetWriteDeadline(time.Time{}) // a stream outlives the normal write timeout
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	ch, stop := d.Hub.Subscribe()
	defer stop()
	ping := time.NewTicker(15 * time.Second)
	defer ping.Stop()
	rc.Flush()
	for {
		select {
		case <-r.Context().Done():
			return
		case e := <-ch:
			if events.Hidden(e.Path, e.Outcome) {
				continue
			}
			b, _ := json.Marshal(e)
			fmt.Fprintf(w, "data: %s\n\n", b)
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n")
		}
		if rc.Flush() != nil {
			return
		}
	}
}

func (d *Dashboard) audit(r *http.Request, typ string, detail map[string]any) {
	if d.Rec == nil {
		return
	}
	info := reqctx.From(r.Context())
	if err := d.Rec.Record(audit.Event{Type: typ, ClientIP: info.ClientIP, RequestID: info.ID,
		Method: r.Method, Path: r.URL.Path, Detail: detail}); err != nil && d.Log != nil {
		d.Log.Error("audit_write_failed", "error", err.Error())
	}
}

func reply(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func jsonError(w http.ResponseWriter, status int, msg, id string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg, "request_id": id})
}
