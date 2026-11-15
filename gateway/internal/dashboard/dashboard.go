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

// SiteStatus is one site and its servers, for the dashboard.
type SiteStatus struct {
	Name       string         `json:"name"`
	Hosts      []string       `json:"hosts"`
	Mode       string         `json:"mode"`
	ConfigMode string         `json:"config_mode"` // the mode in the config file
	WAFMode    string         `json:"waf_mode"`
	MLMode     string         `json:"ml_mode"`
	RateLimits []string       `json:"rate_limits"`
	Servers    []ServerStatus `json:"servers"`
	// Edited is what was changed on the dashboard; ConfigLimits are the
	// rate limits in the config file.
	Edited       SiteSettings      `json:"edited"`
	ConfigLimits map[string]string `json:"config_rate_limits,omitempty"`
}

// SiteSettings are a site's settings that can be changed on the dashboard.
// Empty fields keep the config file's value.
type SiteSettings struct {
	Mode       string            `json:"mode,omitempty"`
	WAFMode    string            `json:"waf_mode,omitempty"`
	MLMode     string            `json:"ml_mode,omitempty"`
	RateLimits map[string]string `json:"rate_limits,omitempty"` // path prefix -> "10/1m"
}

// Empty: nothing changed.
func (s SiteSettings) Empty() bool {
	return s.Mode == "" && s.WAFMode == "" && s.MLMode == "" && len(s.RateLimits) == 0
}

// AlertSettings are where alerts go.
type AlertSettings struct {
	WebhookURL   string `json:"webhook_url"`
	TelegramChat string `json:"telegram_chat_id,omitempty"`
	Burst        int    `json:"burst"`
	On           bool   `json:"on,omitempty"`  // shown: alerts are being sent
	Off          bool   `json:"off,omitempty"` // sent: turn alerts off
}

// ServerStatus is one server behind a site.
type ServerStatus struct {
	Prefix string `json:"prefix"`
	URL    string `json:"url"`
	Up     bool   `json:"up"`
}

type Dashboard struct {
	Sites     func() []SiteStatus                     // nil = not available
	SetMode   func(site, mode string) error           // switch a site between monitor and protect
	SetSite   func(site string, s SiteSettings) error // change a site's modes and rate limits
	Alerts    func() AlertSettings
	SetAlerts func(AlertSettings) error
	Hub       *events.Hub
	Bans      *blocklist.List
	Rec       Recorder
	Log       *slog.Logger
	Info      Info
	Excl      *exclude.Set           // false-alarm exclusions (nil = feature off)
	Reload    func(why string) error // reloads rules, CRS and exclusions
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
		reply(w, d.Hub.Stats(win, r.URL.Query().Get("site")))
	case path == "events" && r.Method == "GET":
		n, _ := strconv.Atoi(r.URL.Query().Get("n"))
		if n <= 0 || n > 1000 {
			n = 200
		}
		reply(w, d.Hub.Recent(n))
	case path == "history" && r.Method == "GET":
		hist := d.Hub.History()
		if hist == nil {
			jsonError(w, http.StatusNotFound, "history is not kept on disk (no usable data folder, or HISTORY_DAYS=0)", info.ID)
			return
		}
		q := r.URL.Query()
		hq := events.Query{Site: q.Get("site"), Stopped: q.Get("stopped") == "1", Text: q.Get("q")}
		hq.Limit, _ = strconv.Atoi(q.Get("limit"))
		var err error
		if v := q.Get("from"); v != "" {
			if hq.From, err = time.Parse(time.RFC3339, v); err != nil {
				jsonError(w, http.StatusBadRequest, "from: use a time like 2026-11-14T08:00:00Z", info.ID)
				return
			}
		}
		if v := q.Get("to"); v != "" {
			if hq.To, err = time.Parse(time.RFC3339, v); err != nil {
				jsonError(w, http.StatusBadRequest, "to: use a time like 2026-11-14T18:00:00Z", info.ID)
				return
			}
		}
		reply(w, hist.Query(hq))
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
	case strings.HasPrefix(path, "sites/") && strings.HasSuffix(path, "/mode") && r.Method == "POST" && d.SetMode != nil:
		name := strings.TrimSuffix(strings.TrimPrefix(path, "sites/"), "/mode")
		if name == "_" {
			name = "" // the only site, when there are no named sites
		}
		var in struct {
			Mode string `json:"mode"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&in); err != nil {
			jsonError(w, http.StatusBadRequest, `send {"mode":"protect"} or {"mode":"monitor"}`, info.ID)
			return
		}
		if err := d.SetMode(name, in.Mode); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error(), info.ID)
			return
		}
		d.audit(r, "dashboard_mode", map[string]any{"site": name, "mode": in.Mode, "by": u.Username})
		reply(w, map[string]any{"site": name, "mode": in.Mode})
	case strings.HasPrefix(path, "sites/") && strings.HasSuffix(path, "/settings") && r.Method == "PUT" && d.SetSite != nil:
		name := strings.TrimSuffix(strings.TrimPrefix(path, "sites/"), "/settings")
		if name == "_" {
			name = ""
		}
		var in SiteSettings
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&in); err != nil {
			jsonError(w, http.StatusBadRequest, `send {"mode","waf_mode","ml_mode","rate_limits":{"/login":"10/1m"}}`, info.ID)
			return
		}
		if err := d.SetSite(name, in); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error(), info.ID)
			return
		}
		d.audit(r, "dashboard_site_settings", map[string]any{"site": name, "settings": in, "by": u.Username})
		reply(w, map[string]any{"site": name, "settings": in})
	case path == "alerts" && r.Method == "GET" && d.Alerts != nil:
		reply(w, d.Alerts())
	case path == "alerts" && r.Method == "PUT" && d.SetAlerts != nil:
		var in AlertSettings
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&in); err != nil {
			jsonError(w, http.StatusBadRequest, `send {"webhook_url","telegram_chat_id","burst"} or {"off":true}`, info.ID)
			return
		}
		if err := d.SetAlerts(in); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error(), info.ID)
			return
		}
		d.audit(r, "dashboard_alerts", map[string]any{"off": in.Off, "burst": in.Burst, "by": u.Username})
		reply(w, d.Alerts())
	case path == "sites" && r.Method == "GET":
		if d.Sites == nil {
			reply(w, []SiteStatus{})
			return
		}
		reply(w, d.Sites())
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
			jsonError(w, http.StatusBadRequest, "send JSON: {rule, path, field, method, site, note}", info.ID)
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
