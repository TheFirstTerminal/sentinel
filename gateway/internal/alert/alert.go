// Package alert sends a message to Slack, Discord, Telegram or any webhook
// when something needs a person: a honeypot hit, a burst of attacks from
// one IP, password guessing, a new admin account, a failed reload.
//
// Alerts are rate-limited per subject (one per IP per cooldown) and in
// total, and sent from a queue: a slow webhook never slows requests, and an
// attack can't be turned into a flood of messages.
package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"

	"sentinel/gateway/internal/events"
)

// Alerter sends alerts.
type Alerter struct {
	URL      string // webhook URL (Slack, Discord, Telegram sendMessage, or any)
	ChatID   string // Telegram chat ID
	Burst    int    // stopped requests from one IP within a minute that make an alert
	Cooldown time.Duration
	Log      *slog.Logger
	Client   *http.Client
	Name     string // shown in messages, e.g. the host name

	queue chan Message
	mu    sync.Mutex
	last  map[string]time.Time   // subject -> last alert
	hits  map[string][]time.Time // IP -> recent stop times
	sent  []time.Time            // for the global cap
	once  sync.Once
	cmu   sync.RWMutex // guards URL, ChatID and Burst (changed on the dashboard)
}

// Set changes where alerts go and the burst size while Sentinel runs. An
// empty url turns alerts off.
func (a *Alerter) Set(url, chatID string, burst int) {
	a.cmu.Lock()
	defer a.cmu.Unlock()
	if burst <= 0 {
		burst = 20
	}
	a.URL, a.ChatID, a.Burst = url, chatID, burst
}

// Settings returns the webhook URL, Telegram chat and burst size.
func (a *Alerter) Settings() (url, chatID string, burst int) {
	if a == nil {
		return "", "", 0
	}
	a.cmu.RLock()
	defer a.cmu.RUnlock()
	return a.URL, a.ChatID, a.Burst
}

func (a *Alerter) on() bool {
	u, _, _ := a.Settings()
	return u != ""
}

// Message is one alert.
type Message struct {
	Title string         `json:"title"`
	Text  string         `json:"text"`
	Event map[string]any `json:"event,omitempty"`
}

const maxPerMinute = 20

func (a *Alerter) init() {
	a.once.Do(func() {
		a.queue = make(chan Message, 100)
		a.last = map[string]time.Time{}
		a.hits = map[string][]time.Time{}
		if a.Client == nil {
			a.Client = SafeClient()
		}
		if a.Cooldown <= 0 {
			a.Cooldown = 10 * time.Minute
		}
		a.cmu.Lock()
		if a.Burst <= 0 {
			a.Burst = 20
		}
		a.cmu.Unlock()
		go a.sender()
	})
}

// Send queues an alert about subject unless one was sent within the
// cooldown. It never blocks.
func (a *Alerter) Send(subject string, m Message) {
	if a == nil || !a.on() {
		return
	}
	a.init()
	now := time.Now()
	a.mu.Lock()
	if t, ok := a.last[subject]; ok && now.Sub(t) < a.Cooldown {
		a.mu.Unlock()
		return
	}
	// Global cap: at most maxPerMinute alerts a minute.
	keep := a.sent[:0]
	for _, t := range a.sent {
		if now.Sub(t) < time.Minute {
			keep = append(keep, t)
		}
	}
	a.sent = keep
	if len(a.sent) >= maxPerMinute {
		a.mu.Unlock()
		return
	}
	a.sent = append(a.sent, now)
	a.last[subject] = now
	a.mu.Unlock()
	select {
	case a.queue <- m:
	default:
		a.Log.Warn("alert queue full, alert dropped", "title", m.Title)
	}
}

// Watch turns live events into alerts until ctx ends. Events are ignored
// while alerts are off (no URL), so alerts can be turned on later.
func (a *Alerter) Watch(ctx context.Context, hub *events.Hub) {
	if a == nil {
		return
	}
	a.init()
	ch, stop := hub.Subscribe()
	defer stop()
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-ch:
			if a.on() {
				a.handle(e)
			}
		}
	}
}

func (a *Alerter) handle(e events.Event) {
	where := e.Method + " " + e.Path
	switch {
	case e.Outcome == "honeypot":
		a.Send("honeypot:"+e.ClientIP, Message{
			Title: "Honeypot touched, IP banned",
			Text:  fmt.Sprintf("%s requested %s (a trap no real user visits) and is now banned.%s", e.ClientIP, e.Path, country(e)),
			Event: ev(e)})
	case e.Outcome == "rate_limited" && e.Rule == "login-guard":
		a.Send("guessing:"+e.User, Message{
			Title: "Password guessing on an account",
			Text:  fmt.Sprintf("Too many failed logins for %q; logins for it are paused. Latest from %s.", e.User, e.ClientIP),
			Event: ev(e)})
	case e.Stopped() || e.Outcome == "monitored" || e.Outcome == "detected":
		a.mu.Lock()
		now := time.Now()
		list := a.hits[e.ClientIP]
		keep := list[:0]
		for _, t := range list {
			if now.Sub(t) < time.Minute {
				keep = append(keep, t)
			}
		}
		keep = append(keep, now)
		a.hits[e.ClientIP] = keep
		n := len(keep)
		if len(a.hits) > 10000 { // forget idle IPs
			for ip, l := range a.hits {
				if len(l) == 0 || now.Sub(l[len(l)-1]) > time.Minute {
					delete(a.hits, ip)
				}
			}
		}
		a.mu.Unlock()
		if _, _, burst := a.Settings(); n == burst {
			a.Send("burst:"+e.ClientIP, Message{
				Title: "Attack burst",
				Text:  fmt.Sprintf("%d requests from %s stopped in the last minute. Latest: %s, %s %s.%s", n, e.ClientIP, where, e.Rule, e.Reason, country(e)),
				Event: ev(e)})
		}
	}
}

func country(e events.Event) string {
	if e.Country != "" && e.Country != "LAN" {
		return " Country: " + e.Country + "."
	}
	return ""
}

func ev(e events.Event) map[string]any {
	return map[string]any{"time": e.Time, "client_ip": e.ClientIP, "method": e.Method, "path": e.Path,
		"outcome": e.Outcome, "rule": e.Rule, "reason": e.Reason, "request_id": e.RequestID}
}

func (a *Alerter) sender() {
	for m := range a.queue {
		body, ctype := a.payload(m)
		var err error
		for attempt := 0; attempt < 2; attempt++ {
			if err = a.post(body, ctype); err == nil {
				break
			}
			time.Sleep(2 * time.Second)
		}
		if err != nil {
			a.Log.Warn("alert not delivered", "error", err.Error(), "title", m.Title)
		}
	}
}

func (a *Alerter) post(body []byte, ctype string) error {
	target, _, _ := a.Settings()
	if target == "" {
		return nil // turned off while the alert waited
	}
	res, err := a.Client.Post(target, ctype, bytes.NewReader(body))
	if err != nil {
		return err
	}
	res.Body.Close()
	if res.StatusCode >= 300 {
		return fmt.Errorf("webhook answered %s", res.Status)
	}
	return nil
}

// payload formats the message for the kind of webhook the URL points at.
func (a *Alerter) payload(m Message) ([]byte, string) {
	name := "Sentinel"
	if a.Name != "" {
		name += " (" + a.Name + ")"
	}
	text := "🚨 " + name + ": " + m.Title + "\n" + m.Text
	target, chatID, _ := a.Settings()
	u, _ := url.Parse(target)
	host := ""
	if u != nil {
		host = strings.ToLower(u.Host)
	}
	var v any
	switch {
	case strings.HasSuffix(host, "hooks.slack.com"):
		v = map[string]any{"text": text}
	case strings.HasSuffix(host, "discord.com") || strings.HasSuffix(host, "discordapp.com"):
		v = map[string]any{"content": text}
	case host == "api.telegram.org":
		v = map[string]any{"chat_id": chatID, "text": text}
	default:
		v = map[string]any{"source": name, "title": m.Title, "text": m.Text, "event": m.Event}
	}
	b, _ := json.Marshal(v)
	return b, "application/json"
}

// SafeClient is the HTTP client for webhooks. The URL is set on the
// dashboard, so a stolen admin session must not turn Sentinel into a way to
// reach the cloud metadata service (169.254.169.254, which hands out
// credentials) or bounce through redirects: link-local and unspecified
// addresses are refused when connecting, and redirects are not followed.
// Private addresses stay allowed (a self-hosted Mattermost or ntfy).
func SafeClient() *http.Client {
	d := &net.Dialer{Timeout: 5 * time.Second, Control: func(network, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		if ip := net.ParseIP(host); ip == nil || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
			return fmt.Errorf("webhook address %s is not allowed (link-local or metadata)", host)
		}
		return nil
	}}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialContext = d.DialContext
	return &http.Client{
		Timeout:   5 * time.Second,
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
