// Package export sends Sentinel's security events to other systems: a
// syslog server (RFC 5424, over UDP, TCP or TLS) and an OpenTelemetry
// collector (OTLP over HTTP, JSON). Both run in the background and never
// slow a request down: when the other side can't keep up, events are
// dropped and counted.
package export

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"sentinel/gateway/internal/events"
)

// Wanted: which events are sent. By default every decision except plain
// allowed requests; all = every request.
func Wanted(e events.Event, all bool) bool {
	return all || e.Outcome != "allowed"
}

// Severity of an event, for syslog and OpenTelemetry.
func severity(e events.Event) (syslog int, otelNum int, otelText string) {
	switch {
	case e.Stopped():
		return 4, 13, "WARN" // warning
	case e.Outcome == "detected" || e.Outcome == "monitored":
		return 5, 10, "INFO" // notice
	default:
		return 6, 9, "INFO" // informational
	}
}

func message(e events.Event) string {
	msg := e.Outcome + " " + e.Method + " " + printable(e.Path) + " from " + e.ClientIP
	if e.Rule != "" {
		msg += " rule=" + e.Rule
	}
	if e.Reason != "" {
		msg += " reason=" + strconv.Quote(e.Reason)
	}
	return msg
}

// printable escapes control characters. A request path is the attacker's
// text (a "%0a" in the URL decodes to a newline), and a log receiver that
// splits on lines must not be fed a forged second event.
func printable(v string) string {
	if strings.IndexFunc(v, func(r rune) bool { return r < 0x20 || r == 0x7f }) < 0 {
		return v
	}
	var b strings.Builder
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			fmt.Fprintf(&b, `\x%02x`, r)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// ---- syslog ---------------------------------------------------------------

// Syslog sends events to a syslog server as RFC 5424 messages with the
// event as structured data.
type Syslog struct {
	Network string // udp, tcp or tls
	Addr    string
	All     bool
	Log     *slog.Logger

	host     string
	conn     net.Conn
	nextDial time.Time // after a failed connection, wait before trying again
	dropped  atomic.Int64
}

// ParseSyslog reads "udp://host:514", "tcp://host:601" or "tls://host:6514".
func ParseSyslog(raw string) (*Syslog, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "udp" && u.Scheme != "tcp" && u.Scheme != "tls") {
		return nil, fmt.Errorf("syslog address %q: use udp://host:514, tcp://host:601 or tls://host:6514", raw)
	}
	if u.Port() == "" || u.Hostname() == "" {
		return nil, fmt.Errorf("syslog address %q needs a host and a port", raw)
	}
	return &Syslog{Network: u.Scheme, Addr: u.Host}, nil
}

func (s *Syslog) dial() error {
	var err error
	d := &net.Dialer{Timeout: 5 * time.Second}
	switch s.Network {
	case "tls":
		host, _, _ := net.SplitHostPort(s.Addr)
		s.conn, err = tls.DialWithDialer(d, "tcp", s.Addr, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	default:
		s.conn, err = d.Dial(s.Network, s.Addr)
	}
	return err
}

// Format is one RFC 5424 line (without framing).
func (s *Syslog) Format(e events.Event) []byte {
	sev, _, _ := severity(e)
	const facility = 13 // log audit
	sd := `[sentinel@32473`
	add := func(k, v string) {
		if v == "" {
			return
		}
		v = strings.NewReplacer(`\`, `\\`, `"`, `\"`, `]`, `\]`).Replace(printable(v))
		sd += " " + k + `="` + v + `"`
	}
	add("outcome", e.Outcome)
	add("ip", e.ClientIP)
	add("method", e.Method)
	add("path", e.Path)
	add("status", strconv.Itoa(e.Status))
	add("rule", e.Rule)
	add("site", e.Site)
	add("country", e.Country)
	add("user", e.User)
	add("request_id", e.RequestID)
	sd += "]"
	host := s.host
	if host == "" {
		host = "-"
	}
	return fmt.Appendf(nil, "<%d>1 %s %s sentinel - %s %s %s", facility*8+sev,
		e.Time.UTC().Format(time.RFC3339Nano), host, strings.ToLower(e.Outcome), sd, message(e))
}

// Watch sends events until ctx ends.
func (s *Syslog) Watch(ctx context.Context, hub *events.Hub) {
	s.host, _ = os.Hostname()
	ch, stop := hub.Subscribe()
	defer stop()
	go s.reportDrops(ctx)
	for {
		select {
		case <-ctx.Done():
			if s.conn != nil {
				s.conn.Close()
			}
			return
		case e := <-ch:
			if Wanted(e, s.All) {
				s.send(s.Format(e))
			}
		}
	}
}

func (s *Syslog) send(line []byte) {
	if s.conn == nil {
		if time.Now().Before(s.nextDial) {
			s.dropped.Add(1)
			return
		}
		if err := s.dial(); err != nil {
			s.nextDial = time.Now().Add(10 * time.Second)
			s.dropped.Add(1)
			return
		}
	}
	msg := line
	if s.Network != "udp" { // RFC 6587 octet counting
		msg = append([]byte(strconv.Itoa(len(line))+" "), line...)
	}
	s.conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if _, err := s.conn.Write(msg); err != nil {
		s.conn.Close()
		s.conn = nil
		s.dropped.Add(1)
	}
}

func (s *Syslog) reportDrops(ctx context.Context) {
	reportDrops(ctx, &s.dropped, s.Log, "syslog")
}

func reportDrops(ctx context.Context, n *atomic.Int64, log *slog.Logger, what string) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if d := n.Swap(0); d > 0 && log != nil {
				log.Warn("export: events not delivered", "to", what, "count", d)
			}
		}
	}
}

// ---- OpenTelemetry ------------------------------------------------------------

// OTLP sends events as OpenTelemetry log records to a collector's
// /v1/logs endpoint (OTLP over HTTP with JSON), in batches.
type OTLP struct {
	Endpoint string            // e.g. http://collector:4318 (/v1/logs is added)
	Headers  map[string]string // e.g. an API key
	All      bool
	Log      *slog.Logger
	Client   *http.Client
	Every    time.Duration // how often a batch is sent; default 2s

	dropped atomic.Int64
}

// ParseOTLP reads the endpoint and "Key=Value,Key2=Value2" headers.
func ParseOTLP(endpoint, headers string) (*OTLP, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("OpenTelemetry endpoint %q: use http://collector:4318", endpoint)
	}
	if !strings.HasSuffix(u.Path, "/v1/logs") {
		u.Path = strings.TrimSuffix(u.Path, "/") + "/v1/logs"
	}
	o := &OTLP{Endpoint: u.String(), Headers: map[string]string{}}
	for _, kv := range strings.Split(headers, ",") {
		if strings.TrimSpace(kv) == "" {
			continue
		}
		k, v, ok := strings.Cut(kv, "=")
		if !ok || strings.TrimSpace(k) == "" {
			return nil, fmt.Errorf("OpenTelemetry headers: %q should be Name=value", kv)
		}
		o.Headers[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return o, nil
}

type kv struct {
	Key   string `json:"key"`
	Value any    `json:"value"`
}

func str(k, v string) kv { return kv{k, map[string]string{"stringValue": v}} }

// Body is the OTLP JSON request for a batch of events.
func (o *OTLP) Body(evs []events.Event) []byte {
	host, _ := os.Hostname()
	records := make([]map[string]any, 0, len(evs))
	for _, e := range evs {
		_, num, text := severity(e)
		attrs := []kv{str("sentinel.outcome", e.Outcome), str("client.address", e.ClientIP),
			str("http.request.method", e.Method), str("url.path", e.Path),
			{"http.response.status_code", map[string]string{"intValue": strconv.Itoa(e.Status)}}}
		for k, v := range map[string]string{"sentinel.rule": e.Rule, "sentinel.reason": e.Reason, "sentinel.site": e.Site,
			"client.geo.country_iso_code": e.Country, "user.name": e.User, "sentinel.request_id": e.RequestID} {
			if v != "" {
				attrs = append(attrs, str(k, v))
			}
		}
		records = append(records, map[string]any{
			"timeUnixNano":   strconv.FormatInt(e.Time.UnixNano(), 10),
			"severityNumber": num, "severityText": text,
			"body":       map[string]string{"stringValue": message(e)},
			"attributes": attrs,
		})
	}
	b, _ := json.Marshal(map[string]any{"resourceLogs": []any{map[string]any{
		"resource":  map[string]any{"attributes": []kv{str("service.name", "sentinel"), str("host.name", host)}},
		"scopeLogs": []any{map[string]any{"scope": map[string]string{"name": "sentinel"}, "logRecords": records}},
	}}})
	return b
}

// Watch sends events in batches until ctx ends.
func (o *OTLP) Watch(ctx context.Context, hub *events.Hub) {
	if o.Client == nil {
		o.Client = &http.Client{Timeout: 10 * time.Second}
	}
	if o.Every <= 0 {
		o.Every = 2 * time.Second
	}
	ch, stop := hub.Subscribe()
	defer stop()
	go reportDrops(ctx, &o.dropped, o.Log, "opentelemetry")
	t := time.NewTicker(o.Every)
	defer t.Stop()
	var batch []events.Event
	for {
		select {
		case <-ctx.Done():
			o.post(batch)
			return
		case e := <-ch:
			if Wanted(e, o.All) {
				batch = append(batch, e)
			}
			if len(batch) >= 500 {
				o.post(batch)
				batch = nil
			}
		case <-t.C:
			if len(batch) > 0 {
				o.post(batch)
				batch = nil
			}
		}
	}
}

func (o *OTLP) post(batch []events.Event) {
	if len(batch) == 0 {
		return
	}
	req, err := http.NewRequest(http.MethodPost, o.Endpoint, bytes.NewReader(o.Body(batch)))
	if err != nil {
		o.dropped.Add(int64(len(batch)))
		return
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range o.Headers {
		req.Header.Set(k, v)
	}
	res, err := o.Client.Do(req)
	if err != nil {
		o.dropped.Add(int64(len(batch)))
		return
	}
	res.Body.Close()
	if res.StatusCode >= 300 {
		o.dropped.Add(int64(len(batch)))
	}
}
