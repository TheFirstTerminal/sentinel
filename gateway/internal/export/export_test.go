package export

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"sentinel/gateway/internal/events"
)

func attack() events.Event {
	return events.Event{Time: time.Now(), ClientIP: "203.0.113.9", Method: "GET", Path: "/search",
		Status: 403, Outcome: "blocked", Rule: "SQLI-001", Reason: `SQL "injection"`, Site: "shop", RequestID: "r1"}
}

func TestSyslogOverTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan string, 4)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		r := bufio.NewReader(c)
		for {
			var n int
			if _, err := fmtSscan(r, &n); err != nil {
				return
			}
			b := make([]byte, n)
			if _, err := io.ReadFull(r, b); err != nil {
				return
			}
			got <- string(b)
		}
	}()
	s, err := ParseSyslog("tcp://" + ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	hub := events.NewHub(10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Watch(ctx, hub)
	time.Sleep(50 * time.Millisecond)
	hub.Publish(events.Event{Time: time.Now(), Outcome: "allowed", Path: "/"}) // not exported
	hub.Publish(attack())
	select {
	case line := <-got:
		for _, want := range []string{"<108>1 ", " sentinel - blocked [sentinel@32473 ", `rule="SQLI-001"`, `site="shop"`, `reason="SQL \"injection\""`, "blocked GET /search from 203.0.113.9"} {
			if !strings.Contains(line, want) {
				t.Errorf("syslog line lacks %q:\n%s", want, line)
			}
		}
	case <-time.After(3 * time.Second):
		t.Fatal("nothing reached the syslog server")
	}
	select {
	case line := <-got:
		t.Errorf("an allowed request was exported: %s", line)
	case <-time.After(100 * time.Millisecond):
	}
}

// fmtSscan reads "123 " (the octet count) from r.
func fmtSscan(r *bufio.Reader, n *int) (int, error) {
	s, err := r.ReadString(' ')
	if err != nil {
		return 0, err
	}
	v := 0
	for _, c := range strings.TrimSpace(s) {
		v = v*10 + int(c-'0')
	}
	*n = v
	return 1, nil
}

func TestOTLP(t *testing.T) {
	bodies := make(chan map[string]any, 2)
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/logs" {
			t.Errorf("path %s", r.URL.Path)
		}
		auth = r.Header.Get("Api-Key")
		var m map[string]any
		json.NewDecoder(r.Body).Decode(&m)
		bodies <- m
	}))
	defer srv.Close()
	o, err := ParseOTLP(srv.URL, "Api-Key=abc")
	if err != nil {
		t.Fatal(err)
	}
	o.Every = 50 * time.Millisecond
	hub := events.NewHub(10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go o.Watch(ctx, hub)
	time.Sleep(50 * time.Millisecond)
	hub.Publish(attack())
	select {
	case m := <-bodies:
		b, _ := json.Marshal(m)
		for _, want := range []string{`"service.name"`, `"stringValue":"sentinel"`, `"severityText":"WARN"`, `"sentinel.rule"`, `"SQLI-001"`, `"client.address"`} {
			if !strings.Contains(string(b), want) {
				t.Errorf("OTLP body lacks %s:\n%s", want, b)
			}
		}
		if auth != "abc" {
			t.Errorf("header not sent: %q", auth)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("nothing reached the collector")
	}
}

func TestParse(t *testing.T) {
	for _, bad := range []string{"host:514", "udp://host", "http://host:514", "udp://:514"} {
		if _, err := ParseSyslog(bad); err == nil {
			t.Errorf("syslog %q must be refused", bad)
		}
	}
	if s, err := ParseSyslog("udp://logs.example.com:514"); err != nil || s.Network != "udp" {
		t.Errorf("udp: %v %v", s, err)
	}
	if _, err := ParseOTLP("collector:4318", ""); err == nil {
		t.Error("an OTLP endpoint without http:// must be refused")
	}
	if _, err := ParseOTLP("http://c:4318", "nokey"); err == nil {
		t.Error("a header without = must be refused")
	}
	if o, _ := ParseOTLP("https://c.example.com/otlp/", ""); o.Endpoint != "https://c.example.com/otlp/v1/logs" {
		t.Errorf("endpoint %s", o.Endpoint)
	}
}
