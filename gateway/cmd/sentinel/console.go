package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"

	"sentinel/gateway/internal/watch"
)

// consoleWriter turns Sentinel's JSON log lines into readable ones for a
// person watching a terminal: one line per decision (the same format as
// `sentinel watch`), plus startup messages. Log files always stay JSON.
type consoleWriter struct {
	mu    sync.Mutex
	out   io.Writer
	buf   []byte
	color bool
}

func (c *consoleWriter) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.buf = append(c.buf, p...)
	for {
		i := bytes.IndexByte(c.buf, '\n')
		if i < 0 {
			break
		}
		if s := c.format(c.buf[:i]); s != "" {
			fmt.Fprintln(c.out, s)
		}
		c.buf = c.buf[i+1:]
	}
	return len(p), nil
}

// Events the per-request line already explains.
var consoleSkip = map[string]bool{"waf_event": true, "ml_event": true, "honeypot_hit": true, "prompt_event": true}

func (c *consoleWriter) format(line []byte) string {
	if s := watch.Format(line, watch.Options{Color: c.color}); s != "" {
		return s
	}
	var m map[string]any
	if json.Unmarshal(line, &m) != nil {
		return string(line)
	}
	msg, _ := m["msg"].(string)
	if msg == "request" || consoleSkip[msg] {
		return ""
	}
	level, _ := m["level"].(string)
	var extra []string
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if k == "time" || k == "level" || k == "msg" || m[k] == "" {
			continue
		}
		extra = append(extra, fmt.Sprintf("%s=%v", k, m[k]))
	}
	tag := map[string]string{"INFO": "·", "WARN": "!", "ERROR": "✗"}[level]
	if tag == "" {
		tag = "·"
	}
	s := fmt.Sprintf("%s %s", tag, msg)
	if len(extra) > 0 {
		s += "  " + strings.Join(extra, " ")
	}
	if c.color && level != "INFO" {
		s = "\x1b[33m" + s + "\x1b[0m"
	}
	return s
}

// consoleFormat decides between "pretty" and "json" for standard output.
func consoleFormat() string {
	switch strings.ToLower(os.Getenv("LOG_FORMAT")) {
	case "json":
		return "json"
	case "pretty", "text":
		return "pretty"
	}
	if fi, err := os.Stdout.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
		return "pretty" // a person is watching a terminal
	}
	return "json"
}
