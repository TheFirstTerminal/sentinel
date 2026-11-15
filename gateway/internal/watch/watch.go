// Package watch is the live "behind the scenes" window:
//
//	sentinel watch /logs/sentinel.log
//
// It follows Sentinel's log file and prints one coloured line per request,
// saying what Sentinel decided and why.
package watch

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

const (
	reset   = "\x1b[0m"
	bold    = "\x1b[1m"
	dim     = "\x1b[2m"
	red     = "\x1b[1;31m"
	green   = "\x1b[1;32m"
	yellow  = "\x1b[1;33m"
	magenta = "\x1b[1;35m"
	cyan    = "\x1b[1;36m"
)

type Options struct {
	Color     bool // ANSI colours
	All       bool // also show static files and health checks
	FromStart bool // replay the whole file instead of only new lines
}

type entry struct {
	Msg      string  `json:"msg"`
	Time     string  `json:"time"`
	Method   string  `json:"method"`
	Path     string  `json:"path"`
	Status   int     `json:"status"`
	Outcome  string  `json:"outcome"`
	Reason   string  `json:"reason"`
	Rule     string  `json:"rule"`
	Detail   string  `json:"detail"`
	User     string  `json:"user"`
	Role     string  `json:"role"`
	MFA      bool    `json:"mfa"`
	Country  string  `json:"country"`
	Risk     *int    `json:"risk"`
	Site     string  `json:"site"`
	Duration float64 `json:"duration_ms"`
}

type style struct{ icon, label, color string }

var styles = map[string]style{
	"allowed":          {"✓", "ALLOWED", green},
	"blocked":          {"✗", "BLOCKED", red},
	"detected":         {"!", "DETECTED", yellow},
	"honeypot":         {"☠", "HONEYPOT", magenta},
	"banned":           {"⊘", "BANNED", red},
	"unauthenticated":  {"✗", "NO LOGIN", red},
	"denied":           {"✗", "DENIED", red},
	"invalid":          {"✗", "INVALID", red},
	"login":            {"✓", "LOGIN", green},
	"login_failed":     {"✗", "LOGIN FAIL", red},
	"mfa_required":     {"…", "2FA WAIT", yellow},
	"mfa_ok":           {"✓", "2FA OK", green},
	"mfa_failed":       {"✗", "2FA FAIL", red},
	"rate_limited":     {"⏱", "TOO MANY", red},
	"geo_blocked":      {"⊘", "GEO BLOCK", red},
	"step_up":          {"…", "NEED 2FA", yellow},
	"risk_blocked":     {"✗", "RISK", red},
	"mtls_required":    {"✗", "NO CERT", red},
	"prompt_injection": {"✗", "PROMPT INJ", red},
	"leak_blocked":     {"✗", "LEAK", red},
	"ml_blocked":       {"✗", "ML", red},
	"monitored":        {"◐", "WOULD BLOCK", yellow},
	"challenged":       {"?", "CHALLENGE", yellow},
}

// Format turns one log line into display text ("" = don't show).
func Format(line []byte, opt Options) string {
	var e entry
	if json.Unmarshal(line, &e) != nil || e.Msg != "request" {
		return ""
	}
	if e.Outcome == "" {
		e.Outcome = "allowed"
	}
	if !opt.All && e.Outcome == "allowed" && noise(e.Path) {
		return ""
	}
	st, ok := styles[e.Outcome]
	if !ok {
		st = style{"•", strings.ToUpper(e.Outcome), cyan}
	}
	c := func(code, s string) string {
		if !opt.Color {
			return s
		}
		return code + s + reset
	}

	ts := e.Time
	if t, err := time.Parse(time.RFC3339Nano, e.Time); err == nil {
		ts = t.Format("15:04:05")
	}
	path := e.Path
	if len(path) > 28 {
		path = path[:25] + "..."
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s  %s  %-6s %-28s %s", c(dim, ts), c(st.color, fmt.Sprintf("%s %-10s", st.icon, st.label)), e.Method, path, c(dim, fmt.Sprint(e.Status)))

	// What to say after the path.
	var why []string
	if e.Rule != "" && e.Outcome != "allowed" {
		why = append(why, c(bold, e.Rule))
	}
	if e.Reason != "" && e.Outcome != "allowed" {
		why = append(why, e.Reason)
	}
	if e.User != "" {
		who := e.User + " (" + e.Role
		if e.MFA {
			who += ", 2FA"
		}
		why = append(why, c(cyan, who+")"))
	}
	if e.Country != "" && e.Country != "LAN" {
		why = append(why, c(dim, "from "+e.Country))
	}
	if e.Risk != nil && *e.Risk > 0 && e.Outcome != "step_up" && e.Outcome != "risk_blocked" {
		why = append(why, c(dim, fmt.Sprintf("risk %d", *e.Risk)))
	}
	if e.Site != "" {
		why = append(why, c(dim, "site "+e.Site))
	}
	if len(why) > 0 {
		b.WriteString("  " + strings.Join(why, "  "))
	}
	if e.Detail != "" && e.Outcome != "allowed" {
		b.WriteString("\n" + strings.Repeat(" ", 24) + c(dim, e.Detail))
	}
	return b.String()
}

// noise: static files the browser loads in bulk, and health checks.
func noise(p string) bool {
	if p == "/__sentinel/health" || strings.HasPrefix(p, "/__sentinel/api/") || strings.HasPrefix(p, "/__sentinel/dashboard") || strings.HasPrefix(p, "/socket.io/") || strings.HasPrefix(p, "/assets/") {
		return true
	}
	for _, ext := range []string{".js", ".css", ".png", ".jpg", ".jpeg", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".map", ".gif"} {
		if strings.HasSuffix(p, ext) {
			return true
		}
	}
	return false
}

// Banner is printed when the window opens.
func Banner(opt Options) string {
	line := strings.Repeat("═", 72)
	title := " SENTINEL · LIVE DECISIONS   (green = let through, red = stopped)"
	if opt.Color {
		return cyan + line + "\n" + title + "\n" + line + reset + "\n"
	}
	return line + "\n" + title + "\n" + line + "\n"
}

// Follow prints new lines of the file as they are written, until ctx ends.
// It survives the file not existing yet and the file being truncated.
func Follow(ctx context.Context, path string, out io.Writer, opt Options) error {
	fmt.Fprint(out, Banner(opt))
	var (
		f       *os.File
		offset  int64
		partial []byte
	)
	defer func() {
		if f != nil {
			f.Close()
		}
	}()
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	first := true

	for {
		if f == nil {
			if opened, err := os.Open(path); err == nil {
				f = opened
				if first && !opt.FromStart {
					offset, _ = f.Seek(0, io.SeekEnd)
				}
				first = false
			}
		}
		if f != nil {
			if st, err := f.Stat(); err == nil && st.Size() < offset {
				offset, partial = 0, nil // truncated or replaced
			}
			f.Seek(offset, io.SeekStart)
			r := bufio.NewReader(f)
			for {
				chunk, err := r.ReadBytes('\n')
				offset += int64(len(chunk))
				if err != nil {
					partial = append(partial, chunk...)
					break
				}
				line := append(partial, chunk...)
				partial = nil
				if s := Format(line, opt); s != "" {
					fmt.Fprintln(out, s)
				}
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}
