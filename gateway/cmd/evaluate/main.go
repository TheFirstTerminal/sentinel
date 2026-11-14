// evaluate measures how well a running Sentinel protects an app, from the
// outside, like an attacker would: it replays attacks (and the same attacks
// rewritten to evade filters) and normal input at the app directly and
// through Sentinel, and measures how much time Sentinel adds.
//
//	evaluate -direct http://juice-shop:3000 -gateway http://gateway:8080 -out evaluation.md
//
// The lab runs it in a container (bash lab/evaluate.sh), together with
// sqlmap, a real attack tool.
package main

import (
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"sentinel/gateway/internal/ml/dataset"
	"sentinel/gateway/internal/ml/evasion"
)

var client = &http.Client{Timeout: 15 * time.Second}

func main() {
	direct := flag.String("direct", "http://localhost:3000", "the app, unprotected")
	gateway := flag.String("gateway", "http://localhost:8080", "the app through Sentinel")
	path := flag.String("path", "/rest/products/search?q=", "where payloads are sent (appended, URL-encoded)")
	n := flag.Int("n", 1000, "attacks (and as many normal inputs) to send")
	out := flag.String("out", "evaluation.md", "report file")
	flag.Parse()

	var rep strings.Builder
	fmt.Fprintf(&rep, "# Sentinel evaluation\n\nRun %s against `%s` (direct) and `%s` (through Sentinel), payloads sent to `%s`.\n\nThe replay uses generated attacks (a different seed than the ML model was trained on) and the same attacks rewritten with evasion techniques. Section 3, if present, is from sqlmap, a real attack tool.\n\n",
		time.Now().Format("2006-01-02 15:04"), *direct, *gateway, *path)

	if code := status(*gateway + "/__sentinel/health"); code != 200 {
		fmt.Fprintf(os.Stderr, "Sentinel is not reachable at %s (HTTP %d)\n", *gateway, code)
		os.Exit(1)
	}

	// 1. Replay.
	data := dataset.Generate(*n, 5) // a seed the model was not trained on
	r := rand.New(rand.NewSource(6))
	type row struct {
		name           string
		sent, stopped  int
		directRefused  int
		examplesMissed []string
	}
	rows := map[string]*row{}
	get := func(k string) *row {
		if rows[k] == nil {
			rows[k] = &row{name: k}
		}
		return rows[k]
	}
	type job struct {
		text, group string
	}
	var jobs []job
	for _, e := range data {
		if e.Attack {
			jobs = append(jobs, job{e.Text, "attack: " + e.Family})
			ev, _ := evasion.Apply(r, e.Text)
			jobs = append(jobs, job{ev, "evasion"})
		} else {
			jobs = append(jobs, job{e.Text, "normal"})
		}
	}
	var mu sync.Mutex
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	start := time.Now()
	for i, j := range jobs {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, j job) {
			defer wg.Done()
			defer func() { <-sem }()
			// Each request "comes from" its own address (the lab trusts
			// X-Forwarded-For from its network), so per-IP limits and bans
			// don't distort the result.
			ip := fmt.Sprintf("10.%d.%d.%d", 100+i/65025%100, i/255%255, i%255+1)
			g := statusFrom(*gateway+*path+url.QueryEscape(j.text), ip)
			d := statusFrom(*direct+*path+url.QueryEscape(j.text), ip)
			mu.Lock()
			defer mu.Unlock()
			for _, k := range []string{j.group, groupOf(j.group)} {
				x := get(k)
				x.sent++
				if stopped(g) {
					x.stopped++
				}
				// Examples worth reading: attacks that got through, and
				// normal input that was wrongly stopped.
				interesting := (k == "normal") == stopped(g)
				if interesting && len(x.examplesMissed) < 5 && k != "all attacks" {
					x.examplesMissed = append(x.examplesMissed, j.text)
				}
				if d >= 400 || d == 0 {
					x.directRefused++
				}
			}
		}(i, j)
	}
	wg.Wait()

	all, ev, norm := get("all attacks"), get("evasion"), get("normal")
	fmt.Fprintf(&rep, "## 1. Attack replay\n\n%d requests in %s. \"Stopped\" means Sentinel refused the request (400, 401, 403, 429 or 502), so the app never saw it.\n\n",
		len(jobs)*2, time.Since(start).Round(time.Second))
	fmt.Fprintf(&rep, "| Traffic | Sent | Stopped by Sentinel |\n|---|---|---|\n")
	fmt.Fprintf(&rep, "| Attacks | %d | **%s** |\n", all.sent, pct(all.stopped, all.sent))
	fmt.Fprintf(&rep, "| Attacks rewritten to evade filters | %d | **%s** |\n", ev.sent, pct(ev.stopped, ev.sent))
	fmt.Fprintf(&rep, "| Normal input (should pass) | %d | **%s** wrongly stopped |\n", norm.sent, pct(norm.stopped, norm.sent))

	fmt.Fprintf(&rep, "\n### Per attack family\n\n| Family | Sent | Stopped |\n|---|---|---|\n")
	var fams []string
	for k := range rows {
		if strings.HasPrefix(k, "attack: ") {
			fams = append(fams, k)
		}
	}
	sort.Strings(fams)
	for _, k := range fams {
		fmt.Fprintf(&rep, "| %s | %d | %s |\n", strings.TrimPrefix(k, "attack: "), rows[k].sent, pct(rows[k].stopped, rows[k].sent))
	}
	list := func(title string, items []string) {
		if len(items) == 0 {
			return
		}
		fmt.Fprintf(&rep, "\n%s\n\n", title)
		for _, s := range items {
			fmt.Fprintf(&rep, "- `%s`\n", strings.ReplaceAll(cut(s, 110), "`", "'"))
		}
	}
	var missed []string
	for _, k := range fams {
		missed = append(missed, rows[k].examplesMissed...)
	}
	list("Attacks that got through (examples):", first(missed, 8))
	list("Evasion variants that got through (examples):", ev.examplesMissed)
	list("Normal input wrongly stopped (examples):", norm.examplesMissed)

	// 2. Overhead.
	fmt.Fprintf(&rep, "\n## 2. Time Sentinel adds\n\n300 normal searches, one at a time, to each.\n\n| | median | 95th percentile | 99th percentile |\n|---|---|---|---|\n")
	for _, t := range []struct{ name, base string }{{"Direct", *direct}, {"Through Sentinel", *gateway}} {
		var ds []time.Duration
		for i := 0; i < 300; i++ {
			q := []string{"apple", "banana juice", "melon", "O'Brien", "green tea 500ml"}[i%5]
			t0 := time.Now()
			statusFrom(t.base+*path+url.QueryEscape(q), fmt.Sprintf("10.250.%d.%d", i/250, i%250+1))
			ds = append(ds, time.Since(t0))
		}
		sort.Slice(ds, func(a, b int) bool { return ds[a] < ds[b] })
		fmt.Fprintf(&rep, "| %s | %s | %s | %s |\n", t.name, ms(ds[len(ds)/2]), ms(ds[len(ds)*95/100]), ms(ds[len(ds)*99/100]))
	}

	if err := os.WriteFile(*out, []byte(rep.String()), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Print(rep.String())
}

func groupOf(g string) string {
	if strings.HasPrefix(g, "attack: ") {
		return "all attacks"
	}
	return "-" + g
}

func stopped(code int) bool {
	switch code {
	case 400, 401, 403, 429, 502:
		return true
	}
	return false
}

func status(u string) int { return statusFrom(u, "") }

func statusFrom(u, ip string) int {
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return 0
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (sentinel-evaluate)")
	if ip != "" {
		req.Header.Set("X-Forwarded-For", ip)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

func pct(a, b int) string {
	if b == 0 {
		return "–"
	}
	return fmt.Sprintf("%.1f%% (%d/%d)", 100*float64(a)/float64(b), a, b)
}

func ms(d time.Duration) string { return fmt.Sprintf("%.1f ms", float64(d.Microseconds())/1000) }

func cut(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

func first(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
