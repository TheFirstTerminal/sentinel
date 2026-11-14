package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"sentinel/gateway/internal/auth"
	"sentinel/gateway/internal/config"
	"sentinel/gateway/internal/crs"
	"sentinel/gateway/internal/ml"
	"sentinel/gateway/internal/ml/dataset"
	"sentinel/gateway/internal/ml/evasion"
	"sentinel/gateway/internal/waf"
)

// benchCmd measures detection and speed on this machine and writes a
// Markdown report (docs/benchmarks.md is made with it).
func benchCmd(args []string, out io.Writer) int {
	fs := flag.NewFlagSet("bench", flag.ContinueOnError)
	crsDir := fs.String("crs", crsPath(""), "OWASP CRS rules/ folder (empty = skip CRS)")
	n := fs.Int("n", 3000, "attacks (and as many normal inputs) for the detection test")
	dur := fs.Duration("duration", 5*time.Second, "how long each speed test runs")
	conc := fs.Int("c", 32, "concurrent clients in the speed test")
	file := fs.String("out", "", "write the report here instead of to the screen")
	if fs.Parse(args) != nil {
		return 2
	}
	var rep bytes.Buffer
	if err := runBench(&rep, *crsDir, *n, *dur, *conc); err != nil {
		fmt.Fprintln(out, "ERROR:", err)
		return 1
	}
	if *file != "" {
		if err := os.WriteFile(*file, rep.Bytes(), 0o644); err != nil {
			fmt.Fprintln(out, "ERROR:", err)
			return 1
		}
		fmt.Fprintln(out, "Wrote", *file)
		return 0
	}
	out.Write(rep.Bytes())
	return 0
}

func runBench(w io.Writer, crsDir string, n int, dur time.Duration, conc int) error {
	rules, err := waf.LoadRules("")
	if err != nil {
		return err
	}
	model, err := ml.Default()
	if err != nil {
		return err
	}
	var set *crs.Set
	if crsDir != "" {
		if set, err = crs.Load(crsDir, 1); err != nil {
			return err
		}
		set.Exclude([]string{"920220"}) // Sentinel's default
	}

	fmt.Fprintf(w, "# Sentinel benchmarks\n\n")
	fmt.Fprintf(w, "Made with `sentinel bench` (version %s) on %s: %d CPU cores, %s, %s/%s. Run it yourself to get numbers for your hardware.\n\n",
		Version, time.Now().Format("2006-01-02"), runtime.NumCPU(), runtime.Version(), runtime.GOOS, runtime.GOARCH)

	// 1. Detection.
	data := dataset.Generate(n, 2) // not the training seed
	r := rand.New(rand.NewSource(3))
	var attacks, evasive, normal []string
	for _, e := range data {
		if e.Attack {
			attacks = append(attacks, e.Text)
			v, _ := evasion.Apply(r, e.Text)
			evasive = append(evasive, v)
		} else {
			normal = append(normal, e.Text)
		}
	}
	type layer struct {
		name   string
		crs, m bool
	}
	layers := []layer{{"Sentinel rules", false, false}, {"Sentinel rules + ML", false, true}}
	if set != nil {
		layers = append(layers, layer{"Sentinel rules + OWASP CRS", true, false}, layer{"Sentinel rules + OWASP CRS + ML", true, true})
	}
	fmt.Fprintf(w, "## 1. Detection\n\n%d generated attacks from %d families, the same attacks rewritten with evasion techniques (encodings, comments, case, whitespace and quote tricks), and %d normal inputs (searches, names, reviews, Arabic text, passwords, JSON...). Each is sent as a search parameter with ordinary browser headers. Data: `internal/ml/dataset` (seed 2, which the ML model was not trained on).\n\n", len(attacks), len(dataset.Families()), len(normal))
	fmt.Fprintf(w, "| Layers | Attacks caught | Evasion variants caught | Normal input wrongly flagged |\n|---|---|---|---|\n")
	for _, l := range layers {
		e := waf.NewEngine(rules, 5)
		if l.crs {
			e.UseCRS(set)
		}
		hit := func(s string) bool {
			req, _ := http.NewRequest("GET", "/search?q="+url.QueryEscape(s), nil)
			req.Host = "shop.example.com"
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36")
			req.Header.Set("Accept", "text/html,application/xhtml+xml")
			if e.Inspect(req, nil).Attack {
				return true
			}
			if l.m {
				p, _ := model.ScoreText(s)
				return p >= 0.9
			}
			return false
		}
		count := func(list []string) string {
			c := 0
			for _, s := range list {
				if hit(s) {
					c++
				}
			}
			return fmt.Sprintf("%.1f%%", 100*float64(c)/float64(len(list)))
		}
		fmt.Fprintf(w, "| %s | %s | %s | %s |\n", l.name, count(attacks), count(evasive), count(normal))
	}
	fmt.Fprintf(w, "\nThe data is generated, so treat these as a comparison between layers, not a promise for real traffic. That is why new installs start in monitor mode.\n\n")

	// 2. Speed.
	fmt.Fprintf(w, "## 2. Speed\n\nA real HTTP server (the \"app\", answering with a small JSON document) and Sentinel in front of it, both on this machine. Clients send a mix of ordinary requests: a search with browser headers and cookies, a JSON POST, and a static file. Every check that applies runs (rate-limit counting, WAF, ML, response leak checks); logs go nowhere.\n\n")
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true,"items":[{"id":1,"name":"Apple Juice","price":1.99}]}`))
	}))
	defer app.Close()
	u, _ := url.Parse(app.URL)

	type setup struct {
		name string
		url  string
	}
	setups := []setup{{"App directly", app.URL}}
	mk := func(withCRS bool) (string, func(), error) {
		cfg := &config.Config{Mode: "protect", UpstreamURL: u, Upstreams: "/=" + app.URL, WAFMode: "block", WAFThreshold: 5,
			MaxBodyBytes: 1 << 20, HoneypotBan: time.Hour, RateLimits: "/=100000000/1m",
			MLMode: "block", MLThreshold: 0.9, LoginFailLimit: 10, SecurityHeaders: true, TrustedProxies: "127.0.0.0/8",
			ResponseCheck: "block", ResponseMaxBytes: 1 << 20}
		e := waf.NewEngine(rules, 5)
		if withCRS {
			e.UseCRS(set)
		}
		authSvc, err := benchAuth()
		if err != nil {
			return "", nil, err
		}
		h, err := NewHandler(cfg, e, authSvc, nil, slog.New(slog.NewJSONHandler(io.Discard, nil)))
		if err != nil {
			return "", nil, err
		}
		gw := httptest.NewServer(h)
		return gw.URL, gw.Close, nil
	}
	gw1, stop1, err := mk(false)
	if err != nil {
		return err
	}
	defer stop1()
	setups = append(setups, setup{"Through Sentinel: rules + ML", gw1})
	if set != nil {
		gw2, stop2, err := mk(true)
		if err != nil {
			return err
		}
		defer stop2()
		setups = append(setups, setup{"Through Sentinel: rules + OWASP CRS + ML", gw2})
	}

	fmt.Fprintf(w, "### Latency: one client, one request at a time\n\nWhat a single user feels.\n\n| Setup | Median | p95 | p99 | Added by Sentinel (median) |\n|---|---|---|---|---|\n")
	var base time.Duration
	for i, s := range setups {
		res := loadTest(s.url, dur/2, 1)
		if i == 0 {
			base = res.p50
			fmt.Fprintf(w, "| %s | %s | %s | %s | |\n", s.name, ms(res.p50), ms(res.p95), ms(res.p99))
			continue
		}
		fmt.Fprintf(w, "| %s | %s | %s | %s | %s |\n", s.name, ms(res.p50), ms(res.p95), ms(res.p99), ms(res.p50-base))
	}
	fmt.Fprintf(w, "\n### Throughput: %d clients at once\n\nThe most requests per second this machine handles. The load generator shares the CPU with Sentinel and the app, so a dedicated server does better; compare the rows.\n\n| Setup | Requests/s | Median | p99 |\n|---|---|---|---|\n", conc)
	for _, s := range setups {
		res := loadTest(s.url, dur, conc)
		fmt.Fprintf(w, "| %s | %.0f | %s | %s |\n", s.name, res.rps, ms(res.p50), ms(res.p99))
		if res.errors > 0 {
			fmt.Fprintf(w, "\n(%d requests failed in this run.)\n", res.errors)
		}
	}
	return nil
}

type loadResult struct {
	rps           float64
	p50, p95, p99 time.Duration
	errors        int
}

// loadTest sends the request mix from conc clients for dur.
func loadTest(base string, dur time.Duration, conc int) loadResult {
	tr := &http.Transport{MaxIdleConnsPerHost: conc * 2}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	defer tr.CloseIdleConnections()
	reqs := []func() *http.Request{
		func() *http.Request {
			r, _ := http.NewRequest("GET", base+"/products/search?q=apple+juice&page=2&sort=price", nil)
			r.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36")
			r.Header.Set("Accept", "text/html,application/xhtml+xml")
			r.Header.Set("Accept-Language", "en-US,en;q=0.9,ar;q=0.8")
			r.Header.Set("Cookie", "language=en; theme=dark; cookieconsent_status=dismiss")
			return r
		},
		func() *http.Request {
			r, _ := http.NewRequest("POST", base+"/api/basket/items", strings.NewReader(`{"productId":12,"quantity":2,"note":"Please deliver after 5pm, thanks!"}`))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("User-Agent", "Mozilla/5.0")
			r.Header.Set("Accept", "application/json")
			return r
		},
		func() *http.Request {
			r, _ := http.NewRequest("GET", base+"/assets/app.js", nil)
			r.Header.Set("User-Agent", "Mozilla/5.0")
			r.Header.Set("Accept", "*/*")
			return r
		},
	}
	var mu sync.Mutex
	var lat []time.Duration
	errs := 0
	deadline := time.Now().Add(dur)
	var wg sync.WaitGroup
	for i := 0; i < conc; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var mine []time.Duration
			bad := 0
			for k := i; time.Now().Before(deadline); k++ {
				req := reqs[k%len(reqs)]()
				req.Header.Set("X-Forwarded-For", fmt.Sprintf("10.1.%d.%d", i/250, i%250+1))
				st := time.Now()
				res, err := client.Do(req)
				if err != nil {
					bad++
					continue
				}
				io.Copy(io.Discard, res.Body)
				res.Body.Close()
				if res.StatusCode >= 400 {
					bad++
					continue
				}
				mine = append(mine, time.Since(st))
			}
			mu.Lock()
			lat = append(lat, mine...)
			errs += bad
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	sort.Slice(lat, func(a, b int) bool { return lat[a] < lat[b] })
	pct := func(p float64) time.Duration {
		if len(lat) == 0 {
			return 0
		}
		return lat[int(p*float64(len(lat)-1))]
	}
	return loadResult{rps: float64(len(lat)) / dur.Seconds(), p50: pct(0.5), p95: pct(0.95), p99: pct(0.99), errors: errs}
}

func ms(d time.Duration) string { return fmt.Sprintf("%.2f ms", float64(d.Microseconds())/1000) }

func benchAuth() (*auth.Service, error) {
	keys, err := auth.DeriveKeys(strings.Repeat("b", 40))
	if err != nil {
		return nil, err
	}
	return auth.NewService(auth.NewMemoryStore(), keys)
}
