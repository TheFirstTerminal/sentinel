package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"sentinel/gateway/internal/config"
	"sentinel/gateway/internal/kube"
	"sentinel/gateway/internal/waf"
)

func TestKubernetesIngressMode(t *testing.T) {
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "web") }))
	defer web.Close()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "api") }))
	defer api.Close()
	var mu sync.Mutex
	ings := []map[string]any{kube.TestIngress("shop", "web", "sentinel", "shop.test", map[string]string{"/": "web:80", "/api/": "api:3000"})}
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path == "/apis/networking.k8s.io/v1/ingresses" {
			json.NewEncoder(w).Encode(map[string]any{"items": ings})
			return
		}
		w.WriteHeader(404)
	}))
	defer fake.Close()
	oldClient, oldEvery := newKubeClient, kubeEvery
	defer func() { newKubeClient, kubeEvery = oldClient, oldEvery }()
	kubeEvery = 50 * time.Millisecond
	newKubeClient = func() (*kube.Client, error) {
		return &kube.Client{Base: fake.URL, HTTP: fake.Client(), ServiceURL: func(ns, name string, port int) string {
			if name == "api" {
				return api.URL
			}
			return web.URL
		}}, nil
	}

	u, _ := url.Parse("http://127.0.0.1:1")
	rules, _ := waf.LoadRules("")
	cfg := &config.Config{UpstreamURL: u, Mode: "protect", WAFMode: "block", WAFThreshold: 5, MaxBodyBytes: 1 << 20,
		HoneypotBan: time.Minute, Upstreams: "/=" + u.String(), Dashboard: true, KubeIngressClass: "sentinel"}
	h, err := NewHandler(cfg, waf.NewEngine(rules, 5), testAuth(t), nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	gw := httptest.NewServer(h)
	defer gw.Close()
	wait := func(host, path string, wantCode int, want string) {
		t.Helper()
		var code int
		var got string
		for i := 0; i < 80; i++ {
			if code, got = hostGet(t, gw, host, path); code == wantCode && (want == "" || got == want) {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Errorf("%s%s: %d %q, want %d %q", host, path, code, got, wantCode, want)
	}
	wait("shop.test", "/", 200, "web")
	wait("shop.test", "/api/orders", 200, "api")
	wait("other.test", "/", 421, "") // no Ingress for it
	if code, _ := hostGet(t, gw, "shop.test", attack); code != 403 {
		t.Errorf("ingress sites are protected (annotation sentinel.io/mode: protect): %d", code)
	}

	// A new Ingress appears; then the first one is deleted.
	mu.Lock()
	ings = append(ings, kube.TestIngress("blog", "blog", "sentinel", "blog.test", map[string]string{"/": "blog:80"}))
	mu.Unlock()
	wait("blog.test", "/", 200, "web")
	mu.Lock()
	ings = ings[1:]
	mu.Unlock()
	wait("shop.test", "/", 421, "")
	wait("blog.test", "/", 200, "web")
}
