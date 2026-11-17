package kube

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIngressesToSites(t *testing.T) {
	ings := []map[string]any{
		TestIngress("shop", "web", "sentinel", "Shop.Example.com", map[string]string{"/": "web:http", "/api/": "api:3000"}),
		TestIngress("blog", "blog", "nginx", "blog.example.com", map[string]string{"/": "blog:80"}),     // another controller's
		TestIngress("x", "dup", "sentinel", "shop.example.com", map[string]string{"/": "x:80"}),         // host taken
		TestIngress("y", "badport", "sentinel", "y.example.com", map[string]string{"/": "web:missing"}), // no such port
	}
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/apis/networking.k8s.io/v1/ingresses":
			json.NewEncoder(w).Encode(map[string]any{"items": ings})
		case "/api/v1/namespaces/shop/services/web", "/api/v1/namespaces/y/services/web":
			json.NewEncoder(w).Encode(map[string]any{"spec": map[string]any{"ports": []map[string]any{{"name": "http", "port": 8080}}}})
		default:
			w.WriteHeader(404)
		}
	}))
	defer api.Close()
	c := &Client{Base: api.URL, Token: func() string { return "test-token" }, HTTP: api.Client()}
	got, err := c.Ingresses(context.Background(), "sentinel")
	if err != nil || len(got) != 3 {
		t.Fatalf("ingresses of the class: %d %v", len(got), err)
	}
	sites, problems := c.Sites(context.Background(), got)
	if len(sites) != 1 {
		t.Fatalf("sites: %+v (problems %v)", sites, problems)
	}
	s := sites[0]
	if s.Name != "k8s-shop-web" || s.Hosts[0] != "shop.example.com" || s.Mode != "protect" ||
		s.Routes["/"] != "http://web.shop.svc.cluster.local:8080" || s.Routes["/api/"] != "http://api.shop.svc.cluster.local:3000" {
		t.Errorf("site: %+v", s)
	}
	all := strings.Join(problems, " | ")
	if len(problems) < 2 || !strings.Contains(all, "already in") || !strings.Contains(all, "no port named") {
		t.Errorf("problems: %v", problems)
	}
	if n := siteName("a-very-long-namespace-name", "and-an-even-longer-ingress-name", 3); len(n) > 40 || !strings.HasSuffix(n, "-3") {
		t.Errorf("site name %q", n)
	}
}
