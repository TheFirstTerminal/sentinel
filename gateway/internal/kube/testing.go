package kube

import "strings"

// TestIngress builds an Ingress (as the API returns it) for tests: paths maps a
// path to "service:port", where port is a number or a port name.
func TestIngress(ns, name, class, host string, paths map[string]string) map[string]any {
	var ps []map[string]any
	for path, svc := range paths {
		svcName, port, _ := strings.Cut(svc, ":")
		p := map[string]any{"name": port}
		n := 0
		for _, c := range port {
			if c < '0' || c > '9' {
				n = -1
				break
			}
			n = n*10 + int(c-'0')
		}
		if n > 0 {
			p = map[string]any{"number": n}
		}
		ps = append(ps, map[string]any{"path": path, "pathType": "Prefix",
			"backend": map[string]any{"service": map[string]any{"name": svcName, "port": p}}})
	}
	return map[string]any{
		"metadata": map[string]any{"name": name, "namespace": ns, "annotations": map[string]string{"sentinel.io/mode": "protect"}},
		"spec":     map[string]any{"ingressClassName": class, "rules": []map[string]any{{"host": host, "http": map[string]any{"paths": ps}}}},
	}
}
