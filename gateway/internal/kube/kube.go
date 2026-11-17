// Package kube lets Sentinel act as a Kubernetes Ingress controller: it
// reads the cluster's Ingress resources for its ingress class and turns
// them into sites (host names, path routes to Services).
//
// It talks to the Kubernetes API directly with the pod's service account
// (read-only: list Ingresses and Services), with no client library.
package kube

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"sentinel/gateway/internal/config"
)

const saDir = "/var/run/secrets/kubernetes.io/serviceaccount"

// Client reads Ingresses and Services.
type Client struct {
	Base   string // e.g. https://10.96.0.1:443
	Token  func() string
	HTTP   *http.Client
	Domain string // cluster domain, default cluster.local
	// ServiceURL is the address of a Service port (default: its cluster DNS
	// name, http://name.namespace.svc.<domain>:port).
	ServiceURL func(namespace, name string, port int) string
}

// InCluster builds a client from the pod's service account.
func InCluster() (*Client, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" {
		return nil, fmt.Errorf("not running in Kubernetes (KUBERNETES_SERVICE_HOST is not set)")
	}
	ca, err := os.ReadFile(saDir + "/ca.crt")
	if err != nil {
		return nil, fmt.Errorf("service account CA: %w", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca)
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return &Client{
		Base: "https://" + host + ":" + port,
		// The token file is rotated by the kubelet: read it each time.
		Token: func() string { b, _ := os.ReadFile(saDir + "/token"); return strings.TrimSpace(string(b)) },
		HTTP:  &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}},
	}, nil
}

func (c *Client) get(ctx context.Context, path string, v any) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.Base+path, nil)
	if c.Token != nil {
		req.Header.Set("Authorization", "Bearer "+c.Token())
	}
	req.Header.Set("Accept", "application/json")
	res, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusForbidden {
		return fmt.Errorf("%s: forbidden (the service account needs list on ingresses and services)", path)
	}
	if res.StatusCode != 200 {
		return fmt.Errorf("%s: %s", path, res.Status)
	}
	return json.NewDecoder(res.Body).Decode(v)
}

// Ingress is the part of networking.k8s.io/v1 Ingress Sentinel uses.
type Ingress struct {
	Metadata struct {
		Name        string            `json:"name"`
		Namespace   string            `json:"namespace"`
		Annotations map[string]string `json:"annotations"`
	} `json:"metadata"`
	Spec struct {
		IngressClassName string    `json:"ingressClassName"`
		DefaultBackend   *Backend  `json:"defaultBackend"`
		Rules            []IngRule `json:"rules"`
	} `json:"spec"`
}

type IngRule struct {
	Host string `json:"host"`
	HTTP *struct {
		Paths []struct {
			Path     string  `json:"path"`
			PathType string  `json:"pathType"`
			Backend  Backend `json:"backend"`
		} `json:"paths"`
	} `json:"http"`
}

type Backend struct {
	Service *struct {
		Name string `json:"name"`
		Port struct {
			Number int    `json:"number"`
			Name   string `json:"name"`
		} `json:"port"`
	} `json:"service"`
}

type service struct {
	Spec struct {
		Ports []struct {
			Name string `json:"name"`
			Port int    `json:"port"`
		} `json:"ports"`
	} `json:"spec"`
}

// Ingresses lists every Ingress of the class (spec.ingressClassName, or
// the older kubernetes.io/ingress.class annotation).
func (c *Client) Ingresses(ctx context.Context, class string) ([]Ingress, error) {
	var list struct {
		Items []Ingress `json:"items"`
	}
	if err := c.get(ctx, "/apis/networking.k8s.io/v1/ingresses", &list); err != nil {
		return nil, err
	}
	var out []Ingress
	for _, in := range list.Items {
		if in.Spec.IngressClassName == class || in.Spec.IngressClassName == "" && in.Metadata.Annotations["kubernetes.io/ingress.class"] == class {
			out = append(out, in)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Metadata.Namespace+"/"+out[i].Metadata.Name < out[j].Metadata.Namespace+"/"+out[j].Metadata.Name
	})
	return out, nil
}

// Sites turns Ingresses into sites, one per host. Problems (a named port
// that doesn't exist, a host in two Ingresses) skip that part and are
// reported, so one bad Ingress doesn't stop the others.
func (c *Client) Sites(ctx context.Context, ings []Ingress) ([]config.Site, []string) {
	domain := c.Domain
	if domain == "" {
		domain = "cluster.local"
	}
	var sites []config.Site
	var problems []string
	hosts := map[string]string{} // host -> ingress that has it
	for _, in := range ings {
		where := in.Metadata.Namespace + "/" + in.Metadata.Name
		url := func(b Backend) (string, error) {
			if b.Service == nil {
				return "", fmt.Errorf("only Service backends are supported")
			}
			port := b.Service.Port.Number
			if port == 0 && b.Service.Port.Name != "" {
				var svc service
				if err := c.get(ctx, "/api/v1/namespaces/"+in.Metadata.Namespace+"/services/"+b.Service.Name, &svc); err != nil {
					return "", err
				}
				for _, p := range svc.Spec.Ports {
					if p.Name == b.Service.Port.Name {
						port = p.Port
					}
				}
				if port == 0 {
					return "", fmt.Errorf("service %s has no port named %q", b.Service.Name, b.Service.Port.Name)
				}
			}
			if port == 0 {
				return "", fmt.Errorf("service %s: no port", b.Service.Name)
			}
			if c.ServiceURL != nil {
				return c.ServiceURL(in.Metadata.Namespace, b.Service.Name, port), nil
			}
			return fmt.Sprintf("http://%s.%s.svc.%s:%d", b.Service.Name, in.Metadata.Namespace, domain, port), nil
		}
		mode := in.Metadata.Annotations["sentinel.io/mode"]
		for i, r := range in.Spec.Rules {
			host := strings.ToLower(r.Host)
			if host == "" {
				host = "*"
			}
			if other, dup := hosts[host]; dup {
				problems = append(problems, fmt.Sprintf("%s: host %s is already in %s; skipped", where, host, other))
				continue
			}
			routes := map[string]any{}
			if r.HTTP != nil {
				for _, p := range r.HTTP.Paths {
					u, err := url(p.Backend)
					if err != nil {
						problems = append(problems, where+": "+err.Error())
						continue
					}
					path := p.Path
					if path == "" {
						path = "/"
					}
					routes[path] = u
				}
			}
			if _, ok := routes["/"]; !ok && in.Spec.DefaultBackend != nil {
				if u, err := url(*in.Spec.DefaultBackend); err == nil {
					routes["/"] = u
				}
			}
			if len(routes) == 0 {
				problems = append(problems, fmt.Sprintf("%s: host %s has no usable backend; skipped", where, host))
				continue
			}
			hosts[host] = where
			sites = append(sites, config.Site{Name: siteName(in.Metadata.Namespace, in.Metadata.Name, i), Hosts: []string{host}, Routes: routes, Mode: mode})
		}
	}
	return sites, problems
}

var notName = regexp.MustCompile(`[^a-z0-9-]+`)

// siteName is "k8s-<namespace>-<ingress>[-n]", at most 40 characters.
func siteName(ns, name string, i int) string {
	n := notName.ReplaceAllString(strings.ToLower("k8s-"+ns+"-"+name), "-")
	suffix := ""
	if i > 0 {
		suffix = fmt.Sprintf("-%d", i)
	}
	if len(n)+len(suffix) > 40 {
		n = n[:40-len(suffix)]
	}
	return strings.TrimRight(n, "-") + suffix
}
