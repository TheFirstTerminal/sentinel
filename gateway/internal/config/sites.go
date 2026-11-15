package config

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// Site is one website or API behind Sentinel, chosen by the request's Host.
// Settings left empty use the global ones.
//
//	sites:
//	  - name: shop
//	    hosts: [shop.example.com, www.shop.example.com]
//	    upstreams: [http://shop-1:3000, http://shop-2:3000]   # shared in turn
//	    routes: { /api/: http://api:8000 }                  # optional, by path
//	    health_check: /healthz
//	    mode: protect
//	    rate_limits: { /login: 10/1m, /: 600/1m }
type Site struct {
	Name        string            `json:"name"`
	Hosts       []string          `json:"hosts"`               // exact names or "*.example.com"; "*" = any other host
	Upstreams   []string          `json:"upstreams,omitempty"` // servers for "/"
	Routes      map[string]any    `json:"routes,omitempty"`    // path prefix -> server or list of servers
	HealthCheck string            `json:"health_check,omitempty"`
	Mode        string            `json:"mode,omitempty"`     // monitor or protect
	WAFMode     string            `json:"waf_mode,omitempty"` // block or detect
	MLMode      string            `json:"ml_mode,omitempty"`  // off, detect or block
	RateLimits  map[string]string `json:"rate_limits,omitempty"`
	// The app's OpenAPI spec and its AI chat endpoints, when they differ
	// from the global api_spec and prompt_guard settings.
	APISpecFile      string   `json:"api_spec_file,omitempty"`
	APISpecPrefix    string   `json:"api_spec_prefix,omitempty"`
	PromptGuardPaths []string `json:"prompt_guard_paths,omitempty"`
	PromptCanary     string   `json:"prompt_canary,omitempty"`
	// Spec is Routes and Upstreams in the UPSTREAMS form ("/api/=http://a|http://b,/=http://c").
	Spec string `json:"-"`
}

var siteName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)

// ParseSites reads the SITES setting (JSON) and checks every site.
func ParseSites(raw string) ([]Site, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var sites []Site
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&sites); err != nil {
		return nil, fmt.Errorf("SITES: %v", err)
	}
	names, hosts := map[string]bool{}, map[string]string{}
	for i := range sites {
		s := &sites[i]
		where := fmt.Sprintf("SITES: site %d", i+1)
		if s.Name == "" {
			return nil, fmt.Errorf("%s needs a name (lowercase letters, digits and -)", where)
		}
		if !siteName.MatchString(s.Name) {
			return nil, fmt.Errorf("%s: name %q: use lowercase letters, digits and - (at most 40)", where, s.Name)
		}
		where = fmt.Sprintf("SITES: site %q", s.Name)
		if names[s.Name] {
			return nil, fmt.Errorf("%s is listed twice", where)
		}
		names[s.Name] = true
		if len(s.Hosts) == 0 {
			return nil, fmt.Errorf("%s needs hosts (e.g. [shop.example.com], or [\"*\"] for any other host)", where)
		}
		for j, h := range s.Hosts {
			h = strings.ToLower(strings.TrimSpace(h))
			if h != "*" && (strings.ContainsAny(h, "/: ") || strings.Count(h, "*") > 1 || strings.Contains(h, "*") && !strings.HasPrefix(h, "*.")) {
				return nil, fmt.Errorf("%s: host %q: use a name like shop.example.com, *.example.com or *", where, h)
			}
			if other, dup := hosts[h]; dup {
				return nil, fmt.Errorf("%s: host %q is already used by site %q", where, h, other)
			}
			hosts[h] = s.Name
			s.Hosts[j] = h
		}
		spec, err := routeSpec(s)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", where, err)
		}
		s.Spec = spec
		if s.HealthCheck != "" && !strings.HasPrefix(s.HealthCheck, "/") {
			return nil, fmt.Errorf("%s: health_check must be a path like /healthz", where)
		}
		if (s.APISpecFile == "") != (s.APISpecPrefix == "") {
			return nil, fmt.Errorf("%s: api_spec_file and api_spec_prefix go together", where)
		}
		for _, p := range s.PromptGuardPaths {
			if !strings.HasPrefix(p, "/") {
				return nil, fmt.Errorf("%s: prompt_guard_paths: %q must start with /", where, p)
			}
		}
		if err := oneOf(s.Mode, "monitor", "protect"); err != nil {
			return nil, fmt.Errorf("%s: mode %v", where, err)
		}
		if err := oneOf(s.WAFMode, "block", "detect"); err != nil {
			return nil, fmt.Errorf("%s: waf_mode %v", where, err)
		}
		if err := oneOf(s.MLMode, "off", "detect", "block"); err != nil {
			return nil, fmt.Errorf("%s: ml_mode %v", where, err)
		}
	}
	return sites, nil
}

// RateLimitSpec is the site's rate limits in the RATE_LIMITS form, or "".
func (s Site) RateLimitSpec() string {
	keys := make([]string, 0, len(s.RateLimits))
	for k := range s.RateLimits {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return len(keys[i]) > len(keys[j]) || len(keys[i]) == len(keys[j]) && keys[i] < keys[j]
	})
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+s.RateLimits[k])
	}
	return strings.Join(parts, ",")
}

func routeSpec(s *Site) (string, error) {
	routes := map[string][]string{}
	if len(s.Upstreams) > 0 {
		routes["/"] = s.Upstreams
	}
	for prefix, v := range s.Routes {
		if !strings.HasPrefix(prefix, "/") {
			return "", fmt.Errorf("route %q must start with /", prefix)
		}
		if _, dup := routes[prefix]; dup {
			return "", fmt.Errorf("route %q is set twice (upstreams sets \"/\")", prefix)
		}
		switch x := v.(type) {
		case string:
			routes[prefix] = []string{x}
		case []any:
			for _, item := range x {
				str, ok := item.(string)
				if !ok {
					return "", fmt.Errorf("route %q: servers must be URLs", prefix)
				}
				routes[prefix] = append(routes[prefix], str)
			}
		default:
			return "", fmt.Errorf("route %q: give a URL or a list of URLs", prefix)
		}
	}
	if len(routes) == 0 {
		return "", fmt.Errorf("needs upstreams (or routes)")
	}
	prefixes := make([]string, 0, len(routes))
	for p, urls := range routes {
		if len(urls) == 0 {
			return "", fmt.Errorf("route %q has no servers", p)
		}
		for _, raw := range urls {
			u, err := url.Parse(raw)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				return "", fmt.Errorf("server %q: expected http://host:port", raw)
			}
		}
		prefixes = append(prefixes, p)
	}
	sort.Slice(prefixes, func(i, j int) bool { return len(prefixes[i]) > len(prefixes[j]) })
	parts := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		parts = append(parts, p+"="+strings.Join(routes[p], "|"))
	}
	return strings.Join(parts, ","), nil
}

func oneOf(v string, allowed ...string) error {
	if v == "" {
		return nil
	}
	for _, a := range allowed {
		if v == a {
			return nil
		}
	}
	return fmt.Errorf("%q must be one of %s", v, strings.Join(allowed, ", "))
}
