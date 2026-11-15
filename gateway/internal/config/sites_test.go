package config

import (
	"strings"
	"testing"
)

func TestAutoDomainsFromSites(t *testing.T) {
	sites := []Site{{Hosts: []string{"shop.example.com", "*.shop.example.com"}}, {Hosts: []string{"api.example.com", "*"}}}
	got := strings.Join(AutoDomains([]string{"sites", "extra.example.com", "shop.example.com"}, sites), ",")
	if got != "shop.example.com,api.example.com,extra.example.com" {
		t.Fatalf("got %s", got)
	}
}
