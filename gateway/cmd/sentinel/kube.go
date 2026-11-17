package main

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"sentinel/gateway/internal/config"
	"sentinel/gateway/internal/kube"
)

// newKubeClient is how Sentinel reaches the Kubernetes API (tests replace it).
var newKubeClient = kube.InCluster

// kubeEvery is how often Ingresses are read again.
var kubeEvery = 10 * time.Second

// watchIngresses keeps the sites in step with the cluster's Ingresses for
// the ingress class, until ctx ends.
func (sh *shared) watchIngresses(ctx context.Context, c *kube.Client, class string, every time.Duration) {
	last := ""
	for {
		ings, err := c.Ingresses(ctx, class)
		if err != nil {
			sh.log.Error("kubernetes: cannot read ingresses", "error", err.Error())
		} else {
			desired, problems := c.Sites(ctx, ings)
			key, _ := json.Marshal(struct {
				S []config.Site
				P []string
			}{desired, problems})
			if string(key) != last {
				last = string(key)
				for _, p := range problems {
					sh.log.Warn("kubernetes: ingress", "problem", p)
				}
				sh.syncIngressSites(desired)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

// syncIngressSites makes the sites that come from Ingresses match desired:
// new ones are added, changed ones rebuilt, gone ones removed. A site that
// clashes with the config file or another site is skipped with a warning.
func (sh *shared) syncIngressSites(desired []config.Site) {
	sh.siteMu.Lock()
	defer sh.siteMu.Unlock()
	cur := sh.siteList()
	byName := map[string]*site{}
	var keep []*site
	var others []config.Site // sites not from Ingresses, for the checks
	for _, s := range cur {
		if s.managed {
			byName[s.name] = s
			continue
		}
		keep = append(keep, s)
		if s.name != "" {
			others = append(others, s.conf)
		}
	}
	edits := sh.loadSiteSettings()
	accepted := append([]config.Site(nil), others...)
	added, changed, removed := 0, 0, 0
	for _, want := range desired {
		effective, err := checkSites(append(append([]config.Site(nil), accepted...), want), edits, false)
		if err != nil {
			sh.log.Warn("kubernetes: ingress site skipped", "site", want.Name, "error", err.Error())
			continue
		}
		accepted = append(accepted, want)
		sc := effective[want.Name]
		if old, ok := byName[want.Name]; ok {
			delete(byName, want.Name)
			if sameSite(old.conf, sc) {
				keep = append(keep, old)
				continue
			}
			old.mu.Lock()
			if old.router != nil {
				old.router.Close()
			}
			old.mu.Unlock()
			changed++
		} else {
			added++
		}
		s := &site{name: sc.Name, hosts: sc.Hosts, conf: sc, managed: true}
		if ed, ok := edits[sc.Name]; ok {
			s.edited = ed
			sc = withEdits(sc, ed)
		}
		if err := sh.sitePipeline(sc, s); err != nil {
			sh.log.Warn("kubernetes: ingress site skipped", "site", sc.Name, "error", err.Error())
			continue
		}
		keep = append(keep, s)
	}
	for _, gone := range byName {
		gone.mu.Lock()
		if gone.router != nil {
			gone.router.Close()
		}
		gone.mu.Unlock()
		removed++
	}
	if len(keep) == 0 {
		return // never happens: the default site stays
	}
	sh.siteSet.Store(&keep)
	if sh.hosts != nil {
		sh.hosts.rebuild(keep)
	}
	if added+changed+removed > 0 {
		var names []string
		for _, s := range keep {
			if s.managed {
				names = append(names, s.name+" ("+strings.Join(s.hosts, ",")+")")
			}
		}
		sh.log.Info("kubernetes: ingress sites updated", "added", added, "changed", changed, "removed", removed, "sites", names)
	}
}

func sameSite(a, b config.Site) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y) && a.Spec == b.Spec
}
