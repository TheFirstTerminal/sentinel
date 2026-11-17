package main

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"sentinel/gateway/internal/alert"
	"sentinel/gateway/internal/config"
	"sentinel/gateway/internal/dashboard"
)

// Settings changed on the dashboard are kept in the data folder and win
// over the config file: site-settings.json (modes and rate limits per site)
// and alerts.json (where alerts go).

// settingsFile is a file in the data folder ("" = no usable data folder).
func (sh *shared) settingsFile(name string) string {
	if sh.cfg.DataDir == "" || !usableDir(sh.cfg.DataDir) {
		return ""
	}
	return filepath.Join(sh.cfg.DataDir, name)
}

// loadSiteSettings reads the dashboard's site changes. Modes saved by older
// versions (site-modes.json) are read too.
func (sh *shared) loadSiteSettings() map[string]dashboard.SiteSettings {
	out := map[string]dashboard.SiteSettings{}
	if file := sh.settingsFile("site-modes.json"); file != "" {
		old := map[string]string{}
		if b, err := os.ReadFile(file); err == nil {
			json.Unmarshal(b, &old)
		}
		for name, m := range old {
			if m == "monitor" || m == "protect" {
				out[name] = dashboard.SiteSettings{Mode: m}
			}
		}
	}
	if file := sh.settingsFile("site-settings.json"); file != "" {
		saved := map[string]dashboard.SiteSettings{}
		if b, err := os.ReadFile(file); err == nil {
			if err := json.Unmarshal(b, &saved); err != nil {
				sh.log.Warn("site settings file is broken and was ignored", "file", file, "error", err.Error())
			}
		}
		for name, ed := range saved {
			if checkSiteSettings(ed) == nil {
				out[name] = ed
			}
		}
	}
	return out
}

func (sh *shared) saveSiteSettings(all map[string]dashboard.SiteSettings) {
	file := sh.settingsFile("site-settings.json")
	if file == "" {
		sh.log.Warn("site settings not saved (no data folder): they last until Sentinel restarts")
		return
	}
	for name, ed := range all {
		if ed.Empty() {
			delete(all, name)
		}
	}
	b, _ := json.MarshalIndent(all, "", "  ")
	if err := os.WriteFile(file, b, 0o600); err != nil {
		sh.log.Warn("site settings not saved: they last until Sentinel restarts", "file", file, "error", err.Error())
		return
	}
	os.Remove(sh.settingsFile("site-modes.json")) // folded into site-settings.json
}

func checkSiteSettings(ed dashboard.SiteSettings) error {
	check := func(what, v string, allowed ...string) error {
		if v == "" {
			return nil
		}
		for _, a := range allowed {
			if v == a {
				return nil
			}
		}
		return fmt.Errorf("%s must be one of %s", what, strings.Join(allowed, ", "))
	}
	if err := check("mode", ed.Mode, "monitor", "protect"); err != nil {
		return err
	}
	if err := check("waf_mode", ed.WAFMode, "block", "detect"); err != nil {
		return err
	}
	if err := check("ml_mode", ed.MLMode, "off", "detect", "block"); err != nil {
		return err
	}
	for p := range ed.RateLimits {
		if !strings.HasPrefix(p, "/") {
			return fmt.Errorf("rate limit path %q must start with /", p)
		}
	}
	return nil
}

// withEdits is the site's configuration with the dashboard's changes.
func withEdits(sc config.Site, ed dashboard.SiteSettings) config.Site {
	if ed.Mode != "" {
		sc.Mode = ed.Mode
	}
	if ed.WAFMode != "" {
		sc.WAFMode = ed.WAFMode
	}
	if ed.MLMode != "" {
		sc.MLMode = ed.MLMode
	}
	if len(ed.RateLimits) > 0 {
		sc.RateLimits = ed.RateLimits
	}
	if len(ed.Hosts) > 0 {
		sc.Hosts = ed.Hosts
	}
	if len(ed.Upstreams) > 0 {
		sc.Upstreams = ed.Upstreams
	}
	if ed.HealthCheck != "" {
		sc.HealthCheck = ed.HealthCheck
	}
	return sc
}

// effectiveSites is the named sites (from the config file and added on the
// dashboard) with the dashboard's changes, checked as a whole the way the
// config file is (host names used twice, server URLs), with their routes
// worked out, by name. Empty when there are no named sites.
func (sh *shared) effectiveSites(edits map[string]dashboard.SiteSettings) (map[string]config.Site, error) {
	named := append(append([]config.Site(nil), sh.cfg.Sites...), sh.added...)
	return checkSites(named, edits, len(sh.cfg.Sites) == 0 && sh.cfg.KubeIngressClass == "")
}

// checkSites checks a list of named sites with edits; withCatchAll: an
// unnamed site already takes every other host, so "*" is refused.
func checkSites(named []config.Site, edits map[string]dashboard.SiteSettings, withCatchAll bool) (map[string]config.Site, error) {
	out := map[string]config.Site{}
	if len(named) == 0 {
		return out, nil
	}
	list := make([]config.Site, len(named))
	for i, sc := range named {
		sc.Hosts = append([]string(nil), sc.Hosts...)
		list[i] = withEdits(sc, edits[sc.Name])
		if withCatchAll && slices.Contains(list[i].Hosts, "*") {
			return nil, fmt.Errorf("site %q: host \"*\" is already the default site's (every other host)", sc.Name)
		}
	}
	b, err := json.Marshal(list)
	if err != nil {
		return nil, err
	}
	parsed, err := config.ParseSites(string(b))
	if err != nil {
		return nil, fmt.Errorf("%s", strings.TrimPrefix(err.Error(), "SITES: "))
	}
	for _, sc := range parsed {
		out[sc.Name] = sc
	}
	return out, nil
}

// siteList is the running sites.
func (sh *shared) siteList() []*site {
	if p := sh.siteSet.Load(); p != nil {
		return *p
	}
	return nil
}

func (sh *shared) loadAdded() []config.Site {
	var out []config.Site
	if file := sh.settingsFile("sites-added.json"); file != "" {
		if b, err := os.ReadFile(file); err == nil {
			if err := json.Unmarshal(b, &out); err != nil {
				sh.log.Warn("sites added on the dashboard: file is broken and was ignored", "file", file, "error", err.Error())
				return nil
			}
		}
	}
	return out
}

func (sh *shared) saveAdded() {
	file := sh.settingsFile("sites-added.json")
	if file == "" {
		sh.log.Warn("added sites not saved (no data folder): they last until Sentinel restarts")
		return
	}
	b, _ := json.MarshalIndent(sh.added, "", "  ")
	if err := os.WriteFile(file, b, 0o600); err != nil {
		sh.log.Warn("added sites not saved: they last until Sentinel restarts", "file", file, "error", err.Error())
	}
}

// addSite adds a site from the dashboard. It starts in monitor mode unless
// told otherwise, and is saved in the data folder.
func (sh *shared) addSite(in dashboard.NewSite) error {
	sh.siteMu.Lock()
	defer sh.siteMu.Unlock()
	if in.Mode == "" {
		in.Mode = "monitor"
	}
	if in.Mode != "monitor" && in.Mode != "protect" {
		return fmt.Errorf("mode must be monitor or protect")
	}
	for _, s := range sh.siteList() {
		if s.name == in.Name {
			return fmt.Errorf("there is already a site %q", in.Name)
		}
	}
	nc := config.Site{Name: in.Name, Hosts: in.Hosts, Upstreams: in.Upstreams, HealthCheck: in.HealthCheck, Mode: in.Mode}
	named := append(append(append([]config.Site(nil), sh.cfg.Sites...), sh.added...), nc)
	effective, err := checkSites(named, sh.loadSiteSettings(), len(sh.cfg.Sites) == 0 && sh.cfg.KubeIngressClass == "")
	if err != nil {
		return err
	}
	sc := effective[in.Name]
	s := &site{name: sc.Name, hosts: sc.Hosts, conf: sc, added: true}
	if err := sh.sitePipeline(sc, s); err != nil {
		return err
	}
	list := append(append([]*site(nil), sh.siteList()...), s)
	sh.siteSet.Store(&list)
	sh.added = append(sh.added, nc)
	if sh.hosts != nil {
		sh.hosts.rebuild(list)
	}
	sh.saveAdded()
	sh.log.Warn("site added on the dashboard", "site", sc.Name, "hosts", sc.Hosts, "upstreams", sc.Spec, "mode", sc.Mode)
	currentAlerter.Send("site-added:"+sc.Name, alert.Message{Title: "Site added",
		Text: fmt.Sprintf("Site %q (%s) was added on the dashboard, in %s mode.", sc.Name, strings.Join(sc.Hosts, ", "), sc.Mode)})
	return nil
}

// removeSite removes a site that was added on the dashboard. Sites from the
// config file are removed there (they would come back on restart).
func (sh *shared) removeSite(name string) error {
	sh.siteMu.Lock()
	defer sh.siteMu.Unlock()
	cur := sh.siteList()
	var s *site
	var keep []*site
	for _, x := range cur {
		if x.name == name {
			s = x
		} else {
			keep = append(keep, x)
		}
	}
	switch {
	case s == nil:
		return fmt.Errorf("no site %q", name)
	case !s.added:
		return fmt.Errorf("site %q comes from the config file: remove it there", name)
	case len(keep) == 0:
		return fmt.Errorf("Sentinel needs at least one site")
	}
	sh.siteSet.Store(&keep)
	if sh.hosts != nil {
		sh.hosts.rebuild(keep)
	}
	s.mu.Lock()
	if s.router != nil {
		s.router.Close()
	}
	s.mu.Unlock()
	var added []config.Site
	for _, a := range sh.added {
		if a.Name != name {
			added = append(added, a)
		}
	}
	sh.added = added
	sh.saveAdded()
	all := sh.loadSiteSettings()
	delete(all, name)
	sh.saveSiteSettings(all)
	sh.log.Warn("site removed on the dashboard", "site", name)
	currentAlerter.Send("site-removed:"+name, alert.Message{Title: "Site removed", Text: fmt.Sprintf("Site %q was removed on the dashboard.", name)})
	return nil
}

// hostNames is the site's current host names.
func (s *site) hostNames() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hosts
}

func findSite(sites []*site, name string) (*site, error) {
	for _, x := range sites {
		if x.name == name {
			return x, nil
		}
	}
	return nil, fmt.Errorf("no site %q", name)
}

// setSite replaces a site's dashboard changes (empty fields = as in the
// config file), rebuilds its checks and saves the changes.
func (sh *shared) setSite(sites []*site, name string, ed dashboard.SiteSettings) error {
	sh.siteMu.Lock()
	defer sh.siteMu.Unlock()
	if err := checkSiteSettings(ed); err != nil {
		return err
	}
	if (ed.MLMode == "detect" || ed.MLMode == "block") && sh.model == nil {
		return fmt.Errorf("the ML model is not loaded: set ml_mode in the config file and restart once")
	}
	s, err := findSite(sites, name)
	if err != nil {
		return err
	}
	if (len(ed.Hosts) > 0 || len(ed.Upstreams) > 0 || ed.HealthCheck != "") && name == "" {
		return fmt.Errorf("host names and servers can be changed here once sites are set up (sites: in the config file)")
	}
	all := sh.loadSiteSettings()
	all[name] = ed
	sc := withEdits(s.conf, ed)
	if effective, err := sh.effectiveSites(all); err != nil {
		return err
	} else if e, ok := effective[name]; ok {
		sc = e
	}
	s.mu.Lock()
	old := s.router
	newServers := s.servers != serversKey(sc, sh.cfg)
	if newServers {
		s.router = nil // sitePipeline builds a new one
	}
	if err := sh.sitePipeline(sc, s); err != nil {
		s.router = old
		s.mu.Unlock()
		return err
	}
	if newServers && old != nil {
		old.Close()
	}
	s.edited = ed
	s.hosts = sc.Hosts
	s.mu.Unlock()
	if sh.hosts != nil {
		sh.hosts.rebuild(sites)
	}
	sh.saveSiteSettings(all)
	sh.log.Warn("site settings changed on the dashboard", "site", siteLabel(name), "mode", s.mode, "waf_mode", s.waf, "ml_mode", s.ml, "rate_limits", s.limits)
	currentAlerter.Send("settings:"+name, alert.Message{Title: "Site settings changed",
		Text: fmt.Sprintf("Site %q: mode %s, WAF %s, ML %s (changed on the dashboard).", siteLabel(name), s.mode, s.waf, s.ml)})
	return nil
}

// setSiteMode switches a site between monitor and protect, keeping its
// other dashboard changes. Choosing the configured mode clears the change.
func (sh *shared) setSiteMode(sites []*site, name, mode string) error {
	if mode != "monitor" && mode != "protect" {
		return fmt.Errorf("mode must be monitor or protect")
	}
	s, err := findSite(sites, name)
	if err != nil {
		return err
	}
	s.mu.Lock()
	ed := s.edited
	configured := pick(s.conf.Mode, sh.cfg.Mode)
	s.mu.Unlock()
	ed.RateLimits = maps.Clone(ed.RateLimits)
	ed.Mode = mode
	if mode == configured {
		ed.Mode = ""
	}
	return sh.setSite(sites, name, ed)
}

func loadAlertSettings(file string) (dashboard.AlertSettings, bool) {
	var a dashboard.AlertSettings
	if file == "" {
		return a, false
	}
	b, err := os.ReadFile(file)
	if err != nil || json.Unmarshal(b, &a) != nil {
		return a, false
	}
	return a, true
}

// alertSettings: where alerts go now. The webhook URL is shown shortened,
// since it often contains a token.
func (sh *shared) alertSettings() dashboard.AlertSettings {
	u, chat, burst := currentAlerter.Settings()
	return dashboard.AlertSettings{WebhookURL: redactURL(u), TelegramChat: chat, Burst: burst, On: u != ""}
}

// setAlerts changes where alerts go. An empty webhook URL keeps the current
// one; Off turns alerts off.
func (sh *shared) setAlerts(in dashboard.AlertSettings) error {
	u, _, _ := currentAlerter.Settings()
	switch {
	case in.Off:
		u = ""
	case in.WebhookURL != "":
		if !strings.HasPrefix(in.WebhookURL, "https://") && !strings.HasPrefix(in.WebhookURL, "http://") {
			return fmt.Errorf("the webhook URL must start with https://")
		}
		u = in.WebhookURL
	}
	if in.Burst < 0 || in.Burst > 100000 {
		return fmt.Errorf("burst must be between 1 and 100000")
	}
	currentAlerter.Set(u, in.TelegramChat, in.Burst)
	u, chat, burst := currentAlerter.Settings()
	if file := sh.settingsFile("alerts.json"); file != "" {
		b, _ := json.MarshalIndent(dashboard.AlertSettings{WebhookURL: u, TelegramChat: chat, Burst: burst}, "", "  ")
		if err := os.WriteFile(file, b, 0o600); err != nil {
			sh.log.Warn("alert settings not saved: they last until Sentinel restarts", "file", file, "error", err.Error())
		}
	}
	sh.log.Warn("alert settings changed on the dashboard", "to", redactURL(u), "burst", burst)
	currentAlerter.Send("alerts-changed", alert.Message{Title: "Alerts set up", Text: "This channel now gets Sentinel's alerts."})
	return nil
}

// serversKey identifies the servers and health check a site's router uses.
func serversKey(sc config.Site, cfg *config.Config) string {
	return sc.Spec + " health=" + pick(sc.HealthCheck, cfg.HealthCheck)
}
