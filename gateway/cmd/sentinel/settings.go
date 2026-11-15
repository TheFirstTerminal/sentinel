package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
	return sc
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
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := sh.sitePipeline(withEdits(s.conf, ed), s); err != nil {
		return err
	}
	s.edited = ed
	all := sh.loadSiteSettings()
	all[name] = ed
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
