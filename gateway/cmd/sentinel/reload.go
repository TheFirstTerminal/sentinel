package main

import (
	"sentinel/gateway/internal/alert"
	"strings"

	"sentinel/gateway/internal/blocklist"

	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"sentinel/gateway/internal/config"
	"sentinel/gateway/internal/crs"
	"sentinel/gateway/internal/middleware"
	"sentinel/gateway/internal/waf"
)

// buildEngine loads Sentinel's rules and, if configured, the Core Rule Set.
func buildEngine(cfg *config.Config, log *slog.Logger) (*waf.Engine, error) {
	rules, err := waf.LoadRules(cfg.RulesFile)
	if err != nil {
		return nil, err
	}
	engine := waf.NewEngine(rules, cfg.WAFThreshold)
	if dir := crsPath(cfg.CRSDir); dir != "" {
		set, err := crs.Load(dir, cfg.CRSParanoia)
		if err != nil {
			return nil, fmt.Errorf("OWASP CRS: %w", err)
		}
		if err := set.Exclude(cfg.CRSExclude); err != nil {
			return nil, fmt.Errorf("CRS_EXCLUDE: %w", err)
		}
		engine.UseCRS(set)
		log.Info("OWASP Core Rule Set loaded", "dir", dir, "rules", set.Stats.Rules,
			"skipped", set.Stats.Skipped, "excluded", set.Stats.Excluded, "paranoia", cfg.CRSParanoia)
		for why, n := range set.Stats.SkipReasons {
			log.Warn("CRS rules skipped (feature not supported)", "reason", why, "count", n)
		}
	}
	return engine, nil
}

// currentAlerter sends alerts (nil = alerts off; Send on nil does nothing).
var currentAlerter *alert.Alerter

// redactURL hides the secret part of a webhook URL in logs.
func redactURL(u string) string {
	if i := strings.Index(u, "://"); i >= 0 {
		if j := strings.IndexByte(u[i+3:], '/'); j >= 0 {
			return u[:i+3+j] + "/…"
		}
	}
	return "(set)"
}

// saveProfile saves the app profile on shutdown (learn mode).
var saveProfile func()

// currentBans is the running gateway's ban list (for metrics).
var currentBans *blocklist.List

// reloadFunc is set when the gateway runs; the dashboard's reload button
// calls it.
var reloadFunc func(why string) error

type reloader struct {
	mu       sync.Mutex
	engine   *waf.Engine
	log      *slog.Logger
	file     string   // config file ("" = none)
	fileVars []string // variables that came from the config file
}

// reload rebuilds what can change safely while running. On any error the
// old rules stay active: a typo must never leave the gateway unprotected.
// Bans, rate-limit counters and the dashboard history are kept.
func (rl *reloader) reload(why string) error {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	fail := func(err error) error {
		rl.log.Error("reload failed, the old rules stay active", "trigger", why, "error", err.Error())
		currentAlerter.Send("reload", alert.Message{Title: "Reload failed", Text: "The old rules stay active. " + err.Error()})
		return err
	}
	if rl.file != "" {
		data, err := os.ReadFile(rl.file)
		if err != nil {
			return fail(err)
		}
		if _, err := config.ParseFile(data); err != nil { // check before changing anything
			return fail(err)
		}
		for _, v := range rl.fileVars {
			os.Unsetenv(v)
		}
		set, err := config.ApplyFile(rl.file)
		if err != nil {
			return fail(err)
		}
		rl.fileVars = set
	}
	cfg, err := config.Load()
	if err != nil {
		return fail(err)
	}
	next, err := buildEngine(cfg, rl.log)
	if err != nil {
		return fail(err)
	}
	if middleware.Exclusions != nil {
		if err := middleware.Exclusions.Reload(); err != nil {
			return fail(err)
		}
	}
	// Everything loaded: switch over.
	rl.engine.Swap(next)
	n := 0
	if middleware.Exclusions != nil {
		n = len(middleware.Exclusions.List())
	}
	rl.log.Info("reloaded: rules, Core Rule Set and exclusions (other settings need a restart)",
		"trigger", why, "rules", rl.engine.RuleCount()+crsRules(rl.engine), "exclusions", n)
	return nil
}

// watch reloads when one of the files changes (checked every 2 seconds).
func (rl *reloader) watch(files ...string) {
	stamp := func(f string) string {
		if f == "" {
			return ""
		}
		st, err := os.Stat(f)
		if errors.Is(err, os.ErrNotExist) {
			return "missing"
		} else if err != nil {
			return ""
		}
		return fmt.Sprint(st.ModTime().UnixNano(), st.Size())
	}
	last := map[string]string{}
	for _, f := range files {
		last[f] = stamp(f)
	}
	for range time.Tick(2 * time.Second) {
		for _, f := range files {
			if f == "" {
				continue
			}
			if s := stamp(f); s != last[f] {
				last[f] = s
				rl.reload("file changed: " + f)
			}
		}
	}
}
