package main

import (
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sentinel/gateway/internal/config"
)

// A rule added to the rules file takes effect on reload; a broken file
// keeps the old rules running.
func TestReloadSwapsRulesAndKeepsThemOnError(t *testing.T) {
	dir := t.TempDir()
	rules := filepath.Join(dir, "rules.json")
	rule := func(id, pattern string) string {
		return `[{"id":"` + id + `","name":"test","category":"x","severity":5,"targets":["query"],"pattern":"` + pattern + `"}]`
	}
	os.WriteFile(rules, []byte(rule("T-1", "alpha")), 0o644)
	cfgFile := filepath.Join(dir, "sentinel.yaml")
	os.WriteFile(cfgFile, []byte("waf:\n  rules_file: "+rules+"\n  crs: off\n"), 0o644)
	for _, v := range []string{"RULES_FILE", "CRS_DIR"} {
		t.Setenv(v, "") // restored afterwards
		os.Unsetenv(v)
	}
	set, err := config.ApplyFile(cfgFile)
	if err != nil {
		t.Fatal(err)
	}
	cfg, _ := config.Load()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	engine, err := buildEngine(cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	hit := func(q string) bool { return engine.Inspect(httptest.NewRequest("GET", "/?q="+q, nil), nil).Attack }
	if !hit("alpha") || hit("beta") {
		t.Fatal("initial rules wrong")
	}
	rl := &reloader{engine: engine, log: log, file: cfgFile, fileVars: set}

	os.WriteFile(rules, []byte(rule("T-2", "beta")), 0o644)
	if err := rl.reload("test"); err != nil {
		t.Fatal(err)
	}
	if hit("alpha") || !hit("beta") {
		t.Error("reload did not swap the rules")
	}

	os.WriteFile(rules, []byte(`[{"id":"broken","pattern":"(unclosed"}]`), 0o644)
	if rl.reload("test") == nil {
		t.Fatal("a broken rules file was accepted")
	}
	if !hit("beta") {
		t.Error("a failed reload removed the working rules")
	}

	os.WriteFile(cfgFile, []byte("waf:\n  treshold: 3\n"), 0o644)
	if err := rl.reload("test"); err == nil || !strings.Contains(err.Error(), "treshold") {
		t.Errorf("a config typo was not reported: %v", err)
	}
	if !hit("beta") {
		t.Error("a bad config file removed the working rules")
	}
}
