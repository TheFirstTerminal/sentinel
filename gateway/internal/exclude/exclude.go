// Package exclude switches off a rule where it misfires: for one path, one
// field, or both. This is how a WAF is tuned without turning rules off for
// everyone ("rule 942100 may see SQL words in the 'comment' field of
// /api/reviews, nowhere else").
//
// Exclusions live in a YAML file people can review and keep in version
// control. The dashboard adds to it with an "Allow" button.
package exclude

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// Exclusion lets requests through one rule. Empty Path, Field and Method
// mean "any". At least one of Path and Field is required, so a click can
// never switch a rule off everywhere.
type Exclusion struct {
	ID     string    `yaml:"id" json:"id"`
	Rule   string    `yaml:"rule" json:"rule"`                     // e.g. "CRS-942100", "SQLI-001", "ML", "PI-001", or a prefix "CRS-942*"
	Path   string    `yaml:"path,omitempty" json:"path,omitempty"` // path prefix
	Field  string    `yaml:"field,omitempty" json:"field,omitempty"`
	Method string    `yaml:"method,omitempty" json:"method,omitempty"`
	Note   string    `yaml:"note,omitempty" json:"note,omitempty"`
	By     string    `yaml:"by,omitempty" json:"by,omitempty"`
	Added  time.Time `yaml:"added,omitempty" json:"added,omitempty"`
}

// Set is the loaded exclusions. A nil *Set excludes nothing.
type Set struct {
	mu      sync.RWMutex
	list    []Exclusion
	presets []Exclusion // from a profile: not saved, not removable
	file    string      // "" = memory only
}

// AddPreset adds built-in exclusions (from a profile). They are checked and
// listed like the others but never written to the file.
func (s *Set) AddPreset(list []Exclusion) error {
	for i := range list {
		if err := check(&list[i]); err != nil {
			return err
		}
		list[i].ID = "preset-" + newID()
	}
	s.mu.Lock()
	s.presets = append(s.presets, list...)
	s.mu.Unlock()
	return nil
}

// Load reads file (a missing file is an empty list). file "" keeps the
// exclusions in memory only.
func Load(file string) (*Set, error) {
	s := &Set{file: file}
	return s, s.Reload()
}

// Reload reads the file again (for SIGHUP and file changes).
func (s *Set) Reload() error {
	if s.file == "" {
		return nil
	}
	data, err := os.ReadFile(s.file)
	if errors.Is(err, os.ErrNotExist) {
		data = nil
	} else if err != nil {
		return err
	}
	var list []Exclusion
	if err := yaml.Unmarshal(data, &list); err != nil {
		return fmt.Errorf("%s: %w", s.file, err)
	}
	for i := range list {
		if err := check(&list[i]); err != nil {
			return fmt.Errorf("%s, entry %d: %w", s.file, i+1, err)
		}
		if list[i].ID == "" {
			list[i].ID = newID()
		}
	}
	s.mu.Lock()
	s.list = list
	s.mu.Unlock()
	return nil
}

// File is where the exclusions are saved ("" = not saved).
func (s *Set) File() string { return s.file }

func check(e *Exclusion) error {
	e.Rule = strings.TrimSpace(e.Rule)
	e.Field = strings.TrimSpace(e.Field)
	e.Method = strings.ToUpper(strings.TrimSpace(e.Method))
	if e.Path != "" && !strings.HasPrefix(e.Path, "/") {
		return errors.New("path must start with /")
	}
	if e.Rule == "" {
		return errors.New("rule is required")
	}
	if e.Path == "" && e.Field == "" {
		return errors.New("give a path or a field (or both): an exclusion may not switch a rule off everywhere")
	}
	if e.Rule == "*" && (e.Path == "" || e.Field == "") {
		return errors.New(`rule "*" needs both a path and a field`)
	}
	return nil
}

// Excluded reports whether rule may not act on field of this request.
func (s *Set) Excluded(rule, method, path, field string) bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.list)+len(s.presets) == 0 {
		return false
	}
	field = NormalizeField(field)
	for _, e := range append(s.list[:len(s.list):len(s.list)], s.presets...) {
		if !ruleMatch(e.Rule, rule) {
			continue
		}
		if e.Method != "" && e.Method != method {
			continue
		}
		if e.Path != "" && !strings.HasPrefix(path, e.Path) {
			continue
		}
		if e.Field != "" && !strings.EqualFold(NormalizeField(e.Field), field) {
			continue
		}
		return true
	}
	return false
}

// Empty reports whether there is nothing to check (the fast path).
func (s *Set) Empty() bool {
	if s == nil {
		return true
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.list)+len(s.presets) == 0
}

func ruleMatch(pattern, rule string) bool {
	if pattern == "*" {
		return true
	}
	if p, ok := strings.CutSuffix(pattern, "*"); ok {
		return len(rule) >= len(p) && strings.EqualFold(rule[:len(p)], p)
	}
	return strings.EqualFold(pattern, rule)
}

// NormalizeField gives the same name for a field however a checker wrote
// it: CRS says "ARGS:comment" or "ARGS:json.comment", Sentinel says
// "comment"; headers are case-insensitive.
func NormalizeField(f string) string {
	if i := strings.IndexByte(f, ':'); i > 0 && strings.ToUpper(f[:i]) == f[:i] {
		f = f[i+1:]
	}
	f = strings.TrimPrefix(f, "json.")
	return strings.ToLower(f)
}

// List returns the exclusions, newest first.
func (s *Set) List() []Exclusion {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := append([]Exclusion(nil), s.list...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Added.After(out[j].Added) })
	return append(out, s.presets...)
}

// Add validates, stores and (with a file) saves an exclusion.
func (s *Set) Add(e Exclusion) (Exclusion, error) {
	if err := check(&e); err != nil {
		return e, err
	}
	e.ID = newID()
	if e.Added.IsZero() {
		e.Added = time.Now().UTC().Truncate(time.Second)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := append(append([]Exclusion(nil), s.list...), e)
	if err := s.save(next); err != nil {
		return e, err
	}
	s.list = next
	return e, nil
}

// Remove deletes an exclusion by ID.
func (s *Set) Remove(id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var next []Exclusion
	for _, e := range s.list {
		if e.ID != id {
			next = append(next, e)
		}
	}
	if len(next) == len(s.list) {
		return false, nil
	}
	if err := s.save(next); err != nil {
		return false, err
	}
	s.list = next
	return true, nil
}

// save writes the list atomically (a crash never leaves half a file).
func (s *Set) save(list []Exclusion) error {
	if s.file == "" {
		return nil
	}
	data, err := yaml.Marshal(list)
	if err != nil {
		return err
	}
	header := "# Sentinel exclusions: rules switched off for one path and/or field.\n# Edited by the dashboard's \"Allow\" button; you can edit it by hand too.\n"
	tmp, err := os.CreateTemp(filepath.Dir(s.file), ".exclusions-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(header + string(data)); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.file)
}

func newID() string {
	b := make([]byte, 6)
	rand.Read(b)
	return hex.EncodeToString(b)
}
