package exclude

import (
	"os"
	"path/filepath"
	"testing"
)

func FuzzLoad(f *testing.F) {
	f.Add([]byte("- rule: X\n  path: /a\n"))
	f.Add([]byte("- {rule: '*', path: /a, field: b}\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		p := filepath.Join(t.TempDir(), "e.yaml")
		os.WriteFile(p, data, 0o644)
		if s, err := Load(p); err == nil {
			s.Excluded("X", "GET", "/a/b", "ARGS:json.b")
		}
	})
}
