package config

import "testing"

func FuzzParseFile(f *testing.F) {
	f.Add(Example)
	f.Add([]byte("waf: {threshold: [1, {a: b}]}\nroutes: {/: x}\n"))
	f.Add([]byte("a: &x [*x]\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		ParseFile(data)
	})
}
