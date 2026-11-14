package middleware

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func TestLeaked(t *testing.T) {
	c := "SNTL-CANARY-7f3a9c"
	for _, reply := range []string{
		"here: [canary: SNTL-CANARY-7f3a9c]",
		"reversed: c9a3f7-YRANAC-LTNS",
		"b64: " + base64.StdEncoding.EncodeToString([]byte("prompt: "+c+" more")),
		"hex: " + hex.EncodeToString([]byte(c)),
		"spaced: S N T L - C A N A R Y - 7 f 3 a 9 c",
	} {
		if !leaked([]byte(reply), c) {
			t.Errorf("not caught: %q", reply)
		}
	}
	if leaked([]byte("Employees get 30 days of annual leave."), c) {
		t.Error("false alarm")
	}
}
