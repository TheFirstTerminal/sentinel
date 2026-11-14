package leak

import (
	"strings"
	"testing"

	"sentinel/gateway/internal/ml/dataset"
)

func TestFindsLeaks(t *testing.T) {
	for want, body := range map[string]string{
		"LEAK-SQL":     `<b>Warning</b>: You have an error in your SQL syntax; check the manual near ''' at line 1`,
		"LEAK-TRACE":   "Traceback (most recent call last):\n  File \"app.py\", line 3, in <module>",
		"LEAK-KEY":     "config:\n-----BEGIN RSA PRIVATE KEY-----\nMIIE...",
		"LEAK-CLOUD":   `{"aws_access_key_id":"AKIAIOSFODNN7EXAMPLE"}`,
		"LEAK-LISTING": `<html><head><title>Index of /backup</title>`,
		"LEAK-CARD":    `{"card":"4111 1111 1111 1111","name":"Ali"}`,
	} {
		got := Check(body)
		if len(got) == 0 || got[0].ID != want {
			t.Errorf("%s: got %+v", want, got)
		}
	}
	if m := MaskCards(`card 4111-1111-1111-1111, order 1234567890123`); m != `card ************1111, order 1234567890123` {
		t.Errorf("mask: %q", m)
	}
}

// Ordinary pages and API answers must not look like leaks.
func TestNormalResponses(t *testing.T) {
	bodies := []string{
		`{"order":"1234567890123456","total":"12500 IQD","phone":"07701234567","ts":1731283200123}`,
		`<html><head><title>Sentinel shop</title></head><body><h1>Index of products</h1>Order #4532015112830366x</body></html>`,
		`{"error":"invalid username or password"}`, `Use SELECT to read rows. at least 12 characters`,
		`{"tracking":"1Z999AA10123456784","iban":"IQ98NBIQ850123456789012"}`,
		`call +44 20 7618 0622 or +1 415 555 0132 or +964 770 123 4567`,
	}
	for _, e := range dataset.Generate(3000, 5) {
		// (The payment family is card numbers typed into a checkout form:
		// in a response they are exactly what must be masked.)
		if !e.Attack && e.Family != "payment" {
			bodies = append(bodies, `{"value":"`+e.Text+`"}`)
		}
	}
	for _, b := range bodies {
		if f := Check(b); len(f) > 0 {
			t.Errorf("%q: %+v", b[:min(80, len(b))], f)
		}
	}
	_ = strings.TrimSpace
}
