package waf

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"unicode/utf8"
)

// MaxDecodedBody caps how far a compressed request body is expanded for
// inspection (the default MAX_BODY_BYTES), so a zip bomb can't exhaust
// memory or CPU.
var MaxDecodedBody = 1 << 20

// decodeBody expands a gzip or deflate request body so the rules see what
// the application will read. ok is true when the encoding is one Sentinel
// can read; a body that only claims to be compressed is inspected as sent.
func decodeBody(r *http.Request, body []byte) (ok bool, out []byte) {
	enc := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding")))
	var zr io.Reader
	switch enc {
	case "gzip", "x-gzip":
		g, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return true, body
		}
		zr = g
	case "deflate":
		zr = flate.NewReader(bytes.NewReader(body))
	case "":
		// sendBeacon and analytics SDKs often post gzip without saying so.
		if len(body) < 2 || body[0] != 0x1f || body[1] != 0x8b {
			return false, body
		}
		g, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return false, body
		}
		dec, err := io.ReadAll(io.LimitReader(g, int64(MaxDecodedBody)+1))
		if len(dec) == 0 || len(dec) > MaxDecodedBody || err != nil && !utf8.Valid(dec) {
			return false, body
		}
		return false, dec
	default:
		return false, body
	}
	dec, err := io.ReadAll(io.LimitReader(zr, int64(MaxDecodedBody)+1))
	if len(dec) > MaxDecodedBody {
		// Too big to inspect once expanded: keep the CRS warning.
		return false, body
	}
	if err != nil && len(dec) == 0 {
		return true, body
	}
	return true, dec
}

// splitLargeJSON replaces a raw body too large to inspect whole with its
// fields when it is JSON sent under another type (text/plain beacons and
// session-replay uploads). Small ones stay raw: their fields read as code
// to the model, and the whole body is cheap to check.
func splitLargeJSON(inputs []Input) []Input {
	for i, in := range inputs {
		if in.Field != "(raw)" || in.Target != TargetBody || MaxFieldBytes <= 0 || len(in.Value) <= MaxFieldBytes {
			continue
		}
		t := strings.TrimSpace(in.Value)
		if t == "" || t[0] != '{' && t[0] != '[' {
			continue
		}
		var v any
		if json.Unmarshal([]byte(t), &v) != nil || depth(v) > MaxJSONDepth {
			continue
		}
		var fields []Input
		walkJSON("", v, &fields)
		out := append([]Input{}, inputs[:i]...)
		out = append(out, fields...)
		return append(out, inputs[i+1:]...)
	}
	return inputs
}
