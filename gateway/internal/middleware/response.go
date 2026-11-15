package middleware

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"

	"sentinel/gateway/internal/leak"
	"sentinel/gateway/internal/reqctx"
)

// ResponseGuard checks what the app sends back (see package leak): card
// numbers are masked; database errors, stack traces, keys and directory
// listings are withheld in "block" mode and logged in "detect" mode.
//
// Only text responses up to maxBytes are held and checked. Streams (SSE, or
// anything that flushes), large and binary responses pass straight through,
// so nothing that streams can break.
func ResponseGuard(mode string, maxBytes int, log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if mode == "off" || mode == "" {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodHead {
				next.ServeHTTP(w, r)
				return
			}
			// Go can only read gzip; ask the app for that or nothing.
			if ae := r.Header.Get("Accept-Encoding"); ae != "" {
				if strings.Contains(strings.ToLower(ae), "gzip") {
					r.Header.Set("Accept-Encoding", "gzip")
				} else {
					r.Header.Del("Accept-Encoding")
				}
			}
			// A text page fetched in small byte ranges would never show a
			// whole error message to check. Media and downloads (never
			// text-checked) keep their ranges.
			if r.Header.Get("Range") != "" && !mediaPath(r.URL.Path) {
				r.Header.Del("Range")
				r.Header.Del("If-Range")
			}
			hw := &holdWriter{w: w, max: maxBytes}
			next.ServeHTTP(hw, r)
			if !hw.holding {
				return // passed through
			}
			hw.finish(r, mode, log)
		})
	}
}

type holdWriter struct {
	w       http.ResponseWriter
	max     int
	status  int
	decided bool
	holding bool
	buf     bytes.Buffer
}

func (h *holdWriter) Header() http.Header { return h.w.Header() }

func (h *holdWriter) decide() {
	if h.decided {
		return
	}
	h.decided = true
	if h.status == 0 {
		h.status = http.StatusOK
	}
	hd := h.w.Header()
	ct := strings.ToLower(hd.Get("Content-Type"))
	enc := strings.ToLower(hd.Get("Content-Encoding"))
	textual := strings.HasPrefix(ct, "text/html") || strings.HasPrefix(ct, "application/json") || strings.HasPrefix(ct, "text/plain") ||
		strings.Contains(ct, "xml") || strings.Contains(ct, "+json") || ct == ""
	small := true
	if cl, err := strconv.Atoi(hd.Get("Content-Length")); err == nil && cl > h.max {
		small = false
	}
	h.holding = textual && small && (enc == "" || enc == "gzip") && h.status != http.StatusNoContent && h.status != http.StatusNotModified &&
		!strings.HasPrefix(ct, "text/event-stream")
	if !h.holding {
		h.w.WriteHeader(h.status)
	}
}

func (h *holdWriter) WriteHeader(code int) {
	if h.decided {
		return
	}
	h.status = code
	h.decide()
}

func (h *holdWriter) Write(b []byte) (int, error) {
	h.decide()
	if !h.holding {
		return h.w.Write(b)
	}
	if h.buf.Len()+len(b) > h.max {
		h.release() // too big to hold: send what we have and stream the rest
		return h.w.Write(b)
	}
	return h.buf.Write(b)
}

// release sends what is held and stops holding (unchecked).
func (h *holdWriter) release() {
	h.holding = false
	h.w.WriteHeader(h.status)
	h.w.Write(h.buf.Bytes())
	h.buf.Reset()
}

// Flush means the app is streaming: stop holding.
func (h *holdWriter) Flush() {
	h.decide()
	if h.holding {
		h.release()
	}
	if f, ok := h.w.(http.Flusher); ok {
		f.Flush()
	}
}

func (h *holdWriter) Unwrap() http.ResponseWriter { return h.w }

func (h *holdWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := h.w.(http.Hijacker); ok {
		h.decided, h.holding = true, false
		return hj.Hijack()
	}
	return nil, nil, errors.New("hijack not supported")
}

func (h *holdWriter) finish(r *http.Request, mode string, log *slog.Logger) {
	raw := h.buf.Bytes()
	text := raw
	gz := strings.EqualFold(h.w.Header().Get("Content-Encoding"), "gzip")
	if gz {
		zr, err := gzip.NewReader(bytes.NewReader(raw))
		if err == nil {
			text, err = io.ReadAll(io.LimitReader(zr, int64(h.max)*4))
		}
		if err != nil { // not really gzip: send as it came
			h.w.WriteHeader(h.status)
			h.w.Write(raw)
			return
		}
	}
	var findings []leak.Finding
	for _, f := range leak.Check(string(text)) {
		if !Exclusions.ExcludedOn(reqctx.From(r.Context()).Site, f.ID, r.Method, r.URL.Path, "response") {
			findings = append(findings, f)
		}
	}
	if len(findings) == 0 {
		h.w.WriteHeader(h.status)
		h.w.Write(raw)
		return
	}
	info := reqctx.From(r.Context())
	f := findings[0]
	var stop *leak.Finding
	for i := range findings {
		if !findings[i].Mask {
			stop = &findings[i]
			break
		}
	}
	if stop != nil {
		f = *stop
	}
	kind := "leak_blocked"
	if mode != "block" || stop == nil {
		kind = "detected"
	}
	info.SetOutcome(reqctx.Outcome{Kind: kind, Rule: f.ID, Reason: "the app's response contained a " + f.Name,
		Detail: "response: " + f.Excerpt, Field: "response"})
	log.Warn("response_leak", "request_id", info.ID, "path", r.URL.Path, "status", h.status, "findings", findings, "action", kind)

	hd := h.w.Header()
	if stop != nil && mode == "block" {
		hd.Del("Content-Encoding")
		hd.Del("Content-Length")
		hd.Del("ETag")
		hd.Set("Content-Type", "text/plain; charset=utf-8")
		hd.Set("Cache-Control", "no-store")
		h.w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(h.w, "The server had an error. Details were withheld by Sentinel because they could help an attacker. Request ID: "+info.ID+"\n")
		return
	}
	if stop == nil { // only card numbers: mask them, whatever the mode
		masked := leak.MaskCards(string(text))
		hd.Del("Content-Encoding")
		hd.Del("ETag")
		hd.Set("Content-Length", strconv.Itoa(len(masked)))
		h.w.WriteHeader(h.status)
		io.WriteString(h.w, masked)
		return
	}
	h.w.WriteHeader(h.status) // detect mode: send it unchanged
	h.w.Write(raw)
}

var mediaExt = map[string]bool{".mp4": true, ".webm": true, ".mov": true, ".mkv": true, ".mp3": true, ".m4a": true, ".ogg": true,
	".wav": true, ".flac": true, ".pdf": true, ".zip": true, ".gz": true, ".tar": true, ".iso": true, ".dmg": true, ".exe": true,
	".msi": true, ".apk": true, ".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".webp": true, ".avif": true, ".m3u8": true, ".ts": true, ".bin": true}

func mediaPath(p string) bool {
	if i := strings.LastIndexByte(p, '.'); i >= 0 && i > strings.LastIndexByte(p, '/') {
		return mediaExt[strings.ToLower(p[i:])]
	}
	return false
}
