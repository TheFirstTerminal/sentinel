package middleware

import (
	"bufio"
	"errors"
	"net"
	"net/http"

	"sentinel/gateway/internal/reqctx"
)

// Shadow runs a check in monitor mode: the check sees the request and logs
// as usual, but if it would refuse the request, its response is thrown away
// and the request goes on to the app. New users start here, watch what
// Sentinel would block for a few days, then switch to protect mode.
//
// A check refuses a request by answering without calling next. Until next is
// called, everything the check writes goes to a gate that discards it; once
// next is called the gate opens and the rest of the chain writes straight
// through to the client.
func Shadow(mw func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			g := &gate{real: w, staged: http.Header{}}
			inner := mw(http.HandlerFunc(func(w2 http.ResponseWriter, r2 *http.Request) {
				g.open()
				next.ServeHTTP(w2, r2)
			}))
			inner.ServeHTTP(g, r)
			if !g.opened {
				reqctx.From(r.Context()).MarkMonitored()
				next.ServeHTTP(w, r)
			}
		})
	}
}

type gate struct {
	real   http.ResponseWriter
	staged http.Header
	opened bool
}

func (g *gate) open() {
	if g.opened {
		return
	}
	g.opened = true
	h := g.real.Header()
	for k, v := range g.staged {
		h[k] = v
	}
}

func (g *gate) Header() http.Header {
	if g.opened {
		return g.real.Header()
	}
	return g.staged
}

func (g *gate) WriteHeader(code int) {
	if g.opened {
		g.real.WriteHeader(code)
	}
}

func (g *gate) Write(b []byte) (int, error) {
	if g.opened {
		return g.real.Write(b)
	}
	return len(b), nil // a refusal that will not be sent
}

// Unwrap lets http.ResponseController (used by the reverse proxy for
// streaming and WebSockets) reach the real writer.
func (g *gate) Unwrap() http.ResponseWriter { return g.real }

func (g *gate) Flush() {
	if f, ok := g.real.(http.Flusher); ok && g.opened {
		f.Flush()
	}
}

func (g *gate) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := g.real.(http.Hijacker); ok && g.opened {
		return h.Hijack()
	}
	return nil, nil, errors.New("hijack not supported")
}
