// Package redisx is a tiny Redis client: just enough of the RESP protocol
// for Sentinel's counters and sets. Writing it ourselves (about 150 lines)
// keeps the gateway free of third-party dependencies for this.
//
// It keeps a small pool of connections and reconnects on error.
package redisx

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Nil is returned when Redis replies with "no value".
var Nil = errors.New("redis: nil")

type Client struct {
	addr     string
	password string
	db       int
	timeout  time.Duration

	mu   sync.Mutex
	idle []*conn
}

type conn struct {
	nc net.Conn
	r  *bufio.Reader
}

// New parses redis://[:password@]host:port[/db].
func New(rawURL string) (*Client, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "redis" || u.Host == "" {
		return nil, fmt.Errorf("REDIS_URL must look like redis://host:6379")
	}
	c := &Client{addr: u.Host, timeout: 2 * time.Second}
	if !strings.Contains(c.addr, ":") {
		c.addr += ":6379"
	}
	if u.User != nil {
		c.password, _ = u.User.Password()
		if c.password == "" {
			c.password = u.User.Username()
		}
	}
	if p := strings.Trim(u.Path, "/"); p != "" {
		if c.db, err = strconv.Atoi(p); err != nil {
			return nil, fmt.Errorf("REDIS_URL database must be a number")
		}
	}
	return c, nil
}

func (c *Client) get(ctx context.Context) (*conn, error) {
	c.mu.Lock()
	if n := len(c.idle); n > 0 {
		cn := c.idle[n-1]
		c.idle = c.idle[:n-1]
		c.mu.Unlock()
		return cn, nil
	}
	c.mu.Unlock()

	d := net.Dialer{Timeout: c.timeout}
	nc, err := d.DialContext(ctx, "tcp", c.addr)
	if err != nil {
		return nil, err
	}
	cn := &conn{nc: nc, r: bufio.NewReader(nc)}
	if c.password != "" {
		if _, err := cn.do(c.timeout, "AUTH", c.password); err != nil {
			nc.Close()
			return nil, err
		}
	}
	if c.db != 0 {
		if _, err := cn.do(c.timeout, "SELECT", strconv.Itoa(c.db)); err != nil {
			nc.Close()
			return nil, err
		}
	}
	return cn, nil
}

func (c *Client) put(cn *conn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.idle) < 16 {
		c.idle = append(c.idle, cn)
		return
	}
	cn.nc.Close()
}

// Do sends one command and returns the reply: string, int64, []any or nil.
// A Redis error reply is returned as an error.
func (c *Client) Do(ctx context.Context, args ...string) (any, error) {
	cn, err := c.get(ctx)
	if err != nil {
		return nil, err
	}
	v, err := cn.do(c.timeout, args...)
	var rerr redisError
	if err != nil && !errors.As(err, &rerr) && !errors.Is(err, Nil) {
		cn.nc.Close() // broken connection: don't reuse it
		return nil, err
	}
	c.put(cn)
	return v, err
}

func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, cn := range c.idle {
		cn.nc.Close()
	}
	c.idle = nil
}

type redisError string

func (e redisError) Error() string { return "redis: " + string(e) }

func (cn *conn) do(timeout time.Duration, args ...string) (any, error) {
	cn.nc.SetDeadline(time.Now().Add(timeout))
	var b strings.Builder
	fmt.Fprintf(&b, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(a), a)
	}
	if _, err := cn.nc.Write([]byte(b.String())); err != nil {
		return nil, err
	}
	return cn.read()
}

func (cn *conn) read() (any, error) {
	line, err := cn.r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	if len(line) < 3 {
		return nil, fmt.Errorf("redis: bad reply")
	}
	kind, body := line[0], line[1:len(line)-2]
	switch kind {
	case '+':
		return body, nil
	case '-':
		return nil, redisError(body)
	case ':':
		return strconv.ParseInt(body, 10, 64)
	case '$':
		n, err := strconv.Atoi(body)
		if err != nil {
			return nil, err
		}
		if n < 0 {
			return nil, Nil
		}
		buf := make([]byte, n+2)
		if _, err := ioReadFull(cn.r, buf); err != nil {
			return nil, err
		}
		return string(buf[:n]), nil
	case '*':
		n, err := strconv.Atoi(body)
		if err != nil {
			return nil, err
		}
		if n < 0 {
			return nil, Nil
		}
		out := make([]any, n)
		for i := range out {
			v, err := cn.read()
			if err != nil && !errors.Is(err, Nil) {
				return nil, err
			}
			out[i] = v
		}
		return out, nil
	}
	return nil, fmt.Errorf("redis: unknown reply type %q", kind)
}

func ioReadFull(r *bufio.Reader, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		m, err := r.Read(buf[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// Int converts a reply to int64.
func Int(v any, err error) (int64, error) {
	if err != nil {
		return 0, err
	}
	switch x := v.(type) {
	case int64:
		return x, nil
	case string:
		return strconv.ParseInt(x, 10, 64)
	}
	return 0, fmt.Errorf("redis: expected a number, got %T", v)
}
