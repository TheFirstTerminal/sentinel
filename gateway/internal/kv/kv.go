// Package kv is the short-lived shared state behind rate limiting and bans:
// counters that expire and "have we seen this before" sets.
//
// Two implementations: Memory (one gateway, lost on restart) and Redis
// (shared by several gateways, survives restarts).
package kv

import (
	"context"
	"strconv"
	"sync"
	"time"

	"sentinel/gateway/internal/redisx"
)

type Store interface {
	// Incr adds 1 to a counter and returns the new value. The counter
	// disappears window after its first increment (fixed window).
	Incr(ctx context.Context, key string, window time.Duration) (int64, error)
	// IncrBy is Incr by n.
	IncrBy(ctx context.Context, key string, n int64, window time.Duration) (int64, error)
	// Get returns a counter's value (0 if missing or expired).
	Get(ctx context.Context, key string) (int64, error)
	// Remember adds member to the set at key and reports whether it was
	// already there. The whole set expires ttl after the last addition.
	Remember(ctx context.Context, key, member string, ttl time.Duration) (seen bool, err error)
	// Has reports whether member is in the set, without changing it.
	Has(ctx context.Context, key, member string) (bool, error)
	// Put stores a string value (ttl 0 = keep). Fetch reads it ("" if missing).
	Put(ctx context.Context, key, value string, ttl time.Duration) error
	Fetch(ctx context.Context, key string) (string, error)
	// Size is how many members the set has.
	Size(ctx context.Context, key string) (int64, error)
	Name() string
}

// ---------------------------------------------------------------- memory ---

type Memory struct {
	mu       sync.Mutex
	counters map[string]counter
	sets     map[string]*set
	values   map[string]string
	now      func() time.Time
	ops      int
}

type counter struct {
	n   int64
	end time.Time
}

type set struct {
	members map[string]bool
	end     time.Time
}

func NewMemory() *Memory {
	return &Memory{counters: map[string]counter{}, sets: map[string]*set{}, values: map[string]string{}, now: time.Now}
}

func (m *Memory) Name() string { return "memory" }

// SetClock is for tests.
func (m *Memory) SetClock(now func() time.Time) { m.now = now }

func (m *Memory) Incr(ctx context.Context, key string, window time.Duration) (int64, error) {
	return m.IncrBy(ctx, key, 1, window)
}

func (m *Memory) IncrBy(_ context.Context, key string, n int64, window time.Duration) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sweep()
	now := m.now()
	c, ok := m.counters[key]
	if !ok || !now.Before(c.end) {
		c = counter{end: now.Add(window)}
	}
	c.n += n
	m.counters[key] = c
	return c.n, nil
}

func (m *Memory) Get(_ context.Context, key string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.counters[key]
	if !ok || !m.now().Before(c.end) {
		return 0, nil
	}
	return c.n, nil
}

func (m *Memory) Remember(_ context.Context, key, member string, ttl time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	s, ok := m.sets[key]
	if !ok || !now.Before(s.end) {
		s = &set{members: map[string]bool{}}
		m.sets[key] = s
	}
	seen := s.members[member]
	s.members[member] = true
	s.end = now.Add(ttl)
	return seen, nil
}

func (m *Memory) Has(_ context.Context, key, member string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sets[key]
	if !ok || !m.now().Before(s.end) {
		return false, nil
	}
	return s.members[member], nil
}

func (m *Memory) Put(_ context.Context, key, value string, _ time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.values[key] = value
	return nil
}

func (m *Memory) Fetch(_ context.Context, key string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.values[key], nil
}

func (m *Memory) Size(_ context.Context, key string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sets[key]
	if !ok || !m.now().Before(s.end) {
		return 0, nil
	}
	return int64(len(s.members)), nil
}

// sweep drops expired entries every 1000 operations so memory stays bounded.
func (m *Memory) sweep() {
	m.ops++
	if m.ops%1000 != 0 {
		return
	}
	now := m.now()
	for k, c := range m.counters {
		if !now.Before(c.end) {
			delete(m.counters, k)
		}
	}
	for k, s := range m.sets {
		if !now.Before(s.end) {
			delete(m.sets, k)
		}
	}
}

// ----------------------------------------------------------------- redis ---

type Redis struct {
	c      *redisx.Client
	prefix string
}

// NewRedis connects and checks the connection with PING.
func NewRedis(ctx context.Context, url string) (*Redis, error) {
	c, err := redisx.New(url)
	if err != nil {
		return nil, err
	}
	if _, err := c.Do(ctx, "PING"); err != nil {
		return nil, err
	}
	return &Redis{c: c, prefix: "sentinel:"}, nil
}

func (r *Redis) Name() string { return "redis" }
func (r *Redis) Close()       { r.c.Close() }

// incrScript increments and sets the expiry only on the first increment,
// in one atomic step (two gateways can't both "start" the window).
const incrScript = `local n = redis.call('INCRBY', KEYS[1], ARGV[2])
if n == tonumber(ARGV[2]) then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
return n`

func (r *Redis) Incr(ctx context.Context, key string, window time.Duration) (int64, error) {
	return r.IncrBy(ctx, key, 1, window)
}

func (r *Redis) IncrBy(ctx context.Context, key string, n int64, window time.Duration) (int64, error) {
	return redisx.Int(r.c.Do(ctx, "EVAL", incrScript, "1", r.prefix+key, ms(window), strconv.FormatInt(n, 10)))
}

func (r *Redis) Get(ctx context.Context, key string) (int64, error) {
	n, err := redisx.Int(r.c.Do(ctx, "GET", r.prefix+key))
	if err == redisx.Nil {
		return 0, nil
	}
	return n, err
}

const rememberScript = `local added = redis.call('SADD', KEYS[1], ARGV[1])
redis.call('PEXPIRE', KEYS[1], ARGV[2])
return added`

func (r *Redis) Remember(ctx context.Context, key, member string, ttl time.Duration) (bool, error) {
	added, err := redisx.Int(r.c.Do(ctx, "EVAL", rememberScript, "1", r.prefix+key, member, ms(ttl)))
	return added == 0, err
}

func (r *Redis) Has(ctx context.Context, key, member string) (bool, error) {
	n, err := redisx.Int(r.c.Do(ctx, "SISMEMBER", r.prefix+key, member))
	return n == 1, err
}

func (r *Redis) Put(ctx context.Context, key, value string, ttl time.Duration) error {
	args := []string{"SET", r.prefix + key, value}
	if ttl > 0 {
		args = append(args, "PX", ms(ttl))
	}
	_, err := r.c.Do(ctx, args...)
	return err
}

func (r *Redis) Fetch(ctx context.Context, key string) (string, error) {
	v, err := r.c.Do(ctx, "GET", r.prefix+key)
	if err == redisx.Nil {
		return "", nil
	}
	s, _ := v.(string)
	return s, err
}

func (r *Redis) Size(ctx context.Context, key string) (int64, error) {
	return redisx.Int(r.c.Do(ctx, "SCARD", r.prefix+key))
}

func ms(d time.Duration) string { return strconv.FormatInt(d.Milliseconds(), 10) }
