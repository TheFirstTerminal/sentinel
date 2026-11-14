package kv

import (
	"context"
	"os"
	"testing"
	"time"
)

func testStore(t *testing.T, s Store, advance func(time.Duration)) {
	ctx := context.Background()
	for i := int64(1); i <= 3; i++ {
		if n, err := s.Incr(ctx, "c", time.Second); err != nil || n != i {
			t.Fatalf("incr %d: %d %v", i, n, err)
		}
	}
	if n, _ := s.Get(ctx, "c"); n != 3 {
		t.Errorf("get = %d", n)
	}
	if n, _ := s.Get(ctx, "missing"); n != 0 {
		t.Errorf("missing = %d", n)
	}
	advance(1100 * time.Millisecond)
	if n, _ := s.Incr(ctx, "c", time.Second); n != 1 {
		t.Errorf("after window: %d, want 1", n)
	}

	if seen, _ := s.Remember(ctx, "set", "a", time.Minute); seen {
		t.Error("a seen before adding")
	}
	if seen, _ := s.Remember(ctx, "set", "a", time.Minute); !seen {
		t.Error("a not seen after adding")
	}
	s.Remember(ctx, "set", "b", time.Minute)
	if ok, _ := s.Has(ctx, "set", "b"); !ok {
		t.Error("Has b")
	}
	if ok, _ := s.Has(ctx, "set", "z"); ok {
		t.Error("Has z")
	}
	if n, _ := s.Size(ctx, "set"); n != 2 {
		t.Errorf("size = %d", n)
	}
	if v, _ := s.Fetch(ctx, "v"); v != "" {
		t.Errorf("missing value = %q", v)
	}
	s.Put(ctx, "v", "12:abc", 0)
	if v, _ := s.Fetch(ctx, "v"); v != "12:abc" {
		t.Errorf("value = %q", v)
	}
}

func TestMemory(t *testing.T) {
	m := NewMemory()
	now := time.Unix(1000, 0)
	m.SetClock(func() time.Time { return now })
	testStore(t, m, func(d time.Duration) { now = now.Add(d) })
}

// Runs against a real Redis when TEST_REDIS_URL is set (CI does).
func TestRedis(t *testing.T) {
	url := os.Getenv("TEST_REDIS_URL")
	if url == "" {
		t.Skip("TEST_REDIS_URL not set")
	}
	r, err := NewRedis(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	r.prefix = "sentinel-test:" + time.Now().Format("150405.000000") + ":"
	testStore(t, r, time.Sleep)
}
