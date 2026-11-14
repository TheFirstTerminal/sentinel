package ratelimit

import (
	"context"
	"testing"
	"time"

	"sentinel/gateway/internal/kv"
)

func TestParse(t *testing.T) {
	rules, err := Parse("/=600/1m, /__sentinel/auth/=10/1m,/staff/=5/m")
	if err != nil {
		t.Fatal(err)
	}
	if rules[0].Prefix != "/__sentinel/auth/" || rules[2].Prefix != "/" {
		t.Errorf("not longest-first: %v", rules)
	}
	if rules[1].Window != time.Minute || rules[1].Limit != 5 {
		t.Errorf("/staff/ rule = %v", rules[1])
	}
	for _, bad := range []string{"staff=1/1m", "/=0/1m", "/=5/1ms", "/=x/1m", "/=5"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestCheck(t *testing.T) {
	rules, _ := Parse("/login/=3/1m")
	m := kv.NewMemory()
	now := time.Unix(0, 0)
	m.SetClock(func() time.Time { return now })
	l := New(rules, m)
	ctx := context.Background()

	for i := 1; i <= 3; i++ {
		if r, _ := l.Check(ctx, "/login/x", "ip:1"); !r.Allowed || r.Remaining != int64(3-i) {
			t.Fatalf("request %d: %+v", i, r)
		}
	}
	if r, _ := l.Check(ctx, "/login/x", "ip:1"); r.Allowed || r.RetryAfter != time.Minute {
		t.Errorf("4th allowed: %+v", r)
	}
	if r, _ := l.Check(ctx, "/login/x", "ip:2"); !r.Allowed {
		t.Error("other client limited")
	}
	if r, _ := l.Check(ctx, "/other", "ip:1"); !r.Allowed || r.Rule != nil {
		t.Error("unmatched path limited")
	}
	now = now.Add(61 * time.Second)
	if r, _ := l.Check(ctx, "/login/x", "ip:1"); !r.Allowed {
		t.Error("still limited after the window")
	}
}
