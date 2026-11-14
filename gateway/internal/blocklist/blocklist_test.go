package blocklist

import (
	"testing"
	"time"
)

func TestBanExpires(t *testing.T) {
	now := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	l := New()
	l.now = func() time.Time { return now }

	l.Ban("10.0.0.5", 5*time.Minute)
	if !l.Banned("10.0.0.5") {
		t.Fatal("should be banned")
	}
	if l.Banned("10.0.0.6") {
		t.Fatal("other IPs must not be banned")
	}
	now = now.Add(6 * time.Minute)
	if l.Banned("10.0.0.5") {
		t.Fatal("ban should have expired")
	}
}

func TestShorterBanDoesNotShortenLonger(t *testing.T) {
	now := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	l := New()
	l.now = func() time.Time { return now }
	l.Ban("10.0.0.5", time.Hour)
	l.Ban("10.0.0.5", time.Minute)
	now = now.Add(10 * time.Minute)
	if !l.Banned("10.0.0.5") {
		t.Fatal("the longer ban should still apply")
	}
}
