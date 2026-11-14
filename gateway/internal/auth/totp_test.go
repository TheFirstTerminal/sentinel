package auth

import (
	"testing"
	"time"
)

func TestCodeValidForFiveMinutes(t *testing.T) {
	secret := GenerateTOTPSecret()
	now := time.Now()
	old, _ := TOTPCode(secret, now.Add(-4*time.Minute-50*time.Second))
	if step, _ := checkTOTP(secret, old, now); step < 0 {
		t.Fatal("a code from 4m50s ago was refused")
	}
	stale, _ := TOTPCode(secret, now.Add(-6*time.Minute))
	if step, _ := checkTOTP(secret, stale, now); step >= 0 {
		t.Fatal("a code from 6 minutes ago was accepted")
	}
}
