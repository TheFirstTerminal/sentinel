package auth

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFileStoreSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	p := filepath.Join(t.TempDir(), "users.json")
	keys, _ := DeriveKeys(strings.Repeat("f", 40))
	st, err := OpenFileStore(p)
	if err != nil {
		t.Fatal(err)
	}
	svc, _ := NewService(st, keys)
	setup, tok, _ := svc.NewSetup(ctx)
	if err := svc.CreateAdmin(ctx, setup, tok, "root", "a-long-password"); err != nil {
		t.Fatal(err)
	}
	secret, _, _ := svc.Begin2FA(ctx, "root")
	code, _ := TOTPCode(secret, time.Now())
	if err := svc.Enable2FA(ctx, "root", code); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Errorf("users file mode %v", fi.Mode().Perm())
	}
	// "Restart": a new store and service from the same file and secret.
	st2, err := OpenFileStore(p)
	if err != nil {
		t.Fatal(err)
	}
	svc2, _ := NewService(st2, keys)
	res, err := svc2.Login(ctx, "root", "a-long-password")
	if err != nil || !res.MFARequired {
		t.Fatalf("after restart: %v %+v", err, res)
	}
	if _, tok, _ := svc2.NewSetup(ctx); tok != "" {
		t.Error("setup link offered again after restart")
	}
}
