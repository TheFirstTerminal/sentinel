package auth

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// runAccounts checks account management on any Store.
func runAccounts(t *testing.T, store Store) {
	ctx := context.Background()
	keys, _ := DeriveKeys("a-test-secret-that-is-long-enough-1234567890")
	svc, err := NewService(store, keys)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateUser(ctx, &User{Username: "root", Role: "admin"}); err != nil {
		t.Fatal(err)
	}
	pw, err := svc.CreateAccount(ctx, "olga", "operator", "it")
	if err != nil || len(pw) != 20 {
		t.Fatalf("create: %q %v", pw, err)
	}
	if r, err := svc.Login(ctx, "olga", pw); err != nil || r.Role != "operator" {
		t.Fatalf("an operator can log in with the one-time password: %+v %v", r, err)
	}
	if err := svc.SetAccountRole(ctx, "root", "olga", "viewer"); err != nil {
		t.Fatal(err)
	}
	if role, ok := svc.RoleOf(ctx, "olga"); !ok || role != "viewer" {
		t.Errorf("role: %q %v", role, ok)
	}
	pw2, err := svc.ResetAccount(ctx, "olga")
	if err != nil || pw2 == pw {
		t.Fatalf("reset: %v", err)
	}
	if _, err := svc.Login(ctx, "olga", pw); err == nil {
		t.Error("the old password must stop working after a reset")
	}
	if _, err := svc.Login(ctx, "olga", pw2); err != nil {
		t.Errorf("the new password: %v", err)
	}
	list, _ := svc.Accounts(ctx)
	if len(list) != 2 || list[0].Username != "olga" || list[1].Username != "root" {
		t.Errorf("accounts: %+v", list)
	}
	if err := svc.DeleteAccount(ctx, "root", "root"); err != ErrSelf {
		t.Errorf("remove yourself: %v", err)
	}
	if err := svc.SetAccountRole(ctx, "olga", "root", "viewer"); err != ErrLastAdmin {
		t.Errorf("demote the last admin: %v", err)
	}
	if err := svc.DeleteAccount(ctx, "root", "olga"); err != nil {
		t.Fatal(err)
	}
	if _, ok := svc.RoleOf(ctx, "olga"); ok {
		t.Error("removed account still found")
	}
}

func TestAccountsMemory(t *testing.T) { runAccounts(t, NewMemoryStore()) }

func TestAccountsFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	fs, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	runAccounts(t, fs)
	again, err := OpenFileStore(path) // changes are saved
	if err != nil {
		t.Fatal(err)
	}
	if list, _ := again.ListUsers(context.Background()); len(list) != 1 || list[0].Username != "root" {
		t.Errorf("after reopening: %+v", list)
	}
}

func TestAccountsPostgres(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pg, err := OpenPG(ctx, url, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	pg.pool.Exec(ctx, `TRUNCATE users, revoked_tokens RESTART IDENTITY`)
	runAccounts(t, pg)
}
