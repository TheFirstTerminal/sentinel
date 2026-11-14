package auth

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

func TestFirstRunSetup(t *testing.T) {
	ctx := context.Background()
	keys, _ := DeriveKeys(strings.Repeat("k", 40))
	svc, _ := NewService(NewMemoryStore(), keys)
	st, tok, err := svc.NewSetup(ctx)
	if err != nil || tok == "" || !st.Active() {
		t.Fatalf("no setup token: %v", err)
	}
	if err := svc.CreateAdmin(ctx, st, "wrong", "root", "a-long-password"); !errors.Is(err, ErrSetupToken) {
		t.Errorf("wrong token: %v", err)
	}
	if err := svc.CreateAdmin(ctx, st, tok, "root", "short"); !errors.Is(err, ErrWeakPassword) {
		t.Errorf("short password: %v", err)
	}
	if err := svc.CreateAdmin(ctx, st, tok, "a b<script>", "a-long-password"); !errors.Is(err, ErrBadUsername) {
		t.Errorf("bad username: %v", err)
	}
	// Two people race for the link: exactly one wins.
	var wg sync.WaitGroup
	wins := make(chan string, 2)
	for _, name := range []string{"alice", "mallory"} {
		wg.Add(1)
		go func(n string) {
			defer wg.Done()
			if svc.CreateAdmin(ctx, st, tok, n, "a-long-password-1") == nil {
				wins <- n
			}
		}(name)
	}
	wg.Wait()
	close(wins)
	if len(wins) != 1 {
		t.Fatalf("%d accounts created", len(wins))
	}
	if st.Active() {
		t.Error("link still active after use")
	}
	winner := <-wins
	res, err := svc.Login(ctx, winner, "a-long-password-1")
	if err != nil || res.Role != "admin" {
		t.Errorf("the new admin can't log in: %v %+v", err, res)
	}
	// With a user present, a fresh start gives no link.
	if _, tok2, _ := svc.NewSetup(ctx); tok2 != "" {
		t.Error("setup offered although an account exists")
	}
}
