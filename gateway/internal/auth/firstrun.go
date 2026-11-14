package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
)

// First-run setup: when Sentinel starts with no users, it prints a one-time
// link. Whoever opens it first creates the admin account; then the link is
// dead. The token is the only secret: it is printed once, compared in
// constant time, and never logged.

var (
	ErrSetupDone    = errors.New("setup is already done: an account exists")
	ErrSetupToken   = errors.New("the setup link is wrong or has expired; restart Sentinel for a new one")
	ErrWeakPassword = errors.New("the password needs at least 12 characters")
	ErrBadUsername  = errors.New("the username needs 3-32 letters, digits, dots, dashes or underscores")
)

// Setup holds the one-time token.
type Setup struct {
	mu    sync.Mutex
	token string // "" = no setup in progress
}

// NewSetup returns a token if the store has no users yet ("" otherwise).
func (s *Service) NewSetup(ctx context.Context) (*Setup, string, error) {
	n, err := s.store.CountUsers(ctx)
	if err != nil || n > 0 {
		return &Setup{}, "", err
	}
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return nil, "", err
	}
	tok := base64.RawURLEncoding.EncodeToString(b)
	return &Setup{token: tok}, tok, nil
}

// Active reports whether a setup link is waiting to be used.
func (st *Setup) Active() bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.token != ""
}

// CreateAdmin creates the first admin if token is right and no user exists.
func (s *Service) CreateAdmin(ctx context.Context, st *Setup, token, username, password string) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(st.token)) != 1 {
		return ErrSetupToken
	}
	if n, err := s.store.CountUsers(ctx); err != nil {
		return err
	} else if n > 0 {
		st.token = ""
		return ErrSetupDone
	}
	if !validUsername(username) {
		return ErrBadUsername
	}
	if utf8.RuneCountInString(password) < 12 {
		return ErrWeakPassword
	}
	if strings.EqualFold(password, username) {
		return fmt.Errorf("%w (and must not be the username)", ErrWeakPassword)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return err
	}
	if err := s.store.CreateUser(ctx, &User{Username: username, PasswordHash: string(hash), Role: "admin", Department: "it"}); err != nil {
		return err
	}
	st.token = "" // one use only
	return nil
}

func validUsername(u string) bool {
	if len(u) < 3 || len(u) > 32 {
		return false
	}
	for _, c := range u {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
