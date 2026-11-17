package auth

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// Dashboard roles, from most to least allowed:
//
//	admin     everything, including accounts
//	operator  bans, exclusions and reloads; not sites, alerts or accounts
//	viewer    looks only
var DashboardRoles = []string{"admin", "operator", "viewer"}

// IsDashboardRole reports whether role may use the dashboard.
func IsDashboardRole(role string) bool {
	for _, r := range DashboardRoles {
		if r == role {
			return true
		}
	}
	return false
}

// RoleRank orders dashboard roles (admin 3, operator 2, viewer 1, other 0).
func RoleRank(role string) int {
	for i, r := range DashboardRoles {
		if r == role {
			return len(DashboardRoles) - i
		}
	}
	return 0
}

var (
	ErrLastAdmin = errors.New("there must stay at least one admin")
	ErrSelf      = errors.New("you can't remove or demote your own account; ask another admin")
	ErrBadRole   = errors.New("role must be admin, operator or viewer")
	roleName     = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
)

// Account is a user as the dashboard lists it (no secrets).
type Account struct {
	Username   string `json:"username"`
	Role       string `json:"role"`
	Department string `json:"department,omitempty"`
	TwoFA      bool   `json:"two_factor"`
}

func (s *Service) checkRole(role string) error {
	if AdminOnly {
		if !IsDashboardRole(role) {
			return ErrBadRole
		}
		return nil
	}
	if !roleName.MatchString(role) {
		return fmt.Errorf("role %q: use lowercase letters, digits, - and _", role)
	}
	return nil
}

// Accounts lists every account, by name.
func (s *Service) Accounts(ctx context.Context) ([]Account, error) {
	users, err := s.store.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Account, 0, len(users))
	for _, u := range users {
		out = append(out, Account{Username: u.Username, Role: u.Role, Department: u.Department, TwoFA: u.TOTPEnabled})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out, nil
}

// RoleOf is an account's current role (ok false when it no longer exists).
func (s *Service) RoleOf(ctx context.Context, username string) (string, bool) {
	u, err := s.store.UserByName(ctx, username)
	if err != nil {
		return "", false
	}
	return u.Role, true
}

// CreateAccount makes an account with a random one-time password, returned
// once. The person sets up 2FA at their first login.
func (s *Service) CreateAccount(ctx context.Context, username, role, dept string) (string, error) {
	if !validUsername(username) {
		return "", ErrBadUsername
	}
	if err := s.checkRole(role); err != nil {
		return "", err
	}
	if _, err := s.store.UserByName(ctx, username); err == nil {
		return "", fmt.Errorf("there is already an account %q", username)
	}
	pw, hash, err := newPassword()
	if err != nil {
		return "", err
	}
	return pw, s.store.CreateUser(ctx, &User{Username: username, PasswordHash: hash, Role: role, Department: dept})
}

// ResetAccount gives an account a new one-time password and turns its 2FA
// off, so the person sets it up again (a lost phone, a forgotten password).
func (s *Service) ResetAccount(ctx context.Context, username string) (string, error) {
	if _, err := s.store.UserByName(ctx, username); err != nil {
		return "", fmt.Errorf("no account %q", username)
	}
	pw, hash, err := newPassword()
	if err != nil {
		return "", err
	}
	if err := s.store.UpdateUser(ctx, username, "", hash, true); err != nil {
		return "", err
	}
	s.mu.Lock()
	delete(s.lastStep, username)
	s.mu.Unlock()
	return pw, nil
}

// SetAccountRole changes an account's role. by is who asks.
func (s *Service) SetAccountRole(ctx context.Context, by, username, role string) error {
	if err := s.checkRole(role); err != nil {
		return err
	}
	u, err := s.store.UserByName(ctx, username)
	if err != nil {
		return fmt.Errorf("no account %q", username)
	}
	if u.Role == "admin" && role != "admin" {
		if username == by {
			return ErrSelf
		}
		if err := s.keepOneAdmin(ctx); err != nil {
			return err
		}
	}
	return s.store.UpdateUser(ctx, username, role, "", false)
}

// DeleteAccount removes an account. by is who asks.
func (s *Service) DeleteAccount(ctx context.Context, by, username string) error {
	if username == by {
		return ErrSelf
	}
	u, err := s.store.UserByName(ctx, username)
	if err != nil {
		return fmt.Errorf("no account %q", username)
	}
	if u.Role == "admin" {
		if err := s.keepOneAdmin(ctx); err != nil {
			return err
		}
	}
	return s.store.DeleteUser(ctx, username)
}

// keepOneAdmin fails unless there are at least two admins (one may go).
func (s *Service) keepOneAdmin(ctx context.Context) error {
	users, err := s.store.ListUsers(ctx)
	if err != nil {
		return err
	}
	n := 0
	for _, u := range users {
		if u.Role == "admin" {
			n++
		}
	}
	if n < 2 {
		return ErrLastAdmin
	}
	return nil
}

// newPassword is 20 random letters and digits (about 119 bits), with its
// bcrypt hash.
func newPassword() (string, string, error) {
	const alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	var sb strings.Builder
	for _, c := range b {
		sb.WriteByte(alphabet[int(c)%len(alphabet)])
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(sb.String()), bcryptCost)
	return sb.String(), string(hash), err
}
