package auth

import (
	"context"
	"errors"
	"sync"
	"time"
)

var ErrNotFound = errors.New("not found")

// User as stored in the database.
type User struct {
	ID            int64
	Username      string
	PasswordHash  string // bcrypt
	Role          string // admin, employee
	Department    string // hr, sales, engineering, it
	TOTPSecretEnc string // AES-GCM encrypted base32 secret ("" = none)
	TOTPEnabled   bool   // 2FA active (secret confirmed with a valid code)
}

// Store is where users and revoked tokens live. PostgreSQL in the lab,
// memory in tests or when no DATABASE_URL is set.
type Store interface {
	UserByName(ctx context.Context, username string) (*User, error)
	CreateUser(ctx context.Context, u *User) error
	SetTOTP(ctx context.Context, username, secretEnc string, enabled bool) error
	CountUsers(ctx context.Context) (int, error)
	RevokeToken(ctx context.Context, jti string, expires time.Time) error
	IsRevoked(ctx context.Context, jti string) (bool, error)
}

// MemoryStore is a Store kept in RAM (lost on restart).
type MemoryStore struct {
	mu      sync.Mutex
	users   map[string]*User
	revoked map[string]time.Time
	nextID  int64
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{users: map[string]*User{}, revoked: map[string]time.Time{}}
}

func (m *MemoryStore) UserByName(_ context.Context, name string) (*User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[name]
	if !ok {
		return nil, ErrNotFound
	}
	c := *u
	return &c, nil
}

func (m *MemoryStore) CreateUser(_ context.Context, u *User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.users[u.Username]; ok {
		return errors.New("user already exists")
	}
	m.nextID++
	c := *u
	c.ID = m.nextID
	m.users[u.Username] = &c
	return nil
}

func (m *MemoryStore) SetTOTP(_ context.Context, name, secretEnc string, enabled bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[name]
	if !ok {
		return ErrNotFound
	}
	u.TOTPSecretEnc, u.TOTPEnabled = secretEnc, enabled
	return nil
}

func (m *MemoryStore) CountUsers(context.Context) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.users), nil
}

func (m *MemoryStore) RevokeToken(_ context.Context, jti string, exp time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revoked[jti] = exp
	return nil
}

func (m *MemoryStore) IsRevoked(_ context.Context, jti string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.revoked[jti]
	return ok, nil
}
