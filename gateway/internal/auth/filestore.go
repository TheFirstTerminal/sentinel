package auth

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// FileStore is a MemoryStore whose users are saved to a JSON file, so a
// single Sentinel keeps its accounts without a database. Passwords are
// bcrypt hashes and 2FA secrets are encrypted, as in PostgreSQL; the file
// is written atomically with owner-only permissions.
type FileStore struct {
	*MemoryStore
	path string
}

// OpenFileStore loads path (a missing file is an empty store).
func OpenFileStore(path string) (*FileStore, error) {
	s := &FileStore{MemoryStore: NewMemoryStore(), path: path}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, s.save() // fail now if the folder isn't writable
	}
	if err != nil {
		return nil, err
	}
	var users []*User
	if err := json.Unmarshal(data, &users); err != nil {
		return nil, err
	}
	for _, u := range users {
		s.users[u.Username] = u
		if u.ID > s.nextID {
			s.nextID = u.ID
		}
	}
	return s, nil
}

func (s *FileStore) save() error {
	s.mu.Lock()
	users := make([]*User, 0, len(s.users))
	for _, u := range s.users {
		c := *u
		users = append(users, &c)
	}
	s.mu.Unlock()
	data, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".users-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}

func (s *FileStore) CreateUser(ctx context.Context, u *User) error {
	if err := s.MemoryStore.CreateUser(ctx, u); err != nil {
		return err
	}
	return s.save()
}

func (s *FileStore) SetTOTP(ctx context.Context, name, secretEnc string, enabled bool) error {
	if err := s.MemoryStore.SetTOTP(ctx, name, secretEnc, enabled); err != nil {
		return err
	}
	return s.save()
}

// Revoked tokens stay in memory: they expire within the token lifetime.
var _ Store = (*FileStore)(nil)
