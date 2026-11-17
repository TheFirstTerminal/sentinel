package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PGStore keeps users and revoked tokens in PostgreSQL.
// Every query uses $1 placeholders, never string concatenation, so the
// database layer itself is not open to SQL injection.
type PGStore struct{ pool *pgxpool.Pool }

const schemaSQL = `
CREATE TABLE IF NOT EXISTS users (
    id               BIGSERIAL PRIMARY KEY,
    username         TEXT UNIQUE NOT NULL,
    password_hash    TEXT NOT NULL,
    role             TEXT NOT NULL,
    department       TEXT NOT NULL DEFAULT '',
    totp_secret_enc  TEXT NOT NULL DEFAULT '',
    totp_enabled     BOOLEAN NOT NULL DEFAULT FALSE,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti         TEXT PRIMARY KEY,
    expires_at  TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS revoked_tokens_expires ON revoked_tokens (expires_at);
`

// OpenPG connects (retrying while the database container starts) and
// creates the tables if they don't exist yet.
func OpenPG(ctx context.Context, url string, wait time.Duration) (*PGStore, error) {
	deadline := time.Now().Add(wait)
	var lastErr error
	for {
		pool, err := pgxpool.New(ctx, url)
		if err == nil {
			if err = pool.Ping(ctx); err == nil {
				if _, err = pool.Exec(ctx, schemaSQL); err == nil {
					return &PGStore{pool: pool}, nil
				}
			}
			pool.Close()
		}
		lastErr = err
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("connecting to PostgreSQL: %w", lastErr)
		}
		time.Sleep(time.Second)
	}
}

func (p *PGStore) Close() { p.pool.Close() }

func (p *PGStore) UserByName(ctx context.Context, name string) (*User, error) {
	var u User
	err := p.pool.QueryRow(ctx, `
		SELECT id, username, password_hash, role, department, totp_secret_enc, totp_enabled
		FROM users WHERE username = $1`, name).
		Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.Department, &u.TOTPSecretEnc, &u.TOTPEnabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (p *PGStore) CreateUser(ctx context.Context, u *User) error {
	return p.pool.QueryRow(ctx, `
		INSERT INTO users (username, password_hash, role, department, totp_secret_enc, totp_enabled)
		VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
		u.Username, u.PasswordHash, u.Role, u.Department, u.TOTPSecretEnc, u.TOTPEnabled).Scan(&u.ID)
}

func (p *PGStore) SetTOTP(ctx context.Context, name, secretEnc string, enabled bool) error {
	tag, err := p.pool.Exec(ctx,
		`UPDATE users SET totp_secret_enc = $2, totp_enabled = $3 WHERE username = $1`,
		name, secretEnc, enabled)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *PGStore) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT id, username, password_hash, role, department, totp_secret_enc, totp_enabled FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.Department, &u.TOTPSecretEnc, &u.TOTPEnabled); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (p *PGStore) UpdateUser(ctx context.Context, name, role, hash string, resetTOTP bool) error {
	tag, err := p.pool.Exec(ctx, `
		UPDATE users SET
			role = COALESCE(NULLIF($2, ''), role),
			password_hash = COALESCE(NULLIF($3, ''), password_hash),
			totp_secret_enc = CASE WHEN $4 THEN '' ELSE totp_secret_enc END,
			totp_enabled = CASE WHEN $4 THEN FALSE ELSE totp_enabled END
		WHERE username = $1`, name, role, hash, resetTOTP)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *PGStore) DeleteUser(ctx context.Context, name string) error {
	tag, err := p.pool.Exec(ctx, `DELETE FROM users WHERE username = $1`, name)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *PGStore) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := p.pool.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&n)
	return n, err
}

func (p *PGStore) RevokeToken(ctx context.Context, jti string, exp time.Time) error {
	// Housekeeping: tokens past their expiry are useless anyway.
	p.pool.Exec(ctx, `DELETE FROM revoked_tokens WHERE expires_at < now()`)
	_, err := p.pool.Exec(ctx,
		`INSERT INTO revoked_tokens (jti, expires_at) VALUES ($1, $2) ON CONFLICT (jti) DO NOTHING`,
		jti, exp)
	return err
}

func (p *PGStore) IsRevoked(ctx context.Context, jti string) (bool, error) {
	var exists bool
	err := p.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM revoked_tokens WHERE jti = $1)`, jti).Scan(&exists)
	return exists, err
}
