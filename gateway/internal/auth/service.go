package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrBadCredentials  = errors.New("invalid username or password")
	ErrBadCode         = errors.New("invalid 2FA code")
	ErrCodeReused      = errors.New("this 2FA code was already used, wait for the next one")
	ErrTooManyAttempts = errors.New("too many wrong 2FA codes, log in again")
	ErrNo2FASetup      = errors.New("2FA setup was not started")
	Err2FAAlreadyOn    = errors.New("2FA is already enabled")
)

const (
	AccessTTL      = 15 * time.Minute // short-lived: a stolen token expires soon
	mfaTTL         = 5 * time.Minute  // time allowed to type the 2FA code
	maxMFAAttempts = 5                // per password login
	bcryptCost     = 12
)

// Service implements login, 2FA and logout.
type Service struct {
	store  Store
	signer *Signer
	seal   *sealer
	now    func() time.Time

	// A bcrypt hash of a random password. Comparing against it when the
	// username doesn't exist makes "no such user" take as long as "wrong
	// password", so attackers can't discover usernames by timing.
	dummyHash []byte

	mu          sync.Mutex
	lastStep    map[string]int64 // username -> last accepted TOTP step (replay protection)
	mfaAttempts map[string]int   // mfa token jti -> wrong codes so far
}

func NewService(store Store, keys Keys) (*Service, error) {
	s, err := newSealer(keys.Encrypt)
	if err != nil {
		return nil, err
	}
	dummy, _ := bcrypt.GenerateFromPassword([]byte(randomID()), bcryptCost)
	return &Service{
		store:       store,
		signer:      NewSigner(keys.JWT),
		seal:        s,
		now:         time.Now,
		dummyHash:   dummy,
		lastStep:    map[string]int64{},
		mfaAttempts: map[string]int{},
	}, nil
}

// LoginResult: either a full access token, or (if the user has 2FA) a
// short-lived MFA token to exchange together with a code.
type LoginResult struct {
	Token       string `json:"token,omitempty"`
	ExpiresIn   int    `json:"expires_in,omitempty"`
	MFARequired bool   `json:"mfa_required,omitempty"`
	MFAToken    string `json:"mfa_token,omitempty"`
	User        string `json:"user"`
	Role        string `json:"role"`
}

func (s *Service) Login(ctx context.Context, username, password string) (*LoginResult, error) {
	u, err := s.store.UserByName(ctx, username)
	if errors.Is(err, ErrNotFound) {
		bcrypt.CompareHashAndPassword(s.dummyHash, []byte(password))
		return nil, ErrBadCredentials
	}
	if err != nil {
		return nil, err
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) != nil {
		return nil, ErrBadCredentials
	}
	// Logins are for Sentinel's own administrators (the dashboard). Other
	// accounts, e.g. left in a shared database, can't sign in.
	if u.Role != "admin" {
		return nil, ErrBadCredentials
	}

	base := Claims{Sub: u.Username, Role: u.Role, Dept: u.Department}
	if u.TOTPEnabled {
		base.Purpose = PurposeMFA
		tok, _, err := s.signer.Sign(base, mfaTTL)
		if err != nil {
			return nil, err
		}
		return &LoginResult{MFARequired: true, MFAToken: tok, User: u.Username, Role: u.Role}, nil
	}
	base.Purpose = PurposeAccess
	tok, _, err := s.signer.Sign(base, AccessTTL)
	if err != nil {
		return nil, err
	}
	return &LoginResult{Token: tok, ExpiresIn: int(AccessTTL.Seconds()), User: u.Username, Role: u.Role}, nil
}

// VerifyMFA exchanges an MFA token + correct code for an access token
// with mfa=true (needed for admin areas).
func (s *Service) VerifyMFA(ctx context.Context, mfaToken, code string) (*LoginResult, error) {
	c, err := s.signer.Verify(mfaToken, PurposeMFA)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	if s.mfaAttempts[c.Jti] >= maxMFAAttempts {
		s.mu.Unlock()
		return nil, ErrTooManyAttempts
	}
	s.mu.Unlock()

	u, err := s.store.UserByName(ctx, c.Sub)
	if err != nil {
		return nil, err
	}
	if !u.TOTPEnabled {
		return nil, ErrNo2FASetup
	}
	secret, err := s.seal.open(u.TOTPSecretEnc)
	if err != nil {
		return nil, err
	}
	if err := s.acceptCode(u.Username, secret, code, c.Jti); err != nil {
		return nil, err
	}

	access := Claims{Sub: u.Username, Role: u.Role, Dept: u.Department, MFA: true, Purpose: PurposeAccess}
	tok, _, err := s.signer.Sign(access, AccessTTL)
	if err != nil {
		return nil, err
	}
	// The MFA token is single-use: burn it.
	s.store.RevokeToken(ctx, c.Jti, time.Unix(c.Exp, 0))
	return &LoginResult{Token: tok, ExpiresIn: int(AccessTTL.Seconds()), User: u.Username, Role: u.Role}, nil
}

// acceptCode checks a TOTP code, counts failures and blocks reuse.
func (s *Service) acceptCode(username, secret, code, attemptKey string) error {
	step, err := checkTOTP(secret, code, s.now())
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if step < 0 {
		if attemptKey != "" {
			s.mfaAttempts[attemptKey]++
		}
		return ErrBadCode
	}
	if step <= s.lastStep[username] {
		return ErrCodeReused
	}
	s.lastStep[username] = step
	return nil
}

// Authenticate verifies an access token and that it wasn't logged out.
func (s *Service) Authenticate(ctx context.Context, token string) (*Claims, error) {
	c, err := s.signer.Verify(token, PurposeAccess)
	if err != nil {
		return nil, err
	}
	revoked, err := s.store.IsRevoked(ctx, c.Jti)
	if err != nil {
		return nil, err
	}
	if revoked {
		return nil, ErrTokenRevoked
	}
	return c, nil
}

// Logout revokes the token so it stops working immediately.
func (s *Service) Logout(ctx context.Context, c *Claims) error {
	return s.store.RevokeToken(ctx, c.Jti, time.Unix(c.Exp, 0))
}

// Begin2FA creates a new secret for the user (not active until confirmed).
func (s *Service) Begin2FA(ctx context.Context, username string) (secret, uri string, err error) {
	u, err := s.store.UserByName(ctx, username)
	if err != nil {
		return "", "", err
	}
	if u.TOTPEnabled {
		return "", "", Err2FAAlreadyOn
	}
	secret = GenerateTOTPSecret()
	if err := s.store.SetTOTP(ctx, username, s.seal.seal(secret), false); err != nil {
		return "", "", err
	}
	return secret, TOTPURI(username, secret), nil
}

// Enable2FA turns 2FA on once the user proves their app shows the right code.
func (s *Service) Enable2FA(ctx context.Context, username, code string) error {
	u, err := s.store.UserByName(ctx, username)
	if err != nil {
		return err
	}
	if u.TOTPEnabled {
		return Err2FAAlreadyOn
	}
	if u.TOTPSecretEnc == "" {
		return ErrNo2FASetup
	}
	secret, err := s.seal.open(u.TOTPSecretEnc)
	if err != nil {
		return err
	}
	if err := s.acceptCode(username, secret, code, ""); err != nil {
		return err
	}
	return s.store.SetTOTP(ctx, username, u.TOTPSecretEnc, true)
}

// SeedUser is an account created by Seed (tests and tooling).
type SeedUser struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	Role       string `json:"role"`
	Department string `json:"department"`
	TOTPSecret string `json:"totp_secret"` // "" = no 2FA
}

// LoadSeedFile reads a JSON array of SeedUser.
func LoadSeedFile(path string) ([]SeedUser, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading seed users: %w", err)
	}
	var users []SeedUser
	if err := json.Unmarshal(data, &users); err != nil {
		return nil, fmt.Errorf("parsing seed users: %w", err)
	}
	for i, u := range users {
		if u.Username == "" || u.Password == "" || u.Role == "" {
			return nil, fmt.Errorf("seed user %d needs username, password and role", i+1)
		}
	}
	return users, nil
}

// Seed creates the demo users if the database has no users yet.
func (s *Service) Seed(ctx context.Context, users []SeedUser) (int, error) {
	n, err := s.store.CountUsers(ctx)
	if err != nil || n > 0 {
		return 0, err
	}
	for _, su := range users {
		hash, err := bcrypt.GenerateFromPassword([]byte(su.Password), bcryptCost)
		if err != nil {
			return 0, err
		}
		u := &User{Username: su.Username, PasswordHash: string(hash), Role: su.Role, Department: su.Department}
		if su.TOTPSecret != "" {
			if _, err := decodeSecret(su.TOTPSecret); err != nil {
				return 0, err
			}
			u.TOTPSecretEnc, u.TOTPEnabled = s.seal.seal(su.TOTPSecret), true
		}
		if err := s.store.CreateUser(ctx, u); err != nil {
			return 0, err
		}
	}
	return len(users), nil
}
