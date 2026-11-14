package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// JWT (JSON Web Token) = header.claims.signature, each part base64url.
// Sentinel signs with HMAC-SHA256 (HS256) using a key only the gateway knows,
// so a client can read its token but cannot change it without breaking the
// signature.
//
// Written with the standard library on purpose: it is ~100 lines, and it
// keeps every check visible in one short file.

const issuer = "sentinel"

// Token purposes. An "mfa" token only proves the password was right; it can
// be exchanged for an access token after 2FA, and is useless for anything else.
const (
	PurposeAccess = "access"
	PurposeMFA    = "mfa"
)

type Claims struct {
	Sub     string `json:"sub"`            // username
	Role    string `json:"role"`           // admin, employee
	Dept    string `json:"dept,omitempty"` // hr, sales...
	MFA     bool   `json:"mfa"`            // passed 2FA
	Purpose string `json:"pur"`            // access or mfa
	Iss     string `json:"iss"`
	Iat     int64  `json:"iat"`
	Exp     int64  `json:"exp"`
	Jti     string `json:"jti"` // unique ID, used to revoke on logout
}

var (
	ErrTokenMalformed = errors.New("token is malformed")
	ErrTokenAlg       = errors.New("token uses an unsupported algorithm")
	ErrTokenSignature = errors.New("token signature is invalid")
	ErrTokenExpired   = errors.New("token has expired")
	ErrTokenPurpose   = errors.New("token is not valid for this use")
	ErrTokenRevoked   = errors.New("token was revoked (logged out)")
)

var jwtHeader = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))

type Signer struct {
	key []byte
	now func() time.Time
}

func NewSigner(key []byte) *Signer {
	return &Signer{key: key, now: time.Now}
}

// Sign fills iss, iat, exp and jti, then signs.
func (s *Signer) Sign(c Claims, ttl time.Duration) (string, Claims, error) {
	now := s.now()
	c.Iss = issuer
	c.Iat = now.Unix()
	c.Exp = now.Add(ttl).Unix()
	c.Jti = randomID()

	payload, err := json.Marshal(c)
	if err != nil {
		return "", c, err
	}
	unsigned := jwtHeader + "." + base64.RawURLEncoding.EncodeToString(payload)
	return unsigned + "." + s.sign(unsigned), c, nil
}

// Verify checks, in order: shape, algorithm, signature, issuer, expiry, purpose.
func (s *Signer) Verify(token, purpose string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrTokenMalformed
	}

	// Only accept exactly HS256. Accepting "none" or letting the token pick
	// its own algorithm is a classic JWT vulnerability.
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrTokenMalformed
	}
	var hdr struct {
		Alg string `json:"alg"`
	}
	if json.Unmarshal(hb, &hdr) != nil {
		return nil, ErrTokenMalformed
	}
	if hdr.Alg != "HS256" {
		return nil, ErrTokenAlg
	}

	want := s.sign(parts[0] + "." + parts[1])
	if !hmac.Equal([]byte(want), []byte(parts[2])) { // constant-time compare
		return nil, ErrTokenSignature
	}

	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrTokenMalformed
	}
	var c Claims
	if json.Unmarshal(pb, &c) != nil {
		return nil, ErrTokenMalformed
	}
	if c.Iss != issuer || c.Sub == "" || c.Jti == "" {
		return nil, ErrTokenMalformed
	}
	if s.now().Unix() >= c.Exp {
		return nil, ErrTokenExpired
	}
	if c.Purpose != purpose {
		return nil, ErrTokenPurpose
	}
	return &c, nil
}

func (s *Signer) sign(unsigned string) string {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(unsigned))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func randomID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
