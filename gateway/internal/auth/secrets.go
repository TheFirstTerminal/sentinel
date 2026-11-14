package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

// Keys are derived from one master secret (SENTINEL_SECRET) with HKDF, so
// the token-signing key and the encryption key are different and neither
// is the raw secret itself.
type Keys struct {
	JWT     []byte // signs tokens
	Encrypt []byte // encrypts TOTP secrets in the database
}

func DeriveKeys(master string) (Keys, error) {
	if len(master) < 32 {
		return Keys{}, errors.New("SENTINEL_SECRET must be at least 32 characters")
	}
	jwtKey, err := hkdf.Key(sha256.New, []byte(master), nil, "sentinel jwt v1", 32)
	if err != nil {
		return Keys{}, err
	}
	encKey, err := hkdf.Key(sha256.New, []byte(master), nil, "sentinel totp-encryption v1", 32)
	if err != nil {
		return Keys{}, err
	}
	return Keys{JWT: jwtKey, Encrypt: encKey}, nil
}

// sealer encrypts TOTP secrets at rest with AES-256-GCM. If the database
// leaks, the attacker gets ciphertext, not working 2FA secrets.
type sealer struct{ aead cipher.AEAD }

func newSealer(key []byte) (*sealer, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &sealer{aead: aead}, nil
}

func (s *sealer) seal(plain string) string {
	nonce := make([]byte, s.aead.NonceSize())
	rand.Read(nonce)
	ct := s.aead.Seal(nonce, nonce, []byte(plain), nil)
	return base64.StdEncoding.EncodeToString(ct)
}

func (s *sealer) open(enc string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(enc)
	if err != nil || len(b) < s.aead.NonceSize() {
		return "", errors.New("stored 2FA secret is corrupt")
	}
	plain, err := s.aead.Open(nil, b[:s.aead.NonceSize()], b[s.aead.NonceSize():], nil)
	if err != nil {
		return "", errors.New("stored 2FA secret could not be decrypted")
	}
	return string(plain), nil
}
