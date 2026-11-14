package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTP (RFC 6238) is what Google Authenticator / Microsoft Authenticator use.
// The server and the phone share a secret. Every 30 seconds both compute
//
//	code = HMAC-SHA1(secret, number of 30s steps since 1970) -> 6 digits
//
// so the codes match without any network connection between them.

const (
	totpStep   = 30 * time.Second
	totpDigits = 6
	// A code stays valid for 5 minutes after it was shown (10 steps back),
	// plus one step ahead for a phone clock that runs fast. The apps still
	// show a new code every 30 seconds: that period is fixed by them. A
	// used code is refused afterwards (see Service.lastStep), so the longer
	// window doesn't allow replaying a code.
	totpPast   = 10
	totpFuture = 1
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateTOTPSecret returns a new random 160-bit secret, base32-encoded.
func GenerateTOTPSecret() string {
	b := make([]byte, 20)
	rand.Read(b)
	return b32.EncodeToString(b)
}

// TOTPCode computes the code for the 30-second window containing t.
func TOTPCode(secret string, t time.Time) (string, error) {
	key, err := decodeSecret(secret)
	if err != nil {
		return "", err
	}
	return hotp(key, uint64(t.Unix())/uint64(totpStep.Seconds())), nil
}

// checkTOTP returns the matching time step, or -1 if the code is wrong.
// The step lets the caller refuse a code that was already used (replay).
func checkTOTP(secret, code string, t time.Time) (int64, error) {
	key, err := decodeSecret(secret)
	if err != nil {
		return -1, err
	}
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return -1, nil
	}
	cur := int64(uint64(t.Unix()) / uint64(totpStep.Seconds()))
	for d := -totpPast; d <= totpFuture; d++ {
		step := cur + int64(d)
		if subtle.ConstantTimeCompare([]byte(hotp(key, uint64(step))), []byte(code)) == 1 {
			return step, nil
		}
	}
	return -1, nil
}

// TOTPURI is what a QR code holds; authenticator apps import it.
func TOTPURI(username, secret string) string {
	label := url.PathEscape("Sentinel:" + username)
	q := url.Values{"secret": {secret}, "issuer": {"Sentinel"}, "digits": {"6"}, "period": {"30"}}
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// hotp is RFC 4226: HMAC-SHA1, then "dynamic truncation" to 6 digits.
func hotp(key []byte, counter uint64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1_000_000)
}

func decodeSecret(secret string) ([]byte, error) {
	s := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	s = strings.TrimRight(s, "=")
	key, err := b32.DecodeString(s)
	if err != nil || len(key) < 10 {
		return nil, fmt.Errorf("invalid TOTP secret")
	}
	return key, nil
}
