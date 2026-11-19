package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// RFC 6238 Appendix B test vectors (SHA1, secret "12345678901234567890").
// Our 6-digit codes are the last 6 digits of the RFC's 8-digit values.
func TestTOTPRFCVectors(t *testing.T) {
	secret := b32.EncodeToString([]byte("12345678901234567890"))
	cases := map[int64]string{
		59:          "287082",
		1111111109:  "081804",
		1111111111:  "050471",
		1234567890:  "005924",
		2000000000:  "279037",
		20000000000: "353130",
	}
	for ts, want := range cases {
		got, err := TOTPCode(secret, time.Unix(ts, 0))
		if err != nil || got != want {
			t.Errorf("t=%d: got %s, want %s (%v)", ts, got, want, err)
		}
	}
}

func TestTOTPAcceptsClockDrift(t *testing.T) {
	secret := GenerateTOTPSecret()
	now := time.Unix(1_800_000_000, 0)
	prev, _ := TOTPCode(secret, now.Add(-30*time.Second))
	if step, _ := checkTOTP(secret, prev, now); step < 0 {
		t.Error("code from the previous 30s window should be accepted")
	}
	old, _ := TOTPCode(secret, now.Add(-6*time.Minute))
	if step, _ := checkTOTP(secret, old, now); step >= 0 {
		t.Error("a 6-minute-old code must be rejected")
	}
}

func newSigner() *Signer { return NewSigner([]byte("0123456789abcdef0123456789abcdef")) }

func TestJWTRoundTrip(t *testing.T) {
	s := newSigner()
	tok, _, _ := s.Sign(Claims{Sub: "alice", Role: "employee", Purpose: PurposeAccess}, time.Minute)
	c, err := s.Verify(tok, PurposeAccess)
	if err != nil || c.Sub != "alice" || c.Role != "employee" {
		t.Fatalf("round trip failed: %+v %v", c, err)
	}
}

func TestJWTRejectsTamperedClaims(t *testing.T) {
	s := newSigner()
	tok, _, _ := s.Sign(Claims{Sub: "alice", Role: "employee", Purpose: PurposeAccess}, time.Minute)
	parts := strings.Split(tok, ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	evil := strings.Replace(string(payload), `"employee"`, `"admin"`, 1) // promote myself
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(evil))
	if _, err := s.Verify(strings.Join(parts, "."), PurposeAccess); !errors.Is(err, ErrTokenSignature) {
		t.Fatalf("tampered token must fail signature check, got %v", err)
	}
}

func TestJWTRejectsAlgNone(t *testing.T) {
	s := newSigner()
	tok, _, _ := s.Sign(Claims{Sub: "alice", Purpose: PurposeAccess}, time.Minute)
	parts := strings.Split(tok, ".")
	none := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	if _, err := s.Verify(none+"."+parts[1]+".", PurposeAccess); !errors.Is(err, ErrTokenAlg) {
		t.Fatalf(`"alg":"none" must be rejected, got %v`, err)
	}
}

func TestJWTRejectsOtherKeyExpiredAndWrongPurpose(t *testing.T) {
	s := newSigner()
	tok, _, _ := s.Sign(Claims{Sub: "alice", Purpose: PurposeMFA}, time.Minute)
	if _, err := NewSigner([]byte("another-key-another-key-another!")).Verify(tok, PurposeMFA); !errors.Is(err, ErrTokenSignature) {
		t.Errorf("token from another key must fail, got %v", err)
	}
	if _, err := s.Verify(tok, PurposeAccess); !errors.Is(err, ErrTokenPurpose) {
		t.Errorf("mfa token must not work as access token, got %v", err)
	}
	s.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	if _, err := s.Verify(tok, PurposeMFA); !errors.Is(err, ErrTokenExpired) {
		t.Errorf("expired token must fail, got %v", err)
	}
}

func TestSealerRoundTripAndTamper(t *testing.T) {
	keys, _ := DeriveKeys(strings.Repeat("k", 40))
	s, _ := newSealer(keys.Encrypt)
	enc := s.seal("JBSWY3DPEHPK3PXP")
	if strings.Contains(enc, "JBSWY3DP") {
		t.Fatal("secret must not be stored in plain text")
	}
	if got, err := s.open(enc); err != nil || got != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("open: %q %v", got, err)
	}
	b, _ := base64.StdEncoding.DecodeString(enc)
	b[len(b)-1] ^= 1
	if _, err := s.open(base64.StdEncoding.EncodeToString(b)); err == nil {
		t.Fatal("modified ciphertext must be rejected")
	}
}

func TestDeriveKeysRequiresLongSecret(t *testing.T) {
	if _, err := DeriveKeys("short"); err == nil {
		t.Fatal("short master secret must be rejected")
	}
	k, _ := DeriveKeys(strings.Repeat("x", 32))
	if string(k.JWT) == string(k.Encrypt) {
		t.Fatal("the two derived keys must differ")
	}
}

const demoSecret = "KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TF"

func newService(t *testing.T, store Store) *Service {
	t.Helper()
	keys, _ := DeriveKeys(strings.Repeat("s", 40))
	svc, err := NewService(store, keys)
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.Seed(context.Background(), []SeedUser{
		{Username: "alice", Password: "Alice#2026", Role: "admin", Department: "it"}, // admin, 2FA not set up yet
		{Username: "bob", Password: "Bob#2026", Role: "employee", Department: "sales"},
		{Username: "admin", Password: "Admin#2026", Role: "admin", Department: "it", TOTPSecret: demoSecret},
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func runFlows(t *testing.T, store Store) {
	ctx := context.Background()
	svc := newService(t, store)

	// Wrong password and unknown user give the same error.
	if _, err := svc.Login(ctx, "alice", "nope"); !errors.Is(err, ErrBadCredentials) {
		t.Errorf("wrong password: %v", err)
	}
	if _, err := svc.Login(ctx, "mallory", "x"); !errors.Is(err, ErrBadCredentials) {
		t.Errorf("unknown user: %v", err)
	}
	// Only administrators may log in: a non-admin account is refused even
	// with its right password, with the same answer.
	if _, err := svc.Login(ctx, "bob", "Bob#2026"); !errors.Is(err, ErrBadCredentials) {
		t.Errorf("non-admin login: %v", err)
	}

	// No 2FA: password gives a token directly, mfa=false.
	res, err := svc.Login(ctx, "alice", "Alice#2026")
	if err != nil || res.Token == "" || res.MFARequired {
		t.Fatalf("alice login: %+v %v", res, err)
	}
	c, err := svc.Authenticate(ctx, res.Token)
	if err != nil || c.MFA {
		t.Fatalf("alice token: %+v %v", c, err)
	}

	// Logout revokes immediately.
	svc.Logout(ctx, c)
	if _, err := svc.Authenticate(ctx, res.Token); !errors.Is(err, ErrTokenRevoked) {
		t.Errorf("token must stop working after logout, got %v", err)
	}

	// 2FA user: password alone is not enough.
	res, err = svc.Login(ctx, "admin", "Admin#2026")
	if err != nil || !res.MFARequired || res.Token != "" {
		t.Fatalf("admin step 1: %+v %v", res, err)
	}
	if _, err := svc.Authenticate(ctx, res.MFAToken); err == nil {
		t.Error("the MFA token must not work as an access token")
	}
	if _, err := svc.VerifyMFA(ctx, res.MFAToken, "000000"); !errors.Is(err, ErrBadCode) {
		t.Errorf("wrong code: %v", err)
	}
	code, _ := TOTPCode(demoSecret, time.Now())
	done, err := svc.VerifyMFA(ctx, res.MFAToken, code)
	if err != nil {
		t.Fatalf("right code: %v", err)
	}
	ac, err := svc.Authenticate(ctx, done.Token)
	if err != nil || !ac.MFA || ac.Role != "admin" {
		t.Fatalf("admin token should carry mfa=true: %+v %v", ac, err)
	}

	// Same code again (replay) is refused, and the MFA token is single-use.
	res2, _ := svc.Login(ctx, "admin", "Admin#2026")
	if _, err := svc.VerifyMFA(ctx, res2.MFAToken, code); !errors.Is(err, ErrCodeReused) {
		t.Errorf("reused code must be refused, got %v", err)
	}
	if _, err := svc.VerifyMFA(ctx, res.MFAToken, code); err == nil {
		t.Error("an MFA token must not be usable twice")
	}
}

func TestFlowsMemory(t *testing.T) { runFlows(t, NewMemoryStore()) }

// Runs against a real PostgreSQL when TEST_DATABASE_URL is set.
func TestFlowsPostgres(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pg, err := OpenPG(ctx, url, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	pg.pool.Exec(ctx, `TRUNCATE users, revoked_tokens RESTART IDENTITY`)
	runFlows(t, pg)

	// Stored 2FA secret is encrypted in the database.
	var enc string
	pg.pool.QueryRow(ctx, `SELECT totp_secret_enc FROM users WHERE username='admin'`).Scan(&enc)
	if enc == "" || strings.Contains(enc, demoSecret) {
		t.Errorf("2FA secret must be stored encrypted, got %q", enc)
	}
}

func TestEnable2FA(t *testing.T) {
	ctx := context.Background()
	svc := newService(t, NewMemoryStore())
	secret, uri, err := svc.Begin2FA(ctx, "alice")
	if err != nil || !strings.HasPrefix(uri, "otpauth://totp/Sentinel:alice?") {
		t.Fatalf("begin: %q %v", uri, err)
	}
	// Not active until confirmed: login still returns a token directly.
	if r, _ := svc.Login(ctx, "alice", "Alice#2026"); r.MFARequired {
		t.Fatal("2FA must not be active before confirmation")
	}
	if err := svc.Enable2FA(ctx, "alice", "123456"); !errors.Is(err, ErrBadCode) {
		t.Fatalf("wrong confirmation code: %v", err)
	}
	code, _ := TOTPCode(secret, time.Now())
	if err := svc.Enable2FA(ctx, "alice", code); err != nil {
		t.Fatal(err)
	}
	if r, _ := svc.Login(ctx, "alice", "Alice#2026"); !r.MFARequired {
		t.Fatal("after enabling, login must require 2FA")
	}
}

func TestTooManyWrongCodes(t *testing.T) {
	ctx := context.Background()
	svc := newService(t, NewMemoryStore())
	res, _ := svc.Login(ctx, "admin", "Admin#2026")
	for i := 0; i < maxMFAAttempts; i++ {
		svc.VerifyMFA(ctx, res.MFAToken, "000000")
	}
	code, _ := TOTPCode(demoSecret, time.Now())
	if _, err := svc.VerifyMFA(ctx, res.MFAToken, code); !errors.Is(err, ErrTooManyAttempts) {
		t.Fatalf("after %d wrong codes even the right one must be refused, got %v", maxMFAAttempts, err)
	}
}

// An MFA token works once, even with a later (unused) code.
func TestMFATokenSingleUse(t *testing.T) {
	ctx := context.Background()
	svc := newService(t, NewMemoryStore())
	res, _ := svc.Login(ctx, "admin", "Admin#2026")
	code, _ := TOTPCode(demoSecret, time.Now())
	if _, err := svc.VerifyMFA(ctx, res.MFAToken, code); err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(30 * time.Second)
	svc.now = func() time.Time { return later }
	next, _ := TOTPCode(demoSecret, later)
	if _, err := svc.VerifyMFA(ctx, res.MFAToken, next); !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("used MFA token must be refused, got %v", err)
	}
}

// Codes sent in parallel count against the same limit.
func TestParallelWrongCodes(t *testing.T) {
	ctx := context.Background()
	svc := newService(t, NewMemoryStore())
	res, _ := svc.Login(ctx, "admin", "Admin#2026")
	var wg sync.WaitGroup
	var mu sync.Mutex
	tried := 0
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := svc.VerifyMFA(ctx, res.MFAToken, "000000"); errors.Is(err, ErrBadCode) {
				mu.Lock()
				tried++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if tried > maxMFAAttempts {
		t.Fatalf("%d codes were checked, limit is %d", tried, maxMFAAttempts)
	}
}

// TestSessionAfterEnable: turning 2FA on logs the user in with mfa=true and
// retires the password-only token it was done with.
func TestSessionAfterEnable(t *testing.T) {
	ctx := context.Background()
	svc := newService(t, NewMemoryStore())
	r, _ := svc.Login(ctx, "alice", "Alice#2026")
	c, err := svc.Authenticate(ctx, r.Token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SessionAfterEnable(ctx, c); !errors.Is(err, ErrNo2FASetup) {
		t.Fatalf("before 2FA is on: %v", err)
	}
	secret, _, _ := svc.Begin2FA(ctx, "alice")
	code, _ := TOTPCode(secret, time.Now())
	if err := svc.Enable2FA(ctx, "alice", code); err != nil {
		t.Fatal(err)
	}
	res, err := svc.SessionAfterEnable(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	ac, err := svc.Authenticate(ctx, res.Token)
	if err != nil || !ac.MFA {
		t.Fatalf("new token: %+v %v", ac, err)
	}
	if _, err := svc.Authenticate(ctx, r.Token); err == nil {
		t.Fatal("the password-only token must be revoked")
	}
}
