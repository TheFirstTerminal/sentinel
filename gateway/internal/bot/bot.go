// Package bot keeps automated attack tools and simple bots out.
//
// Scanner blocking: requests whose User-Agent names a known attack tool are
// refused. Trivial to fake, but most automated attacks don't bother, and it
// removes a lot of noise.
//
// JavaScript challenge: a client that looks automated (or every client, on
// paths you choose, such as a login page) gets a small proof-of-work page.
// A browser solves it in about half a second and receives a signed pass
// cookie bound to its IP and User-Agent; scripts that don't run JavaScript
// never get past it. Requests that don't ask for HTML (APIs) are never
// challenged, so APIs keep working.
package bot

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/bits"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var scanners = regexp.MustCompile(`(?i)\b(?:sqlmap|nikto|nmap|masscan|zgrab|nuclei|wpscan|dirbuster|gobuster|feroxbuster|ffuf|wfuzz|acunetix|netsparker|nessus|openvas|w3af|havij|commix|xsstrike|jaeles|arachni|skipfish|whatweb|joomscan|droopescan|burpcollaborator|interactsh|zmeu|morfeus|libwww-perl|python-httpx/0\.1[0-3])\b`)

var automated = regexp.MustCompile(`(?i)headlesschrome|phantomjs|selenium|webdriver|puppeteer|playwright|slimerjs|htmlunit`)

// Scanner returns the tool a User-Agent names, or "".
func Scanner(ua string) string {
	return strings.ToLower(scanners.FindString(ua))
}

// Suspicious says why a request looks automated ("" = it doesn't).
func Suspicious(r *http.Request) string {
	ua := r.UserAgent()
	switch {
	case ua == "":
		return "no User-Agent"
	case automated.MatchString(ua):
		return "automation tool: " + strings.ToLower(automated.FindString(ua))
	case strings.HasPrefix(ua, "Mozilla/") && r.Header.Get("Accept-Language") == "":
		return "claims to be a browser but sends no Accept-Language"
	}
	return ""
}

// WantsHTML: only page loads from a browser can run a challenge.
func WantsHTML(r *http.Request) bool {
	return (r.Method == http.MethodGet || r.Method == http.MethodHead) &&
		strings.Contains(r.Header.Get("Accept"), "text/html")
}

// Challenger issues and checks challenges and passes.
type Challenger struct {
	Key        []byte        // HMAC key (from SENTINEL_SECRET)
	Difficulty int           // leading zero bits of the proof of work
	PassFor    time.Duration // how long a pass lasts
	now        func() time.Time
}

const (
	PassCookie = "__sentinel_pass"
	WorkCookie = "__sentinel_work"
)

func (c *Challenger) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

func (c *Challenger) sign(parts ...string) string {
	m := hmac.New(sha256.New, c.Key)
	m.Write([]byte(strings.Join(parts, "|")))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil)[:18])
}

func uaHash(ua string) string {
	h := sha256.Sum256([]byte(ua))
	return hex.EncodeToString(h[:6])
}

// HasPass reports whether the request carries a valid pass.
func (c *Challenger) HasPass(r *http.Request, ip string) bool {
	ck, err := r.Cookie(PassCookie)
	if err != nil {
		return false
	}
	exp, sig, ok := strings.Cut(ck.Value, ".")
	if !ok {
		return false
	}
	t, err := strconv.ParseInt(exp, 10, 64)
	if err != nil || c.clock().Unix() > t {
		return false
	}
	return hmac.Equal([]byte(sig), []byte(c.sign("pass", exp, ip, uaHash(r.UserAgent()))))
}

// Pass makes a pass cookie for this client.
func (c *Challenger) Pass(r *http.Request, ip string) *http.Cookie {
	exp := strconv.FormatInt(c.clock().Add(c.PassFor).Unix(), 10)
	return &http.Cookie{Name: PassCookie, Value: exp + "." + c.sign("pass", exp, ip, uaHash(r.UserAgent())),
		Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: r.TLS != nil, MaxAge: int(c.PassFor.Seconds())}
}

// Solved checks a proof of work sent back in the work cookie. It returns
// true when the work is valid, fresh and made for this client.
func (c *Challenger) Solved(r *http.Request, ip string) bool {
	ck, err := r.Cookie(WorkCookie)
	if err != nil {
		return false
	}
	p := strings.Split(ck.Value, ".")
	if len(p) != 4 {
		return false
	}
	nonce, exp, sig, counter := p[0], p[1], p[2], p[3]
	t, err := strconv.ParseInt(exp, 10, 64)
	if err != nil || c.clock().Unix() > t {
		return false
	}
	if !hmac.Equal([]byte(sig), []byte(c.sign("work", nonce, exp, ip, uaHash(r.UserAgent())))) {
		return false
	}
	return leadingZeroBits(nonce+counter) >= c.Difficulty
}

func leadingZeroBits(s string) int {
	h := sha256.Sum256([]byte(s))
	n := 0
	for i := 0; i < len(h); i += 8 {
		v := binary.BigEndian.Uint64(h[i : i+8])
		if v != 0 {
			return n + bits.LeadingZeros64(v)
		}
		n += 64
	}
	return n
}

//go:embed challenge.html
var page string

// Page returns the challenge page for this client.
func (c *Challenger) Page(r *http.Request, ip string) string {
	b := make([]byte, 12)
	rand.Read(b)
	nonce := base64.RawURLEncoding.EncodeToString(b)
	exp := strconv.FormatInt(c.clock().Add(5*time.Minute).Unix(), 10)
	token := nonce + "." + exp + "." + c.sign("work", nonce, exp, ip, uaHash(r.UserAgent()))
	return strings.NewReplacer("{{TOKEN}}", token, "{{BITS}}", fmt.Sprint(c.Difficulty), "{{COOKIE}}", WorkCookie).Replace(page)
}

// Solve does what the challenge page's script does (for tests and
// for checking the page works).
func Solve(page string) (cookie string) {
	token := regexp.MustCompile(`const token = "([^"]+)", bits = (\d+)`).FindStringSubmatch(page)
	bits, _ := strconv.Atoi(token[2])
	nonce := strings.Split(token[1], ".")[0]
	for i := 0; ; i++ {
		if leadingZeroBits(nonce+strconv.Itoa(i)) >= bits {
			return token[1] + "." + strconv.Itoa(i)
		}
	}
}
