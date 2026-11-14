// Package reqctx carries per-request information through the pipeline:
// the request ID, the real client IP, who the user is (once logged in) and
// the final outcome (allowed, blocked, denied...) that the access log and the
// live watch window display.
package reqctx

import (
	"context"
	"sync"
)

// Identity is the authenticated user, taken from a verified Sentinel token.
type Identity struct {
	Username string
	Role     string
	Dept     string
	MFA      bool   // passed 2FA in this session
	TokenID  string // jti, used for logout
	Expires  int64  // unix seconds
}

// Outcome is the decision Sentinel made about a request.
type Outcome struct {
	Kind   string // allowed, blocked, detected, honeypot, banned, unauthenticated, denied, invalid, login, login_failed, mfa_required, mfa_ok, mfa_failed
	Reason string // short human text, e.g. "role 'employee' is not allowed"
	Rule   string // rule or policy name, e.g. "SQLI-001" or "staff-salary"
	Detail string // extra context, e.g. "field: q  matched: ' or 1=1"
	Field  string // the field that triggered it (for exclusions)
	// Related are other rules that fired on the same field.
	Related []string
}

// Info is stored in the request context. Use the helpers below.
type Info struct {
	ID       string
	ClientIP string
	Country  string // set by the geo check: "IQ", "LAN", "" = unknown
	Site     string // the site (SITES) the request is for; "" = the only one
	Login    string // username a login attempt was for (set by the login API)

	mu           sync.Mutex
	user         *Identity
	tokenInvalid string // why a presented token was rejected (expired, revoked...)
	outcome      *Outcome
}

type key struct{}

func With(ctx context.Context, info *Info) context.Context {
	return context.WithValue(ctx, key{}, info)
}

// From never returns nil, so callers don't need to check.
func From(ctx context.Context) *Info {
	if info, ok := ctx.Value(key{}).(*Info); ok && info != nil {
		return info
	}
	return &Info{}
}

func (i *Info) SetUser(id *Identity) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.user = id
}

func (i *Info) User() *Identity {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.user
}

func (i *Info) SetTokenInvalid(reason string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.tokenInvalid = reason
}

func (i *Info) TokenInvalid() string {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.tokenInvalid
}

// SetOutcome records the decision. The first decision wins, so an early
// check (e.g. a ban) is not overwritten by a later default.
func (i *Info) SetOutcome(o Outcome) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.outcome == nil {
		i.outcome = &o
	}
}

func (i *Info) Outcome() (Outcome, bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.outcome == nil {
		return Outcome{}, false
	}
	return *i.outcome, true
}

// MarkMonitored turns a block decision into "monitored": in monitor mode the
// request is forwarded anyway, and the logs show what would have happened.
func (i *Info) MarkMonitored() {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.outcome == nil {
		i.outcome = &Outcome{Kind: "monitored", Reason: "would have been refused"}
		return
	}
	if i.outcome.Kind != "monitored" {
		i.outcome.Reason = "would be " + i.outcome.Kind + ": " + i.outcome.Reason
		i.outcome.Kind = "monitored"
	}
}
