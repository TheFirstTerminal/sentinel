// Package audit holds the security events Sentinel's checks record (a
// blocked attack, a honeypot hit, a ban from the dashboard). A Recorder
// stores them; the free edition has none, and the events reach the log and
// the dashboard through the access log.
package audit

// Event is what the rest of the gateway records.
type Event struct {
	Type      string // e.g. "waf_block", "honeypot_hit"
	ClientIP  string
	RequestID string
	Method    string
	Path      string
	Detail    any // anything JSON-serialisable
}
