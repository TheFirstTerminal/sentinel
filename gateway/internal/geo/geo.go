// Package geo answers "which country is this IP from?" and applies the
// IP and country allow/deny lists (geo-filtering).
//
// The country database is a CSV file with one IP range per line:
//
//	# cidr,country
//	5.62.60.0/22,RU
//	2001:db8::/32,ZZ
//
// Any IP-to-country export (MaxMind GeoLite2 CSV, IP2Location LITE, DB-IP)
// can be converted to this shape, and it works fully offline. Private and
// loopback addresses always count as "LAN".
package geo

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"
)

const LAN = "LAN"

type entry struct {
	prefix  netip.Prefix
	country string
}

type DB struct {
	entries []entry // longest prefix first
}

// Load reads a CSV file. An empty path gives a DB that only knows LAN.
func Load(path string) (*DB, error) {
	db := &DB{}
	if path == "" {
		return db, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	line := 0
	for sc.Scan() {
		line++
		t := strings.TrimSpace(sc.Text())
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		cidr, cc, ok := strings.Cut(t, ",")
		if !ok {
			return nil, fmt.Errorf("%s line %d: expected cidr,country", path, line)
		}
		p, err := netip.ParsePrefix(strings.TrimSpace(cidr))
		if err != nil {
			return nil, fmt.Errorf("%s line %d: %v", path, line, err)
		}
		db.entries = append(db.entries, entry{p.Masked(), strings.ToUpper(strings.TrimSpace(cc))})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	sort.SliceStable(db.entries, func(i, j int) bool { return db.entries[i].prefix.Bits() > db.entries[j].prefix.Bits() })
	return db, nil
}

func (db *DB) Size() int { return len(db.entries) }

// Country returns the two-letter code, "LAN" for private addresses, or ""
// when unknown.
func (db *DB) Country(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	a = a.Unmap()
	if a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() {
		return LAN
	}
	for _, e := range db.entries {
		if e.prefix.Contains(a) {
			return e.country
		}
	}
	return ""
}

// Filter is the allow/deny configuration.
type Filter struct {
	DenyIPs        []netip.Prefix
	AllowIPs       []netip.Prefix // if set, only these IPs may connect
	DenyCountries  map[string]bool
	AllowCountries map[string]bool // if set, only these countries (and LAN)
	BlockUnknown   bool            // with AllowCountries: block IPs with no country
}

func (f *Filter) Enabled() bool {
	return len(f.DenyIPs) > 0 || len(f.AllowIPs) > 0 || len(f.DenyCountries) > 0 || len(f.AllowCountries) > 0
}

// Check returns "" if allowed, otherwise the reason.
func (f *Filter) Check(ip, country string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return "unreadable client address"
	}
	a = a.Unmap()
	for _, p := range f.DenyIPs {
		if p.Contains(a) {
			return "IP " + ip + " is on the deny list (" + p.String() + ")"
		}
	}
	if len(f.AllowIPs) > 0 {
		ok := false
		for _, p := range f.AllowIPs {
			if p.Contains(a) {
				ok = true
				break
			}
		}
		if !ok {
			return "IP " + ip + " is not on the allow list"
		}
	}
	if country == LAN {
		return ""
	}
	if f.DenyCountries[country] {
		return "country " + country + " is blocked"
	}
	if len(f.AllowCountries) > 0 {
		if country == "" {
			if f.BlockUnknown {
				return "country unknown and only " + keys(f.AllowCountries) + " are allowed"
			}
			return ""
		}
		if !f.AllowCountries[country] {
			return "country " + country + " is not allowed (only " + keys(f.AllowCountries) + ")"
		}
	}
	return ""
}

// ParsePrefixes reads "10.0.0.0/8, 1.2.3.4" (a bare IP means just that IP).
func ParsePrefixes(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, p := range splitList(s) {
		if !strings.Contains(p, "/") {
			a, err := netip.ParseAddr(p)
			if err != nil {
				return nil, fmt.Errorf("%q is not an IP or CIDR range", p)
			}
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
			continue
		}
		pr, err := netip.ParsePrefix(p)
		if err != nil {
			return nil, fmt.Errorf("%q is not an IP or CIDR range", p)
		}
		out = append(out, pr.Masked())
	}
	return out, nil
}

// ParseCountries reads "RU, KP" into a set of upper-case codes.
func ParseCountries(s string) map[string]bool {
	out := map[string]bool{}
	for _, c := range splitList(s) {
		out[strings.ToUpper(c)] = true
	}
	return out
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func keys(m map[string]bool) string {
	var k []string
	for c := range m {
		k = append(k, c)
	}
	sort.Strings(k)
	return strings.Join(k, ", ")
}
