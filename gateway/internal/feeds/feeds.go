// Package feeds keeps public lists of known-bad IP addresses (IP_FEEDS)
// and refreshes them once a day. Nothing is sent anywhere: each list is
// downloaded from its publisher, kept in the data folder so a restart
// without internet still has it, and matched in memory.
package feeds

import (
	"bufio"
	"context"
	"fmt"
	"hash/crc32"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Known lists by name. Any https:// URL also works (one IP or CIDR per
// line; text after # or ; is ignored).
var Known = map[string]string{
	// Addresses no legitimate traffic comes from: hijacked and criminal
	// networks (several curated lists combined by FireHOL).
	"firehol_level1": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
	// Spamhaus DROP: networks run by criminals.
	"spamhaus_drop": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/spamhaus_drop.netset",
	// Tor exit relays: this blocks Tor users too, so only where nobody needs Tor.
	"tor_exits": "https://check.torproject.org/torbulkexitlist",
}

// Every is how often the lists are downloaded again.
const Every = 24 * time.Hour

const maxBytes = 32 << 20

// Reserved ranges are never blocked, even when a list contains them
// (FireHOL level 1 lists private networks as bogons).
var reserved = mustPrefixes("0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/3", "::/8", "fc00::/7", "fe80::/10", "ff00::/8")

func mustPrefixes(s ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(s))
	for i, p := range s {
		out[i] = netip.MustParsePrefix(p)
	}
	return out
}

type span struct {
	lo, hi uint32
	list   string
}

type v6entry struct {
	p    netip.Prefix
	list string
}

type table struct {
	v4    []span // sorted by lo, not overlapping
	v6    []v6entry
	count map[string]int
}

// Feeds holds the lists in use. A nil *Feeds matches nothing.
type Feeds struct {
	names []string
	urls  map[string]string
	dir   string
	log   *slog.Logger
	cur   atomic.Pointer[table]
	mu    sync.Mutex
	lists map[string][]netip.Prefix // last good copy of each list
}

// New reads the setting: names from Known or https URLs, comma separated.
func New(setting, dataDir string, log *slog.Logger) (*Feeds, error) {
	f := &Feeds{urls: map[string]string{}, lists: map[string][]netip.Prefix{}, log: log}
	for _, s := range strings.FieldsFunc(setting, func(r rune) bool { return r == ',' || r == ' ' || r == '[' || r == ']' }) {
		name, url := s, Known[s]
		if url == "" {
			if !strings.HasPrefix(s, "https://") {
				return nil, fmt.Errorf("%q is not a known list (%s) or an https:// URL", s, strings.Join(KnownNames(), ", "))
			}
			url = s
		}
		if _, dup := f.urls[name]; !dup {
			f.names = append(f.names, name)
		}
		f.urls[name] = url
	}
	if dataDir != "" {
		f.dir = filepath.Join(dataDir, "feeds")
	}
	return f, nil
}

// KnownNames lists the built-in list names, sorted.
func KnownNames() []string {
	var n []string
	for k := range Known {
		n = append(n, k)
	}
	sort.Strings(n)
	return n
}

// Enabled reports whether any list is configured.
func (f *Feeds) Enabled() bool { return f != nil && len(f.names) > 0 }

// Start loads the saved copies, then downloads every list now and once a
// day until ctx ends.
func (f *Feeds) Start(ctx context.Context) {
	if !f.Enabled() {
		return
	}
	f.mu.Lock()
	for _, n := range f.names {
		if p := f.file(n); p != "" {
			if b, err := os.ReadFile(p); err == nil {
				ps := parse(strings.NewReader(string(b)))
				if c := coverage(ps); c > MaxShare {
					f.warn("saved IP list covers too much of the internet; ignoring it", n, fmt.Sprintf("%.1f%% of IPv4 addresses", 100*c))
					continue
				}
				f.lists[n] = ps
			}
		}
	}
	f.rebuild()
	f.mu.Unlock()
	go func() {
		for {
			f.refresh(ctx)
			select {
			case <-ctx.Done():
				return
			case <-time.After(Every):
			}
		}
	}()
}

func (f *Feeds) file(name string) string {
	if f.dir == "" {
		return ""
	}
	suffix := ""
	if _, known := Known[name]; !known {
		// Different URLs can clean up to the same name; keep them apart.
		suffix = fmt.Sprintf("-%08x", crc32.ChecksumIEEE([]byte(name)))
	}
	return filepath.Join(f.dir, strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-' {
			return r
		}
		return '_'
	}, strings.ToLower(name))+suffix+".txt")
}

func (f *Feeds) refresh(ctx context.Context) {
	f.mu.Lock()
	defer f.mu.Unlock()
	changed := false
	for _, n := range f.names {
		body, err := fetch(ctx, f.urls[n])
		if err != nil {
			f.warn("IP list download failed; keeping the last copy", n, err.Error())
			continue
		}
		ps := parse(strings.NewReader(body))
		if len(ps) == 0 {
			f.warn("IP list downloaded empty; keeping the last copy", n, "")
			continue
		}
		if c := coverage(ps); c > MaxShare {
			f.warn("IP list covers too much of the internet; keeping the last copy", n, fmt.Sprintf("%.1f%% of IPv4 addresses", 100*c))
			continue
		}
		f.lists[n] = ps
		changed = true
		if p := f.file(n); p != "" && os.MkdirAll(f.dir, 0o755) == nil {
			os.WriteFile(p, []byte(body), 0o644)
		}
	}
	if changed {
		f.rebuild()
	}
}

func (f *Feeds) warn(msg, list, err string) {
	if f.log != nil {
		f.log.Warn(msg, "list", list, "error", err)
	}
}

func fetch(ctx context.Context, url string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Sentinel IP list update")
	client := *http.DefaultClient
	client.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		if r.URL.Scheme != "https" || len(via) >= 5 {
			return fmt.Errorf("redirect to %s refused (https only, at most 5)", r.URL.Redacted())
		}
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return "", err
	}
	if len(b) > maxBytes {
		return "", fmt.Errorf("larger than %d MB", maxBytes>>20)
	}
	return string(b), nil
}

// parse reads one IP or CIDR per line and drops reserved ranges.
func parse(r io.Reader) []netip.Prefix {
	var out []netip.Prefix
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 64<<10)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		var p netip.Prefix
		if strings.Contains(fields[0], "/") {
			pp, err := netip.ParsePrefix(fields[0])
			if err != nil {
				continue
			}
			p = pp.Masked()
		} else {
			a, err := netip.ParseAddr(fields[0])
			if err != nil {
				continue
			}
			a = a.Unmap()
			p = netip.PrefixFrom(a, a.BitLen())
		}
		if p.Addr().Is4() && p.Bits() < 8 || p.Addr().Is6() && p.Bits() < 16 {
			continue // a list entry that large is a mistake
		}
		skip := false
		for _, rv := range reserved {
			if rv.Overlaps(p) {
				skip = true
				break
			}
		}
		if !skip {
			out = append(out, p)
		}
	}
	return out
}

// MaxShare is the most of the IPv4 space one list may cover. FireHOL level 1
// covers about 0.4%; a list that suddenly covers far more was broken or
// tampered with, and would block normal visitors.
const MaxShare = 0.03

// coverage is the share of IPv4 addresses a list covers (overlaps counted
// twice, which only makes the check stricter).
func coverage(ps []netip.Prefix) float64 {
	var n float64
	for _, p := range ps {
		if p.Addr().Is4() {
			n += float64(uint64(1) << (32 - p.Bits()))
		}
	}
	return n / (1 << 32)
}

func v4num(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// rebuild makes the lookup table from f.lists; f.mu must be held.
func (f *Feeds) rebuild() {
	t := &table{count: map[string]int{}}
	for _, n := range f.names {
		for _, p := range f.lists[n] {
			t.count[n]++
			if p.Addr().Is4() {
				lo := v4num(p.Addr())
				hi := lo | (uint32(1)<<(32-p.Bits()) - 1)
				t.v4 = append(t.v4, span{lo, hi, n})
			} else {
				t.v6 = append(t.v6, v6entry{p, n})
			}
		}
	}
	sort.Slice(t.v4, func(i, j int) bool { return t.v4[i].lo < t.v4[j].lo })
	merged := t.v4[:0]
	for _, s := range t.v4 {
		if k := len(merged) - 1; k >= 0 && merged[k].hi != ^uint32(0) && s.lo <= merged[k].hi+1 {
			if s.hi > merged[k].hi {
				merged[k].hi = s.hi
			}
			continue
		}
		merged = append(merged, s)
	}
	t.v4 = merged
	f.cur.Store(t)
	if f.log != nil {
		var args []any
		for _, n := range f.names {
			args = append(args, n, t.count[n])
		}
		f.log.Info("IP lists loaded (entries per list)", args...)
	}
}

// Match returns the name of the list that contains ip, or "".
func (f *Feeds) Match(ip netip.Addr) string {
	if f == nil {
		return ""
	}
	t := f.cur.Load()
	if t == nil {
		return ""
	}
	ip = ip.Unmap()
	if ip.Is4() {
		n := v4num(ip)
		i := sort.Search(len(t.v4), func(i int) bool { return t.v4[i].hi >= n })
		if i < len(t.v4) && t.v4[i].lo <= n {
			return t.v4[i].list
		}
		return ""
	}
	for _, e := range t.v6 {
		if e.p.Contains(ip) {
			return e.list
		}
	}
	return ""
}

// Counts is the number of entries per list.
func (f *Feeds) Counts() map[string]int {
	out := map[string]int{}
	if f == nil {
		return out
	}
	if t := f.cur.Load(); t != nil {
		for k, v := range t.count {
			out[k] = v
		}
	}
	return out
}
