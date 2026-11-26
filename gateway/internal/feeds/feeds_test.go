package feeds

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseSkipsReservedAndJunk(t *testing.T) {
	ps := parse(strings.NewReader("# comment\n10.0.0.0/8\n1.2.3.0/24 ; SBL1\n5.6.7.8\nnot-an-ip\n192.168.1.1\n2001:db8::/32\n0.0.0.0/0\n"))
	var got []string
	for _, p := range ps {
		got = append(got, p.String())
	}
	if want := "1.2.3.0/24 5.6.7.8/32 2001:db8::/32"; strings.Join(got, " ") != want {
		t.Fatalf("got %v, want %s", got, want)
	}
}

func TestMatch(t *testing.T) {
	f, err := New("a, b", "", nil)
	if err == nil {
		t.Fatal("unknown names should be refused")
	}
	f, _ = New("https://x.example/a.txt", "", nil)
	f.lists[f.names[0]] = parse(strings.NewReader("1.2.3.0/24\n1.2.4.0/24\n9.9.9.9\n2001:db8::/32\n"))
	f.rebuild()
	for ip, want := range map[string]bool{"1.2.3.4": true, "1.2.4.255": true, "1.2.5.0": false, "9.9.9.9": true, "9.9.9.10": false,
		"::ffff:1.2.3.9": true, "2001:db8::1": true, "2001:db9::1": false, "8.8.8.8": false} {
		if got := f.Match(netip.MustParseAddr(ip)) != ""; got != want {
			t.Errorf("%s: match %v, want %v", ip, got, want)
		}
	}
	var nilF *Feeds
	if nilF.Match(netip.MustParseAddr("1.2.3.4")) != "" {
		t.Error("nil matched")
	}
}

func TestCoverageCap(t *testing.T) {
	var big strings.Builder
	for i := 11; i < 30; i++ { // nineteen /8s: 7.4% of IPv4
		big.WriteString(netip.AddrFrom4([4]byte{byte(i), 0, 0, 0}).String() + "/8\n")
	}
	if c := coverage(parse(strings.NewReader(big.String()))); c <= MaxShare {
		t.Fatalf("coverage %v", c)
	}
	if c := coverage(parse(strings.NewReader("1.2.3.0/24\n"))); c > MaxShare {
		t.Fatalf("coverage %v", c)
	}
}

func TestDownloadAndKeepCopy(t *testing.T) {
	body := "203.0.113.0/24\n"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
	defer srv.Close()
	old := http.DefaultClient
	http.DefaultClient = srv.Client()
	defer func() { http.DefaultClient = old }()

	dir := t.TempDir()
	f, err := New(srv.URL+"/list", dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.refresh(context.Background())
	if f.Match(netip.MustParseAddr("203.0.113.7")) == "" {
		t.Fatal("downloaded list not used")
	}
	files, _ := filepath.Glob(filepath.Join(dir, "feeds", "*.txt"))
	if len(files) != 1 {
		t.Fatalf("saved copies: %v", files)
	}
	// A failed download keeps the last good list; a restart reads the copy.
	body = ""
	f.refresh(context.Background())
	if f.Match(netip.MustParseAddr("203.0.113.7")) == "" {
		t.Fatal("empty download replaced the list")
	}
	g, _ := New(srv.URL+"/list", dir, nil)
	srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	g.Start(ctx)
	if g.Match(netip.MustParseAddr("203.0.113.7")) == "" {
		t.Fatal("saved copy not loaded at start")
	}
	if _, err := os.Stat(files[0]); err != nil {
		t.Fatal(err)
	}
}
