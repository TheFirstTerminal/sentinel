package geo

import "testing"

func TestCountryAndFilter(t *testing.T) {
	db, err := Load("../../testdata/geoip.csv")
	if err != nil {
		t.Fatal(err)
	}
	for ip, want := range map[string]string{
		"198.51.100.7": "DE", "192.0.2.5": "RU", "192.0.2.200": "KP", "203.0.113.1": "IQ",
		"10.1.2.3": LAN, "127.0.0.1": LAN, "172.18.0.1": LAN, "::ffff:192.0.2.5": "RU",
		"8.8.8.8": "", "2001:db8::1": "DE", "garbage": "",
	} {
		if got := db.Country(ip); got != want {
			t.Errorf("Country(%s) = %q, want %q", ip, got, want)
		}
	}

	deny, _ := ParsePrefixes("6.6.6.0/24, 7.7.7.7")
	f := &Filter{DenyIPs: deny, DenyCountries: ParseCountries("kp")}
	cases := []struct {
		ip, cc string
		ok     bool
	}{
		{"6.6.6.9", "", false}, {"7.7.7.7", "", false}, {"7.7.7.8", "", true},
		{"192.0.2.200", "KP", false}, {"198.51.100.1", "DE", true}, {"10.0.0.1", LAN, true},
	}
	for _, c := range cases {
		if got := f.Check(c.ip, c.cc) == ""; got != c.ok {
			t.Errorf("deny filter %s/%s: allowed=%v want %v", c.ip, c.cc, got, c.ok)
		}
	}

	only := &Filter{AllowCountries: ParseCountries("IQ"), BlockUnknown: true}
	if only.Check("203.0.113.1", "IQ") != "" || only.Check("10.0.0.1", LAN) != "" {
		t.Error("allow-list refused IQ or LAN")
	}
	if only.Check("198.51.100.1", "DE") == "" || only.Check("8.8.8.8", "") == "" {
		t.Error("allow-list let DE or unknown through")
	}

	if _, err := ParsePrefixes("10.0.0.0/33"); err == nil {
		t.Error("bad CIDR accepted")
	}
}
