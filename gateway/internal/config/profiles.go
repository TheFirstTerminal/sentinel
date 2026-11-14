package config

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

// A Profile is a starting point for a kind of app: settings that fit it,
// honeypot traps it must not have (they are real pages there), and
// exclusions for its known false alarms. Anything set in the file or the
// environment still wins.
type Profile struct {
	Description string
	Vars        map[string]string
	RemoveTraps []string
	Exclusions  []ProfileExclusion
}

// ProfileExclusion switches the listed rules off for one path and/or field.
type ProfileExclusion struct {
	Rules       []string
	Path, Field string
	Note        string
}

var contentRules = []string{"CRS-941*", "CRS-942*", "CRS-932*", "CRS-933*", "CRS-934*", "SQLI-*", "XSS-*", "CMDI-*", "SSTI-*", "ML"}
var tokenRules = []string{"CRS-942*", "CRS-941*", "ML"}

// Profiles are the built-in profiles.
var Profiles = map[string]Profile{
	"wordpress": {
		Description: "WordPress: the admin pages are real (not traps), logins are rate-limited, post content may contain HTML and code",
		Vars:        map[string]string{"RATE_LIMITS": "/wp-login.php=10/1m,/xmlrpc.php=20/1m,/__sentinel/auth/=10/1m,/=600/1m"},
		RemoveTraps: []string{"/wp-admin", "/wp-login.php"},
		Exclusions: []ProfileExclusion{
			{contentRules, "/wp-admin/post.php", "content", "post editor"},
			{contentRules, "/wp-admin/post.php", "excerpt", "post editor"},
			{contentRules, "/wp-json/wp/v2/", "content", "block editor (REST)"},
			{contentRules, "/wp-json/wp/v2/", "content.raw", "block editor (REST)"},
			{contentRules, "/wp-admin/customize.php", "customized", "theme customizer"},
			{contentRules, "/wp-admin/theme-editor.php", "newcontent", "theme file editor"},
			{contentRules, "/wp-admin/plugin-editor.php", "newcontent", "plugin file editor"},
		},
	},
	"laravel": {
		Description: "Laravel: encrypted session and XSRF cookies, rate-limited login and password reset",
		Vars:        map[string]string{"RATE_LIMITS": "/login=10/1m,/password/=10/1m,/__sentinel/auth/=10/1m,/=600/1m"},
		Exclusions: []ProfileExclusion{
			{tokenRules, "", "laravel_session", "encrypted session cookie"},
			{tokenRules, "", "xsrf-token", "encrypted CSRF cookie"},
			{tokenRules, "", "_token", "CSRF form field"},
		},
	},
	"django": {
		Description: "Django: CSRF and session tokens, rate-limited admin and account logins",
		Vars:        map[string]string{"RATE_LIMITS": "/admin/login/=10/1m,/accounts/login/=10/1m,/__sentinel/auth/=10/1m,/=600/1m"},
		Exclusions: []ProfileExclusion{
			{tokenRules, "", "csrftoken", "CSRF cookie"},
			{tokenRules, "", "csrfmiddlewaretoken", "CSRF form field"},
			{tokenRules, "", "sessionid", "session cookie"},
		},
	},
	"nextjs": {
		Description: "Next.js: build assets skipped by the ML model, rate-limited auth routes",
		Vars: map[string]string{
			"ML_SKIP_PATHS": "/_next/static/,/_next/image",
			"RATE_LIMITS":   "/api/auth/=20/1m,/__sentinel/auth/=10/1m,/=900/1m",
		},
		Exclusions: []ProfileExclusion{
			{tokenRules, "", "next-auth.session-token", "encrypted session cookie"},
			{tokenRules, "", "__secure-next-auth.session-token", "encrypted session cookie"},
			{tokenRules, "", "next-auth.csrf-token", "CSRF cookie"},
		},
	},
	"ai": {
		Description: "AI apps: the prompt-injection guard on the usual chat and completion endpoints",
		Vars: map[string]string{
			"PROMPT_GUARD_PATHS": "/api/chat,/api/generate,/v1/chat/completions,/v1/completions,/v1/messages,/v1/responses",
		},
	},
}

// ProfileNames lists the profiles for messages.
func ProfileNames() string {
	var n []string
	for k := range Profiles {
		n = append(n, k)
	}
	sort.Strings(n)
	return strings.Join(n, ", ")
}

// applyProfile sets the profile's settings that nothing else set.
func applyProfile(name string) (*Profile, error) {
	if name == "" || name == "none" {
		return nil, nil
	}
	p, ok := Profiles[strings.ToLower(name)]
	if !ok {
		return nil, fmt.Errorf("unknown profile %q (choose one of: %s)", name, ProfileNames())
	}
	for k, v := range p.Vars {
		if _, set := os.LookupEnv(k); !set {
			os.Setenv(k, v)
		}
	}
	return &p, nil
}
