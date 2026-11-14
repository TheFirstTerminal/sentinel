package main

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sentinel/gateway/internal/config"
)

// A SQL tutorial forum: posts legitimately contain SQL. The admin clicks
// "Allow" for that rule, path and field; the post goes through, and the
// same text anywhere else is still blocked.
func TestExclusionFixesFalseAlarmOnlyWhereItApplies(t *testing.T) {
	file := filepath.Join(t.TempDir(), "exclusions.yaml")
	l := newLabWith(t, func(c *config.Config) { c.Dashboard = true; c.ExclusionsFile = file })
	post := "/forum/posts?comment=" + url.QueryEscape("Example: SELECT name FROM a UNION SELECT name FROM b")
	other := "/search?q=" + url.QueryEscape("Example: SELECT name FROM a UNION SELECT name FROM b")

	if code, _ := l.do("GET", post, "", ""); code != 403 {
		t.Fatalf("expected the false alarm first, got %d", code)
	}
	if !strings.Contains(l.logBuf.String(), `"field":"comment"`) {
		t.Error("the block does not name the field (the Allow button needs it)")
	}
	admin := l.login("admin", "Admin#2026")
	code, out := l.do("POST", "/__sentinel/api/exclusions", admin, `{"rule":"SQLI-001","path":"/forum/posts","field":"comment","note":"SQL tutorial posts"}`)
	if code != 200 || out["by"] != "admin" {
		t.Fatalf("add exclusion: %d %v", code, out)
	}
	if code, _ := l.do("POST", "/__sentinel/api/exclusions", admin, `{"rule":"SQLI-001"}`); code != 400 {
		t.Errorf("an exclusion for every path and field was accepted: %d", code)
	}
	if code, _ := l.do("GET", post, "", ""); code != 200 {
		t.Errorf("excluded field still blocked: %d", code)
	}
	if code, _ := l.do("GET", other, "", ""); code != 403 {
		t.Errorf("the same text elsewhere got through: %d", code)
	}
	data, _ := os.ReadFile(file)
	if !strings.Contains(string(data), "SQL tutorial posts") {
		t.Errorf("not saved:\n%s", data)
	}
	// Removing it brings the block back.
	_, list := l.do("GET", "/__sentinel/api/exclusions", admin, "")
	id := list["exclusions"].([]any)[0].(map[string]any)["id"].(string)
	if code, _ := l.do("DELETE", "/__sentinel/api/exclusions/"+id, admin, ""); code != 200 {
		t.Fatalf("remove: %d", code)
	}
	if code, _ := l.do("GET", post, "", ""); code != 403 {
		t.Errorf("still allowed after removal: %d", code)
	}
}

// The WordPress profile: an admin opening /wp-admin is not banned, and the
// post editor may contain code; the same code elsewhere is still blocked.
func TestWordPressProfile(t *testing.T) {
	prof := config.Profiles["wordpress"]
	l := newLabWith(t, func(c *config.Config) {
		c.Profile, c.ProfileData = "wordpress", &prof
	})
	if code, _ := l.do("GET", "/wp-admin/", "", "", from("10.7.7.7")...); code == 404 || code == 403 {
		t.Fatalf("/wp-admin is still a trap: %d", code)
	}
	if code, _ := l.do("GET", "/", "", "", from("10.7.7.7")...); code != 200 {
		t.Fatalf("the WordPress admin's IP was banned: %d", code)
	}
	post := "content=" + url.QueryEscape("<p>Use <code>SELECT * FROM a UNION SELECT * FROM b</code></p><script>hljs.highlightAll()</script>")
	code, _ := l.doForm("/wp-admin/post.php", post, "10.7.7.8")
	if code != 200 {
		t.Errorf("post editor content blocked: %d", code)
	}
	if code, _ := l.doForm("/contact", post, "10.7.7.9"); code != 403 {
		t.Errorf("the same content elsewhere was let through: %d", code)
	}
	if code, _ := l.do("GET", "/.env", "", "", from("10.7.7.10")...); code != 404 {
		t.Errorf("other traps must stay: %d", code)
	}
}
