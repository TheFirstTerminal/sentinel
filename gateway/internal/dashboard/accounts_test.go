package dashboard

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"sentinel/gateway/internal/auth"
	"sentinel/gateway/internal/reqctx"
)

func TestAccountsAndRoles(t *testing.T) {
	d := newDash(t)
	store := auth.NewMemoryStore()
	keys, _ := auth.DeriveKeys(strings.Repeat("k", 40))
	svc, err := auth.NewService(store, keys)
	if err != nil {
		t.Fatal(err)
	}
	store.CreateUser(context.Background(), &auth.User{Username: "admin", Role: "admin"})
	d.Auth = svc
	who := func(name, role string) *reqctx.Identity {
		return &reqctx.Identity{Username: name, Role: role, MFA: true}
	}

	create := func(name, role string) string {
		t.Helper()
		code, body := call(d, admin, "POST", APIPrefix+"accounts", `{"username":"`+name+`","role":"`+role+`"}`)
		var out struct{ Password string }
		json.Unmarshal([]byte(body), &out)
		if code != 200 || len(out.Password) != 20 {
			t.Fatalf("create %s: %d %s", name, code, body)
		}
		return out.Password
	}
	create("olga", "operator")
	create("vic", "viewer")
	if code, _ := call(d, admin, "POST", APIPrefix+"accounts", `{"username":"x1","role":"owner"}`); code != 400 {
		t.Errorf("an unknown role must be refused: %d", code)
	}
	if code, _ := call(d, admin, "POST", APIPrefix+"accounts", `{"username":"olga","role":"viewer"}`); code != 400 {
		t.Errorf("a taken name must be refused: %d", code)
	}

	vic, olga := who("vic", "viewer"), who("olga", "operator")
	for _, c := range []struct {
		id     *reqctx.Identity
		method string
		path   string
		body   string
		want   int
	}{
		{vic, "GET", "stats", "", 200},
		{vic, "GET", "me", "", 200},
		{vic, "POST", "bans", `{"ip":"203.0.113.7","minutes":5}`, 403},
		{vic, "GET", "accounts", "", 403},
		{olga, "POST", "bans", `{"ip":"203.0.113.7","minutes":5}`, 200},
		{olga, "PUT", "alerts", `{"off":true}`, 403},
		{olga, "PUT", "sites/_/settings", `{}`, 403},
		{olga, "POST", "accounts", `{"username":"z9","role":"admin"}`, 403},
		{who("vic", "admin"), "POST", "accounts", `{"username":"z9","role":"admin"}`, 403}, // the role in the token is not trusted
	} {
		if code, body := call(d, c.id, c.method, APIPrefix+c.path, c.body); code != c.want {
			t.Errorf("%s %s %s: %d, want %d (%s)", c.id.Role, c.method, c.path, code, c.want, body)
		}
	}
	if _, body := call(d, vic, "GET", APIPrefix+"me", ""); !strings.Contains(body, `"role":"viewer"`) {
		t.Errorf("me: %s", body)
	}

	// An admin can't remove or demote themself, and one admin must stay.
	if code, body := call(d, admin, "DELETE", APIPrefix+"accounts/admin", ""); code != 400 || !strings.Contains(body, "own account") {
		t.Errorf("remove yourself: %d %s", code, body)
	}
	create("ada", "admin")
	if code, body := call(d, who("ada", "admin"), "PUT", APIPrefix+"accounts/admin", `{"role":"viewer"}`); code != 200 {
		t.Errorf("demote another admin when two exist: %d %s", code, body)
	}
	if code, body := call(d, admin, "GET", APIPrefix+"accounts", ""); code != 403 {
		t.Errorf("a demoted admin loses admin rights at once: %d %s", code, body)
	}
	if code, body := call(d, who("ada", "admin"), "PUT", APIPrefix+"accounts/ada", `{"role":"viewer"}`); code != 400 {
		t.Errorf("demote the last admin: %d %s", code, body)
	}

	// Removed: no access, even with a token that is still valid.
	if code, _ := call(d, who("ada", "admin"), "DELETE", APIPrefix+"accounts/vic", ""); code != 200 {
		t.Fatal("remove vic")
	}
	if code, _ := call(d, vic, "GET", APIPrefix+"stats", ""); code != 403 {
		t.Errorf("a removed account must lose access at once: %d", code)
	}
	// Reset: a new password, 2FA off.
	code, body := call(d, who("ada", "admin"), "POST", APIPrefix+"accounts/olga/reset", "")
	if code != 200 || !strings.Contains(body, "password") {
		t.Errorf("reset: %d %s", code, body)
	}
	if _, body := call(d, who("ada", "admin"), "GET", APIPrefix+"accounts", ""); !strings.Contains(body, `"username":"olga","role":"operator","two_factor":false`) {
		t.Errorf("accounts after reset: %s", body)
	}
}
