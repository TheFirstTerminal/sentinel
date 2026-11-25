package dashboard

import (
	_ "embed"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"sentinel/gateway/internal/auth"
	"sentinel/gateway/internal/reqctx"
)

// SetupPath serves the first-run page that creates the admin account.
const SetupPath = "/__sentinel/setup"

//go:embed setup.html
var setupPage []byte

// Setup serves the first-run page and its API.
type Setup struct {
	Svc   *auth.Service
	State *auth.Setup
	Log   *slog.Logger
	Rec   Recorder // audit log (may be nil)
	// OnCreated runs after the admin account is created (alerts).
	OnCreated func(username, clientIP string)
}

func (s *Setup) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	info := reqctx.From(r.Context())
	switch {
	case r.URL.Path == SetupPath && r.Method == http.MethodGet:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Write(setupPage)
	case r.URL.Path == SetupPath+"/api" && r.Method == http.MethodGet:
		reply(w, map[string]any{"active": s.State.Active()})
	case r.URL.Path == SetupPath+"/api" && r.Method == http.MethodPost:
		var in struct{ Token, Username, Password string }
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in); err != nil {
			jsonError(w, http.StatusBadRequest, "send JSON: {token, username, password}", info.ID)
			return
		}
		err := s.Svc.CreateAdmin(r.Context(), s.State, in.Token, in.Username, in.Password)
		switch {
		case errors.Is(err, auth.ErrSetupToken), errors.Is(err, auth.ErrSetupDone):
			info.SetOutcome(reqctx.Outcome{Kind: "denied", Reason: "first-run setup refused: " + err.Error(), Rule: "setup"})
			jsonError(w, http.StatusForbidden, err.Error(), info.ID)
		case errors.Is(err, auth.ErrWeakPassword), errors.Is(err, auth.ErrBadUsername):
			jsonError(w, http.StatusBadRequest, err.Error(), info.ID)
		case err != nil:
			s.Log.Error("first-run setup", "error", err.Error())
			jsonError(w, http.StatusInternalServerError, "could not create the account", info.ID)
		default:
			s.Log.Warn("first-run setup done: admin account created", "username", in.Username)
			if s.OnCreated != nil {
				s.OnCreated(in.Username, info.ClientIP)
			}
			(&Dashboard{Rec: s.Rec, Log: s.Log}).audit(r, "admin_created", map[string]any{"username": in.Username, "how": "first-run setup"})
			reply(w, map[string]any{"created": in.Username})
		}
	default:
		jsonError(w, http.StatusNotFound, "unknown setup path", info.ID)
	}
}
