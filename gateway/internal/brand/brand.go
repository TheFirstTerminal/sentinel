// Package brand serves a copy of The First Terminal's brand kit (tft.css,
// the arch logo and the Readex Pro / Noto Kufi Arabic fonts) from Sentinel
// itself, so the dashboard and setup pages look like every TFT product
// without loading anything from the internet.
//
// The files are copied from TheFirstTerminal/tft-home public/brand/ (the
// source of truth; the style guide is docs/brand-guide.html there); refresh them when
// the brand changes. The fonts are under the SIL Open Font License
// (files/fonts/OFL-LICENSE.txt).
package brand

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

// Path is where the kit is served: Path+"tft.css", Path+"logo.svg",
// Path+"fonts/...".
const Path = "/__sentinel/brand/"

//go:embed files
var files embed.FS

var sub, _ = fs.Sub(files, "files")

// Handler serves the kit. Files are public and cached for a day.
func Handler() http.Handler {
	fsrv := http.StripPrefix(strings.TrimSuffix(Path, "/"), http.FileServer(http.FS(sub)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/") { // no directory listings
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		fsrv.ServeHTTP(w, r)
	})
}
