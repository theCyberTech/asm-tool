package dashboard

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"unicode"
)

//go:embed all:webdist
var webDist embed.FS

func spaFileSystem() (http.FileSystem, fs.FS, error) {
	sub, err := fs.Sub(webDist, "webdist")
	if err != nil {
		return nil, nil, err
	}
	return http.FS(sub), sub, nil
}

// ServeSPA serves hashed frontend assets when they exist and otherwise the SPA index.
func ServeSPA(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodHead)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	httpFS, fsys, err := spaFileSystem()
	if err != nil {
		http.Error(w, "frontend unavailable", http.StatusInternalServerError)
		return
	}

	rel := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
	if rel == "index.html" {
		ServeIndex(w, r)
		return
	}
	if rel != "" && rel != "." && !strings.Contains(rel, "..") {
		if serveDashboardJS(w, r, fsys, rel) {
			return
		}
		if f, err := fsys.Open(rel); err == nil {
			_ = f.Close()
			http.FileServer(httpFS).ServeHTTP(w, r)
			return
		}
		if looksLikeStaticAsset(rel) {
			http.NotFound(w, r)
			return
		}
	}

	ServeIndex(w, r)
}

// ServeIndex writes the TypeScript SPA shell.
func ServeIndex(w http.ResponseWriter, r *http.Request) {
	_, fsys, err := spaFileSystem()
	if err != nil {
		http.Error(w, "frontend unavailable", http.StatusInternalServerError)
		return
	}
	data, err := fs.ReadFile(fsys, "index.html")
	if err != nil {
		http.Error(w, "frontend unavailable", http.StatusInternalServerError)
		return
	}
	html := string(data)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.Header().Set("Content-Security-Policy", "frame-ancestors *")
	_, _ = w.Write([]byte(html))
}

func serveDashboardJS(w http.ResponseWriter, r *http.Request, fsys fs.FS, rel string) bool {
	if rel != "assets/index.js" && !hashedIndexJSRequest(rel) {
		return false
	}
	fallback, ok := currentIndexJS(fsys)
	if !ok {
		return false
	}
	w.Header().Set("Cache-Control", "no-cache")
	http.ServeFileFS(w, r, fsys, fallback)
	return true
}

func currentIndexJS(fsys fs.FS) (string, bool) {
	if f, err := fsys.Open("assets/index.js"); err == nil {
		_ = f.Close()
		return "assets/index.js", true
	}
	data, err := fs.ReadFile(fsys, "index.html")
	if err != nil {
		return "", false
	}
	html := string(data)
	for {
		idx := strings.Index(html, "/assets/")
		if idx < 0 {
			return "", false
		}
		rest := html[idx+1:]
		end := strings.IndexAny(rest, `"' >`)
		if end > 0 {
			rel := rest[:end]
			if strings.HasPrefix(rel, "assets/index") && strings.HasSuffix(rel, ".js") {
				if f, err := fsys.Open(rel); err == nil {
					_ = f.Close()
					return rel, true
				}
			}
		}
		html = html[idx+1:]
	}
}

func hashedIndexJSRequest(rel string) bool {
	if !strings.HasPrefix(rel, "assets/index-") || !strings.HasSuffix(rel, ".js") {
		return false
	}
	name := strings.TrimSuffix(strings.TrimPrefix(rel, "assets/index-"), ".js")
	if name == "" {
		return false
	}
	for _, r := range name {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func looksLikeStaticAsset(rel string) bool {
	if strings.HasPrefix(rel, "assets/") {
		return true
	}
	switch path.Ext(rel) {
	case ".js", ".css", ".map", ".svg", ".png", ".ico", ".woff", ".woff2", ".json":
		return true
	default:
		return false
	}
}
