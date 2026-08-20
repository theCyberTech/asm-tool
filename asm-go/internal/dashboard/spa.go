package dashboard

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
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
	if rel != "" && rel != "." && !strings.Contains(rel, "..") {
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
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(data)
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
