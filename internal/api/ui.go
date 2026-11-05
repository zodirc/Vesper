package api

import (
	"io/fs"
	"net/http"
	"path"
	"strings"

	"github.com/zodirc/Vesper/web"
)

// userInterface 提供嵌入的管理界面。API 路径不从这里返回页面。
// userInterface serves the embedded management interface. API paths are not served as pages from here.
//
// 已构建的文件按路径返回。没有对应文件的 GET 返回 index.html，供浏览器内路由使用。
// Built files are returned by path. A GET without a matching file returns index.html for in-browser routes.
func (s *Server) userInterface() http.Handler {
	root, err := fs.Sub(web.Dist, "dist")
	if err != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeError(w, http.StatusInternalServerError, "ui_unavailable", err.Error())
		})
	}
	files := http.FileServer(http.FS(root))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'")
		name := strings.TrimPrefix(r.URL.Path, "/")
		if name == "" {
			name = "index.html"
		}
		if _, statErr := fs.Stat(root, name); statErr != nil {
			// 带扩展名的路径是静态资源。缺失时返回 404，避免把 index.html 当成脚本执行。
			// A path with an extension is a static asset. A missing one returns 404 so index.html is not executed as a script.
			if strings.Contains(path.Base(name), ".") {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Cache-Control", "no-cache")
			r.URL.Path = "/"
			files.ServeHTTP(w, r)
			return
		}
		if name == "index.html" {
			w.Header().Set("Cache-Control", "no-cache")
		}
		files.ServeHTTP(w, r)
	})
}
