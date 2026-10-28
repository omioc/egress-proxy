package controller

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed assets/index.html
var uiFS embed.FS

// UIHandler 返回内置单页 WebUI 的处理器
// 页面本身不依赖后端即可渲染骨架（后端不可用时显示错误态），
// 因此这里对任何非 API 路径都返回同一个 index.html
func UIHandler() http.Handler {
	content, err := fs.ReadFile(uiFS, "assets/index.html")
	if err != nil {
		return http.NotFoundHandler()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write(content)
	})
}
