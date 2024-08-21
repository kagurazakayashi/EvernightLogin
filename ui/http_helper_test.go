package ui

import (
	"net/http"

	"github.com/kagurazakayashi/EvernightLogin/httpapi"
	"github.com/kagurazakayashi/EvernightLogin/internal/httpassemble"
)

// newUIHTTPHandler 是 UI 测试专用 HTTP 组装器；生产入口仍由根门面提供。
func newUIHTTPHandler(options httpapi.HTTPOptions) (http.Handler, error) {
	return httpassemble.NewHTTPHandler(options, "test-ui")
}
