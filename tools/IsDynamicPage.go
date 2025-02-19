package tools

import (
	"net/http"
	"strings"
)

func IsDynamicPage(resp *http.Response, body string) bool {
	// 检测1: 检查是否含有常见SPA框架标记
	if strings.Contains(body, "react-root") || strings.Contains(body, "ng-app") || strings.Contains(body, "vue-app") {
		return true
	}

	// 检测2: 检查是否缺少服务器端渲染内容
	if strings.Contains(body, "<noscript>") || strings.Contains(body, "JavaScript required") {
		return true
	}

	// 检测3: 检查Content-Type
	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "text/html") && len(body) < 1024 {
		return true
	}

	// 检测4: 检查是否有异步加载标记
	if strings.Contains(body, "window.__ASYNC_DATA__") || strings.Contains(body, "lazy-load") {
		return true
	}

	return false
}
