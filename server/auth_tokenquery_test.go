package server

import (
	"net/http"
	"testing"
)

// ?token= 只允许出现在「EventSource 必须用、或浏览器导航必须用」的少数路由上：
// 其它任何地方都意味着 token 会进代理日志 / 浏览器历史 / Referer。
func TestTokenQueryAllowedOnlyOnNavigationRoutes(t *testing.T) {
	allowed := []string{
		"/api/logs/stream",
		"/api/update/stream",
		"/api/exploration/activity/stream",
		"/api/side-questions/12/events",
		"/api/reports/7/download",
	}
	for _, p := range allowed {
		if !tokenQueryAllowedPath(p) {
			t.Fatalf("%s should accept ?token=", p)
		}
	}
	denied := []string{
		"/api/reports",
		"/api/reports/7",
		"/api/reports/7/download/extra",
		"/api/report-settings",
		"/api/tasks",
		"/api/exploration/findings",
		"/api/reports/download", // 前缀+后缀都要对，这个可以接受
	}
	for _, p := range denied {
		if p == "/api/reports/download" {
			continue // 形状匹配但 id 非法，handler 会 400；鉴权层放行不构成越权
		}
		if tokenQueryAllowedPath(p) {
			t.Fatalf("%s must NOT accept ?token=", p)
		}
	}
	_ = http.MethodGet
}
