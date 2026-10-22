package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestSecurityHeadersOnEveryRoute checks the headers land on the static UI as well
// as on API responses: clickjacking and MIME sniffing are enforced by the browser
// only when the header is on the document itself, and the exported index.html is
// served outside the API chain.
func TestSecurityHeadersOnEveryRoute(t *testing.T) {
	h := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	for _, path := range []string{"/", "/dashboard", "/api/health", "/_next/static/x.js"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		got := rec.Header()
		if got.Get("X-Frame-Options") != "DENY" {
			t.Fatalf("%s: X-Frame-Options = %q", path, got.Get("X-Frame-Options"))
		}
		if got.Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("%s: X-Content-Type-Options = %q", path, got.Get("X-Content-Type-Options"))
		}
		if got.Get("Referrer-Policy") != "no-referrer" {
			t.Fatalf("%s: Referrer-Policy = %q", path, got.Get("Referrer-Policy"))
		}
		csp := got.Get("Content-Security-Policy")
		if !strings.Contains(csp, "frame-ancestors 'none'") || !strings.Contains(csp, "object-src 'none'") {
			t.Fatalf("%s: CSP 缺少关键指令: %q", path, csp)
		}
	}
}

// TestContentSecurityPolicyConnectExtra verifies the documented escape hatch for
// deployments that serve the UI from a different origin than the SSE backend.
func TestContentSecurityPolicyConnectExtra(t *testing.T) {
	t.Setenv("ARTEX_CSP_CONNECT_EXTRA", "https://api.example.com")
	csp := contentSecurityPolicy()
	if !strings.Contains(csp, "connect-src 'self' https://api.example.com") {
		t.Fatalf("CSP 未包含额外连接源: %q", csp)
	}
	// The extra origin must not leak into script-src (a caller could otherwise
	// widen the script policy by setting an env var meant for EventSource).
	script := csp[strings.Index(csp, "script-src"):strings.Index(csp, "connect-src")]
	if strings.Contains(script, "api.example.com") {
		t.Fatalf("额外连接源污染了 script-src: %q", script)
	}
}
