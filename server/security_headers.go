package server

import (
	"net/http"
	"os"
	"strings"
)

// contentSecurityPolicy is applied to every response the binary serves. The UI is
// a self-contained static export (all assets are same-origin, no CDN, no external
// fonts, no eval), so the only relaxations needed are the ones Next's static
// export itself requires:
//
//   - script-src 'unsafe-inline' — the theme bootstrap script and Next's hydration
//     bootstrap are inline in the exported HTML. A nonce would need a server-side
//     rewrite of every exported page, which static export cannot do.
//   - style-src 'unsafe-inline' — React writes element styles inline (popovers,
//     chart sizing), and Tailwind ships inline style attributes.
//
// Everything else stays closed: no remote script/style/frame/worker origin, no
// <base> rewriting, no plugins. frame-ancestors 'none' also covers the older
// X-Frame-Options value, but both are sent for clients that predate CSP.
//
// connect-src is 'self' by default. A deployment that builds the UI with a
// cross-origin NEXT_PUBLIC_SSE_BASE (see web/src/lib/api.ts) must name that origin
// in ARTEX_CSP_CONNECT_EXTRA or its EventSource streams will be blocked.
func contentSecurityPolicy() string {
	connect := "'self'"
	if extra := strings.TrimSpace(os.Getenv("ARTEX_CSP_CONNECT_EXTRA")); extra != "" {
		connect += " " + extra
	}
	return "default-src 'self'; " +
		"base-uri 'self'; " +
		"object-src 'none'; " +
		"frame-ancestors 'none'; " +
		"form-action 'self'; " +
		"img-src 'self' data: blob:; " +
		"font-src 'self' data:; " +
		"style-src 'self' 'unsafe-inline'; " +
		"script-src 'self' 'unsafe-inline'; " +
		"connect-src " + connect + "; " +
		"worker-src 'self' blob:"
}

// securityHeaders adds the response headers a browser needs to constrain what the
// page can load and who can embed it. Without them a crafted link can frame the
// admin UI (clickjacking on the approval/decide buttons), and a reflected string
// in a download response can be sniffed as HTML. These are cheap, apply to every
// route including the static assets, and never change behaviour for the app.
func securityHeaders(next http.Handler) http.Handler {
	csp := contentSecurityPolicy() // env is read once, not per request
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
		next.ServeHTTP(w, r)
	})
}
