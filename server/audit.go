package server

import (
	"log"
	"net/http"
	"time"
)

// audit is the request-level audit trail for the API. It is mounted INSIDE
// requireAuth, so it only ever sees authenticated requests — the 401 rejections
// are already handled before audit runs. It logs every mutating call
// (POST/PUT/DELETE/PATCH, not GET/HEAD/OPTIONS) regardless of success, because
// an attempted delete/settings-change is exactly as worth recording as a
// successful one.
//
// Reads are deliberately not logged: they are high-volume, low-signal, and would
// drown the [audit] lines a human actually needs (who changed the LLM config, who
// deleted a task, who approved an intercept, who triggered a self-update). The
// log lands in the standard logger → logSink → the 日志 page, so it survives
// restart and is searchable there.
//
// Fields: method, path, client IP, final status, and elapsed time. The status is
// captured with a thin wrapper so 2xx/4xx/5xx all land in the same line.
func (s *Server) audit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		next.ServeHTTP(rec, r)
		log.Printf("[audit] %s %s ip=%s status=%d %s",
			r.Method, r.URL.Path, clientIP(r), rec.status, time.Since(start).Round(time.Millisecond))
	})
}

// statusRecorder captures the response status code so the audit line reports the
// real outcome (writeErr/writeJSON both call WriteHeader, which is what this
// intercepts). It forwards everything else untouched.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}
