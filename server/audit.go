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
		elapsed := time.Since(start).Round(time.Millisecond)
		actor := ""
		if acc := CurrentAccess(r); acc != nil {
			actor = acc.User.Username
		}
		log.Printf("[audit] %s %s ip=%s actor=%s status=%d %s",
			r.Method, r.URL.Path, clientIP(r), actor, rec.status, elapsed)
		// 落库一份（结构化，带 actor）：后端日志用于排障，这张表用于回答"谁动了什么"。
		// result 用状态码归类，message 记路径与耗时，detail 留原始状态码便于筛选。
		if s.m != nil && s.m.pg != nil {
			result := "success"
			if rec.status >= 500 {
				result = "error"
			} else if rec.status >= 400 {
				result = "denied"
			}
			s.m.pg.RecordAudit(actor, "api", r.Method+" "+r.URL.Path, result, clientIP(r),
				"", map[string]any{"status": rec.status, "ms": elapsed.Milliseconds()})
		}
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

// auditFrom 写一条带 actor 的审计记录。actor 取当前请求的授权画像，
// 没有画像时（未鉴权路径，例如登录本身）用调用方显式给的名字。
//
// best-effort：写失败只记后端日志，绝不让审计故障影响业务操作。
func (s *Server) auditFrom(r *http.Request, actor, category, action, result, message string, detail map[string]any) {
	if s.m == nil || s.m.pg == nil {
		return
	}
	if acc := CurrentAccess(r); acc != nil && acc.User.Username != "" {
		actor = acc.User.Username
	}
	s.m.pg.RecordAudit(actor, category, action, result, clientIP(r), message, detail)
}
