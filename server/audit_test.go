package server

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// captureLogs redirects the standard logger to a buffer for the duration of f.
func captureLogs(t *testing.T, f func()) string {
	t.Helper()
	old := log.Writer()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(old)
	f()
	return buf.String()
}

func newAuditServer(t *testing.T) *Server {
	t.Helper()
	return &Server{m: &Manager{}}
}

// Mutating authenticated calls must be audited with the real outcome status;
// reads must not be (they are high-volume, low-signal).
func TestAuditLogsMutatingSkipsReads(t *testing.T) {
	s := newAuditServer(t)

	var got string
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/tasks", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"n": 1})
	})
	mux.HandleFunc("PUT /api/tasks/{id}", func(w http.ResponseWriter, r *http.Request) {
		got = r.PathValue("id")
		writeJSON(w, 200, map[string]any{"ok": true})
	})
	mux.HandleFunc("POST /api/bad", func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, 400, "nope")
	})
	h := s.audit(mux)

	out := captureLogs(t, func() {
		// GET → not audited.
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "/api/tasks", nil))
		// PUT 200 → audited.
		w = httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("PUT", "/api/tasks/42", nil))
		// POST 400 → audited with the real status.
		w = httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("POST", "/api/bad", strings.NewReader("x")))
	})

	if !strings.Contains(out, "[audit] PUT /api/tasks/42") || !strings.Contains(out, "status=200") {
		t.Fatalf("PUT 200 not audited correctly:\n%s", out)
	}
	if !strings.Contains(out, "[audit] POST /api/bad") || !strings.Contains(out, "status=400") {
		t.Fatalf("POST 400 not audited with real status:\n%s", out)
	}
	if strings.Contains(out, "GET") {
		t.Fatalf("GET should not be audited:\n%s", out)
	}
	if got != "42" {
		t.Fatalf("handler saw id=%q, want 42", got)
	}
}

// The status recorder must report non-2xx statuses (writeErr path).
func TestStatusRecorderCapturesNon2xx(t *testing.T) {
	rec := &statusRecorder{ResponseWriter: httptest.NewRecorder(), status: http.StatusOK}
	writeErr(rec, 503, "unavailable")
	if rec.status != 503 {
		t.Fatalf("status = %d, want 503", rec.status)
	}
}
