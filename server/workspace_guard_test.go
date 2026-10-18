package server

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newWSServer builds the minimum Server for the workspace handlers over a
// Manager rooted at a temp dir. The ws* handlers only touch m.dir, so a DB-less
// Manager is enough — no postgres needed, and the guard logic is tested for real
// rather than skipped when the DB is absent.
func newWSServer(t *testing.T) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	return &Server{m: &Manager{dir: dir}}, dir
}

// The MITM CA private key, the capture index, evidence and jwt.key must never
// be reachable through the workspace manager (list/read/download/write/delete/
// mkdir/upload) — that is the whole point of the sensitive-path gate.
func TestWorkspaceSensitivePathsBlocked(t *testing.T) {
	s, dir := newWSServer(t)
	for _, p := range []string{"traffic/_ca/mitmproxy-ca.pem", "traffic/_index/index.sqlite", "evidence/x.bin", "jwt.key"} {
		full := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("secret"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// read / download must refuse the secret files (top-level AND deep paths).
	for _, p := range []string{"traffic/_ca/mitmproxy-ca.pem", "traffic/_index/index.sqlite", "jwt.key", "evidence"} {
		w := httptest.NewRecorder()
		s.wsRead(w, httptest.NewRequest("GET", "/api/workspace/read?path="+p, nil))
		if w.Code != 403 {
			t.Fatalf("wsRead(%s) = %d, want 403 (body %s)", p, w.Code, w.Body.String())
		}
		w = httptest.NewRecorder()
		s.wsDownload(w, httptest.NewRequest("GET", "/api/workspace/download?path="+p, nil))
		if w.Code != 403 {
			t.Fatalf("wsDownload(%s) = %d, want 403 (body %s)", p, w.Code, w.Body.String())
		}
	}

	// write / mkdir / delete must refuse to touch the protected trees.
	for _, p := range []string{"traffic/evil.txt", "jwt.key", "evidence/sub"} {
		body := `{"path":"` + p + `","content":"x"}`
		w := httptest.NewRecorder()
		s.wsWrite(w, httptest.NewRequest("POST", "/api/workspace/write", strings.NewReader(body)))
		if w.Code != 403 {
			t.Fatalf("wsWrite(%s) = %d, want 403 (body %s)", p, w.Code, w.Body.String())
		}
		w = httptest.NewRecorder()
		s.wsMkdir(w, httptest.NewRequest("POST", "/api/workspace/mkdir", strings.NewReader(`{"path":"`+p+`"}`)))
		if w.Code != 403 {
			t.Fatalf("wsMkdir(%s) = %d, want 403 (body %s)", p, w.Code, w.Body.String())
		}
	}
	w := httptest.NewRecorder()
	s.wsDelete(w, httptest.NewRequest("DELETE", "/api/workspace/delete?path=traffic", nil))
	if w.Code != 403 {
		t.Fatalf("wsDelete(traffic) = %d, want 403 (body %s)", w.Code, w.Body.String())
	}

	// upload into a protected dir must refuse.
	w = httptest.NewRecorder()
	s.wsUpload(w, httptest.NewRequest("POST", "/api/workspace/upload?path=traffic", nil))
	if w.Code != 403 {
		t.Fatalf("wsUpload(traffic) = %d, want 403 (body %s)", w.Code, w.Body.String())
	}

	// nothing may have been created inside the protected trees.
	if _, err := os.Stat(filepath.Join(dir, "traffic", "evil.txt")); !os.IsNotExist(err) {
		t.Fatal("wsWrite managed to create a file inside traffic/")
	}
	// ...and the CA key itself must still be there, unharmed.
	if _, err := os.Stat(filepath.Join(dir, "traffic", "_ca", "mitmproxy-ca.pem")); err != nil {
		t.Fatalf("CA key file missing after guard test: %v", err)
	}
}

// Protected trees are hidden from the directory listing, while normal entries
// remain visible.
func TestWorkspaceListHidesSensitiveEntries(t *testing.T) {
	s, dir := newWSServer(t)
	if err := os.MkdirAll(filepath.Join(dir, "traffic/_ca"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "jwt.key"), []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "normal.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	s.wsList(w, httptest.NewRequest("GET", "/api/workspace/list?path=", nil))
	if w.Code != 200 {
		t.Fatalf("wsList = %d, want 200 (body %s)", w.Code, w.Body.String())
	}
	var out struct {
		Entries []wsEntry `json:"entries"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, e := range out.Entries {
		names[e.Name] = true
	}
	if !names["normal.txt"] {
		t.Fatalf("normal entry missing from listing: %v", out.Entries)
	}
	for _, hidden := range []string{"traffic", "jwt.key"} {
		if names[hidden] {
			t.Fatalf("protected entry %q visible in listing", hidden)
		}
	}

	// Listing INSIDE a protected tree is refused outright.
	w = httptest.NewRecorder()
	s.wsList(w, httptest.NewRequest("GET", "/api/workspace/list?path=traffic", nil))
	if w.Code != 403 {
		t.Fatalf("wsList(traffic) = %d, want 403 (body %s)", w.Code, w.Body.String())
	}
}

// Ordinary files still flow through unchanged (the gate must not over-block).
func TestWorkspaceNormalPathsUnaffected(t *testing.T) {
	s, _ := newWSServer(t)
	w := httptest.NewRecorder()
	s.wsWrite(w, httptest.NewRequest("POST", "/api/workspace/write", strings.NewReader(`{"path":"notes/hello.txt","content":"hello"}`)))
	if w.Code != 200 {
		t.Fatalf("wsWrite = %d, want 200 (body %s)", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	s.wsRead(w, httptest.NewRequest("GET", "/api/workspace/read?path=notes/hello.txt", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "hello") {
		t.Fatalf("wsRead = %d body %s, want 200 + content", w.Code, w.Body.String())
	}
}
