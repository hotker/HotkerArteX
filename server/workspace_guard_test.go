package server

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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

// A symlink inside the work dir that points at a protected file must not become
// a way around the sensitive-path gate: the guards check the *resolved* path,
// not just the requested string. Without this, `ln -s traffic/_ca/mitmproxy-ca.pem
// notes.txt` (or one an agent creates) hands out the MITM CA private key.
func TestWorkspaceSymlinkEscapeBlocked(t *testing.T) {
	s, dir := newWSServer(t)
	secret := filepath.Join(dir, "traffic", "_ca", "mitmproxy-ca.pem")
	if err := os.MkdirAll(filepath.Dir(secret), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secret, []byte("PRIVATE-KEY"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "innocent.txt")
	if err := os.Symlink(secret, link); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	// A directory symlink into the protected tree covers the create-under-link case.
	dirLink := filepath.Join(dir, "logs")
	if err := os.Symlink(filepath.Join(dir, "traffic"), dirLink); err != nil {
		t.Fatal(err)
	}

	for _, p := range []string{"innocent.txt", "logs/_ca/mitmproxy-ca.pem"} {
		w := httptest.NewRecorder()
		s.wsRead(w, httptest.NewRequest("GET", "/api/workspace/read?path="+p, nil))
		if w.Code != 403 {
			t.Fatalf("wsRead(%s) = %d, want 403 (body %s)", p, w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "PRIVATE-KEY") {
			t.Fatalf("wsRead(%s) leaked the CA key", p)
		}
		w = httptest.NewRecorder()
		s.wsDownload(w, httptest.NewRequest("GET", "/api/workspace/download?path="+p, nil))
		if w.Code != 403 {
			t.Fatalf("wsDownload(%s) = %d, want 403 (body %s)", p, w.Code, w.Body.String())
		}
	}

	// Creating a file through a symlinked directory must be refused too.
	w := httptest.NewRecorder()
	s.wsWrite(w, httptest.NewRequest("POST", "/api/workspace/write", strings.NewReader(`{"path":"logs/evil.txt","content":"x"}`)))
	if w.Code != 403 {
		t.Fatalf("wsWrite(logs/evil.txt) = %d, want 403 (body %s)", w.Code, w.Body.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "traffic", "evil.txt")); !os.IsNotExist(err) {
		t.Fatal("wsWrite wrote through the symlinked directory")
	}
	// ...and writing through the file symlink must not clobber the target either.
	w = httptest.NewRecorder()
	s.wsWrite(w, httptest.NewRequest("POST", "/api/workspace/write", strings.NewReader(`{"path":"innocent.txt","content":"pwned"}`)))
	if w.Code == 200 {
		t.Fatalf("wsWrite(innocent.txt) = %d, want refusal", w.Code)
	}
	if b, err := os.ReadFile(secret); err != nil || string(b) != "PRIVATE-KEY" {
		t.Fatalf("CA key was modified through the symlink: %q err=%v", b, err)
	}

	// The listing must not advertise the escaping link.
	w = httptest.NewRecorder()
	s.wsList(w, httptest.NewRequest("GET", "/api/workspace/list?path=", nil))
	if w.Code != 200 {
		t.Fatalf("wsList = %d (body %s)", w.Code, w.Body.String())
	}
	var out struct {
		Entries []wsEntry `json:"entries"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	for _, e := range out.Entries {
		if e.Name == "innocent.txt" || e.Name == "logs" {
			t.Fatalf("escaping symlink %q advertised in listing", e.Name)
		}
	}
}

// A different spelling of a protected tree must not get through. On APFS (macOS
// default) and NTFS the filesystem resolves "Traffic/_ca/mitmproxy-ca.pem" to the
// real tree, so an exact-match guard would hand out the MITM CA private key to
// anyone who capitalises the path — EvalSymlinks does not canonicalise case, so
// the resolved-path guard has the same hole. The comparison must be
// case-insensitive on every platform, not only the case-insensitive ones.
func TestWorkspaceSensitivePathsCaseInsensitive(t *testing.T) {
	s, dir := newWSServer(t)
	secret := filepath.Join(dir, "traffic", "_ca", "mitmproxy-ca.pem")
	if err := os.MkdirAll(filepath.Dir(secret), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secret, []byte("PRIVATE-KEY"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "jwt.key"), []byte("SIGNING-KEY"), 0o600); err != nil {
		t.Fatal(err)
	}

	spellings := []string{
		"Traffic/_ca/mitmproxy-ca.pem",
		"TRAFFIC/_ca/mitmproxy-ca.pem",
		"JWT.key",
		"Jwt.Key",
		"Evidence/x.bin",
	}
	for _, p := range spellings {
		w := httptest.NewRecorder()
		s.wsRead(w, httptest.NewRequest("GET", "/api/workspace/read?path="+p, nil))
		if w.Code != 403 {
			t.Fatalf("wsRead(%s) = %d, want 403 (body %s)", p, w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "PRIVATE-KEY") || strings.Contains(w.Body.String(), "SIGNING-KEY") {
			t.Fatalf("wsRead(%s) leaked a key", p)
		}
		w = httptest.NewRecorder()
		s.wsDownload(w, httptest.NewRequest("GET", "/api/workspace/download?path="+p, nil))
		if w.Code != 403 {
			t.Fatalf("wsDownload(%s) = %d, want 403 (body %s)", p, w.Code, w.Body.String())
		}
	}

	// Listing through the differently-spelled directory is refused as well.
	for _, p := range []string{"Traffic", "EVIDENCE", "traffic/_ca"} {
		w := httptest.NewRecorder()
		s.wsList(w, httptest.NewRequest("GET", "/api/workspace/list?path="+p, nil))
		if w.Code != 403 {
			t.Fatalf("wsList(%s) = %d, want 403 (body %s)", p, w.Code, w.Body.String())
		}
	}
}

// A FIFO planted in the work dir must not be servable: http.ServeFile opens the
// target, so a FIFO with no writer blocks the handler goroutine (and its
// connection) forever — a cheap way to exhaust the server from one shell command.
func TestWorkspaceDownloadRejectsNonRegularFiles(t *testing.T) {
	s, dir := newWSServer(t)
	fifo := filepath.Join(dir, "hang")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo unsupported: %v", err)
	}
	w := httptest.NewRecorder()
	s.wsDownload(w, httptest.NewRequest("GET", "/api/workspace/download?path=hang", nil))
	if w.Code != 400 {
		t.Fatalf("wsDownload(fifo) = %d, want 400 (body %s)", w.Code, w.Body.String())
	}
}
