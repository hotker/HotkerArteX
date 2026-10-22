package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestRenderTemplateCommand(t *testing.T) {
	// command: string params shell-quoted; array → JSON (also quoted).
	got := renderTemplate("nmap -p {ports} {target}", map[string]any{
		"target": "10.0.0.1; rm -rf /", // injection attempt → must be single-quoted
		"ports":  []any{80.0, 443.0},
	}, shellQuote)
	if !strings.Contains(got, `'10.0.0.1; rm -rf /'`) {
		t.Fatalf("target not shell-quoted: %q", got)
	}
	if strings.Contains(got, "rm -rf /'") && !strings.Contains(got, `'10.0.0.1; rm -rf /'`) {
		t.Fatalf("possible injection leak: %q", got)
	}
	if strings.Contains(got, "{target}") || strings.Contains(got, "{ports}") {
		t.Fatalf("placeholders not replaced: %q", got)
	}
	// Nested placeholder: a value containing another param's placeholder must be
	// substituted as data, never re-expanded. With sequential ReplaceAll the
	// params {"url":"{x}","x":"$(id)"} render to `curl ''$(id)''` on roughly half
	// of the attempts (Go randomises map order): the injected quotes close the
	// shell quoting and $(id) runs. One pass must keep the braces as literal text.
	nested := renderTemplate("curl {url}", map[string]any{
		"url": "{x}",
		"x":   "$(id)",
	}, shellQuote)
	if nested != "curl '{x}'" {
		t.Fatalf("nested placeholder was expanded: %q (want %q)", nested, "curl '{x}'")
	}
	if strings.Contains(nested, "$(id)") {
		t.Fatalf("sibling param leaked into the command: %q", nested)
	}
}

func TestRenderTemplateHTTP(t *testing.T) {
	// http: identity (no shell quoting) — raw substitution into url/body.
	got := renderTemplate("https://x/submit?flag={flag}", map[string]any{"flag": "CTF{abc}"}, identity)
	if got != "https://x/submit?flag=CTF{abc}" {
		t.Fatalf("http render: %q", got)
	}
	// HTTP also must not rescanned nested placeholders.
	got = renderTemplate("POST /api?key={key}", map[string]any{"key": "{secret}"}, identity)
	if got != "POST /api?key={secret}" {
		t.Fatalf("http nesting failed: %q", got)
	}
}

func TestScalarStr(t *testing.T) {
	cases := []struct {
		v    any
		want string
		ok   bool
	}{
		{"hi", "hi", true},
		{true, "true", true},
		{float64(80), "80", true},   // integer-valued float → no decimal
		{float64(1.5), "1.5", true}, // real float
		{[]any{1, 2}, "", false},    // array → not scalar
		{map[string]any{}, "", false},
	}
	for _, c := range cases {
		got, ok := scalarStr(c.v)
		if ok != c.ok || (ok && got != c.want) {
			t.Fatalf("scalarStr(%v) = (%q,%v), want (%q,%v)", c.v, got, ok, c.want, c.ok)
		}
	}
}

func TestEnsureSchema(t *testing.T) {
	// empty → thin {args:string}
	m := ensureSchema(nil)
	props, _ := m["properties"].(map[string]any)
	if _, ok := props["args"]; !ok {
		t.Fatalf("empty schema should default to args: %v", m)
	}
	// non-empty → passthrough
	raw := json.RawMessage(`{"type":"object","properties":{"target":{"type":"string"}}}`)
	m2 := ensureSchema(raw)
	p2, _ := m2["properties"].(map[string]any)
	if _, ok := p2["target"]; !ok {
		t.Fatalf("non-empty schema should pass through: %v", m2)
	}
}

func TestShellQuote(t *testing.T) {
	if got := shellQuote("a'b"); got != `'a'\''b'` {
		t.Fatalf("shellQuote(a'b) = %q", got)
	}
}

// TestExecPython runs a real Python script end-to-end: it must read params from
// stdin JSON and the mirrored env var, then print — verifying the whole script
// param-passing path. Skips if no python3.
func TestExecPython(t *testing.T) {
	interp, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	code := `import json,sys,os
a = json.load(sys.stdin)
print("stdin_target=" + a["target"])
print("env_target=" + os.environ.get("TOOL_TARGET",""))
print("port=" + str(a["port"]))
`
	out, err := execPython(context.Background(), interp, "test", code,
		map[string]any{"target": "example.com", "port": float64(8080)},
		t.TempDir(), nil, 10*time.Second)
	if err != nil {
		t.Fatalf("execPython error: %v", err)
	}
	for _, want := range []string{"stdin_target=example.com", "env_target=example.com", "port=8080"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
}

// TestRunHTTPTool functionally exercises the http executor against a local server:
// method/url/header/body templates are rendered from params, the request is sent,
// and the response status+body are returned. No recording proxy → s.m untouched.
func TestRunHTTPTool(t *testing.T) {
	var gotMethod, gotAuth, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	execRaw, _ := json.Marshal(map[string]any{
		"method":  "POST",
		"url":     srv.URL + "/submit?flag={flag}",
		"headers": map[string]string{"Authorization": "Bearer {token}"},
		"body":    `{"flag":"{flag}"}`,
	})
	res, err := (&Server{}).runHTTPTool(context.Background(), execRaw,
		map[string]any{"flag": "CTF{x}", "token": "sekret"}, nil)
	if err != nil {
		t.Fatalf("runHTTPTool: %v", err)
	}
	if res.IsError || len(res.Content) == 0 {
		t.Fatalf("unexpected result: %+v", res)
	}
	var out struct {
		Status int    `json:"status"`
		Body   string `json:"body"`
	}
	_ = json.Unmarshal([]byte(res.Content[0].Text), &out)

	if gotMethod != "POST" {
		t.Fatalf("method: %q", gotMethod)
	}
	if gotAuth != "Bearer sekret" {
		t.Fatalf("header template not rendered: %q", gotAuth)
	}
	if gotBody != `{"flag":"CTF{x}"}` {
		t.Fatalf("body template not rendered: %q", gotBody)
	}
	if out.Status != 201 || !strings.Contains(out.Body, `"ok":true`) {
		t.Fatalf("response not captured: %+v", out)
	}
}

func TestDetectPython(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 unavailable")
	}
	if p := detectPython(); p == "" {
		t.Fatal("detectPython returned empty despite python3 on PATH")
	}
}

// The http tool must truncate an oversized response through norma's Capture, the
// same valve every other tool uses — a session with no OutputDir falls back to a
// head+tail cut, so a body far past the default cap comes back shortened.
func TestHTTPToolTruncatesLargeBody(t *testing.T) {
	big := strings.Repeat("x", 40000) // past Capture's 30000 default
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(big))
	}))
	defer srv.Close()

	execRaw, _ := json.Marshal(map[string]any{"method": "GET", "url": srv.URL})
	res, err := (&Server{}).runHTTPTool(context.Background(), execRaw, map[string]any{}, nil)
	if err != nil {
		t.Fatalf("runHTTPTool: %v", err)
	}
	out := res.Flatten()
	if len(out) >= 40000 {
		t.Fatalf("oversized http body was not truncated: len=%d", len(out))
	}
}

// The custom HTTP tool's URL comes from the model, so it must not reach
// link-local endpoints such as the cloud metadata service.
func TestGuardLinkLocalDial(t *testing.T) {
	for _, addr := range []string{"169.254.169.254:80", "[fe80::1]:443", "0.0.0.0:80"} {
		if err := blockLinkLocalDial("tcp", addr, nil); err == nil {
			t.Errorf("blockLinkLocalDial(%q) allowed", addr)
		}
	}
	for _, addr := range []string{"127.0.0.1:8788", "192.168.0.2:8080", "10.1.2.3:443"} {
		if err := blockLinkLocalDial("tcp", addr, nil); err != nil {
			t.Errorf("blockLinkLocalDial(%q) = %v, want nil", addr, err)
		}
	}
}
