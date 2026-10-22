// Package guard implements the safety boundary layer (docs §11): an audit log,
// user-configured intercept-rule evaluation, and Observer/G5 failure attribution.
// Every tool call passes through the PreToolUse hook before executing.
// (The RoE authorization-scope mechanism was removed; a replacement may be added
// later.) Destructive/exfil gating is no longer hard-coded here — it lives in the
// DB intercept rules (seeded as ordinary [内置] rules, so users can disable or
// delete them), evaluated via applyIntercept.
package guard

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/norma/hook"
)

// AuditEntry records one gated tool call.
type AuditEntry struct {
	TS      int64  `json:"ts"`
	Tool    string `json:"tool"`
	Action  string `json:"action"` // allow|block
	Reason  string `json:"reason,omitempty"`
	Command string `json:"command,omitempty"`
}

// Guard enforces the side-effect policy via agent-core hooks.
type Guard struct {
	mu          sync.Mutex
	audit       []AuditEntry
	attrib      map[string]int // failure attribution counts (Observer / G5)
	reg         *hook.Registry
	interceptor *intercept.Interceptor // optional; nil disables user-configured rules
}

// New creates a Guard without user-configured intercept rules (used for pentest
// tasks where the Interceptor is not yet available).
func New() *Guard { return newGuard(nil) }

// NewWithInterceptor creates a Guard with user-configured intercept rules.
func NewWithInterceptor(ic *intercept.Interceptor) *Guard { return newGuard(ic) }

func newGuard(ic *intercept.Interceptor) *Guard {
	g := &Guard{attrib: map[string]int{}, interceptor: ic}
	g.reg = hook.NewRegistry().
		On(hook.PreToolUse, g.preToolUse).
		On(hook.PostToolUse, g.postToolUse)
	return g
}

// Hooks returns the hook registry to attach to an agent session.
func (g *Guard) Hooks() *hook.Registry { return g.reg }

// protectedPaths holds the absolute roots agents must never touch (the traffic
// capture tree, the evidence blob store, the JWT key); replaced atomically at
// server startup and read lock-free on every tool call.
var protectedPaths atomic.Pointer[[]string]

// SetProtectedPaths installs the absolute roots every agent must never touch —
// the traffic capture tree (MITM CA *private* key + plaintext index), the
// evidence blob store, and the JWT signing key. The workspace HTTP layer already
// refuses these (server/workspace.go sensitiveWorkspaceTrees), but that gate is
// reachable only through the API: an agent's CWD is inside the data dir, so
// `cat ../../traffic/_ca/mitmproxy-ca.pem` opens the same file directly. Holding
// that key forges TLS for any domain the operator intercepts; holding jwt.key
// forges an admin session. Called once at server startup; an unset value (tests,
// standalone guards) leaves agents unrestricted, as before.
func SetProtectedPaths(paths []string) {
	clean := make([]string, 0, len(paths)*2)
	add := func(p string) {
		for _, have := range clean {
			if have == p {
				return
			}
		}
		clean = append(clean, p)
	}
	for _, p := range paths {
		if p = filepath.Clean(strings.TrimSpace(p)); p == "" || p == "." {
			continue
		}
		add(p)
		// Also store the symlink-resolved spelling: macOS /var → /private/var and
		// bind-mounted Docker volumes make the configured and the resolved form
		// differ, and a containment check against only one side is vacuous.
		if real, err := filepath.EvalSymlinks(p); err == nil && real != p {
			add(real)
		}
	}
	protectedPaths.Store(&clean)
}

// ProtectedPaths returns the currently installed protected roots (read-only).
func ProtectedPaths() []string {
	if p := protectedPaths.Load(); p != nil {
		return *p
	}
	return nil
}

// protectedTrees are the data-dir top-level trees agents must never read
// directly: the traffic capture tree (MITM CA private key + plaintext capture
// index) and the evidence blob store (raw target request/response bytes). Agents
// get dedicated tool APIs for both instead.
var protectedTrees = []string{"traffic", "evidence"}

// protectedDirs are the internal subdirectories under those trees that hold the
// material itself (the CA key, the SQLite index, the body blobs). Matched at any
// depth so `../traffic/_ca/mitmproxy-ca.pem` and an absolute path are both hit.
var protectedDirs = []string{"traffic/_ca", "traffic/_index", "traffic/_blobs", "evidence/blobs"}

// protectedFiles is the set of file names to refuse wherever they appear: the
// session signing key (never in an agent's read set) and the CA private key.
// Matching the basename also closes the gap a stateful shell leaves open —
// `cd traffic; cd _ca; cat mitmproxy-ca.pem` never puts the directory and the
// file in the same token.
var protectedFiles = []string{
	"jwt.key",
	"jwt.key.migrated",
	"mitmproxy-ca.pem", // the CA *private* key
}

// pathFields names the tool-input keys that carry a filesystem path; only these
// are inspected for structured file tools.
var pathFields = []string{"file_path", "notebook_path", "path", "dir_path", "target_file", "from", "to"}

// shellSplit separates a command line on whitespace and shell metacharacters, so
// each resulting token can be treated as a candidate path.
var shellSplit = regexp.MustCompile(`[\s"'` + "`" + `=<>|;&(){}\[\],]+`)

// pathHit reports whether a raw token names protected content. It is deliberately
// spelling-tolerant: a shell command is only text until the kernel resolves it,
// and the guard never learns the agent's working directory, so it cannot do a
// real containment check. It therefore matches, in order:
//
//   - the key file by basename, wherever it appears;
//   - the internal material directories (`traffic/_ca`, `traffic/_index`,
//     `traffic/_blobs`, `evidence/blobs`) at any depth — these names are
//     unambiguous, and a symlink planted in the run dir cannot hide them;
//   - a protected top-level tree reached by a climb (`../../traffic/...`) or by
//     an absolute path.
//
// A bare relative `traffic/…` is allowed on purpose: every agent work dir is a
// subdirectory of the data dir, so it can only ever resolve *inside* the run dir
// (a local folder the agent may legitimately create) and never to the data dir's
// traffic tree. URLs are skipped — a request to https://target/traffic/_ca goes
// to the target, not to the local disk.
func pathHit(p string) string {
	if strings.Contains(p, "://") {
		return ""
	}
	p = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(p), "\\", "/"))
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	if p == "" {
		return ""
	}
	// Key files are refused by name no matter where they sit.
	base := p
	if i := strings.LastIndexByte(base, '/'); i >= 0 {
		base = base[i+1:]
	}
	for _, f := range protectedFiles {
		if base == f {
			return f
		}
	}
	// The CA *public* certificate in that directory is meant to be shared (it is
	// downloadable from /api/traffic/ca-cert and referenced by the proxy env), so
	// `curl --cacert traffic/_ca/mitmproxy-ca-cert.pem` must keep working.
	if base == "mitmproxy-ca-cert.pem" || base == "mitmproxy-ca-cert.cer" {
		return ""
	}
	// Internal layout directories, at any depth and behind any climb.
	for _, d := range protectedDirs {
		if p == d || strings.HasPrefix(p, d+"/") || strings.Contains(p, "/"+d+"/") || strings.HasSuffix(p, "/"+d) {
			return d
		}
	}
	// Top-level trees only when the token climbs or is absolute.
	climbed := strings.HasPrefix(p, "../") || strings.HasPrefix(p, "/")
	for i := 0; ; i++ {
		if strings.HasPrefix(p, "../") {
			p = p[3:]
			climbed = true
			continue
		}
		if strings.HasPrefix(p, "./") {
			p = p[2:]
			continue
		}
		if strings.HasPrefix(p, "/") {
			p = p[1:]
			climbed = true
			continue
		}
		if i > 64 {
			return ""
		}
		break
	}
	if !climbed || !strings.Contains(p, "/") {
		return ""
	}
	seg := p
	if i := strings.IndexByte(seg, '/'); i >= 0 {
		seg = seg[:i]
	}
	for _, t := range protectedTrees {
		if seg == t {
			return t
		}
	}
	return ""
}

// protectedHit reports which protected path (if any) the call touches, or "".
// cmd is the shell command already extracted by the caller ("" for file tools).
func protectedHit(toolName string, input json.RawMessage, cmd string) string {
	paths := ProtectedPaths()
	if len(paths) == 0 {
		return ""
	}
	// Shell-family tools: the command is opaque, so every token is treated as a
	// candidate path. Absolute paths under a protected root are also caught by
	// containment, which covers references the tree list does not name.
	if _, isShell := shellTools[toolName]; isShell {
		if cmd == "" {
			cmd = string(input)
		}
		for _, tok := range shellSplit.Split(cmd, -1) {
			if hit := pathHit(tok); hit != "" {
				return hit
			}
			if hit := matchProtected(tok, paths); hit != "" {
				return hit
			}
		}
		return ""
	}
	// Structured file tools: resolve the declared path fields and compare against
	// the protected roots (lexically, after following symlinks, and by tree name).
	var in map[string]json.RawMessage
	if json.Unmarshal(input, &in) != nil {
		return ""
	}
	for _, key := range pathFields {
		raw, ok := in[key]
		if !ok {
			continue
		}
		var p string
		if json.Unmarshal(raw, &p) != nil || p == "" {
			continue
		}
		if hit := pathHit(p); hit != "" {
			return hit
		}
		if hit := matchProtected(p, paths); hit != "" {
			return hit
		}
	}
	return ""
}

// matchProtected compares one declared path against the protected roots. The
// path may be relative (tool paths resolve against the agent's own working dir,
// which the guard does not know), in which case the tree-name check above is
// what catches it.
func matchProtected(p string, paths []string) string {
	cand := []string{filepath.Clean(p)}
	if real, err := filepath.EvalSymlinks(p); err == nil {
		cand = append(cand, real)
	}
	for _, c := range cand {
		for _, prot := range paths {
			// The protected root itself, or anything beneath it.
			if c == prot || strings.HasPrefix(c, prot+string(os.PathSeparator)) {
				return prot
			}
		}
	}
	return ""
}

// shellTools are the tools whose input carries a shell command that the audit
// log should record and the protected-path check should scan. Monitor runs a
// command too (in the background, through the task manager) and was previously
// missing here in both places — so `Monitor{command:"…"}` executed with no audit
// trail and no intercept match.
var shellTools = map[string]string{
	"Bash":       "command",
	"shell_open": "command",
	"shell_send": "text",
	"Monitor":    "command",
}

// extractCommand returns the shell command a tool call would run ("" if none).
func extractCommand(toolName string, input json.RawMessage) string {
	key, ok := shellTools[toolName]
	if !ok {
		return ""
	}
	var in map[string]json.RawMessage
	if json.Unmarshal(input, &in) != nil {
		return ""
	}
	var s string
	if raw, ok := in[key]; ok {
		_ = json.Unmarshal(raw, &s)
	}
	return s
}

// unwrapDeferred expands an ExecuteExtraTool call into the tool it actually
// invokes. Deferred tools (every MCP tool, and custom tools flagged deferred)
// have their schema withheld, so the model calls them as
// ExecuteExtraTool{tool_name, params}; the inner call runs directly with no
// second PreToolUse. Gating the outer name therefore reviewed nothing:
// ExecuteExtraTool was not in the enabled set, so `mcp__*` never reached the
// seeded ^mcp__ ask rule and custom command/script tools ran unapproved.
func unwrapDeferred(toolName string, input json.RawMessage) (string, json.RawMessage, bool) {
	if toolName != "ExecuteExtraTool" {
		return "", nil, false
	}
	var in struct {
		ToolName string          `json:"tool_name"`
		Params   json.RawMessage `json:"params"`
	}
	if json.Unmarshal(input, &in) != nil || strings.TrimSpace(in.ToolName) == "" {
		return "", nil, false
	}
	params := in.Params
	if len(params) == 0 {
		params = json.RawMessage("{}")
	}
	return in.ToolName, params, true
}

func (g *Guard) preToolUse(ctx context.Context, ev hook.Event) hook.Result {
	// Deferred tools run through ExecuteExtraTool; review the call that will
	// actually execute, not the wrapper.
	effective := ev
	forced := false
	if inner, params, ok := unwrapDeferred(ev.ToolName, ev.Input); ok {
		effective = hook.Event{ToolName: inner, Input: params}
		forced = true
	}
	cmd := extractCommand(effective.ToolName, effective.Input)

	// Hard floor: the platform's own key material is off-limits regardless of
	// intercept configuration (which is user-editable and can be disabled).
	if hit := protectedHit(effective.ToolName, effective.Input, cmd); hit != "" {
		return g.block(effective.ToolName, systemBlockMessage(
			"访问系统保留文件 "+hit+"（其中包含可用于伪造任意站点 TLS 的 CA 私钥 / 会话签名密钥），严禁读取、复制或外传"), cmd)
	}
	g.record(effective.ToolName, "allow", "", cmd)
	return g.applyIntercept(ctx, effective, forced)
}

// applyIntercept evaluates user-configured intercept rules against the tool call.
// Both rules and the fallback judge receive the complete tool input. force skips
// the enabled-tools filter — used for tools unwrapped out of ExecuteExtraTool,
// where the wrapper itself already proves the call needs review.
func (g *Guard) applyIntercept(ctx context.Context, ev hook.Event, force bool) hook.Result {
	if g.interceptor == nil {
		return hook.Result{}
	}
	if !force && !g.interceptor.IsToolEnabled(ev.ToolName) {
		return hook.Result{}
	}
	ctx = intercept.WithCall(ctx, ev.ToolName, ev.Input)
	dec, matched := g.interceptor.Match(ev.ToolName, ev.Input)
	if !matched {
		// No rule matched. Ask the LLM fallback judge (if enabled); when it is off
		// or unwired, keep current behavior and allow.
		d, judged := g.interceptor.Judge(ctx, ev.ToolName, ev.Input)
		if !judged {
			return hook.Result{}
		}
		dec = d
	}
	switch dec.Action {
	case "deny":
		// 观测:deny 命中不阻塞审批,直接记一条 denied（历史/任务拦截页可见）。
		g.interceptor.Log(ctx, intercept.ConvIDFromContext(ctx), dec, ev.ToolName, ev.Input, "denied")
		return g.block(ev.ToolName, systemBlockMessage(dec.Message), "")
	case "allow":
		// Record explicit rule and model approvals so review details remain auditable.
		g.interceptor.Log(ctx, intercept.ConvIDFromContext(ctx), dec, ev.ToolName, ev.Input, "allowed")
		return hook.Result{}
	case "ask":
		// If the worker context is already cancelled (task stopped / killed), block
		// immediately without creating a pending record — avoids orphaned DB entries
		// and makes execOne complete fast, reducing the race against drainSynthetic.
		if ctx.Err() != nil {
			return g.block(ev.ToolName, systemBlockMessage("工作已取消，平台安全管控阻止执行"), "")
		}
		convID := intercept.ConvIDFromContext(ctx)
		if !g.interceptor.HandleAsk(ctx, convID, dec, ev.ToolName, ev.Input) {
			return g.block(ev.ToolName, systemBlockMessage("人工审批未通过（用户拒绝或审批超时）"), "")
		}
		return hook.Result{}
	}
	return hook.Result{}
}

// systemBlockMessage frames an intercept block as an ARTEX platform-governance
// decision so the agent does not mistake it for a target-side defense.
//
// The bare reasons ("禁止执行此工具" / "用户拒绝") read exactly like a WAF/403 on
// the target, so a pentest agent's instinct is to bypass them — rewrite the
// command, swap the payload, re-encode, retry. That is both futile (the platform
// blocks the class of action, not one string) and wrong (it's a policy decision,
// not an obstacle to defeat). This prefix states plainly that the block comes
// from the platform, is not the target's protection, and that the operation is
// forbidden — so the agent pivots to another approach instead of evading it.
// Audit/history rows keep the raw reason (see Interceptor.Log); only the
// model-facing tool_result carries this framing.
func systemBlockMessage(reason string) string {
	return "【ARTEX 平台管控·非目标防御】此调用被平台拦截。" +
		"原因：" + reason + "。此操作被禁止。"
}

var reBlocked = regexp.MustCompile(`(?i)\b(403|forbidden|waf|blocked|rate.?limit|429|captcha|denied)\b`)

// postToolUse is the Observer failure-attribution hook (G5): it classifies tool
// results into blocked / error / ok so the planner can change strategy instead
// of giving up at a WAF.
func (g *Guard) postToolUse(_ context.Context, ev hook.Event) hook.Result {
	if ev.ToolName != "Bash" {
		return hook.Result{}
	}
	class := "ok"
	switch {
	case reBlocked.Match(ev.Result):
		class = "blocked"
	case ev.IsError:
		class = "error"
	}
	g.mu.Lock()
	g.attrib[class]++
	g.mu.Unlock()
	return hook.Result{}
}

// Attributions returns failure-attribution counts (Observer / G5).
func (g *Guard) Attributions() map[string]int {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make(map[string]int, len(g.attrib))
	for k, v := range g.attrib {
		out[k] = v
	}
	return out
}

func (g *Guard) block(tool, reason, cmd string) hook.Result {
	g.record(tool, "block", reason, cmd)
	return hook.Result{Decision: "block", Message: reason}
}

func (g *Guard) record(tool, action, reason, cmd string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.audit = append(g.audit, AuditEntry{TS: time.Now().Unix(), Tool: tool, Action: action, Reason: reason, Command: cmd})
	if len(g.audit) > 2000 {
		g.audit = g.audit[len(g.audit)-2000:]
	}
}

// Audit returns a snapshot of recent gated calls (most recent last).
func (g *Guard) Audit() []AuditEntry {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]AuditEntry, len(g.audit))
	copy(out, g.audit)
	return out
}
