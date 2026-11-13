package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func resetLoginLimiter() {
	loginLim.mu.Lock()
	loginLim.byKey = map[string]*loginFailEntry{}
	loginLim.mu.Unlock()
}

func reqWithAddr(remoteAddr string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/api/auth/login", nil)
	r.RemoteAddr = remoteAddr
	return r
}

func TestLoginLimiterLocksAfterThreshold(t *testing.T) {
	resetLoginLimiter()
	t.Cleanup(resetLoginLimiter)
	r := reqWithAddr("1.2.3.4:5678")

	for i := 0; i < maxLoginFails-1; i++ {
		if remain := loginLim.noteFail("1.2.3.4|Foxker"); remain > 0 {
			t.Fatalf("fail %d: locked early", i+1)
		}
	}
	if remain := loginLim.noteFail("1.2.3.4|Foxker"); remain <= 0 {
		t.Fatalf("expected lock after %d failures", maxLoginFails)
	}
	w := httptest.NewRecorder()
	if !loginThrottled(w, r, "Foxker") {
		t.Fatal("expected throttled response")
	}
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("want 429, got %d", w.Code)
	}
	// 成功登录清零后不再锁定。
	loginLim.clear("1.2.3.4|Foxker")
	if until := loginLim.lockedUntil("1.2.3.4|Foxker"); !until.IsZero() {
		t.Fatal("still locked after successful login")
	}
}

func TestLoginLimiterIsPerIPAndUser(t *testing.T) {
	resetLoginLimiter()
	t.Cleanup(resetLoginLimiter)
	for i := 0; i < maxLoginFails; i++ {
		loginLim.noteFail("1.1.1.1|Foxker")
	}
	// 同 IP 不同用户、同用户不同 IP 都不受影响。
	if u := loginLim.lockedUntil("1.1.1.1|other"); !u.IsZero() {
		t.Fatal("lock leaked across usernames")
	}
	if u := loginLim.lockedUntil("2.2.2.2|Foxker"); !u.IsZero() {
		t.Fatal("lock leaked across IPs")
	}
}

func TestLoginLimiterWindowExpiry(t *testing.T) {
	resetLoginLimiter()
	t.Cleanup(resetLoginLimiter)
	loginLim.mu.Lock()
	loginLim.byKey["9.9.9.9|Foxker"] = &loginFailEntry{
		fails:     maxLoginFails,
		lastFail:  time.Now().Add(-2 * loginFailWindow),
		lockedOut: time.Now().Add(-1 * time.Hour),
	}
	loginLim.mu.Unlock()
	if u := loginLim.lockedUntil("9.9.9.9|Foxker"); !u.IsZero() {
		t.Fatal("stale lock not expired")
	}
	if _, ok := loginLim.byKey["9.9.9.9|Foxker"]; ok {
		t.Fatal("stale entry not pruned")
	}
}

func TestClientIP(t *testing.T) {
	r := reqWithAddr("10.0.0.7:1234")
	if got := clientIP(r); got != "10.0.0.7" {
		t.Fatalf("RemoteAddr: got %q", got)
	}
	// XFF is client-controlled, so it is ignored unless a reverse proxy is
	// explicitly trusted: honouring it by default lets an attacker step the
	// throttle key with every request and never trip the lock.
	r.Header.Set("X-Forwarded-For", "203.0.113.9, 10.0.0.1")
	if got := clientIP(r); got != "10.0.0.7" {
		t.Fatalf("untrusted XFF must be ignored: got %q", got)
	}
	t.Setenv(trustedProxyEnv, "1")
	if got := clientIP(r); got != "203.0.113.9" {
		t.Fatalf("trusted XFF: got %q", got)
	}
	r.Header.Set("X-Forwarded-For", "")
	if got := clientIP(r); got != "10.0.0.7" {
		t.Fatalf("empty XFF fallback: got %q", got)
	}
}

// Rotating the source IP (spoofed XFF, a botnet, or just retries from different
// addresses) must not make password guessing free: the global failure budget
// throttles the endpoint regardless of which key the attempts land on.
func TestLoginLimiterGlobalCooldown(t *testing.T) {
	resetLoginLimiter()
	loginLim.globalFailures = nil
	t.Cleanup(func() {
		resetLoginLimiter()
		loginLim.globalFailures = nil
	})
	for i := 0; i < maxGlobalLoginFails; i++ {
		loginLim.noteGlobalFail()
	}
	w := httptest.NewRecorder()
	if !loginThrottled(w, reqWithAddr("198.51.100.1:1111"), "Foxker") {
		t.Fatal("expected global cooldown to throttle a fresh source")
	}
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("want 429, got %d", w.Code)
	}
	if wait := loginLim.globalCooldown(); wait <= 0 {
		t.Fatalf("globalCooldown = %v, want > 0", wait)
	}
	// A single failure must not trip it (a human mistyping once is normal).
	resetLoginLimiter()
	loginLim.globalFailures = nil
	loginLim.noteGlobalFail()
	if wait := loginLim.globalCooldown(); wait != 0 {
		t.Fatalf("one failure triggered the global cooldown (%v)", wait)
	}
}

func TestCORSOnlySameOrigin(t *testing.T) {
	handler := cors(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))

	// 无 Origin（同源自页面/内嵌 UI）：不加头，正常放行。
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/tasks", nil))
	if w.Code != 200 || w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("no-origin: code=%d acao=%q", w.Code, w.Header().Get("Access-Control-Allow-Origin"))
	}

	// 同源 Origin：回显。
	w = httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "http://host:8787/api/tasks", nil)
	r.Header.Set("Origin", "http://host:8787")
	handler.ServeHTTP(w, r)
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "http://host:8787" {
		t.Fatalf("same-origin: acao=%q", got)
	}

	// 跨源 Origin：不回显，浏览器会拦截。
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "http://host:8787/api/tasks", nil)
	r.Header.Set("Origin", "https://evil.example")
	handler.ServeHTTP(w, r)
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("cross-origin: acao=%q, want empty", got)
	}
}

func TestOriginHost(t *testing.T) {
	cases := map[string]string{
		"http://host:8787":       "host:8787",
		"https://host:8787/path": "host:8787",
		"null":                   "null",
	}
	for in, want := range cases {
		if got := originHost(in); got != want {
			t.Errorf("originHost(%q)=%q want %q", in, got, want)
		}
	}
}
