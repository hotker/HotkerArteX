package server

import (
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 登录防爆破（内存级，单实例语义与 JWT 密钥一致：进程内生效，重启清零可接受——
// 重启本身需要本地权限，不构成提权路径）。
//
// 策略：同一 (来源IP, 用户名) 在失败窗口内累计 maxLoginFails 次失败后，锁定
// loginLock 时长。窗口/锁都从"最近一次失败"起算，因此慢速爆破（每次间隔几分钟）
// 也会被前几次失败拖进锁定窗口。成功登录清零该 key。
//
// 为什么放在内存而不用 PG：登录路径在密码未初始化/数据库故障时也要能限流，
// 把限流器挂到数据库上等于在数据库挂掉时恰好失去保护。
const (
	loginFailWindow = 15 * time.Minute
	loginLock       = 15 * time.Minute
	maxLoginFails   = 5
	// maxGlobalLoginFails / globalLoginCooldown bound brute force that rotates
	// source IPs (each per-IP key then never reaches maxLoginFails). The ceiling is
	// far above a human mistyping a password and far below a useful attack rate.
	maxGlobalLoginFails = 20
	globalLoginCooldown = 5 * time.Minute
)

type loginFailEntry struct {
	fails     int
	lastFail  time.Time
	lockedOut time.Time // 非零 = 当前处于锁定期
}

type loginLimiter struct {
	mu    sync.Mutex
	byKey map[string]*loginFailEntry
	// maxFails is the per-key failure budget; 0 means maxLoginFails.
	maxFails int
	// global is a sliding window of recent failures regardless of source. It is
	// the backstop for the per-key limiter: keeping the key space populated by
	// rotating source IPs no longer makes brute force free.
	globalFailures []time.Time
}

func (l *loginLimiter) budget() int {
	if l.maxFails > 0 {
		return l.maxFails
	}
	return maxLoginFails
}

// globalCooldown reports how long the process should keep refusing login attempts
// after a burst of failures from many sources. Recovery is automatic and costs an
// operator at most loginLock when someone is actively attacking.
func (l *loginLimiter) globalCooldown() time.Duration {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	cut := now.Add(-loginFailWindow)
	kept := l.globalFailures[:0]
	for _, t := range l.globalFailures {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	l.globalFailures = kept
	if len(l.globalFailures) < maxGlobalLoginFails {
		return 0
	}
	wait := time.Until(l.globalFailures[len(l.globalFailures)-1].Add(globalLoginCooldown))
	if wait < 0 {
		return 0
	}
	return wait
}

func (l *loginLimiter) noteGlobalFail() {
	l.mu.Lock()
	l.globalFailures = append(l.globalFailures, time.Now())
	l.mu.Unlock()
}

var loginLim = &loginLimiter{byKey: map[string]*loginFailEntry{}}

// trustedProxyEnv opts into honouring X-Forwarded-For. It is off by default
// because the header is client-supplied: since the throttle key contains the
// source IP, honouring an unvalidated XFF lets an attacker step the key with
// every request (X-Forwarded-For: 10.0.0.1, 10.0.0.2, …) and never trip the
// lock, which turns the 15-minute lockout into no protection at all. Only set
// this when a reverse proxy in front of Foxker is what writes the header.
const trustedProxyEnv = "ARTEX_TRUST_XFF"

func trustForwardedFor() bool {
	v := strings.TrimSpace(os.Getenv(trustedProxyEnv))
	return v == "1" || strings.EqualFold(v, "true")
}

// clientIP 取请求来源 IP。默认只信 RemoteAddr（TCP 对端，无法伪造）；
// 只有在显式配置了 ARTEX_TRUST_XFF=1（确实部署在反代之后）时才取 X-Forwarded-For
// 首段，否则伪造 XFF 就能逐个换 key 绕过登录限流。
func clientIP(r *http.Request) string {
	if trustForwardedFor() {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if first := strings.TrimSpace(strings.Split(xff, ",")[0]); first != "" {
				return first
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// lockedUntil 返回该 key 当前的锁定期截止时间（零值 = 未锁定），并顺带清理过期
// 条目，防止被枚举的用户名把 map 撑大。
func (l *loginLimiter) lockedUntil(key string) time.Time {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.byKey[key]
	if !ok {
		return time.Time{}
	}
	if now.Sub(e.lastFail) > loginFailWindow && e.lockedOut.Before(now) {
		delete(l.byKey, key)
		return time.Time{}
	}
	for k, v := range l.byKey {
		if now.Sub(v.lastFail) > loginFailWindow && v.lockedOut.Before(now) {
			delete(l.byKey, k)
		}
	}
	return e.lockedOut
}

// noteFail 记一次失败；返回剩余锁定时长（0 = 未锁定）。
func (l *loginLimiter) noteFail(key string) time.Duration {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.byKey[key]
	if e == nil {
		e = &loginFailEntry{}
		l.byKey[key] = e
	}
	// 窗口过期则重新计数。
	if now.Sub(e.lastFail) > loginFailWindow {
		e.fails = 0
	}
	e.fails++
	e.lastFail = now
	if e.fails >= l.budget() && e.lockedOut.Before(now) {
		e.lockedOut = now.Add(loginLock)
	}
	until := time.Until(e.lockedOut)
	if until < 0 {
		return 0
	}
	return until
}

// clear 登录成功后清零。
func (l *loginLimiter) clear(key string) {
	l.mu.Lock()
	delete(l.byKey, key)
	l.mu.Unlock()
}

// initLim throttles the first-run password setup separately from login: it runs
// bcrypt before the "already set" check can fail, so an unauthenticated caller
// could otherwise burn CPU at will, and whoever reaches the port first wins the
// installation. Three tries per window in each direction is plenty for a human
// who mistyped a password; it is not enough to grind bcrypt or to race a real
// operator meaningfully.
var initLim = &loginLimiter{byKey: map[string]*loginFailEntry{}, maxFails: maxInitTries}

const maxInitTries = 3

// initThrottled reports whether setup attempts from this source should be refused.
func initThrottled(w http.ResponseWriter, r *http.Request) bool {
	key := "init|" + clientIP(r)
	if until := initLim.lockedUntil(key); !until.IsZero() {
		secs := int(time.Until(until).Seconds()) + 1
		log.Printf("[auth] 初始化密码尝试过多 ip=%s 剩余 %ds", clientIP(r), secs)
		writeErr(w, http.StatusTooManyRequests, "初始化尝试过多，请 "+strconv.Itoa(secs)+" 秒后重试")
		return true
	}
	return false
}

// initNoteAttempt counts one setup attempt (success or failure) against the source.
func initNoteAttempt(r *http.Request) {
	key := "init|" + clientIP(r)
	if d := initLim.noteFail(key); d > 0 {
		log.Printf("[auth] 初始化密码连续尝试 %d 次，锁定 %ds", maxInitTries, int(d.Seconds()))
	}
}

func initDone(r *http.Request) { initLim.clear("init|" + clientIP(r)) }

// loginThrottled 在登录处理器最前面调用：命中锁定期则直接 429 并返回 true。
func loginThrottled(w http.ResponseWriter, r *http.Request, username string) bool {
	// 全局失败预算：per-IP key 只能挡住「同一个来源」的爆破。伪造 XFF（未开
	// ARTEX_TRUST_XFF 时已无效）或从多个出口 IP 轮换仍能把每个 key 的失败数
	// 摊薄到阈值以下，所以再加一道与来源无关的总量限制——它不锁定任何人，
	// 只是在窗口内失败太多时把后续尝试挡在门外，窗口一过自动恢复。
	if wait := loginLim.globalCooldown(); wait > 0 {
		log.Printf("[auth] 全局登录失败过多，暂停受理 %.0fs", wait.Seconds())
		writeErr(w, http.StatusTooManyRequests, "登录尝试过于频繁，请 "+strconv.Itoa(int(wait.Seconds())+1)+" 秒后重试")
		return true
	}
	key := clientIP(r) + "|" + username
	if until := loginLim.lockedUntil(key); !until.IsZero() {
		secs := int(time.Until(until).Seconds()) + 1
		log.Printf("[auth] 登录已锁定 ip=%s user=%s 剩余 %ds", clientIP(r), username, secs)
		writeErr(w, http.StatusTooManyRequests, "失败次数过多，请 "+strconv.Itoa(secs)+" 秒后重试")
		return true
	}
	return false
}

func loginNoteFail(r *http.Request, username string) {
	remain := loginLim.noteFail(clientIP(r) + "|" + username)
	loginLim.noteGlobalFail()
	log.Printf("[auth] 登录失败 ip=%s user=%q", clientIP(r), username)
	if remain > 0 {
		log.Printf("[auth] 登录连续失败 %d 次，锁定 %ds", maxLoginFails, int(remain.Seconds()))
	}
}

func loginNoteSuccess(r *http.Request, username string) {
	loginLim.clear(clientIP(r) + "|" + username)
}
