package server

import (
	"log"
	"net"
	"net/http"
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
)

type loginFailEntry struct {
	fails     int
	lastFail  time.Time
	lockedOut time.Time // 非零 = 当前处于锁定期
}

type loginLimiter struct {
	mu    sync.Mutex
	byKey map[string]*loginFailEntry
}

var loginLim = &loginLimiter{byKey: map[string]*loginFailEntry{}}

// clientIP 取请求来源 IP：优先 X-Forwarded-For 首段（反代部署），否则 RemoteAddr。
// 不校验反代可信链——本项目是单管理员工具，XFF 伪造的最坏后果只是把限流打到
// 别人头上（自 DoS），不会绕过它。
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if first := strings.TrimSpace(strings.Split(xff, ",")[0]); first != "" {
			return first
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
	if e.fails >= maxLoginFails && e.lockedOut.Before(now) {
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

// loginThrottled 在登录处理器最前面调用：命中锁定期则直接 429 并返回 true。
func loginThrottled(w http.ResponseWriter, r *http.Request, username string) bool {
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
	log.Printf("[auth] 登录失败 ip=%s user=%q", clientIP(r), username)
	if remain > 0 {
		log.Printf("[auth] 登录连续失败 %d 次，锁定 %ds", maxLoginFails, int(remain.Seconds()))
	}
}

func loginNoteSuccess(r *http.Request, username string) {
	loginLim.clear(clientIP(r) + "|" + username)
}
