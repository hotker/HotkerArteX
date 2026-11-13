package server

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Autumn-27/artex/db"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const (
	jwtKeyFilename = "jwt.key"
	authPassKey    = "auth.password_hash"
	// authTokenGenKey persists the token generation. Bumping it (on password
	// change) revokes every token signed under the previous generation.
	authTokenGenKey = "auth.token_gen"
	jwtTTL          = 7 * 24 * time.Hour
	keyChars        = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	// 下限与 setup 页的前端校验一致——校验只放在前端等于没放，直接打 API 就能
	// 绕过。上限是 bcrypt 的硬限制：超过 72 字节 GenerateFromPassword 会返回
	// ErrPasswordTooLong，提前挡掉好过让用户收到一句含义不明的「密码加密失败」。
	minPasswordRunes = 8
	maxPasswordBytes = 72
)

// errDataSourceUnavailable 是密码相关读操作失败时统一的回复。这些 handler 绝不能
// 把"读不到"当成"没有设置"：authInit 曾因此在数据库报错时放行，让未认证请求覆盖
// 掉已有的管理员密码。
const errDataSourceUnavailable = "数据源暂时不可用，请稍后重试"

// validatePassword 返回空串表示通过，否则返回可直接展示给用户的中文原因。
func validatePassword(pw string) string {
	if utf8.RuneCountInString(pw) < minPasswordRunes {
		return fmt.Sprintf("密码长度至少 %d 位", minPasswordRunes)
	}
	if len(pw) > maxPasswordBytes {
		return fmt.Sprintf("密码长度不能超过 %d 字节", maxPasswordBytes)
	}
	return ""
}

// loadOrCreateJWTKey reads the 32-byte signing key from keyDir/jwt.key. keyDir is
// the project base dir (next to the executable), NOT the browsable workspace root
// (dataDir) — the signing key must never be listable/downloadable via the file
// manager. Legacy installs kept it at dataDir/jwt.key; if present there and not yet
// at the new location, it is migrated (key preserved, so sessions stay valid) and
// the old file removed so it disappears from the workspace. On first run a random
// key is generated and persisted.
func loadOrCreateJWTKey(keyDir, dataDir string) ([]byte, error) {
	path := filepath.Join(keyDir, jwtKeyFilename)
	// one-time migration out of the old in-workspace location.
	if legacy := filepath.Join(dataDir, jwtKeyFilename); legacy != path {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			if data, rerr := os.ReadFile(legacy); rerr == nil {
				if werr := os.WriteFile(path, data, 0o600); werr == nil {
					_ = os.Remove(legacy)
					log.Printf("[auth] JWT key 已从 %s 迁移到 %s（移出可浏览工作区）", legacy, path)
				}
			}
		}
	}
	if data, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(data))) >= 32 {
		return []byte(strings.TrimSpace(string(data))), nil
	}
	buf := make([]byte, 32)
	for i := range buf {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(keyChars))))
		if err != nil {
			return nil, fmt.Errorf("generate jwt key: %w", err)
		}
		buf[i] = keyChars[n.Int64()]
	}
	if err := os.WriteFile(path, buf, 0600); err != nil {
		return nil, fmt.Errorf("write jwt key: %w", err)
	}
	log.Printf("[auth] 新 JWT key 已写入 %s", path)
	return buf, nil
}

// signJWT issues a generation-0 7-day HS256 token for user Foxker (no generation
// claim). Kept as the one-arg form for tests and as the fresh-install path; the
// server signs new tokens with the current generation via signJWTGen.
func signJWT(key []byte) (string, error) { return signJWTGen(key, 0) }

// authClaims is the JWT payload.
//
//   - Gen：全局令牌世代（见 auth.token_gen）。gen==0 省略，让全新安装的 token 与
//     引入世代之前的旧 token 完全同形。
//   - Uid：用户 id（rbac_users.id）。多用户后"令牌属于谁"必须写进签名，否则
//     sub 里一个共享用户名无法区分人。
//   - Ver：该用户自己的 token_version。改密/停用/管理员强制下线时自增，
//     携带旧版本号的 token 立即失效 —— 这是"只踢某个人"的能力。
type authClaims struct {
	jwt.RegisteredClaims
	Gen string `json:"gen,omitempty"`
	Uid string `json:"uid,omitempty"`
	Ver int    `json:"ver,omitempty"`
}

// signJWTGen issues a 7-day HS256 token stamped with gen (the current token
// generation, see auth.token_gen). gen==0 — a fresh install that has never
// rotated — is omitted, so such tokens look exactly like the legacy
// (pre-generation) ones and nothing downstream needs to change.
// loginUsernames 是登录页接受的用户名（大小写不敏感）。
//
// 改名为 Foxker 后仍保留 ARTEX 作为别名：现网可能有脚本 / 书签 / 反代配置里写死了旧
// 用户名，一次改名就让它们全部登录失败，代价远大于多一个字符串。展示与 JWT sub 一律
// 用新名（见 signJWTGen），别名只影响"能不能登进来"。
var loginUsernames = []string{"foxker", "artex"}

func validLoginUsername(u string) bool {
	u = strings.TrimSpace(strings.ToLower(u))
	if u == "" {
		return false
	}
	for _, want := range loginUsernames {
		if u == want {
			return true
		}
	}
	return false
}

func signJWTGen(key []byte, gen int64) (string, error) {
	return signJWTFor(key, gen, "", 0)
}

// signJWTFor 签发一个绑定了具体用户与版本号的 token。
func signJWTFor(key []byte, gen int64, uid string, ver int) (string, error) {
	subject := "Foxker"
	if uid != "" {
		subject = uid
	}
	claims := authClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   subject,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(jwtTTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		Uid: uid,
		Ver: ver,
	}
	if gen > 0 {
		claims.Gen = strconv.FormatInt(gen, 10)
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(key)
}

// parseJWT 校验签名与过期，返回 claims（无效时 error）。
func parseJWT(tokenStr string, key []byte) (*authClaims, error) {
	var claims authClaims
	_, err := jwt.ParseWithClaims(tokenStr, &claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return key, nil
	})
	if err != nil {
		return nil, err
	}
	return &claims, nil
}

// tokenGenOf 从 claims 里取全局世代（缺失 = 0）。
func tokenGenOf(c *authClaims) int64 {
	if c == nil || c.Gen == "" {
		return 0
	}
	n, _ := strconv.ParseInt(c.Gen, 10, 64)
	return n
}

// verifyJWT returns true when tokenStr is a valid, non-expired HS256 token whose
// embedded generation matches currentGen. A token with no generation claim (every
// pre-generation token, and all tokens from a fresh install) is treated as
// generation 0 — valid until the first password change bumps the generation,
// after which it (and everything else signed before) is revoked.
func verifyJWT(tokenStr string, key []byte, currentGen int64) bool {
	t, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return key, nil
	})
	if err != nil || !t.Valid {
		return false
	}
	claims, ok := t.Claims.(jwt.MapClaims)
	if !ok {
		return false
	}
	var tokenGen int64 // 0 when the claim is absent (legacy / fresh-install token)
	switch v := claims["gen"].(type) {
	case string:
		tokenGen, _ = strconv.ParseInt(v, 10, 64)
	case float64: // some decoders yield numbers
		tokenGen = int64(v)
	case int64:
		tokenGen = v
	case int:
		tokenGen = int64(v)
	}
	return tokenGen == currentGen
}

// tokenQueryPaths are the only routes that accept a token in the query string.
// EventSource cannot set an Authorization header, so the SSE endpoints need it;
// everywhere else a token in the URL leaks into proxy logs, browser history and
// Referer headers, and stays valid for the full 7-day TTL.
var tokenQueryPaths = []string{
	"/api/logs/stream",
	"/api/update/stream",
	"/api/exploration/activity/stream",
}

// 报告文件下载同样只能在链接里带凭据：<a download> 触发的是浏览器导航，没有地方
// 放 Authorization 头。这里按【前缀】而非精确路径匹配 /api/reports/{id}/download，
// 并且只认这一种形状 —— 不能让 ?token= 悄悄扩散到其它 /api/reports/* 路由。
func tokenQueryAllowedPath(p string) bool {
	if tokenQueryAllowed(p) {
		return true
	}
	return strings.HasPrefix(p, "/api/reports/") && strings.HasSuffix(p, "/download")
}

func tokenQueryAllowed(p string) bool {
	for _, prefix := range tokenQueryPaths {
		if p == prefix {
			return true
		}
	}
	// Side-question event streams: /api/side-questions/{id}/events
	if strings.HasPrefix(p, "/api/side-questions/") && strings.HasSuffix(p, "/events") {
		return true
	}
	return false
}

// extractToken reads the JWT from Authorization: Bearer header, artex_token
// cookie, or — only on the streaming endpoints — ?token=.
func extractToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	if c, err := r.Cookie("artex_token"); err == nil && c.Value != "" {
		return c.Value
	}
	if tokenQueryAllowedPath(r.URL.Path) {
		return r.URL.Query().Get("token")
	}
	return ""
}

// requireAuth wraps h with JWT validation + RBAC resolution + enforcement.
// /api/auth/* and /api/health are exempt from *authentication*.
//
// 解析画像（rbac_users / 角色 / 权限）就放在这里而不是各 handler 里：
// 一是每个请求本来就要过这一层，二是"忘了加权限检查"这类漏洞只能靠统一入口堵住。
// 画像不缓存：权限一改立刻生效，缓存的失效逻辑比一次索引查询更容易出错。
func (s *Server) requireAuth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if strings.HasPrefix(p, "/api/auth/") || p == "/api/health" {
			h.ServeHTTP(w, r)
			return
		}
		tok := extractToken(r)
		if tok == "" {
			writeErr(w, 401, "未授权")
			return
		}
		claims, err := parseJWT(tok, s.jwtKey)
		if err != nil {
			writeErr(w, 401, "token 无效或已过期")
			return
		}
		if tokenGenOf(claims) != s.tokenGen.Load() {
			writeErr(w, 401, "token 无效或已过期")
			return
		}
		if acc := s.resolveAccess(claims); acc != nil {
			if acc.User.TokenVersion != claims.Ver {
				writeErr(w, 401, "登录状态已失效，请重新登录")
				return
			}
			r = withAccess(r, acc)
			if !s.enforceRBAC(w, r, acc) {
				return
			}
		}
		h.ServeHTTP(w, r)
	})
}

// resolveAccess 从 claims 解析授权画像。
//
// 兼容两类 token：
//   - 带 uid 的（多用户之后签发）：按 id 取用户；
//   - 无 uid 的（升级前签发、尚未过期）：按内置 admin 处理 —— 那时候平台只有
//     一个管理员，把它当作 admin 既符合历史语义，也不会在升级瞬间把所有在线会话踢掉。
//
// 解析失败（PG 暂时不可用）返回 nil：鉴权已通过，交给 handler 自己报数据源错误，
// 不要在这里把用户判成"无权限"，那会变成一次假的 403。
func (s *Server) resolveAccess(claims *authClaims) *db.RBACAccess {
	if s.m == nil || s.m.pg == nil || claims == nil {
		return nil
	}
	uid := claims.Uid
	if uid == "" {
		uid = "admin" // 升级前的单用户 token
	}
	acc, err := s.m.pg.ResolveRBACAccess(uid)
	if err != nil {
		log.Printf("[rbac] 解析授权画像失败 uid=%s: %v", uid, err)
		return nil
	}
	return acc
}

// GET /api/auth/status — reports whether the admin password has been initialised.
// 读失败必须回 503 而不是 initialized:false：前端在 initialized:false 时会把用户
// 送到 /setup 去设置密码（login/page.tsx），把数据库故障包装成 200 等于把用户往
// 覆盖已有密码的路上推。
func (s *Server) authStatus(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	// 初始化与否以 rbac_users 为准（多用户后它是唯一真值）。旧单用户版本的
	// auth.password_hash 只作为迁移来源，不再决定"是否已初始化"。
	admin, err := pg.GetRBACUserByID("admin")
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	initialized := admin != nil && admin.PasswordHash != "" && admin.PasswordHash != "!"
	writeJSON(w, 200, map[string]any{"initialized": initialized})
}

// POST /api/auth/init — sets the password for the first time; rejected if already set.
func (s *Server) authInit(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	// Rate limited before anything else: bcrypt runs before the "already set"
	// check can reject, so an unauthenticated peer could otherwise burn CPU here
	// for free, and a fresh install is exactly when nobody is watching the port.
	if initThrottled(w, r) {
		return
	}
	// "已初始化"的判据是【有一个能用的密码】，不是"存在用户行"：
	// bootstrap 会先建内置 admin（哈希为占位 "!"），只存在用户行但不能登录，
	// 若拿它当判据，全新安装会永远卡在"密码已设置"而进不去。
	admin, err := pg.GetRBACUserByID("admin")
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if admin != nil && admin.PasswordHash != "" && admin.PasswordHash != "!" {
		writeErr(w, 403, "密码已设置")
		return
	}
	initNoteAttempt(r)
	var req struct {
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil || req.Password == "" {
		writeErr(w, 400, "密码不能为空")
		return
	}
	if msg := validatePassword(req.Password); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, "密码加密失败")
		return
	}
	// bootstrap 已经把内置 admin 建好（密码哈希是占位 "!"，任何密码都验不过）。
	// 这里写入真正的哈希。并发下用条件更新避免覆盖掉另一个请求刚设的密码：
	// 只有当前哈希仍是占位值时才写。
	res, err := pg.Exec(`UPDATE rbac_users SET password_hash=$1, token_version = token_version + 1, updated_at=now()
		WHERE id='admin' AND COALESCE(password_hash,'') IN ('','!')`, string(hash))
	if err != nil {
		writeErr(w, 500, "保存失败: "+err.Error())
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		writeErr(w, 403, "密码已设置")
		return
	}
	initDone(r)
	adminUser, err := pg.GetRBACUserByID("admin")
	if err != nil || adminUser == nil {
		writeErr(w, 500, "读取管理员失败")
		return
	}
	tok, err := signJWTFor(s.jwtKey, s.tokenGen.Load(), adminUser.ID, adminUser.TokenVersion)
	if err != nil {
		writeErr(w, 500, "token 生成失败")
		return
	}
	writeJSON(w, 200, map[string]any{"token": tok})
}

// resolveLoginUser 把登录框里的用户名解析成一个平台用户。
//
// 优先级：先按 rbac_users 精确/忽略大小写匹配；再退回历史用户名（Foxker / ARTEX），
// 它们指向内置 admin —— 改名与多用户化都不该让现网的脚本与书签失效。
func (s *Server) resolveLoginUser(pg *db.DB, username string) (*db.RBACUser, error) {
	name := strings.TrimSpace(username)
	if name == "" {
		return nil, nil
	}
	u, err := pg.GetRBACUserByUsername(name)
	if err != nil || u != nil {
		return u, err
	}
	if validLoginUsername(name) {
		return pg.GetRBACUserByID("admin")
	}
	return nil, nil
}

// userDTO 是回给前端的用户视图（不含哈希）。
func userDTO(u *db.RBACUser) map[string]any {
	if u == nil {
		return nil
	}
	return map[string]any{
		"id": u.ID, "username": u.Username, "display_name": u.DisplayName,
		"enabled": u.Enabled, "is_builtin": u.IsBuiltin,
	}
}

// POST /api/auth/change-password — changes the admin password. Requires a valid
// token (this route is under /api/auth/* which requireAuth exempts, so the token
// is validated here) AND the current password. Changing the password also bumps
// the token generation, which revokes every token signed under the previous
// generation (other tabs / devices holding a stale token are logged out); the
// response carries a fresh token for the caller's own session so it stays logged in.
func (s *Server) authChangePassword(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	acc := CurrentAccess(r)
	if acc == nil {
		writeErr(w, 401, "未授权")
		return
	}
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	if req.NewPassword == "" {
		writeErr(w, 400, "新密码不能为空")
		return
	}
	if msg := validatePassword(req.NewPassword); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	if strings.TrimSpace(acc.User.PasswordHash) == "" || acc.User.PasswordHash == "!" {
		writeErr(w, 403, "密码未初始化，请先设置密码")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(acc.User.PasswordHash), []byte(req.OldPassword)); err != nil {
		writeErr(w, 401, "当前密码错误")
		return
	}
	// 改自己的密码 → 自增自己的 token_version（其它设备上的旧 token 立即失效），
	// 同时保留全局世代自增（兼容升级前签发的无 uid token，让它们也一起失效）。
	if err := pg.SetRBACUserPassword(acc.User.ID, req.NewPassword); err != nil {
		writeErr(w, 500, "保存失败: "+err.Error())
		return
	}
	// Bump the token generation so every token signed under the previous
	// generation is revoked (other tabs / devices are logged out). Persist FIRST
	// so a restart keeps the bump; on a persist failure roll the in-memory value
	// back so memory and the database agree (stale tokens stay valid, but the
	// password change still held — the rarer of the two bad outcomes).
	newGen := s.tokenGen.Add(1)
	if err := pg.SetSetting(authTokenGenKey, strconv.FormatInt(newGen, 10)); err != nil {
		s.tokenGen.Add(-1)
		log.Printf("[auth] 令牌世代持久化失败，旧 token 暂不失效: %v", err)
		writeJSON(w, 200, map[string]any{"ok": true})
		return
	}
	// Hand the caller a token stamped with the new generation so its own session
	// stays logged in without re-login.
	fresh, err := pg.GetRBACUserByID(acc.User.ID)
	if err != nil || fresh == nil {
		writeErr(w, 500, "读取用户失败")
		return
	}
	tok, err := signJWTFor(s.jwtKey, newGen, fresh.ID, fresh.TokenVersion)
	if err != nil {
		writeErr(w, 500, "token 生成失败")
		return
	}
	s.auditFrom(r, acc.User.Username, "auth", "change_password", "success", "修改了自己的密码", nil)
	writeJSON(w, 200, map[string]any{"ok": true, "token": tok})
}

// POST /api/auth/login — validates username/password and returns a JWT.
func (s *Server) authLogin(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	if loginThrottled(w, r, req.Username) {
		return
	}
	// 用户名解析：多用户后按 rbac_users 查；旧用户名（Foxker / ARTEX）继续指向内置 admin，
	// 避免升级后现网脚本与书签全部登不进来。
	user, err := s.resolveLoginUser(pg, req.Username)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if user == nil {
		loginNoteFail(r, req.Username)
		writeErr(w, 401, "用户名或密码错误")
		return
	}
	if !user.Enabled {
		loginNoteFail(r, req.Username)
		writeErr(w, 403, "账号已停用")
		return
	}
	if strings.TrimSpace(user.PasswordHash) == "" || user.PasswordHash == "!" {
		writeErr(w, 403, "密码未初始化，请先设置密码")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		loginNoteFail(r, req.Username)
		writeErr(w, 401, "用户名或密码错误")
		return
	}
	loginNoteSuccess(r, req.Username)
	tok, err := signJWTFor(s.jwtKey, s.tokenGen.Load(), user.ID, user.TokenVersion)
	if err != nil {
		writeErr(w, 500, "token 生成失败")
		return
	}
	s.auditFrom(r, user.Username, "auth", "login", "success", "登录成功", nil)
	writeJSON(w, 200, map[string]any{"token": tok, "user": userDTO(user)})
}
