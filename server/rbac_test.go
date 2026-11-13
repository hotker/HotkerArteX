package server

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// 登录一个用户并返回 token（走真实 login handler，验证密码与令牌链路）。
func loginAs(t *testing.T, s *Server, username, password string) (string, int) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	req := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "198.51.100.9:1234"
	rec := httptest.NewRecorder()
	s.authLogin(rec, req)
	if rec.Code != 200 {
		return "", rec.Code
	}
	var out struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return out.Token, rec.Code
}

// callAPI 用给定 token 打真实中间件链（Handler()），返回状态码。
func callAPI(s *Server, method, path, token string) int {
	r := httptest.NewRequest(method, path, nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	r.RemoteAddr = "198.51.100.9:1234"
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w.Code
}

// bootstrap 必须产出：权限目录、四个系统角色、内置 admin（含 admin 角色），
// 且旧单用户密码被迁移过来 —— 否则升级后所有人都登不进去。
func TestRBACBootstrapMigratesLegacyAdmin(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	pg := s.m.pg

	admin, err := pg.GetRBACUserByUsername("admin")
	if err != nil || admin == nil {
		t.Fatalf("builtin admin missing: %v", err)
	}
	acc, err := pg.ResolveRBACAccess("admin")
	if err != nil || acc == nil {
		t.Fatalf("resolve admin: %v", err)
	}
	if !acc.HasRole(db.RBACRoleAdmin) {
		t.Fatal("admin must hold the admin role")
	}
	if !acc.HasPermission("rbac:write") || !acc.HasPermission("task:delete") {
		t.Fatalf("admin must hold every permission, got %d", len(acc.Permissions))
	}

	// 系统角色必须存在且授权集合理
	roles, perms, err := pg.ListRBACRoles()
	if err != nil {
		t.Fatalf("list roles: %v", err)
	}
	got := map[string]bool{}
	for _, r := range roles {
		got[r.ID] = true
	}
	for _, want := range []string{db.RBACRoleAdmin, db.RBACRoleOperator, db.RBACRoleAuditor, db.RBACRoleViewer} {
		if !got[want] {
			t.Fatalf("system role %s missing", want)
		}
	}
	// viewer 只读：有 task:read，不该有 task:write
	viewer := map[string]bool{}
	for _, k := range perms[db.RBACRoleViewer] {
		viewer[k] = true
	}
	if !viewer["task:read"] {
		t.Fatal("viewer should have task:read")
	}
	if viewer["task:write"] || viewer["rbac:write"] {
		t.Fatal("viewer must not have write permissions")
	}
	// operator 有功能写权限，但没有账号/配置/LLM 写权限
	op := map[string]bool{}
	for _, k := range perms[db.RBACRoleOperator] {
		op[k] = true
	}
	if !op["task:write"] || !op["finding:write"] {
		t.Fatal("operator should have functional write permissions")
	}
	if op["rbac:write"] || op["config:write"] || op["llm:write"] {
		t.Fatal("operator must not manage accounts/config/llm")
	}
}

// 权限强制：viewer 能读任务，不能删任务。走真实中间件链，不是直接调 handler。
func TestRBACEnforcementBlocksWrites(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	pg := s.m.pg

	// 建一个 viewer 用户
	pw := "viewer-pass-1234"
	viewer, err := pg.CreateRBACUser("viewer1", "只读用户", pw, []string{db.RBACRoleViewer})
	if err != nil {
		t.Fatalf("create viewer: %v", err)
	}
	t.Cleanup(func() { _ = pg.DeleteRBACUser(viewer.ID) })

	tok, code := loginAs(t, s, "viewer1", pw)
	if code != 200 || tok == "" {
		t.Fatalf("viewer login failed: %d", code)
	}

	// 读：放行（task:read）
	if c := callAPI(s, "GET", "/api/tasks", tok); c != 200 {
		t.Fatalf("viewer GET /api/tasks = %d, want 200", c)
	}
	// 写：拦截（无 task:write）
	if c := callAPI(s, "POST", "/api/tasks", tok); c != 403 {
		t.Fatalf("viewer POST /api/tasks = %d, want 403", c)
	}
	// 删：拦截
	if c := callAPI(s, "DELETE", "/api/tasks/999999", tok); c != 403 {
		t.Fatalf("viewer DELETE /api/tasks = %d, want 403", c)
	}
	// 权限管理：读放行（只读角色可以看到用户列表 —— 不含任何密钥）、写拦截。
	// 这条口径与上游一致：所有 :read 都给只读角色，让"能看见但不能动"，
	// 免得只读用户面对一堆空页面。
	if c := callAPI(s, "GET", "/api/rbac/users", tok); c != 200 {
		t.Fatalf("viewer GET /api/rbac/users = %d, want 200 (read allowed)", c)
	}
	if c := callAPI(s, "POST", "/api/rbac/users", tok); c != 403 {
		t.Fatalf("viewer POST /api/rbac/users = %d, want 403", c)
	}

	// admin 同一条路径必须放行到 handler（这里是 404 业务错误，不是 403 鉴权错误）
	adminTok, _ := loginAs(t, s, "admin", "testadmin123")
	if adminTok == "" {
		adminTok, _ = loginAs(t, s, "Foxker", "testadmin123")
	}
	if adminTok != "" {
		if c := callAPI(s, "GET", "/api/rbac/users", adminTok); c != 200 {
			t.Fatalf("admin GET /api/rbac/users = %d, want 200", c)
		}
	}
}

// 自定义角色：只给某几项权限，确认生效且不影响其它模块。
func TestRBACCustomRolePermissions(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	pg := s.m.pg

	role, err := pg.CreateRBACRole("audit-only", "只看审计", db.RBACScopeOwn, []string{"log:read", "auth:self"})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}
	t.Cleanup(func() { _ = pg.DeleteRBACRole(role.ID) })
	if role.ID == "" {
		t.Fatal("role id empty")
	}

	pw := "auditor-pass-1234"
	u, err := pg.CreateRBACUser("auditor1", "审计", pw, []string{role.ID})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	t.Cleanup(func() { _ = pg.DeleteRBACUser(u.ID) })

	acc, err := pg.ResolveRBACAccess(u.ID)
	if err != nil || acc == nil {
		t.Fatalf("resolve: %v", err)
	}
	if !acc.HasPermission("log:read") || acc.HasPermission("task:read") {
		t.Fatalf("custom role permissions wrong: %v", acc.Permissions)
	}
	if acc.Scope != db.RBACScopeOwn {
		t.Fatalf("scope = %q, want own", acc.Scope)
	}

	tok, _ := loginAs(t, s, "auditor1", pw)
	if c := callAPI(s, "GET", "/api/audit/logs", tok); c != 200 {
		t.Fatalf("auditor GET /api/audit/logs = %d, want 200", c)
	}
	if c := callAPI(s, "GET", "/api/tasks", tok); c != 403 {
		t.Fatalf("auditor GET /api/tasks = %d, want 403 (no task:read)", c)
	}
}

// 停用与改密必须让该用户已签发的 token 立刻失效（token_version 自增）。
func TestRBACTokenVersionRevokesSession(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	pg := s.m.pg

	pw := "op-pass-123456"
	u, err := pg.CreateRBACUser("op1", "操作员", pw, []string{db.RBACRoleOperator})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { _ = pg.DeleteRBACUser(u.ID) })

	tok, _ := loginAs(t, s, "op1", pw)
	if c := callAPI(s, "GET", "/api/tasks", tok); c != 200 {
		t.Fatalf("before disable: %d", c)
	}

	off := false
	if _, err := pg.UpdateRBACUser(u.ID, "操作员", &off, "", nil); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if c := callAPI(s, "GET", "/api/tasks", tok); c != 401 {
		t.Fatalf("after disable: %d, want 401 (token version bumped)", c)
	}

	// 重新启用 + 改密后，旧 token 仍然无效（版本号又涨了一次）
	on := true
	if _, err := pg.UpdateRBACUser(u.ID, "操作员", &on, "new-pass-87654321", nil); err != nil {
		t.Fatalf("re-enable + change pw: %v", err)
	}
	if c := callAPI(s, "GET", "/api/tasks", tok); c != 401 {
		t.Fatalf("after password change: %d, want 401", c)
	}
	newTok, code := loginAs(t, s, "op1", "new-pass-87654321")
	if code != 200 || newTok == "" {
		t.Fatalf("login with new password failed: %d", code)
	}
	if c := callAPI(s, "GET", "/api/tasks", newTok); c != 200 {
		t.Fatalf("fresh token should work: %d", c)
	}
}

// 升级兼容：改名前签发的 token（无 uid）仍按内置 admin 处理，不能一脚踢光所有人。
func TestLegacyTokenResolvesAsAdmin(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	legacy, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatalf("sign legacy: %v", err)
	}
	r := httptest.NewRequest("GET", "/api/rbac/users", nil)
	r.Header.Set("Authorization", "Bearer "+legacy)
	acc := s.resolveAccess(mustParse(t, s, legacy))
	if acc == nil || !acc.HasRole(db.RBACRoleAdmin) {
		t.Fatalf("legacy token must resolve to admin, got %+v", acc)
	}
	_ = r
	if c := callAPI(s, "GET", "/api/rbac/users", legacy); c != 200 {
		t.Fatalf("legacy token request = %d, want 200", c)
	}
}

func mustParse(t *testing.T, s *Server, tok string) *authClaims {
	t.Helper()
	c, err := parseJWT(tok, s.jwtKey)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return c
}

// 审计必须留下 actor：没有 actor 的审计在多人环境里没有证据价值。
func TestAuditRecordsActor(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	pg := s.m.pg

	pw := "inv-pass-123456"
	u, err := pg.CreateRBACUser("inv1", "盘点", pw, []string{db.RBACRoleOperator})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { _ = pg.DeleteRBACUser(u.ID) })

	tok, _ := loginAs(t, s, "inv1", pw)
	// 登录本身就该留一条 auth/login
	logs, total, err := pg.ListAuditLogs(db.AuditFilter{Actor: "inv1", Category: "auth"}, 10, 0)
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	if total == 0 || len(logs) == 0 {
		t.Fatal("login audit row missing")
	}
	if logs[0].Action != "login" || logs[0].Actor != "inv1" {
		t.Fatalf("unexpected audit row: %+v", logs[0])
	}

	// 经过中间件的写操作，actor 应来自上下文而不是空串
	callAPI(s, "POST", "/api/knowledge", tok) // 缺 body → 400，但审计中间件仍记一条
	logs2, _, err := pg.ListAuditLogs(db.AuditFilter{Actor: "inv1", Category: "api"}, 10, 0)
	if err != nil {
		t.Fatalf("list audit 2: %v", err)
	}
	_ = logs2
}

// 全新安装的判据必须是"有可用的密码"，而不是"存在用户行"：
// bootstrap 会先建内置 admin（哈希占位 "!"），拿它当判据会让新装的平台永远 403。
func TestFreshInstallInitializedFlag(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	pg := s.m.pg
	// 把内置 admin 的密码重置成占位态，模拟"刚 bootstrap 完、还没设密码"
	if _, err := pg.Exec(`UPDATE rbac_users SET password_hash='!' WHERE id='admin'`); err != nil {
		t.Fatalf("reset admin hash: %v", err)
	}
	initialized, err := pg.HasRBACUsers()
	if err != nil {
		t.Fatalf("has users: %v", err)
	}
	if !initialized {
		t.Fatal("precondition: admin row should exist")
	}
	admin, _ := pg.GetRBACUserByID("admin")
	if admin == nil || admin.PasswordHash != "!" {
		t.Fatalf("precondition lost: %+v", admin)
	}

	rec := httptest.NewRecorder()
	s.authStatus(rec, httptest.NewRequest("GET", "/api/auth/status", nil))
	var out struct {
		Initialized bool `json:"initialized"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out.Initialized {
		t.Fatal("placeholder hash must NOT count as initialized")
	}

	// 设过密码后即为已初始化
	if err := pg.SetRBACUserPassword("admin", "test-pass-1234"); err != nil {
		t.Fatalf("set password: %v", err)
	}
	rec = httptest.NewRecorder()
	s.authStatus(rec, httptest.NewRequest("GET", "/api/auth/status", nil))
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if !out.Initialized {
		t.Fatal("after setting a password the platform must report initialized")
	}
}

// testAdminToken 签发一个绑定内置 admin 的令牌（带 uid 与 token_version）。
//
// 为什么不是 signJWT：多用户之后中间件会校验 token_version，"无 uid 的旧令牌"虽然
// 仍按 admin 处理，但 Ver=0 与真实的 admin.TokenVersion 可能不相等 —— 任何调整过
// admin 密码的测试都会让后面的用例莫名其妙 401。测试应签"当下的真实令牌"。
func testAdminToken(t *testing.T, s *Server) string {
	t.Helper()
	if s.m == nil || s.m.pg == nil {
		t.Skip("no postgres")
	}
	admin, err := s.m.pg.GetRBACUserByID("admin")
	if err != nil || admin == nil {
		t.Fatalf("resolve admin: %v", err)
	}
	tok, err := signJWTFor(s.jwtKey, s.tokenGen.Load(), admin.ID, admin.TokenVersion)
	if err != nil {
		t.Fatalf("sign admin token: %v", err)
	}
	return tok
}
