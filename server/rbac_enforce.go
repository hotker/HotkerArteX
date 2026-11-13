package server

import (
	"context"
	"log"
	"net/http"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// RBAC 请求级强制：路由 → 所需权限。
//
// 三条安全阀，缺一不可：
//  1. **未映射的路由放行**（返回 ""）。宁可能漏一处拦截，也不能因为漏映射把整个平台打成 403
//     —— 后者是"功能全挂"，前者是"少防一处"，排障成本差一个量级。所以本文件的路由表要
//     与 server.go 的 mux 保持同步，测试里会比对两者（见 rbac_routes_test.go）。
//  2. **admin 永不被拦**（HasPermission 对 admin 恒真）。没有这条，一次映射错误就能把
//     管理员锁在门外，而管理员恰恰是唯一能修它的人。
//  3. **开关 rbac.enforce 默认 true**，可关（老部署升级后想先观察一段时间时用）。

// accessCtxKey 是 RBACAccess 在请求上下文里的键。
type accessCtxKey struct{}

// CurrentAccess 取当前请求的授权画像；未鉴权 / 未解析时为 nil。
func CurrentAccess(r *http.Request) *db.RBACAccess {
	if r == nil {
		return nil
	}
	if v, ok := r.Context().Value(accessCtxKey{}).(*db.RBACAccess); ok {
		return v
	}
	return nil
}

func withAccess(r *http.Request, acc *db.RBACAccess) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), accessCtxKey{}, acc))
}

// isAdmin 报告当前请求是否由内置 admin 角色发起。用于额外收紧「能在宿主机执行命令」
// 这类高危操作（stdio MCP、command/script 自定义工具）——它们等价于主机命令执行，
// 不该随 tool:write / mcp:write 下放。
func isAdmin(r *http.Request) bool {
	return CurrentAccess(r).HasRole(db.RBACRoleAdmin)
}

// crudPerm 按 HTTP 方法给出 module 的 read/write/delete 权限键。
func crudPerm(method, module string) string {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return module + ":read"
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		return module + ":write"
	case http.MethodDelete:
		if _, ok := db.RBACPermissions[module+":delete"]; ok {
			return module + ":delete"
		}
		return module + ":write"
	}
	return module + ":read"
}

// permissionForRequest 返回该请求所需权限；"" 表示未映射（放行）。
//
// 匹配按「路径前缀」而不是逐条路由枚举：路由有 270 条，逐条维护必然漏；
// 前缀映射只要顶层段稳定就能覆盖，且新增同模块路由自动继承。
func permissionForRequest(method, fullPath string) string {
	p := strings.TrimPrefix(fullPath, "/api")
	switch {
	case p == "/rbac/me":
		return "auth:self"
	case strings.HasPrefix(p, "/rbac"), strings.HasPrefix(p, "/audit"):
		if p == "/rbac/me" {
			return "auth:self"
		}
		if strings.HasPrefix(p, "/audit") {
			return "log:read"
		}
		return crudPerm(method, "rbac")
	case strings.HasPrefix(p, "/logs"):
		return "log:read"
	case p == "/stats", strings.HasPrefix(p, "/tokens"):
		return "dashboard:read"
	case strings.HasPrefix(p, "/tasks"), p == "/active", strings.HasPrefix(p, "/exploration"),
		strings.HasPrefix(p, "/chat"), strings.HasPrefix(p, "/conversations"),
		strings.HasPrefix(p, "/side-questions"), strings.HasPrefix(p, "/task-archives"),
		strings.HasPrefix(p, "/task-templates"), strings.HasPrefix(p, "/task-categories"):
		return crudPerm(method, "task")
	case strings.HasPrefix(p, "/findings"):
		return crudPerm(method, "finding")
	case strings.HasPrefix(p, "/traffic"):
		return "traffic:read"
	case strings.HasPrefix(p, "/assets"), strings.HasPrefix(p, "/companies"),
		strings.HasPrefix(p, "/sync"), strings.HasPrefix(p, "/asset-intercept"):
		return crudPerm(method, "asset")
	case strings.HasPrefix(p, "/llm"):
		return crudPerm(method, "llm")
	case strings.HasPrefix(p, "/agents"), strings.HasPrefix(p, "/triggers"), strings.HasPrefix(p, "/visibility"):
		return crudPerm(method, "agent")
	case strings.HasPrefix(p, "/mcp"):
		return crudPerm(method, "mcp")
	case strings.HasPrefix(p, "/skills"):
		return crudPerm(method, "skill")
	case strings.HasPrefix(p, "/tools"), strings.HasPrefix(p, "/commands"):
		return crudPerm(method, "tool")
	case strings.HasPrefix(p, "/intercept"):
		return crudPerm(method, "intercept")
	case strings.HasPrefix(p, "/knowledge"):
		// 检索 / 分类 / 审计是读动作，即使走 POST。
		if p == "/knowledge/search" || p == "/knowledge/categories" || p == "/knowledge/logs" {
			return "knowledge:read"
		}
		return crudPerm(method, "knowledge")
	case strings.HasPrefix(p, "/report"), strings.HasPrefix(p, "/reports"):
		return crudPerm(method, "report")
	case strings.HasPrefix(p, "/settings"), strings.HasPrefix(p, "/update"),
		strings.HasPrefix(p, "/notify"), strings.HasPrefix(p, "/gc"):
		return crudPerm(method, "config")
	case strings.HasPrefix(p, "/workspace"):
		// 工作空间是人机共享的文件区：读要 task:read，写要 task:write。
		return crudPerm(method, "task")
	default:
		return "" // 未映射 → 放行（见文件头安全阀 1）
	}
}

// enforceRBAC 在 requireAuth 解析出画像后判定一次。
func (s *Server) enforceRBAC(w http.ResponseWriter, r *http.Request, acc *db.RBACAccess) bool {
	if acc == nil {
		return true // 无画像（PG 不可用等）：交给后续 handler 自己处理
	}
	if !acc.User.Enabled {
		writeErr(w, 403, "账号已停用")
		return false
	}
	if s.m == nil || s.m.pg == nil {
		return true
	}
	if !s.m.pg.GetBool(settingRBACEnforce, true) {
		return true
	}
	if perm := permissionForRequest(r.Method, r.URL.Path); perm != "" && !acc.HasPermission(perm) {
		writeErr(w, 403, "权限不足："+perm)
		return false
	}
	return true
}

// settingRBACEnforce 控制是否强制校验（默认开）。
const settingRBACEnforce = "rbac.enforce"

// bootstrapRBAC 播种权限目录 / 系统角色 / 内置 admin，并把旧单用户密码迁移过来。
// 幂等：每次启动都跑（这样升级新增的权限能自动落到系统角色上）。
func (s *Server) bootstrapRBAC() {
	if s.m == nil || s.m.pg == nil {
		return
	}
	legacyHash, _, _ := s.m.pg.GetSetting(authPassKey)
	if err := s.m.pg.BootstrapRBAC(legacyHash); err != nil {
		log.Printf("[rbac] bootstrap 失败（平台将以单用户兜底继续运行）: %v", err)
		return
	}
	if strings.TrimSpace(legacyHash) != "" {
		log.Printf("[rbac] 多用户权限已就绪（旧单用户密码已迁移为内置 admin）")
	} else {
		log.Printf("[rbac] 多用户权限已就绪（权限 %d 项 / 系统角色 4 个）", len(db.RBACPermissions))
	}
}
