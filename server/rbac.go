package server

import (
	"net/http"
	"sort"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// 平台权限管理 API（/api/rbac/*）。
//
// 授权本身由 rbac_enforce.go 统一拦截；本文件只负责"把用户与角色管起来"。
// 两条不可绕过的约束：
//   - 内置 admin 不可删除、不可停用、始终保留 admin 角色（否则平台会失去唯一管理入口）；
//   - 系统角色不可改（它们的授权由 bootstrap 重建，改了下次启动也会被覆盖 —— 不如直接拒绝）。

// GET /api/rbac/me —— 当前登录用户的身份、角色与权限。
func (s *Server) rbacMe(w http.ResponseWriter, r *http.Request) {
	acc := CurrentAccess(r)
	if acc == nil {
		writeErr(w, 401, "会话无效")
		return
	}
	perms := make([]string, 0, len(acc.Permissions))
	for k, v := range acc.Permissions {
		if v {
			perms = append(perms, k)
		}
	}
	sort.Strings(perms)
	writeJSON(w, 200, map[string]any{
		"user":        userDTO(&acc.User),
		"roles":       acc.Roles,
		"permissions": perms,
		"scope":       acc.Scope,
		"is_admin":    acc.HasRole(db.RBACRoleAdmin),
	})
}

// GET /api/rbac/metadata —— 权限目录 + 分组（前端渲染权限矩阵用）。
func (s *Server) rbacMetadata(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"permissions": db.PermissionCatalog(),
		"scopes": []map[string]string{
			{"value": db.RBACScopeAll, "label": "全部资源"},
			{"value": db.RBACScopeAssigned, "label": "被授权的任务"},
			{"value": db.RBACScopeOwn, "label": "自己创建的"},
		},
		"system_roles": []string{db.RBACRoleAdmin, db.RBACRoleOperator, db.RBACRoleAuditor, db.RBACRoleViewer},
	})
}

// GET /api/rbac/users
func (s *Server) rbacListUsers(w http.ResponseWriter, r *http.Request) {
	users, roleSets, err := s.m.pg.ListRBACUsers()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	out := make([]map[string]any, 0, len(users))
	for i, u := range users {
		ids := make([]string, 0, len(roleSets[i]))
		for rid := range roleSets[i] {
			ids = append(ids, rid)
		}
		sort.Strings(ids)
		d := userDTO(u)
		d["roles"] = ids
		out = append(out, d)
	}
	writeJSON(w, 200, map[string]any{"users": out})
}

type rbacUserReq struct {
	Username    string   `json:"username"`
	DisplayName string   `json:"display_name"`
	Password    string   `json:"password"`
	Enabled     *bool    `json:"enabled"`
	RoleIDs     []string `json:"role_ids"`
}

// POST /api/rbac/users
func (s *Server) rbacCreateUser(w http.ResponseWriter, r *http.Request) {
	var req rbacUserReq
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	if strings.TrimSpace(req.Username) == "" {
		writeErr(w, 400, "用户名不能为空")
		return
	}
	if msg := validatePassword(req.Password); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	if len(req.RoleIDs) == 0 {
		writeErr(w, 400, "至少选择一个角色")
		return
	}
	u, err := s.m.pg.CreateRBACUser(req.Username, req.DisplayName, req.Password, req.RoleIDs)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.auditFrom(r, "", "rbac", "create_user", "success", "创建用户 "+u.Username,
		map[string]any{"user_id": u.ID, "roles": req.RoleIDs})
	dto := userDTO(u)
	if roles, err := s.m.pg.UserRoleIDs(u.ID); err == nil {
		dto["roles"] = roles
	}
	writeJSON(w, 200, dto)
}

// PUT /api/rbac/users/{id} —— 改昵称 / 启停 / 密码 / 角色。密码留空表示不改。
func (s *Server) rbacUpdateUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if strings.TrimSpace(id) == "" {
		writeErr(w, 400, "缺少用户 id")
		return
	}
	var req rbacUserReq
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	if req.Password != "" {
		if msg := validatePassword(req.Password); msg != "" {
			writeErr(w, 400, msg)
			return
		}
	}
	// 内置 admin 不能被停用 —— 否则没人能再登录修它。
	if id == "admin" && req.Enabled != nil && !*req.Enabled {
		writeErr(w, 400, "内置管理员不可停用")
		return
	}
	// 不能让 admin 丢掉 admin 角色：UpdateRBACUser 内部已经兜底补回，这里只提示。
	u, err := s.m.pg.UpdateRBACUser(id, req.DisplayName, req.Enabled, req.Password, req.RoleIDs)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if u == nil {
		writeErr(w, 404, "用户不存在")
		return
	}
	s.auditFrom(r, "", "rbac", "update_user", "success", "更新用户 "+u.Username, map[string]any{"user_id": u.ID})
	dto := userDTO(u)
	if roles, err := s.m.pg.UserRoleIDs(u.ID); err == nil {
		dto["roles"] = roles
	}
	writeJSON(w, 200, dto)
}

// DELETE /api/rbac/users/{id}
func (s *Server) rbacDeleteUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.m.pg.DeleteRBACUser(id); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	s.auditFrom(r, "", "rbac", "delete_user", "success", "删除用户 "+id, map[string]any{"user_id": id})
	writeJSON(w, 200, map[string]any{"ok": true})
}

// GET /api/rbac/roles
func (s *Server) rbacListRoles(w http.ResponseWriter, r *http.Request) {
	roles, perms, err := s.m.pg.ListRBACRoles()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	out := make([]map[string]any, 0, len(roles))
	for _, role := range roles {
		out = append(out, map[string]any{
			"id": role.ID, "name": role.Name, "description": role.Description,
			"scope": role.Scope, "is_system": role.IsSystem,
			"permissions": perms[role.ID],
		})
	}
	writeJSON(w, 200, map[string]any{"roles": out})
}

type rbacRoleReq struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Scope       string   `json:"scope"`
	Permissions []string `json:"permissions"`
}

// POST /api/rbac/roles
func (s *Server) rbacCreateRole(w http.ResponseWriter, r *http.Request) {
	var req rbacRoleReq
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	role, err := s.m.pg.CreateRBACRole(req.Name, req.Description, req.Scope, req.Permissions)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	s.auditFrom(r, "", "rbac", "create_role", "success", "创建角色 "+role.Name, map[string]any{"role_id": role.ID})
	writeJSON(w, 200, role)
}

// PUT /api/rbac/roles/{id}
func (s *Server) rbacUpdateRole(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req rbacRoleReq
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	role, err := s.m.pg.UpdateRBACRole(id, req.Name, req.Description, req.Scope, req.Permissions)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	s.auditFrom(r, "", "rbac", "update_role", "success", "更新角色 "+role.Name,
		map[string]any{"role_id": role.ID, "permissions": req.Permissions})
	writeJSON(w, 200, role)
}

// DELETE /api/rbac/roles/{id}
func (s *Server) rbacDeleteRole(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.m.pg.DeleteRBACRole(id); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	s.auditFrom(r, "", "rbac", "delete_role", "success", "删除角色 "+id, map[string]any{"role_id": id})
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---- 审计 ----

// GET /api/audit/logs?actor=&category=&result=&q=&limit=&offset=
func (s *Server) auditLogs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := db.AuditFilter{
		Actor:    q.Get("actor"),
		Category: q.Get("category"),
		Result:   q.Get("result"),
		Query:    q.Get("q"),
	}
	limit := atoiDefault(q.Get("limit"), 100)
	offset := atoiDefault(q.Get("offset"), 0)
	logs, total, err := s.m.pg.ListAuditLogs(f, limit, offset)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	cats, _ := s.m.pg.AuditCategories()
	writeJSON(w, 200, map[string]any{"logs": logs, "total": total, "categories": cats})
}
