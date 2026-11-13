package db

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// 多用户权限（RBAC）的数据层：用户 / 角色 / 权限目录 / 授权。
//
// 设计只有一条硬约束：**权限是扁平目录 + 角色带资源 scope**。不做树形继承——
// 继承会让"这个人为啥能删任务"要靠推导，而合规要求是一眼看懂。
//
// 系统角色（admin/operator/auditor/viewer）的授权集由 BootstrapRBAC 确定性重建，
// 页面改不动；自定义角色随便勾。这样升级时新增权限能自动落到系统角色上
// （否则老库升级后 admin 会突然缺权限），用户的定制又不会被覆盖。

const (
	RBACRoleAdmin    = "admin"
	RBACRoleOperator = "operator"
	RBACRoleAuditor  = "auditor"
	RBACRoleViewer   = "viewer"

	RBACScopeAll      = "all"      // 全部资源
	RBACScopeAssigned = "assigned" // 被显式授权给自己的任务
	RBACScopeOwn      = "own"      // 自己创建的任务
)

// RBACPermissions 是权限目录（module:action → 中文说明）。
//
// 命名规则：读用 :read、写用 :write、删用 :delete。前端按模块分组渲染矩阵。
// 新增模块时在这里加一项即可，BootstrapRBAC 会自动把它发给 admin。
var RBACPermissions = map[string]string{
	"auth:self":       "管理自己的会话和密码",
	"dashboard:read":  "查看仪表盘总览",
	"task:read":       "查看任务 / 探索链路 / 会话",
	"task:write":      "创建与控制任务、发送对话引导、修改范围与约束",
	"task:delete":     "删除与归档任务",
	"finding:read":    "查看漏洞发现",
	"finding:write":   "创建 / 更新 / 复测漏洞发现",
	"finding:delete":  "删除漏洞发现",
	"traffic:read":    "查看与导出录制流量",
	"asset:read":      "查看资产 / 公司",
	"asset:write":     "创建 / 导入 / 同步资产",
	"asset:delete":    "删除资产",
	"llm:read":        "查看 LLM 配置与用量",
	"llm:write":       "管理 LLM 配置、轮询与角色绑定",
	"agent:read":      "查看 Agent 配置与提示词",
	"agent:write":     "管理 Agent / 提示词 / 触发器 / 可见性",
	"mcp:read":        "查看 MCP 服务",
	"mcp:write":       "管理 MCP 服务",
	"skill:read":      "查看技能",
	"skill:write":     "创建 / 更新技能",
	"skill:delete":    "删除技能",
	"tool:read":       "查看工具",
	"tool:write":      "管理工具 / 自定义工具",
	"intercept:read":  "查看拦截规则 / 审批记录",
	"intercept:write": "管理拦截规则 / 处理审批",
	"log:read":        "查看后端日志 / 审计日志",
	"config:read":     "查看系统配置",
	"config:write":    "修改系统配置 / 一键更新",
	"knowledge:read":  "查看知识库 / 检索",
	"knowledge:write": "管理知识库文档、embedder 配置与重建索引",
	"report:read":     "查看报告设置 / 下载报告",
	"report:write":    "生成报告 / 管理报告设置与模版",
	"report:delete":   "删除报告",
	"rbac:read":       "查看用户与角色",
	"rbac:write":      "管理用户 / 角色 / 授权",
}

// PermissionGroups 给前端渲染权限矩阵用的分组（按模块前缀）。
var permissionGroups = map[string]string{
	"auth": "会话", "dashboard": "仪表盘", "task": "任务", "finding": "漏洞",
	"traffic": "流量", "asset": "资产", "llm": "LLM", "agent": "Agent",
	"mcp": "MCP", "skill": "技能", "tool": "工具", "intercept": "拦截",
	"log": "日志与审计", "config": "系统配置", "knowledge": "知识库",
	"report": "报告", "rbac": "权限管理",
}

// RBACUser 是一个平台用户。
type RBACUser struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	DisplayName  string    `json:"display_name"`
	Enabled      bool      `json:"enabled"`
	IsBuiltin    bool      `json:"is_builtin"`
	TokenVersion int       `json:"token_version"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	// 密码哈希永不序列化（json:"-"）：即便是管理员接口也不该回显它。
	PasswordHash string `json:"-"`
}

// RBACRole 是一个角色。
type RBACRole struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Scope       string    `json:"scope"`
	IsSystem    bool      `json:"is_system"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// RBACAccess 是一个用户的完整授权画像（每次请求解析，不缓存）。
// 不缓存是有意的：权限变更要立刻生效，缓存的失效逻辑比一次索引查询更容易出错。
type RBACAccess struct {
	User        RBACUser        `json:"user"`
	Roles       []RBACRole      `json:"roles"`
	Permissions map[string]bool `json:"permissions"`
	Scope       string          `json:"scope"`
}

// HasPermission 报告是否持有某项权限；admin 恒为 true。
func (a *RBACAccess) HasPermission(key string) bool {
	if a == nil {
		return false
	}
	for _, r := range a.Roles {
		if r.ID == RBACRoleAdmin {
			return true
		}
	}
	return a.Permissions[key]
}

// HasRole 报告是否持有某个角色。
func (a *RBACAccess) HasRole(id string) bool {
	if a == nil {
		return false
	}
	for _, r := range a.Roles {
		if r.ID == id {
			return true
		}
	}
	return false
}

// mergeScope 取更宽的那个 scope（all > assigned > own）。
func mergeScope(a, b string) string {
	rank := func(s string) int {
		switch s {
		case RBACScopeAll:
			return 3
		case RBACScopeAssigned:
			return 2
		case RBACScopeOwn:
			return 1
		}
		return 0
	}
	if rank(a) >= rank(b) {
		return a
	}
	return b
}

const rbacUserCols = `id, username, display_name, COALESCE(password_hash,''), enabled, is_builtin, COALESCE(token_version,0), created_at, updated_at`

func scanRBACUser(sc interface{ Scan(...any) error }) (*RBACUser, error) {
	u := &RBACUser{}
	if err := sc.Scan(&u.ID, &u.Username, &u.DisplayName, &u.PasswordHash, &u.Enabled, &u.IsBuiltin, &u.TokenVersion, &u.CreatedAt, &u.UpdatedAt); err != nil {
		return nil, err
	}
	return u, nil
}

// BootstrapRBAC 播种权限目录、系统角色与内置 admin（幂等，每次启动跑）。
//
// legacyAdminHash 是旧单用户版本的密码哈希（settings.auth.password_hash）：首启时把它
// 迁移成内置 admin 的密码，**升级后不掉线**。迁移成功后旧 key 保留（回滚仍能登录），
// 但登录路径已切到 rbac_users，不再读它。
func (d *DB) BootstrapRBAC(legacyAdminHash string) error {
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if err := coordinateWithSchemaMigration(tx); err != nil {
		return err
	}

	// 1) 权限目录：upsert（描述可能随版本更新）
	keys := make([]string, 0, len(RBACPermissions))
	for k := range RBACPermissions {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if _, err := tx.Exec(`INSERT INTO rbac_permissions(key,description) VALUES($1,$2)
			ON CONFLICT (key) DO UPDATE SET description=EXCLUDED.description`, k, RBACPermissions[k]); err != nil {
			return err
		}
	}

	// 2) 系统角色：upsert（名称/描述/scope 跟随代码）
	sysRoles := []RBACRole{
		{ID: RBACRoleAdmin, Name: "管理员", Description: "全局管理权限，包含账号与核心配置", Scope: RBACScopeAll},
		{ID: RBACRoleOperator, Name: "操作员", Description: "可执行日常安全工作流，不能管理账号、核心配置与 LLM", Scope: RBACScopeAssigned},
		{ID: RBACRoleAuditor, Name: "审计员", Description: "只读查看审计、监控与资产", Scope: RBACScopeAll},
		{ID: RBACRoleViewer, Name: "只读用户", Description: "只读查看被授权资源", Scope: RBACScopeAssigned},
	}
	now := time.Now()
	for _, r := range sysRoles {
		if _, err := tx.Exec(`INSERT INTO rbac_roles(id,name,description,scope,is_system,created_at,updated_at)
			VALUES($1,$2,$3,$4,true,$5,$5)
			ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name, description=EXCLUDED.description,
			  scope=EXCLUDED.scope, is_system=true, updated_at=EXCLUDED.updated_at`,
			r.ID, r.Name, r.Description, r.Scope, now); err != nil {
			return err
		}
	}

	// 3) 系统角色授权：确定性重建（这样新增权限能自动落到系统角色上）
	if _, err := tx.Exec(`DELETE FROM rbac_role_permissions WHERE role_id IN ($1,$2,$3,$4)`,
		RBACRoleAdmin, RBACRoleOperator, RBACRoleAuditor, RBACRoleViewer); err != nil {
		return err
	}
	grant := func(role, key string) error {
		_, err := tx.Exec(`INSERT INTO rbac_role_permissions(role_id,permission_key) VALUES($1,$2) ON CONFLICT DO NOTHING`, role, key)
		return err
	}
	for _, key := range keys {
		if err := grant(RBACRoleAdmin, key); err != nil {
			return err
		}
		isRead := strings.HasSuffix(key, ":read")
		switch {
		case key == "auth:self":
			for _, rid := range []string{RBACRoleOperator, RBACRoleAuditor, RBACRoleViewer} {
				if err := grant(rid, key); err != nil {
					return err
				}
			}
		case isRead:
			// 所有 :read 都给 operator/auditor/viewer —— 能看到全部页面，但不能操作。
			for _, rid := range []string{RBACRoleOperator, RBACRoleAuditor, RBACRoleViewer} {
				if err := grant(rid, key); err != nil {
					return err
				}
			}
		case strings.HasPrefix(key, "rbac:"), strings.HasPrefix(key, "config:"), strings.HasPrefix(key, "llm:"):
			// 平台管理类的写/删：只给 admin（上面已授）。operator 也不该改 LLM 与核心配置。
		default:
			// 功能类写/删：给 operator。
			if err := grant(RBACRoleOperator, key); err != nil {
				return err
			}
		}
	}

	// 4) 首启建内置 admin（迁移旧单用户密码）
	var userCount int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM rbac_users`).Scan(&userCount); err != nil {
		return err
	}
	if userCount == 0 {
		hash := strings.TrimSpace(legacyAdminHash)
		if hash == "" {
			// 没有可迁移的密码：先建一个不可登录的占位（hash 为非法值，任何密码都验不过），
			// 用户在 /setup 页设密码时再写入真正的哈希。这样"已初始化"判断仍以 rbac_users 为准。
			hash = "!"
		}
		if _, err := tx.Exec(`INSERT INTO rbac_users(id,username,display_name,password_hash,enabled,is_builtin,created_at,updated_at)
			VALUES($1,$2,$3,$4,true,true,$5,$5)`, "admin", "admin", "管理员", hash, now); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO rbac_user_roles(user_id,role_id) VALUES('admin',$1) ON CONFLICT DO NOTHING`, RBACRoleAdmin); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// HasRBACUsers 报告是否已存在平台用户（决定 /setup 是否还允许设置密码）。
func (d *DB) HasRBACUsers() (bool, error) {
	var n int
	err := d.QueryRow(`SELECT COUNT(*) FROM rbac_users`).Scan(&n)
	return n > 0, err
}

// GetRBACUserByUsername 按用户名（大小写不敏感）取用户；不存在返回 nil, nil。
func (d *DB) GetRBACUserByUsername(username string) (*RBACUser, error) {
	u, err := scanRBACUser(d.QueryRow(`SELECT `+rbacUserCols+` FROM rbac_users WHERE lower(username)=lower($1)`, strings.TrimSpace(username)))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return u, err
}

// GetRBACUserByID 按 id 取用户；不存在返回 nil, nil。
func (d *DB) GetRBACUserByID(id string) (*RBACUser, error) {
	u, err := scanRBACUser(d.QueryRow(`SELECT `+rbacUserCols+` FROM rbac_users WHERE id=$1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return u, err
}

// ResolveRBACAccess 解析一个用户的完整授权画像（角色 + 权限并集 + 最宽 scope）。
func (d *DB) ResolveRBACAccess(userID string) (*RBACAccess, error) {
	u, err := d.GetRBACUserByID(userID)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, nil
	}
	acc := &RBACAccess{User: *u, Permissions: map[string]bool{}, Scope: RBACScopeOwn}
	rows, err := d.Query(`SELECT r.id, r.name, r.description, r.scope, r.is_system, r.created_at, r.updated_at
		FROM rbac_roles r JOIN rbac_user_roles ur ON ur.role_id = r.id
		WHERE ur.user_id = $1 ORDER BY r.is_system DESC, r.name`, userID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var r RBACRole
		if err := rows.Scan(&r.ID, &r.Name, &r.Description, &r.Scope, &r.IsSystem, &r.CreatedAt, &r.UpdatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		acc.Roles = append(acc.Roles, r)
		acc.Scope = mergeScope(acc.Scope, r.Scope)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	prows, err := d.Query(`SELECT DISTINCT rp.permission_key FROM rbac_role_permissions rp
		JOIN rbac_user_roles ur ON ur.role_id = rp.role_id WHERE ur.user_id = $1`, userID)
	if err != nil {
		return nil, err
	}
	defer prows.Close()
	for prows.Next() {
		var k string
		if err := prows.Scan(&k); err != nil {
			return nil, err
		}
		acc.Permissions[k] = true
	}
	return acc, prows.Err()
}

// ListRBACUsers 列出全部用户（含各自角色 id），按用户名排序。
func (d *DB) ListRBACUsers() ([]*RBACUser, []map[string]bool, error) {
	rows, err := d.Query(`SELECT ` + rbacUserCols + ` FROM rbac_users ORDER BY username`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var users []*RBACUser
	for rows.Next() {
		u, err := scanRBACUser(rows)
		if err != nil {
			return nil, nil, err
		}
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	roleSets := make([]map[string]bool, len(users))
	for i := range roleSets {
		roleSets[i] = map[string]bool{}
	}
	rrows, err := d.Query(`SELECT user_id, role_id FROM rbac_user_roles`)
	if err != nil {
		return nil, nil, err
	}
	defer rrows.Close()
	idx := map[string]int{}
	for i, u := range users {
		idx[u.ID] = i
	}
	for rrows.Next() {
		var uid, rid string
		if err := rrows.Scan(&uid, &rid); err != nil {
			return nil, nil, err
		}
		if i, ok := idx[uid]; ok {
			roleSets[i][rid] = true
		}
	}
	return users, roleSets, rrows.Err()
}

// CreateRBACUser 建用户（bcrypt 哈希密码）并绑定角色。
func (d *DB) CreateRBACUser(username, displayName, password string, roleIDs []string) (*RBACUser, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return nil, errors.New("用户名不能为空")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	tx, err := d.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(`INSERT INTO rbac_users(id,username,display_name,password_hash,enabled,is_builtin)
		VALUES($1,$2,$3,$4,true,false)`, id, username, strings.TrimSpace(displayName), string(hash)); err != nil {
		return nil, err
	}
	for _, rid := range roleIDs {
		if _, err := tx.Exec(`INSERT INTO rbac_user_roles(user_id,role_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, id, rid); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return d.GetRBACUserByID(id)
}

// UserRoleIDs 返回某用户的角色 id 列表（新建/更新后回填给前端）。
func (d *DB) UserRoleIDs(id string) ([]string, error) {
	rows, err := d.Query(`SELECT role_id FROM rbac_user_roles WHERE user_id=$1 ORDER BY role_id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var rid string
		if err := rows.Scan(&rid); err != nil {
			return nil, err
		}
		out = append(out, rid)
	}
	return out, rows.Err()
}

// UpdateRBACUser 更新昵称 / 启用状态 / 密码 / 角色。密码为空表示不改；
// 改了密码或停用账号都会自增 token_version（旧会话立即失效）。
func (d *DB) UpdateRBACUser(id, displayName string, enabled *bool, newPassword string, roleIDs []string) (*RBACUser, error) {
	tx, err := d.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	if _, err := tx.Exec(`UPDATE rbac_users SET display_name=$2, updated_at=now() WHERE id=$1`, id, strings.TrimSpace(displayName)); err != nil {
		return nil, err
	}
	bump := false
	if enabled != nil {
		if _, err := tx.Exec(`UPDATE rbac_users SET enabled=$2, updated_at=now() WHERE id=$1`, id, *enabled); err != nil {
			return nil, err
		}
		if !*enabled {
			bump = true // 停用即踢下线
		}
	}
	if strings.TrimSpace(newPassword) != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
		if err != nil {
			return nil, err
		}
		if _, err := tx.Exec(`UPDATE rbac_users SET password_hash=$2, updated_at=now() WHERE id=$1`, id, string(hash)); err != nil {
			return nil, err
		}
		bump = true
	}
	if bump {
		if _, err := tx.Exec(`UPDATE rbac_users SET token_version = token_version + 1 WHERE id=$1`, id); err != nil {
			return nil, err
		}
	}
	if roleIDs != nil {
		// 内置 admin 必须始终持有 admin 角色，否则平台会失去唯一的管理入口。
		if _, err := tx.Exec(`DELETE FROM rbac_user_roles WHERE user_id=$1`, id); err != nil {
			return nil, err
		}
		for _, rid := range roleIDs {
			if _, err := tx.Exec(`INSERT INTO rbac_user_roles(user_id,role_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, id, rid); err != nil {
				return nil, err
			}
		}
		if id == "admin" {
			if _, err := tx.Exec(`INSERT INTO rbac_user_roles(user_id,role_id) VALUES('admin',$1) ON CONFLICT DO NOTHING`, RBACRoleAdmin); err != nil {
				return nil, err
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return d.GetRBACUserByID(id)
}

// SetRBACUserPassword 直接设密码并自增 token_version（/setup 与改密共用）。
func (d *DB) SetRBACUserPassword(id, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = d.Exec(`UPDATE rbac_users SET password_hash=$2, token_version = token_version + 1, updated_at=now() WHERE id=$1`, id, string(hash))
	return err
}

// TouchRBACUserToken 自增 token_version（强制该用户的所有会话重新登录）。
func (d *DB) TouchRBACUserToken(id string) error {
	_, err := d.Exec(`UPDATE rbac_users SET token_version = token_version + 1, updated_at=now() WHERE id=$1`, id)
	return err
}

// DeleteRBACUser 删除用户；内置 admin 拒绝删除。
func (d *DB) DeleteRBACUser(id string) error {
	if id == "admin" {
		return errors.New("内置管理员不可删除")
	}
	res, err := d.Exec(`DELETE FROM rbac_users WHERE id=$1 AND is_builtin=false`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("用户不存在或为内置账号")
	}
	return nil
}

// ListRBACRoles 列出全部角色及各自的权限键。
func (d *DB) ListRBACRoles() ([]*RBACRole, map[string][]string, error) {
	rows, err := d.Query(`SELECT id, name, description, scope, is_system, created_at, updated_at FROM rbac_roles ORDER BY is_system DESC, name`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var roles []*RBACRole
	for rows.Next() {
		r := &RBACRole{}
		if err := rows.Scan(&r.ID, &r.Name, &r.Description, &r.Scope, &r.IsSystem, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, nil, err
		}
		roles = append(roles, r)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	perms := map[string][]string{}
	prows, err := d.Query(`SELECT role_id, permission_key FROM rbac_role_permissions`)
	if err != nil {
		return nil, nil, err
	}
	defer prows.Close()
	for prows.Next() {
		var rid, key string
		if err := prows.Scan(&rid, &key); err != nil {
			return nil, nil, err
		}
		perms[rid] = append(perms[rid], key)
	}
	for k := range perms {
		sort.Strings(perms[k])
	}
	return roles, perms, prows.Err()
}

// CreateRBACRole 建自定义角色（id 由名称派生，冲突时加随机后缀）。
func (d *DB) CreateRBACRole(name, description, scope string, permissions []string) (*RBACRole, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, errors.New("角色名不能为空")
	}
	if !validScope(scope) {
		scope = RBACScopeAssigned
	}
	base := slugID(name)
	id := base
	var exists bool
	_ = d.QueryRow(`SELECT EXISTS(SELECT 1 FROM rbac_roles WHERE id=$1)`, id).Scan(&exists)
	if exists {
		suffix, err := randomID()
		if err != nil {
			return nil, err
		}
		id = base + "-" + suffix[:6]
	}
	tx, err := d.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.Exec(`INSERT INTO rbac_roles(id,name,description,scope,is_system) VALUES($1,$2,$3,$4,false)`,
		id, name, strings.TrimSpace(description), scope); err != nil {
		return nil, err
	}
	for _, key := range permissions {
		if _, ok := RBACPermissions[key]; !ok {
			continue // 未知权限静默丢弃：目录是唯一真值
		}
		if _, err := tx.Exec(`INSERT INTO rbac_role_permissions(role_id,permission_key) VALUES($1,$2) ON CONFLICT DO NOTHING`, id, key); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	roles, perms, err := d.ListRBACRoles()
	if err != nil {
		return nil, err
	}
	for _, r := range roles {
		if r.ID == id {
			_ = perms
			return r, nil
		}
	}
	return nil, fmt.Errorf("角色 %s 创建后读不到", id)
}

// UpdateRBACRole 改自定义角色；系统角色拒绝修改（它们的授权由 bootstrap 重建）。
func (d *DB) UpdateRBACRole(id, name, description, scope string, permissions []string) (*RBACRole, error) {
	var isSystem bool
	if err := d.QueryRow(`SELECT is_system FROM rbac_roles WHERE id=$1`, id).Scan(&isSystem); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("角色不存在")
		}
		return nil, err
	}
	if isSystem {
		return nil, errors.New("系统角色不可修改")
	}
	if !validScope(scope) {
		scope = RBACScopeAssigned
	}
	tx, err := d.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.Exec(`UPDATE rbac_roles SET name=$2, description=$3, scope=$4, updated_at=now() WHERE id=$1`,
		id, strings.TrimSpace(name), strings.TrimSpace(description), scope); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(`DELETE FROM rbac_role_permissions WHERE role_id=$1`, id); err != nil {
		return nil, err
	}
	for _, key := range permissions {
		if _, ok := RBACPermissions[key]; !ok {
			continue
		}
		if _, err := tx.Exec(`INSERT INTO rbac_role_permissions(role_id,permission_key) VALUES($1,$2) ON CONFLICT DO NOTHING`, id, key); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	r := &RBACRole{ID: id}
	if err := d.QueryRow(`SELECT name, description, scope, is_system, created_at, updated_at FROM rbac_roles WHERE id=$1`, id).
		Scan(&r.Name, &r.Description, &r.Scope, &r.IsSystem, &r.CreatedAt, &r.UpdatedAt); err != nil {
		return nil, err
	}
	return r, nil
}

// DeleteRBACRole 删除自定义角色（用户绑定级联删除）；系统角色拒绝。
func (d *DB) DeleteRBACRole(id string) error {
	res, err := d.Exec(`DELETE FROM rbac_roles WHERE id=$1 AND is_system=false`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("角色不存在或为系统角色")
	}
	return nil
}

// PermissionCatalog 返回排序后的权限目录（key + 说明 + 分组）。
func PermissionCatalog() []map[string]string {
	keys := make([]string, 0, len(RBACPermissions))
	for k := range RBACPermissions {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]map[string]string, 0, len(keys))
	for _, k := range keys {
		mod := k
		if i := strings.Index(k, ":"); i > 0 {
			mod = k[:i]
		}
		group := permissionGroups[mod]
		if group == "" {
			group = mod
		}
		out = append(out, map[string]string{"key": k, "description": RBACPermissions[k], "group": group})
	}
	return out
}

func validScope(s string) bool {
	switch s {
	case RBACScopeAll, RBACScopeAssigned, RBACScopeOwn:
		return true
	}
	return false
}

// randomID 生成 32 hex 字符的随机 id。
func randomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// slugID 把角色名压成 id：只留小写字母/数字/连字符，中文名退化为随机段。
func slugID(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		case r == ' ':
			b.WriteRune('-')
		}
	}
	s := strings.Trim(b.String(), "-")
	if len(s) < 2 {
		if id, err := randomID(); err == nil {
			return "role-" + id[:8]
		}
		return "role"
	}
	if len(s) > 40 {
		s = s[:40]
	}
	return s
}
