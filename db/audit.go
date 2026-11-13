package db

import (
	"database/sql"
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// 审计日志数据层。
//
// 与 server_logs 的分工要分清：server_logs 记的是「程序说了什么」（排障用，混杂、易变），
// 这张表记的是「人动了什么」（合规用：谁、什么时候、对哪个资源、做了什么、结果如何）。
// 所以这里有 actor 字段而那里没有 —— 也正是有了 RBAC 之后，actor 才有意义。

// AuditLog 是一条审计记录。
type AuditLog struct {
	ID        int64          `json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	Actor     string         `json:"actor"`
	Category  string         `json:"category"`
	Action    string         `json:"action"`
	Result    string         `json:"result"`
	IP        string         `json:"ip"`
	Message   string         `json:"message"`
	Detail    map[string]any `json:"detail,omitempty"`
}

// RecordAudit 写一条审计（best-effort：出错只记日志，绝不影响主流程 ——
// 审计写失败不该让一次合法的删除操作失败）。
func (d *DB) RecordAudit(actor, category, action, result, ip, message string, detail map[string]any) {
	if strings.TrimSpace(result) == "" {
		result = "success"
	}
	var raw []byte
	if detail != nil {
		raw, _ = json.Marshal(detail)
	}
	var detailVal any
	if len(raw) > 0 {
		detailVal = string(raw)
	}
	_, _ = d.Exec(`INSERT INTO audit_logs(actor,category,action,result,ip,message,detail)
		VALUES($1,$2,$3,$4,$5,$6,$7::jsonb)`,
		strings.TrimSpace(actor), strings.TrimSpace(category), strings.TrimSpace(action),
		result, strings.TrimSpace(ip), strings.TrimSpace(message), detailVal)
}

// AuditFilter 是审计查询条件。
type AuditFilter struct {
	Actor    string
	Category string
	Result   string
	Query    string // 在 message/action 上模糊匹配
}

// ListAuditLogs 按条件分页查询（新的在前），并返回命中总数。
func (d *DB) ListAuditLogs(f AuditFilter, limit, offset int) ([]*AuditLog, int, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	var conds []string
	var args []any
	add := func(cond string, val any) {
		args = append(args, val)
		conds = append(conds, strings.ReplaceAll(cond, "?", "$"+strconv.Itoa(len(args))))
	}
	if v := strings.TrimSpace(f.Actor); v != "" {
		add("actor = ?", v)
	}
	if v := strings.TrimSpace(f.Category); v != "" {
		add("category = ?", v)
	}
	if v := strings.TrimSpace(f.Result); v != "" {
		add("result = ?", v)
	}
	if v := strings.TrimSpace(f.Query); v != "" {
		args = append(args, "%"+v+"%")
		n := "$" + strconv.Itoa(len(args))
		conds = append(conds, "(message ILIKE "+n+" OR action ILIKE "+n+")")
	}
	where := ""
	if len(conds) > 0 {
		where = " WHERE " + strings.Join(conds, " AND ")
	}

	var total int
	if err := d.QueryRow(`SELECT count(*) FROM audit_logs`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, limit, offset)
	q := `SELECT id, created_at, actor, category, action, result, ip, message, detail::text
		FROM audit_logs` + where + ` ORDER BY id DESC LIMIT $` + strconv.Itoa(len(args)-1) + ` OFFSET $` + strconv.Itoa(len(args))
	rows, err := d.Query(q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []*AuditLog{}
	for rows.Next() {
		l := &AuditLog{}
		var detail sql.NullString
		if err := rows.Scan(&l.ID, &l.CreatedAt, &l.Actor, &l.Category, &l.Action, &l.Result, &l.IP, &l.Message, &detail); err != nil {
			return nil, 0, err
		}
		if detail.Valid && detail.String != "" {
			_ = json.Unmarshal([]byte(detail.String), &l.Detail)
		}
		out = append(out, l)
	}
	return out, total, rows.Err()
}

// AuditCategories 返回已出现过的 category 列表（供前端筛选下拉）。
func (d *DB) AuditCategories() ([]string, error) {
	rows, err := d.Query(`SELECT DISTINCT category FROM audit_logs WHERE category <> '' ORDER BY category`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// PruneAuditLogs 保留最近 keep 条（防止长跑部署把表撑大）。返回删除条数。
func (d *DB) PruneAuditLogs(keep int) (int64, error) {
	if keep <= 0 {
		keep = 50000
	}
	res, err := d.Exec(`DELETE FROM audit_logs WHERE id NOT IN (SELECT id FROM audit_logs ORDER BY id DESC LIMIT $1)`, keep)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
