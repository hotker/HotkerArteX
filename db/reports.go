package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// 交付级报告（report management）的数据层：组织级设置 + 已生成报告记录。
//
// 设置是单行表（id 恒 true）：报告封面上的「出具方 / 客户 / 密级 / 署名人员 / 版本」
// 属于组织属性而不是某次测试的属性，放单行最省事，也避免了"多个设置行谁生效"的歧义。

// ReportPerson 是一名署名人员。
type ReportPerson struct {
	Name    string `json:"name"`
	Role    string `json:"role"`
	Contact string `json:"contact"`
}

// ReportSettings 是组织级报告设置。
type ReportSettings struct {
	Company      string         `json:"company"`
	Client       string         `json:"client"`
	Confidential string         `json:"confidential"`
	Lang         string         `json:"lang"`
	Version      string         `json:"version"`
	People       []ReportPerson `json:"people"`
	UpdatedAt    time.Time      `json:"updated_at"`
}

// ErrReportSettingsMissing 表示还没有设置行（首次使用）。
var ErrReportSettingsMissing = errors.New("report settings not configured")

// GetReportSettings 返回设置；没有行时返回默认值 + ErrReportSettingsMissing，
// 让调用方既能直接渲染空表单，也知道"从未保存过"。
func (d *DB) GetReportSettings() (*ReportSettings, error) {
	st := &ReportSettings{Lang: "zh-CN", Version: "v1.0", People: []ReportPerson{}}
	var people string
	var updated sql.NullTime
	err := d.QueryRow(`SELECT company, client, confidential, lang, version, people::text, updated_at
		FROM report_settings WHERE id=true`).
		Scan(&st.Company, &st.Client, &st.Confidential, &st.Lang, &st.Version, &people, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return st, ErrReportSettingsMissing
	}
	if err != nil {
		return nil, err
	}
	if updated.Valid {
		st.UpdatedAt = updated.Time
	}
	_ = json.Unmarshal([]byte(people), &st.People)
	if st.People == nil {
		st.People = []ReportPerson{}
	}
	return st, nil
}

// SaveReportSettings upserts the single settings row.
func (d *DB) SaveReportSettings(st *ReportSettings) error {
	if st == nil {
		return errors.New("settings required")
	}
	if st.Lang == "" {
		st.Lang = "zh-CN"
	}
	people := st.People
	if people == nil {
		people = []ReportPerson{}
	}
	raw, err := json.Marshal(people)
	if err != nil {
		return err
	}
	_, err = d.Exec(`INSERT INTO report_settings (id, company, client, confidential, lang, version, people, updated_at)
		VALUES (true, $1, $2, $3, $4, $5, $6::jsonb, now())
		ON CONFLICT (id) DO UPDATE SET company=$1, client=$2, confidential=$3, lang=$4, version=$5, people=$6::jsonb, updated_at=now()`,
		st.Company, st.Client, st.Confidential, st.Lang, st.Version, string(raw))
	return err
}

// Report 是一条已生成报告记录。
type Report struct {
	ID            int64     `json:"id"`
	TaskID        *int64    `json:"task_id,omitempty"`
	Title         string    `json:"title"`
	Lang          string    `json:"lang"`
	FilePath      string    `json:"file_path"`
	FileName      string    `json:"file_name"`
	SizeBytes     int64     `json:"size_bytes"`
	FindingsCount int       `json:"findings_count"`
	CreatedAt     time.Time `json:"created_at"`
}

// CreateReport inserts a generated-report record and returns it with its id.
func (d *DB) CreateReport(r *Report) (*Report, error) {
	if r == nil {
		return nil, errors.New("report required")
	}
	err := d.QueryRow(`INSERT INTO reports (task_id, title, lang, file_path, file_name, size_bytes, findings_count)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, created_at`,
		r.TaskID, r.Title, r.Lang, r.FilePath, r.FileName, r.SizeBytes, r.FindingsCount).
		Scan(&r.ID, &r.CreatedAt)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// ListReports returns newest first, optionally filtered by task id (0 = all).
func (d *DB) ListReports(taskID int64, limit int) ([]*Report, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	q := `SELECT id, task_id, title, lang, file_path, file_name, size_bytes, findings_count, created_at FROM reports`
	args := []any{}
	if taskID > 0 {
		q += ` WHERE task_id=$1`
		args = append(args, taskID)
	}
	q += ` ORDER BY created_at DESC, id DESC LIMIT ` + itoaInt(limit)
	rows, err := d.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Report{}
	for rows.Next() {
		r := &Report{}
		if err := rows.Scan(&r.ID, &r.TaskID, &r.Title, &r.Lang, &r.FilePath, &r.FileName, &r.SizeBytes, &r.FindingsCount, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetReport returns one report record (nil, nil when absent).
func (d *DB) GetReport(id int64) (*Report, error) {
	r := &Report{}
	err := d.QueryRow(`SELECT id, task_id, title, lang, file_path, file_name, size_bytes, findings_count, created_at
		FROM reports WHERE id=$1`, id).
		Scan(&r.ID, &r.TaskID, &r.Title, &r.Lang, &r.FilePath, &r.FileName, &r.SizeBytes, &r.FindingsCount, &r.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return r, nil
}

// DeleteReport removes the record (the caller deletes the file).
func (d *DB) DeleteReport(id int64) (int64, error) {
	res, err := d.Exec(`DELETE FROM reports WHERE id=$1`, id)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func itoaInt(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
