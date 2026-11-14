package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// 漏洞富化：AI 生成 / 人工编辑的结构化覆盖层。
//
// 为什么独立成表而不是往 findings 加列：findings 是 worker 的**原始产出**，
// planner 每轮都会读它（graph_overview）；把叙述正文和 CVSS 结构塞进去会让图谱膨胀，
// 也会让"原始观测"与"交付改写"混在一起、无法区分谁写的。富化是交付层，单独放。
//
// JSONB 列用 json.RawMessage 承载，db 包因此不依赖任何报告层类型。

// FindingEnrichment 是一条漏洞的结构化交付数据。
type FindingEnrichment struct {
	FindingID    int64           `json:"finding_id"`
	Name         string          `json:"name"`
	Target       string          `json:"target"`
	Module       string          `json:"module"`
	Severity     string          `json:"severity"` // 人工覆盖；空 = 用 find./payload 的
	Status       string          `json:"status"`   // open | confirmed | fixed | false_positive | ignored
	CVSSScore    float64         `json:"cvss_score"`
	CVSSVector   string          `json:"cvss_vector"`
	CVSSMetrics  json.RawMessage `json:"cvss_metrics"`
	Description  json.RawMessage `json:"description"`
	TestProcess  json.RawMessage `json:"test_process"`
	RiskAnalysis json.RawMessage `json:"risk_analysis"`
	Remediation  json.RawMessage `json:"remediation"`
	Source       string          `json:"source"` // ai | manual
	CreatedAt    time.Time       `json:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at"`
}

func rawOr(r json.RawMessage, def string) string {
	if len(r) == 0 {
		return def
	}
	return string(r)
}

func strOr(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

const feSelect = `SELECT finding_id, name, target, module, severity, status, cvss_score, cvss_vector,
	cvss_metrics::text, description::text, test_process::text, risk_analysis::text, remediation::text,
	source, created_at, updated_at FROM finding_enrichment`

func scanFE(sc interface{ Scan(...any) error }) (*FindingEnrichment, error) {
	e := &FindingEnrichment{}
	var cvss, desc, tp, risk, rem string
	if err := sc.Scan(&e.FindingID, &e.Name, &e.Target, &e.Module, &e.Severity, &e.Status,
		&e.CVSSScore, &e.CVSSVector, &cvss, &desc, &tp, &risk, &rem, &e.Source, &e.CreatedAt, &e.UpdatedAt); err != nil {
		return nil, err
	}
	e.CVSSMetrics, e.Description = json.RawMessage(cvss), json.RawMessage(desc)
	e.TestProcess, e.RiskAnalysis, e.Remediation = json.RawMessage(tp), json.RawMessage(risk), json.RawMessage(rem)
	return e, nil
}

// GetFindingEnrichment 取一条富化；不存在返回 nil, nil。
func (d *DB) GetFindingEnrichment(findingID int64) (*FindingEnrichment, error) {
	e, err := scanFE(d.QueryRow(feSelect+" WHERE finding_id=$1", findingID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return e, err
}

// GetFindingEnrichments 批量取（按 id 循环；单任务的漏洞数量级很小）。
func (d *DB) GetFindingEnrichments(findingIDs []int64) (map[int64]*FindingEnrichment, error) {
	out := make(map[int64]*FindingEnrichment, len(findingIDs))
	for _, id := range findingIDs {
		e, err := d.GetFindingEnrichment(id)
		if err != nil {
			return out, err
		}
		if e != nil {
			out[id] = e
		}
	}
	return out, nil
}

// UpsertFindingEnrichment 覆盖式写入（AI 生成后落库用）。
func (d *DB) UpsertFindingEnrichment(e *FindingEnrichment) error {
	_, err := d.Exec(`INSERT INTO finding_enrichment
		(finding_id, name, target, module, severity, status, cvss_score, cvss_vector,
		 cvss_metrics, description, test_process, risk_analysis, remediation, source, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10::jsonb,$11::jsonb,$12::jsonb,$13::jsonb,$14, now())
		ON CONFLICT (finding_id) DO UPDATE SET
			name=EXCLUDED.name, target=EXCLUDED.target, module=EXCLUDED.module,
			severity=EXCLUDED.severity, status=EXCLUDED.status,
			cvss_score=EXCLUDED.cvss_score, cvss_vector=EXCLUDED.cvss_vector,
			cvss_metrics=EXCLUDED.cvss_metrics, description=EXCLUDED.description,
			test_process=EXCLUDED.test_process, risk_analysis=EXCLUDED.risk_analysis,
			remediation=EXCLUDED.remediation, source=EXCLUDED.source, updated_at=now()`,
		e.FindingID, e.Name, e.Target, e.Module, e.Severity, strOr(e.Status, "open"),
		e.CVSSScore, e.CVSSVector, rawOr(e.CVSSMetrics, "{}"), rawOr(e.Description, "[]"),
		rawOr(e.TestProcess, "[]"), rawOr(e.RiskAnalysis, "[]"), rawOr(e.Remediation, "[]"),
		strOr(e.Source, "ai"))
	return err
}

// UpdateFindingEnrichmentFields 局部更新人工可编辑字段。
//
// 空字段**保留原值**（而不是清空）：前端做的是"只改我填的那几项"，
// 一次只改状态不该把 AI 已经写好的 name/target 冲掉。行不存在时创建。
func (d *DB) UpdateFindingEnrichmentFields(findingID int64, name, target, severity, status string) error {
	_, err := d.Exec(`INSERT INTO finding_enrichment (finding_id, name, target, severity, status, source, updated_at)
		VALUES ($1,$2,$3,$4,COALESCE(NULLIF($5,''),'open'),'manual', now())
		ON CONFLICT (finding_id) DO UPDATE SET
			name     = COALESCE(NULLIF($2, ''), finding_enrichment.name),
			target   = COALESCE(NULLIF($3, ''), finding_enrichment.target),
			severity = COALESCE(NULLIF($4, ''), finding_enrichment.severity),
			status   = COALESCE(NULLIF($5, ''), finding_enrichment.status),
			source='manual', updated_at=now()`,
		findingID, strings.TrimSpace(name), strings.TrimSpace(target), strings.TrimSpace(severity), strings.TrimSpace(status))
	return err
}

// DeleteFindingEnrichment 删除富化（漏洞删除时由 FK 级联，这里给"重置为未富化"用）。
func (d *DB) DeleteFindingEnrichment(findingID int64) error {
	_, err := d.Exec(`DELETE FROM finding_enrichment WHERE finding_id=$1`, findingID)
	return err
}

// HasEnrichmentProse 报告该富化是否已含 AI 正文（描述/风险/修复至少一项非空）。
// 用于"确认即富化"：只有还没富化过的才触发一次后台生成。
func HasEnrichmentProse(e *FindingEnrichment) bool {
	if e == nil {
		return false
	}
	nonEmptyArr := func(raw json.RawMessage) bool {
		s := strings.TrimSpace(string(raw))
		return s != "" && s != "[]" && s != "null"
	}
	return nonEmptyArr(e.Description) || nonEmptyArr(e.RiskAnalysis) || nonEmptyArr(e.Remediation)
}
