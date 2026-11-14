package db

import (
	"database/sql"
	"errors"
	"strings"
	"time"
)

// 漏洞证据截图的元数据。文件本身落盘（不进库）：把几 MB 的 PNG 塞进行里，
// 会让备份/查询/迁移全部变慢，而截图恰恰是最该被"文件级备份"的那类东西。
type FindingEvidence struct {
	ID        int64     `json:"id"`
	FindingID int64     `json:"finding_id"`
	Filename  string    `json:"filename"`
	Caption   string    `json:"caption"`
	StepIndex int       `json:"step_index"`
	SortOrder int       `json:"sort_order"`
	Width     int       `json:"width"`
	Height    int       `json:"height"`
	Bytes     int64     `json:"bytes"`
	CreatedAt time.Time `json:"created_at"`
}

const evidenceCols = `id, finding_id, filename, caption, step_index, sort_order, width, height, bytes, created_at`

func scanEvidence(sc interface{ Scan(...any) error }) (*FindingEvidence, error) {
	e := &FindingEvidence{}
	if err := sc.Scan(&e.ID, &e.FindingID, &e.Filename, &e.Caption, &e.StepIndex, &e.SortOrder,
		&e.Width, &e.Height, &e.Bytes, &e.CreatedAt); err != nil {
		return nil, err
	}
	return e, nil
}

// CreateFindingEvidence 新增一条（文件已落盘），sort_order 自动取当前最大 +1。
func (d *DB) CreateFindingEvidence(findingID int64, filename, caption string, stepIndex, width, height int, bytes int64) (*FindingEvidence, error) {
	var next int
	_ = d.QueryRow(`SELECT COALESCE(MAX(sort_order),0)+1 FROM finding_evidence WHERE finding_id=$1`, findingID).Scan(&next)
	return scanEvidence(d.QueryRow(`
INSERT INTO finding_evidence(finding_id, filename, caption, step_index, sort_order, width, height, bytes)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
RETURNING `+evidenceCols,
		findingID, filename, strings.TrimSpace(caption), stepIndex, next, width, height, bytes))
}

// ListFindingEvidence 列出某漏洞的全部截图（按 sort_order, id）。
func (d *DB) ListFindingEvidence(findingID int64) ([]*FindingEvidence, error) {
	rows, err := d.Query(`SELECT `+evidenceCols+` FROM finding_evidence WHERE finding_id=$1 ORDER BY sort_order, id`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*FindingEvidence{}
	for rows.Next() {
		e, err := scanEvidence(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// GetFindingEvidence 取一条；不存在返回 nil, nil。
func (d *DB) GetFindingEvidence(id int64) (*FindingEvidence, error) {
	e, err := scanEvidence(d.QueryRow(`SELECT `+evidenceCols+` FROM finding_evidence WHERE id=$1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return e, err
}

// EvidenceForReport 取报告要用的截图：按漏洞分组的全部截图。
func (d *DB) EvidenceForReport(findingIDs []int64) (map[int64][]*FindingEvidence, error) {
	out := make(map[int64][]*FindingEvidence, len(findingIDs))
	for _, id := range findingIDs {
		list, err := d.ListFindingEvidence(id)
		if err != nil {
			return out, err
		}
		if len(list) > 0 {
			out[id] = list
		}
	}
	return out, nil
}

// UpdateFindingEvidence 改图注 / 归属步骤 / 排序（空字段保留原值）。
func (d *DB) UpdateFindingEvidence(id int64, caption string, stepIndex, sortOrder int) error {
	_, err := d.Exec(`UPDATE finding_evidence SET
		caption    = COALESCE(NULLIF($2,''), caption),
		step_index = CASE WHEN $3 >= 0 THEN $3 ELSE step_index END,
		sort_order = CASE WHEN $4 > 0 THEN $4 ELSE sort_order END
		WHERE id = $1`, id, strings.TrimSpace(caption), stepIndex, sortOrder)
	return err
}

// DeleteFindingEvidence 删记录；返回被删的那条（调用方据此删盘上文件）。
func (d *DB) DeleteFindingEvidence(id int64) (*FindingEvidence, error) {
	ev, err := d.GetFindingEvidence(id)
	if err != nil || ev == nil {
		return nil, err
	}
	if _, err := d.Exec(`DELETE FROM finding_evidence WHERE id=$1`, id); err != nil {
		return nil, err
	}
	return ev, nil
}
