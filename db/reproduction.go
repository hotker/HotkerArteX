package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
)

// 结构化复现过程（reproduction）—— 报告里"怎么复现"的那一半。
//
// 与 finding_traffic_bindings 的分工：
//   - bindings 是【证据】：真实报文快照，用来证明"我确实打到了"；
//   - reproduction 是【路径】：入口 → 前置 → 逐步利用，用来让人从零复现。
//
// 两者不可互相替代。绑定能证明一条请求发生过，却说明不了"第 2 步依赖第 1 步的输出"；
// 复现步骤能说明链路，但单独看没有原始报文可点。报告同时渲染两者。
//
// 存成一列 JSONB 而不是多张表：步骤是有序整体，永远随漏洞一起读写，拆表只有连接成本。

// ReproStep 是一个复现步骤。Request/Response 约定为【逐字真实报文】。
type ReproStep struct {
	Request  string `json:"request,omitempty"`
	Response string `json:"response,omitempty"`
	Expected string `json:"expected,omitempty"`
	Proves   string `json:"proves,omitempty"`
}

// Reproduction 是一条漏洞的复现路径。
type Reproduction struct {
	EntryPoint    string      `json:"entry_point,omitempty"`   // 触发漏洞的关键接口：方法 + URL
	Prerequisites string      `json:"prerequisites,omitempty"` // 前置：账号/角色/前序步骤；需账号时写清如何注册
	Steps         []ReproStep `json:"steps,omitempty"`
	Provenance    string      `json:"provenance,omitempty"` // 攻击链来源/依赖
}

// StepCap 是单步报文的存库上限（字符）。超长报文由流量库承载（bindings 里已有原文），
// 这里截断并留下明确标记 —— 绝不让一步几 MB 的 HTML 把整条漏洞撑爆。
const (
	StepFieldCap = 8000
	MaxSteps     = 40
)

// Normalize 做入库前的清洗：裁空白、去空步、限条数、截超长字段。
// 返回 nil 表示"没有可存的复现信息"（调用方存 NULL 而不是空对象）。
func (r *Reproduction) Normalize() *Reproduction {
	if r == nil {
		return nil
	}
	out := &Reproduction{
		EntryPoint:    strings.TrimSpace(r.EntryPoint),
		Prerequisites: strings.TrimSpace(r.Prerequisites),
		Provenance:    strings.TrimSpace(r.Provenance),
	}
	for _, st := range r.Steps {
		step := ReproStep{
			Request:  clipField(st.Request),
			Response: clipField(st.Response),
			Expected: strings.TrimSpace(st.Expected),
			Proves:   strings.TrimSpace(st.Proves),
		}
		if step.Request == "" && step.Response == "" && step.Expected == "" && step.Proves == "" {
			continue // 模型有时会塞空对象占位
		}
		if len(out.Steps) >= MaxSteps {
			break
		}
		out.Steps = append(out.Steps, step)
	}
	if out.EntryPoint == "" && out.Prerequisites == "" && out.Provenance == "" && len(out.Steps) == 0 {
		return nil
	}
	return out
}

// clipField 截断超长字段并留下可识别标记（读的人知道它不是全文）。
func clipField(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= StepFieldCap {
		return s
	}
	// 按 rune 边界截，避免把多字节字符劈开变成乱码。
	cut := StepFieldCap
	for cut > 0 && !isRuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "\n…[已截断，完整报文见关联流量]"
}

// isRuneStart 判断 UTF-8 字节 b 是否是某个字符的首字节。
func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }

// Encode 序列化成 JSONB 写入值（nil → NULL）。
func (r *Reproduction) Encode() (sql.NullString, error) {
	n := r.Normalize()
	if n == nil {
		return sql.NullString{}, nil
	}
	b, err := json.Marshal(n)
	if err != nil {
		return sql.NullString{}, err
	}
	return sql.NullString{String: string(b), Valid: true}, nil
}

// DecodeReproduction 从列值还原（NULL/坏数据 → nil，调用方按"未登记"处理）。
func DecodeReproduction(raw sql.NullString) *Reproduction {
	if !raw.Valid || strings.TrimSpace(raw.String) == "" {
		return nil
	}
	var r Reproduction
	if err := json.Unmarshal([]byte(raw.String), &r); err != nil {
		return nil
	}
	if r.EntryPoint == "" && r.Prerequisites == "" && r.Provenance == "" && len(r.Steps) == 0 {
		return nil
	}
	return &r
}

// ErrNoReproduction 表示该漏洞没有登记复现过程。
var ErrNoReproduction = errors.New("finding has no reproduction")

// SetFindingReproduction 写入/覆盖复现过程（传 nil 即清空）。
func (d *DB) SetFindingReproduction(id int64, r *Reproduction) (int64, error) {
	val, err := r.Encode()
	if err != nil {
		return 0, err
	}
	res, err := d.Exec(`UPDATE findings SET reproduction=$1 WHERE id=$2`, val, id)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// GetFindingReproduction 读回复现过程（nil = 未登记）。
func (d *DB) GetFindingReproduction(id int64) (*Reproduction, error) {
	var raw sql.NullString
	err := d.QueryRow(`SELECT reproduction FROM findings WHERE id=$1`, id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return DecodeReproduction(raw), nil
}
