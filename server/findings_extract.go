package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/report"
)

// 会话漏洞补录（POST /api/tasks/{id}/extract-findings）。
//
// 解决的问题很具体：agent 可能把问题写在回复里、或在探索图里记了 fact，却没调用
// report_finding 把它升级成漏洞 —— 于是报告里少了它，而人往往在生成报告时才发现。
// 这里把「会话记录 + 探索图事实」一起喂给模型，让它把**已验证但未落库**的补出来。
//
// 三道闸门，缺一不可（AI 补录最容易出的问题就是幻觉与重复）：
//  1. 提示层要求只补有实际请求/响应支撑的；
//  2. 解析层丢弃没有 evidence 的条目（写在提示里不算，代码里才算）；
//  3. 落库层按「类型+名称」去重，已有的不重复补。
type extractRequest struct {
	DryRun bool   `json:"dry_run"` // 只看会补什么，不落库（前端先预览）
	Lang   string `json:"lang"`
}

func (s *Server) extractFindings(w http.ResponseWriter, r *http.Request) {
	taskID := pathIntOr(r, "id")
	if taskID <= 0 {
		writeErr(w, 400, "无效的任务 id")
		return
	}
	task, err := s.m.pg.GetTask(taskID)
	if err != nil || task == nil {
		writeErr(w, 404, "任务不存在")
		return
	}
	var req extractRequest
	_ = decode(r, &req) // 允许空 body

	transcript := s.taskTranscript(taskID)
	facts := s.taskFactDigest(taskID)
	if strings.TrimSpace(transcript) == "" && strings.TrimSpace(facts) == "" {
		writeErr(w, 400, "该任务暂无可分析的内容（没有会话记录也没有已记录的事实）")
		return
	}
	existing, existingNames := s.existingFindingDigest(taskID)

	complete, err := s.reportComplete()
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	raw, err := complete(ctx,
		report.ExtractSystemPrompt(),
		report.ExtractUserPrompt(transcript, facts, existing, orDefault(req.Lang, "zh-CN")),
		5000)
	if err != nil {
		writeErr(w, 502, "AI 调用失败："+err.Error())
		return
	}
	got, err := report.ParseExtracted(raw)
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}

	// 去重：已落库的「类型+名称」不重复补。用归一化的 key，避免"SQL注入"/"SQL 注入"各补一条。
	type kept struct {
		report.ExtractedFinding
		Duplicate bool `json:"duplicate"`
	}
	out := make([]kept, 0, len(got))
	for _, f := range got {
		k := dedupKey(f.VulnClass, f.Name)
		dup := existingNames[k]
		out = append(out, kept{ExtractedFinding: f, Duplicate: dup})
	}

	if req.DryRun {
		writeJSON(w, 200, map[string]any{"findings": out, "created": 0, "dry_run": true})
		return
	}

	created := 0
	var ids []int64
	for _, f := range out {
		if f.Duplicate {
			continue
		}
		id, err := s.m.pg.AddFinding(taskID, 0, f.VulnClass, f.Name, f.Severity, f.Summary, f.Evidence, "extract", nil)
		if err != nil {
			log.Printf("[extract] task %d 补录失败: %v", taskID, err)
			continue
		}
		// 补录出来的漏洞状态是 pending（待确认）—— 它来自模型推断的"转录里有证据"，
		// 但人还没看过。直接标 confirmed 会让未经复核的东西进报告。
		ids = append(ids, id)
		created++
	}
	s.auditFrom(r, "", "finding", "extract", "success",
		fmt.Sprintf("会话补录：任务 #%d 新增 %d 条漏洞", taskID, created),
		map[string]any{"task_id": taskID, "created": created, "candidates": len(got)})
	writeJSON(w, 200, map[string]any{
		"findings": out, "created": created, "ids": ids, "existing": len(existingNames),
	})
}

// taskTranscript 取任务的可分析会话记录（worker 的分析与工具调用摘要）。
//
// 只取"发生了什么"：工具调用、请求/响应摘要、分析文本。不取原始思维链 —— 它又长又噪声，
// 而补录需要的是事实而不是推理过程。
func (s *Server) taskTranscript(taskID int64) string {
	rows, err := s.m.pg.Query(`SELECT kind, COALESCE(tool,''), COALESCE(detail,'')
		FROM activity WHERE exploration_id = (
			SELECT exploration_id FROM tasks WHERE id = $1
		) AND kind IN ('tool_use','tool_result','text') ORDER BY id DESC LIMIT 400`, taskID)
	if err != nil {
		return ""
	}
	defer rows.Close()
	var b strings.Builder
	for rows.Next() {
		var kind, tool, detail string
		if err := rows.Scan(&kind, &tool, &detail); err != nil {
			continue
		}
		detail = strings.TrimSpace(detail)
		if detail == "" {
			continue
		}
		if r := []rune(detail); len(r) > 800 {
			detail = string(r[:800]) + "…"
		}
		fmt.Fprintf(&b, "[%s %s] %s\n", kind, tool, detail)
		if b.Len() > 60000 {
			break
		}
	}
	return b.String()
}

// taskFactDigest 把探索图里的 fact 节点压成一段清单。
//
// 为什么单独喂 fact：worker 用 record_fact 记下的暴露/信息泄露，很多时候没被升级成
// 漏洞 —— 而它们恰恰是"报告漏了东西"的主要来源。
func (s *Server) taskFactDigest(taskID int64) string {
	task, err := s.m.pg.GetTask(taskID)
	if err != nil || task == nil {
		return ""
	}
	nodes, err := s.m.pg.Exploration(task.ExplorationID).ListByKind(db.KindFact, 200)
	if err != nil || len(nodes) == 0 {
		return ""
	}
	var b strings.Builder
	for _, n := range nodes {
		var p struct {
			Summary string `json:"summary"`
			Detail  string `json:"detail"`
		}
		_ = json.Unmarshal(n.Payload, &p)
		sum := strings.TrimSpace(p.Summary)
		if sum == "" {
			continue
		}
		d := strings.TrimSpace(p.Detail)
		if r := []rune(d); len(r) > 200 {
			d = string(r[:200]) + "…"
		}
		fmt.Fprintf(&b, "- %s", sum)
		if d != "" {
			fmt.Fprintf(&b, "：%s", d)
		}
		b.WriteString("\n")
	}
	return b.String()
}

// existingFindingDigest 返回已落库漏洞的清单文本 + 归一化去重集合。
func (s *Server) existingFindingDigest(taskID int64) (string, map[string]bool) {
	list, _, err := s.m.pg.ListFindingsPage(db.FindingFilter{TaskID: fmt.Sprint(taskID)}, 1, 500)
	if err != nil {
		return "", map[string]bool{}
	}
	var b strings.Builder
	keys := map[string]bool{}
	for _, f := range list {
		fmt.Fprintf(&b, "- [%s] %s：%s\n", f.Severity, orDefault(f.VulnClass, "-"), orDefault(f.Name, "-"))
		keys[dedupKey(f.VulnClass, f.Name)] = true
	}
	return b.String(), keys
}

// dedupKey 归一化「类型+名称」：去掉空白与大小写差异，避免同一个漏洞补两遍。
func dedupKey(vulnClass, name string) string {
	norm := func(s string) string {
		var b strings.Builder
		for _, r := range strings.ToLower(s) {
			if r == ' ' || r == '\t' || r == '\n' || r == '\u3000' {
				continue
			}
			b.WriteRune(r)
		}
		return b.String()
	}
	return norm(vulnClass) + "|" + norm(name)
}

func orDefault(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}
