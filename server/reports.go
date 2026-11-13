package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/report"
)

// 本文件实现「交付级报告」的服务端：组织级报告设置、按任务生成 .docx、报告列表与下载。
//
// 和上游的关键差别：上游的报告正文由一次 LLM 调用现写（每次出报告内容都不一样，且必须
// 有可用的模型），这里只渲染【库里已有的确定事实】—— 漏洞字段、证据、关联流量、范围。
// 同一份数据任何时候渲染出来都一样，这是"能交付"的前提（客户会拿报告逐条复核）。
// 想补充叙述性文字？那是富化字段的职责（findings.impact / remediation / report），
// 人工或 agent 先写进库，报告只负责排版。

// reportDir 是报告文件的存放目录（<dataDir>/reports）。与数据目录同卷，
// 备份/迁移时跟着走，不需要单独的挂载点。
func (s *Server) reportDir() string { return filepath.Join(s.m.dir, "reports") }

// ---------------- 设置 ----------------

type reportSettingsReq struct {
	Company      string            `json:"company"`
	Client       string            `json:"client"`
	Confidential string            `json:"confidential"`
	Lang         string            `json:"lang"`
	Version      string            `json:"version"`
	People       []db.ReportPerson `json:"people"`
}

// getReportSettings 返回组织级报告设置。从未保存过时返回默认值 + configured=false，
// 前端据此展示"尚未配置"而不是报错。
func (s *Server) getReportSettings(w http.ResponseWriter, r *http.Request) {
	st, err := s.m.pg.GetReportSettings()
	if err != nil && err != db.ErrReportSettingsMissing {
		writeErr(w, 500, err.Error())
		return
	}
	configured := err == nil
	writeJSON(w, 200, map[string]any{
		"configured":   configured,
		"company":      st.Company,
		"client":       st.Client,
		"confidential": st.Confidential,
		"lang":         st.Lang,
		"version":      st.Version,
		"people":       st.People,
		"updated_at":   st.UpdatedAt,
	})
}

// putReportSettings 保存设置（整表覆盖语义：前端总是提交完整表单）。
func (s *Server) putReportSettings(w http.ResponseWriter, r *http.Request) {
	var req reportSettingsReq
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	lang := string(report.NormalizeLang(req.Lang))
	st := &db.ReportSettings{
		Company:      strings.TrimSpace(req.Company),
		Client:       strings.TrimSpace(req.Client),
		Confidential: strings.TrimSpace(req.Confidential),
		Lang:         lang,
		Version:      strings.TrimSpace(req.Version),
	}
	if st.Version == "" {
		st.Version = "v1.0"
	}
	for _, p := range req.People {
		p.Name = strings.TrimSpace(p.Name)
		if p.Name == "" {
			continue // 空行是前端"加一行"留下的，不落库
		}
		st.People = append(st.People, db.ReportPerson{
			Name: p.Name, Role: strings.TrimSpace(p.Role), Contact: strings.TrimSpace(p.Contact),
		})
	}
	if err := s.m.pg.SaveReportSettings(st); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "lang": lang})
}

// ---------------- 生成 ----------------

type generateReportReq struct {
	TaskID     string  `json:"task_id"`
	Title      string  `json:"title"`
	Lang       string  `json:"lang"`
	FindingIDs []int64 `json:"finding_ids"` // 空 = 该任务全部漏洞
}

// generateReport 生成一份 .docx 并落库。
//
// 为什么同步生成：docx 是纯 Go 渲染（毫秒级），没有 python 子进程、也没有 LLM 调用，
// 同步返回可以立刻把"生成成功 + 文件大小 + 漏洞数"告诉用户；异步队列只会让失败更难定位。
// buildReportForTask 是生成流程的核心（handler 只负责解析参数/写响应）：
// 取设置 → 取漏洞 → 渲染 docx → 落盘 → 落库。抽出来是为了能被测试直接驱动，
// 也因为这段逻辑里每一步失败都该有明确错误，而不是混在 HTTP 处理里。
func (s *Server) buildReportForTask(taskID int64, onlyIDs []int64, reqLang, reqTitle string) (*db.Report, error) {
	task, err := s.m.pg.GetTask(taskID)
	if err != nil {
		return nil, err
	}
	if task == nil {
		return nil, fmt.Errorf("task %d not found", taskID)
	}
	settings, serr := s.m.pg.GetReportSettings()
	if serr != nil && serr != db.ErrReportSettingsMissing {
		return nil, serr
	}
	lang := report.NormalizeLang(firstNonBlank(reqLang, settings.Lang))

	findings, err := s.reportFindings(taskID, onlyIDs)
	if err != nil {
		return nil, err
	}
	assets := s.reportTaskAssets(taskID)
	in := report.DocInput{
		TaskTitle:   firstNonBlank(reqTitle, task.Name, task.Description),
		Goal:        task.Goal,
		Scope:       s.reportScopeText(taskID),
		GeneratedAt: time.Now(),
		AssetCount:  len(assets),
		Assets:      assets,
		Settings: report.Settings{
			Company:      settings.Company,
			Client:       settings.Client,
			Confidential: settings.Confidential,
			Lang:         string(lang),
			Version:      settings.Version,
			People:       toReportPeople(settings.People),
		},
		Findings: s.toReportFindings(findings),
	}
	if !task.CreatedAt.IsZero() {
		in.StartedAt = task.CreatedAt
	}

	blob, err := report.RenderReport(in)
	if err != nil {
		return nil, fmt.Errorf("渲染报告失败: %w", err)
	}
	dir := s.reportDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	name := fmt.Sprintf("%s_%s_%s.docx",
		safeFileToken(firstNonBlank(reqTitle, task.Name, fmt.Sprintf("task-%d", taskID))),
		string(lang), time.Now().Format("20060102-150405"))
	rel := filepath.Join("reports", name)
	if err := os.WriteFile(filepath.Join(s.m.dir, rel), blob, 0o644); err != nil {
		return nil, err
	}
	rec, err := s.m.pg.CreateReport(&db.Report{
		TaskID: &taskID, Title: in.TaskTitle, Lang: string(lang),
		FilePath: rel, FileName: name, SizeBytes: int64(len(blob)), FindingsCount: len(in.Findings),
	})
	if err != nil {
		_ = os.Remove(filepath.Join(s.m.dir, rel)) // 记录失败就别留孤儿文件
		return nil, err
	}
	log.Printf("[report] 已生成报告 #%d task=%d lang=%s findings=%d size=%dB", rec.ID, taskID, lang, len(in.Findings), len(blob))
	return rec, nil
}

// generateReport 解析请求、生成、返回记录。同步生成：docx 是纯 Go 渲染（无 python
// 子进程、无 LLM 调用），毫秒级返回，直接给出"文件大小 + 漏洞数"比异步轮询更好定位失败。
func (s *Server) generateReport(w http.ResponseWriter, r *http.Request) {
	var req generateReportReq
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	taskID := int64(atoiDefault(req.TaskID, 0))
	if taskID <= 0 {
		writeErr(w, 400, "task_id 必填")
		return
	}
	rec, err := s.buildReportForTask(taskID, req.FindingIDs, req.Lang, req.Title)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeErr(w, 404, err.Error())
			return
		}
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, rec)
}

// reportFindings 取报告用的漏洞（含 report/cvss/impact/remediation 完整字段）。
func (s *Server) reportFindings(taskID int64, ids []int64) ([]*db.DBFinding, error) {
	f := db.FindingFilter{TaskID: strconv.FormatInt(taskID, 10)}
	if len(ids) > 0 {
		return s.m.pg.ListFindingsForExport(db.FindingFilter{}, ids)
	}
	return s.m.pg.ListFindingsForExport(f, nil)
}

// toReportFindings 把库里的漏洞翻成报告结构。
func (s *Server) toReportFindings(fs []*db.DBFinding) []report.Finding {
	out := make([]report.Finding, 0, len(fs))
	// 资产 id → 可读名，一次性解析（报告里写 "app.local:8443" 而不是 "#37"）。
	var ids []int64
	for _, f := range fs {
		ids = append(ids, f.AssetIDs...)
	}
	assets := s.resolveAssetIDs(ids)
	for _, f := range fs {
		rf := report.Finding{
			ID: f.ID, Name: f.Name, VulnClass: f.VulnClass, Severity: f.Severity,
			Status: f.Status, CVSS: f.CVSS, Summary: f.Summary, Impact: f.Impact,
			Remediation: f.Remediation, Evidence: f.Evidence, Detail: f.Report,
			Traffic: trafficLines(f),
		}
		for _, aid := range f.AssetIDs {
			if a, ok := assets[aid]; ok {
				if label := reportAssetLabel(a); label != "" {
					rf.Assets = append(rf.Assets, label)
				}
			}
		}
		out = append(out, rf)
	}
	return out
}

// trafficLines 把关联流量压成 "GET https://host/path → 200" 形式的一行一条。
func trafficLines(f *db.DBFinding) []string {
	out := make([]string, 0, len(f.TrafficBindings))
	for _, b := range f.TrafficBindings {
		line := strings.TrimSpace(b.Snapshot.Method + " " + b.Snapshot.URL)
		if b.Snapshot.Status > 0 {
			line += fmt.Sprintf(" → %d", b.Snapshot.Status)
		}
		if b.Role != "" {
			line += "（" + b.Role + "）"
		}
		if line != "" {
			out = append(out, strings.TrimSpace(line))
		}
	}
	return out
}

// reportAssetLabel 复用 dto.go 的 assetLabel（它对 app/endpoint/domain/ip 各类资产都
// 给了可读形式），只额外压掉空值 —— 报告里写 "app.local:8443" 而不是 "#37"。
func reportAssetLabel(a *db.Asset) string {
	if a == nil {
		return ""
	}
	return strings.TrimSpace(assetLabel(a))
}

// reportTaskAssets 返回任务的资产标识列表（报告"范围"与"附录"用）。
func (s *Server) reportTaskAssets(taskID int64) []string {
	list, err := s.m.pg.Assets().QueryByTask(taskID, "", 500, 0)
	if err != nil {
		log.Printf("[report] 读取任务资产失败: %v", err)
		return nil
	}
	out := make([]string, 0, len(list))
	for _, a := range list {
		if l := reportAssetLabel(a); l != "" {
			out = append(out, l)
		}
	}
	sort.Strings(out)
	return out
}

// reportScopeText 把任务声明的测试范围（task_scope）渲染成多行文本。
func (s *Server) reportScopeText(taskID int64) string {
	rows, err := s.m.pg.Query(`SELECT kind,
		COALESCE(domain, ''), COALESCE(net::text, ''), COALESCE(value, ''),
		COALESCE((SELECT name FROM companies c WHERE c.id = task_scope.company_id), '')
		FROM task_scope WHERE task_id=$1 ORDER BY id`, taskID)
	if err != nil {
		log.Printf("[report] 读取任务范围失败: %v", err)
		return ""
	}
	defer rows.Close()
	var lines []string
	for rows.Next() {
		var kind, domain, net, value, company string
		if err := rows.Scan(&kind, &domain, &net, &value, &company); err != nil {
			continue
		}
		switch kind {
		case "company":
			if company != "" {
				lines = append(lines, company)
			}
		case "root_domain", "subdomain":
			if domain != "" {
				lines = append(lines, domain)
			}
		case "ip", "cidr":
			if net != "" {
				lines = append(lines, net)
			}
		default:
			if value != "" {
				lines = append(lines, value)
			}
		}
	}
	return strings.Join(lines, "\n")
}

func toReportPeople(ps []db.ReportPerson) []report.Person {
	out := make([]report.Person, 0, len(ps))
	for _, p := range ps {
		out = append(out, report.Person{Name: p.Name, Role: p.Role, Contact: p.Contact})
	}
	return out
}

// ---------------- 列表 / 下载 / 删除 ----------------

func (s *Server) listReports(w http.ResponseWriter, r *http.Request) {
	taskID := int64(atoiDefault(r.URL.Query().Get("task_id"), 0))
	list, err := s.m.pg.ListReports(taskID, 200)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"reports": list})
}

// downloadReport 以附件形式返回 .docx。逐段 ServeFile 而不是整块读进内存：
// 报告文件可能几 MB，且要支持浏览器的断点/范围请求。
func (s *Server) downloadReport(w http.ResponseWriter, r *http.Request) {
	id := int64(atoiDefault(r.PathValue("id"), 0))
	if id <= 0 {
		writeErr(w, 400, "bad report id")
		return
	}
	rec, err := s.m.pg.GetReport(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if rec == nil {
		writeErr(w, 404, "report not found")
		return
	}
	// 路径来自我们自己的写入，但仍按"只允许 reports 目录内的相对路径"复核一次：
	// DB 一旦被写入脏数据，这里不该变成任意文件读取。
	if !filepath.IsLocal(rec.FilePath) {
		writeErr(w, 400, "报告路径非法")
		return
	}
	full := filepath.Join(s.m.dir, rec.FilePath)
	f, err := os.Open(full)
	if err != nil {
		writeErr(w, 404, "报告文件不存在（可能已被清理），请重新生成")
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, rec.FileName))
	w.Header().Set("X-Report-Id", strconv.FormatInt(rec.ID, 10))
	http.ServeContent(w, r, rec.FileName, st.ModTime(), f)
}

func (s *Server) deleteReport(w http.ResponseWriter, r *http.Request) {
	id := int64(atoiDefault(r.PathValue("id"), 0))
	if id <= 0 {
		writeErr(w, 400, "bad report id")
		return
	}
	rec, err := s.m.pg.GetReport(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if rec == nil {
		writeErr(w, 404, "report not found")
		return
	}
	if _, err := s.m.pg.DeleteReport(id); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if filepath.IsLocal(rec.FilePath) {
		_ = os.Remove(filepath.Join(s.m.dir, rec.FilePath))
	}
	writeJSON(w, 200, map[string]any{"deleted": id})
}

// ---------------- 小工具 ----------------

func firstNonBlank(v ...string) string {
	for _, s := range v {
		if strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

// safeFileToken 把任意标题压成安全的文件名片段（保留中日韩字符，剔除路径分隔符）。
func safeFileToken(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '/' || r == '\\' || r == ':' || r == '*' || r == '?' || r == '"' || r == '<' || r == '>' || r == '|':
			b.WriteRune('_')
		case r < 0x20:
			// skip
		default:
			b.WriteRune(r)
		}
	}
	out := strings.TrimSpace(b.String())
	if len([]rune(out)) > 60 {
		out = string([]rune(out)[:60])
	}
	if out == "" {
		out = "report"
	}
	return out
}

// 下面两个占位用于编译期确认 sql 包在本文件仍被引用（reportFindings 走 store API，
// 但后续若加"按 id 直查"会用到）。保持最小依赖，不做无意义 import。
var _ = sql.ErrNoRows
var _ = context.Background
var _ = json.Marshal
