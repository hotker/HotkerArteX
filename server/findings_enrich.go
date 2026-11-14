package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/report"
	"github.com/Autumn-27/norma/llm"
)

// 漏洞 AI 富化的服务端编排：异步 job + 状态轮询 + 落库。
//
// 为什么异步：一次富化是一次完整 LLM 往返（几秒到几十秒）。同步会卡住页面，
// 超时还会让用户以为"点了没反应"。这里立即返回 analyzing，前端轮询；
// 重复点击**复用**正在跑的那个 job，不会并发打两次同样的请求。
//
// job 状态只放内存：它是"这次点击的进度"，不是数据。真正的结果落 finding_enrichment，
// 所以重启后 GET status 会从库里读回已完成的结果（见 enrichStatus）。

type enrichJob struct {
	Status  string         `json:"status"` // idle | analyzing | done | failed
	Error   string         `json:"error,omitempty"`
	Result  *enrichmentDTO `json:"result,omitempty"`
	Started time.Time      `json:"started_at"`
	Ended   *time.Time     `json:"ended_at,omitempty"`
}

// enrichmentDTO 是回给前端的富化视图。
type enrichmentDTO struct {
	FindingID    int64             `json:"finding_id"`
	Name         string            `json:"name"`
	Target       string            `json:"target"`
	Module       string            `json:"module"`
	Severity     string            `json:"severity"`
	Status       string            `json:"status"`
	CVSSScore    float64           `json:"cvss_score"`
	CVSSVector   string            `json:"cvss_vector"`
	CVSSMetrics  map[string]string `json:"cvss_metrics"`
	Description  []string          `json:"description"`
	TestProcess  []reproStepDTO    `json:"test_process"` // 真实复现步骤（不由模型生成）
	RiskAnalysis []string          `json:"risk_analysis"`
	Remediation  []string          `json:"remediation"`
	Source       string            `json:"source"`
	UpdatedAt    string            `json:"updated_at,omitempty"`
}

type reproStepDTO struct {
	Request  string `json:"request,omitempty"`
	Response string `json:"response,omitempty"`
	Expected string `json:"expected,omitempty"`
	Proves   string `json:"proves,omitempty"`
}

// toEnrichmentDTO 把库里的行翻成前端视图，并把**真实的复现步骤**拼进来。
//
// 复现步骤不来自模型：优先 findings.reproduction（agent 就地记录），
// 退回到原始 PoC 文本。这条口径与报告渲染完全一致 —— 页面看到的步骤与报告里的一致。
func toEnrichmentDTO(e *db.FindingEnrichment, f *db.DBFinding) *enrichmentDTO {
	if e == nil {
		return nil
	}
	d := &enrichmentDTO{
		FindingID: e.FindingID, Name: e.Name, Target: e.Target, Module: e.Module,
		Severity: e.Severity, Status: e.Status, CVSSScore: e.CVSSScore, CVSSVector: e.CVSSVector,
		Source: e.Source, UpdatedAt: e.UpdatedAt.Format(time.RFC3339),
	}
	_ = json.Unmarshal(e.Description, &d.Description)
	_ = json.Unmarshal(e.RiskAnalysis, &d.RiskAnalysis)
	_ = json.Unmarshal(e.Remediation, &d.Remediation)
	if len(e.CVSSMetrics) > 0 {
		_ = json.Unmarshal(e.CVSSMetrics, &d.CVSSMetrics)
	}
	if f != nil {
		if r := f.Reproduction; r != nil {
			for _, st := range r.Steps {
				d.TestProcess = append(d.TestProcess, reproStepDTO{
					Request: st.Request, Response: st.Response, Expected: st.Expected, Proves: st.Proves,
				})
			}
		}
		if len(d.TestProcess) == 0 && strings.TrimSpace(f.Evidence) != "" {
			d.TestProcess = []reproStepDTO{{Request: f.Evidence}}
		}
	}
	return d
}

// enrichJobs 返回该 server 实例的 job 表（惰性初始化）。
// 放在 Server 上而不是包级：测试会并发起多个 Server，包级表会互相串。
func (s *Server) enrichJobs() map[int64]*enrichJob {
	s.enrichMu.Lock()
	defer s.enrichMu.Unlock()
	if s.enrichJobsMap == nil {
		s.enrichJobsMap = map[int64]*enrichJob{}
	}
	return s.enrichJobsMap
}

// startEnrich 起一次富化（或复用正在跑的那个）。返回当前 job 快照。
func (s *Server) startEnrich(f *db.DBFinding, lang string) enrichJob {
	jobs := s.enrichJobs()
	s.enrichMu.Lock()
	if j := jobs[f.ID]; j != nil && j.Status == "analyzing" {
		snap := *j
		s.enrichMu.Unlock()
		return snap
	}
	job := &enrichJob{Status: "analyzing", Started: time.Now()}
	jobs[f.ID] = job
	snap := *job
	s.enrichMu.Unlock()

	go s.runEnrich(f, lang)
	return snap
}

// runEnrich 在后台跑一次富化并把结果落库。用 server ctx，页面切换/断开都不会中断它。
func (s *Server) runEnrich(f *db.DBFinding, lang string) {
	fail := func(msg string) {
		jobs := s.enrichJobs()
		s.enrichMu.Lock()
		if j := jobs[f.ID]; j != nil {
			now := time.Now()
			j.Status, j.Error, j.Ended = "failed", msg, &now
		}
		s.enrichMu.Unlock()
		log.Printf("[enrich] finding=%d 失败: %s", f.ID, msg)
	}
	defer func() {
		if rec := recover(); rec != nil {
			fail(fmt.Sprintf("富化异常：%v", rec))
		}
	}()

	complete, err := s.reportComplete()
	if err != nil {
		fail(err.Error())
		return
	}
	in := report.EnrichInput{
		VulnClass: f.VulnClass, Severity: f.Severity, Summary: f.Summary,
		Evidence: f.Evidence, Transcript: s.enrichTranscript(f),
	}
	if f.Reproduction != nil {
		if raw, e := json.Marshal(f.Reproduction); e == nil {
			in.Reproduction = string(raw)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	raw, err := complete(ctx, report.EnrichSystemPrompt(""), report.EnrichUserPrompt(in, lang), 4000)
	if err != nil {
		fail("AI 调用失败：" + err.Error())
		return
	}
	enr, perr := report.ParseEnrichment(raw)
	if perr != nil || enr.Empty() {
		msg := "模型未返回可用内容（可能超时或被截断）"
		if perr != nil {
			msg = perr.Error()
		}
		fail(msg)
		return
	}

	row := &db.FindingEnrichment{
		FindingID: f.ID, Name: enr.Title, Target: enr.Target, Module: enr.Module,
		Severity: f.Severity, Status: statusOrDefault(f.Status),
		CVSSScore: enr.CVSSScore, CVSSVector: enr.CVSSVector,
		Source: "ai",
	}
	row.CVSSMetrics = jsonRaw(enr.CVSSMetrics)
	row.Description = jsonRaw(enr.Description)
	row.RiskAnalysis = jsonRaw(enr.RiskAnalysis)
	row.Remediation = jsonRaw(enr.Remediation)
	row.TestProcess = jsonRaw([]any{}) // 步骤由真实证据渲染，不存模型输出
	// 保留人工已定的处置状态（富化不该把"已确认"冲回"open"）
	if prev, _ := s.m.pg.GetFindingEnrichment(f.ID); prev != nil && prev.Status != "" {
		row.Status = prev.Status
	}
	if err := s.m.pg.UpsertFindingEnrichment(row); err != nil {
		fail("保存失败: " + err.Error())
		return
	}
	saved, _ := s.m.pg.GetFindingEnrichment(f.ID)
	dto := toEnrichmentDTO(saved, f)
	jobs := s.enrichJobs()
	s.enrichMu.Lock()
	if j := jobs[f.ID]; j != nil {
		now := time.Now()
		j.Status, j.Result, j.Ended = "done", dto, &now
	}
	s.enrichMu.Unlock()
	log.Printf("[enrich] finding=%d 完成（%d 段描述 / CVSS %.1f）", f.ID, len(enr.Description), enr.CVSSScore)
}

// enrichStatus 返回该漏洞的富化状态：优先活着的 job，否则从库里读已完成结果。
func (s *Server) enrichStatus(f *db.DBFinding) enrichJob {
	jobs := s.enrichJobs()
	s.enrichMu.Lock()
	j := jobs[f.ID]
	var snap *enrichJob
	if j != nil {
		cp := *j
		snap = &cp
	}
	s.enrichMu.Unlock()
	// 顺序很重要：
	//   1. 还活着（analyzing）→ 报进度；
	//   2. 已经失败 → 报失败原因（否则前端永远看不到"为什么没结果"，只会一直显示 idle）；
	//   3. 有持久化结果 → done（重启后也能读回）；
	//   4. 其余 → idle。
	if snap != nil && snap.Status == "analyzing" {
		return *snap
	}
	if snap != nil && snap.Status == "failed" {
		return *snap
	}
	if saved, _ := s.m.pg.GetFindingEnrichment(f.ID); saved != nil {
		return enrichJob{Status: "done", Result: toEnrichmentDTO(saved, f)}
	}
	return enrichJob{Status: "idle"}
}

// reportComplete 返回一次"纯文本补全"的函数（富化 / 报告叙述共用）。
//
// 用当前生效的 LLM（全局激活或任务链），不额外引入第四种选路：
// 富化是低频操作，为它单独做一套 provider 解析只会多一处漂移。
func (s *Server) reportComplete() (report.CompleteFunc, error) {
	prov, _, ok := s.globalProvider()
	if !ok || prov == nil {
		return nil, fmt.Errorf("未配置 LLM：请到「系统 → LLM」添加一个配置后再试")
	}
	model := ""
	s.cfgMu.Lock()
	model = s.llmCfg.Model
	s.cfgMu.Unlock()
	return func(ctx context.Context, system, user string, maxTokens int) (string, error) {
		req := llm.CompletionRequest{
			System:    []string{system},
			Messages:  []llm.Message{llm.UserText(user)},
			MaxTokens: maxTokens,
			Thinking:  "disabled",
		}
		_ = model
		msg, _, _, err := prov.Complete(ctx, req)
		if err != nil {
			return "", err
		}
		return msg.Text(), nil
	}, nil
}

// enrichTranscript 取该漏洞的"真实工作转录"喂给模型（可选，取不到就空）。
//
// 只取该漏洞来源意图的执行摘要，不拉整条会话：转录越大越贵，而富化只需要
// "当时看到了什么现象"。取不到不算错 —— 富化退化为纯摘要改写，仍然有用。
func (s *Server) enrichTranscript(f *db.DBFinding) string {
	if f.TaskID == nil || f.NodeID == nil {
		return ""
	}
	task, err := s.m.pg.GetTask(*f.TaskID)
	if err != nil || task == nil {
		return ""
	}
	acts, err := s.m.pg.Exploration(task.ExplorationID).ActivityTrace(*f.NodeID, 40)
	if err != nil || len(acts) == 0 {
		return ""
	}
	var b strings.Builder
	for _, a := range acts {
		switch a.Kind {
		case "tool_use", "tool_result", "text":
			d := strings.TrimSpace(a.Detail)
			if d == "" {
				continue
			}
			if r := []rune(d); len(r) > 600 {
				d = string(r[:600]) + "…"
			}
			fmt.Fprintf(&b, "[%s %s] %s\n", a.Kind, a.Tool, d)
		}
		if b.Len() > 12000 {
			break
		}
	}
	return b.String()
}

func statusOrDefault(s string) string {
	if strings.TrimSpace(s) == "" {
		return "open"
	}
	return s
}

func jsonRaw(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage("[]")
	}
	return b
}

// ---- HTTP ----

// POST /api/findings/{id}/enrich?lang=zh-CN —— 起一次（或复用）AI 富化。
// 立即返回 202 + analyzing；用 GET .../enrich/status 轮询。
func (s *Server) findingEnrich(w http.ResponseWriter, r *http.Request) {
	id := pathIntOr(r, "id")
	if id <= 0 {
		writeErr(w, 400, "无效的 finding id")
		return
	}
	f, err := s.m.pg.GetFinding(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if f == nil {
		writeErr(w, 404, "未找到漏洞")
		return
	}
	lang := strings.TrimSpace(r.URL.Query().Get("lang"))
	job := s.startEnrich(f, lang)
	s.auditFrom(r, "", "finding", "enrich", "success", fmt.Sprintf("触发漏洞 #%d 的 AI 富化", id), map[string]any{"finding_id": id})
	writeJSON(w, 202, job)
}

// GET /api/findings/{id}/enrich/status —— 轮询富化结果。
func (s *Server) findingEnrichStatus(w http.ResponseWriter, r *http.Request) {
	id := pathIntOr(r, "id")
	if id <= 0 {
		writeErr(w, 400, "无效的 finding id")
		return
	}
	f, err := s.m.pg.GetFinding(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if f == nil {
		writeErr(w, 404, "未找到漏洞")
		return
	}
	writeJSON(w, 200, s.enrichStatus(f))
}

// GET /api/findings/{id}/enrichment —— 直接读持久化的富化（不触发任何生成）。
func (s *Server) getFindingEnrichment(w http.ResponseWriter, r *http.Request) {
	id := pathIntOr(r, "id")
	if id <= 0 {
		writeErr(w, 400, "无效的 finding id")
		return
	}
	f, err := s.m.pg.GetFinding(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if f == nil {
		writeErr(w, 404, "未找到漏洞")
		return
	}
	e, err := s.m.pg.GetFindingEnrichment(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	resp := map[string]any{"enrichment": toEnrichmentDTO(e, f), "enriched": e != nil}
	if prev, _ := s.m.pg.GetFindingEnrichment(id); prev == nil {
		resp["enrichment"] = nil
	}
	writeJSON(w, 200, resp)
}

// PUT /api/findings/{id}/enrichment —— 人工编辑结构化字段（局部更新，空值保留原值）。
func (s *Server) updateFindingEnrichment(w http.ResponseWriter, r *http.Request) {
	id := pathIntOr(r, "id")
	if id <= 0 {
		writeErr(w, 400, "无效的 finding id")
		return
	}
	var req struct {
		Name     string `json:"name"`
		Target   string `json:"target"`
		Severity string `json:"severity"`
		Status   string `json:"status"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	if err := s.m.pg.UpdateFindingEnrichmentFields(id, req.Name, req.Target, req.Severity, req.Status); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.auditFrom(r, "", "finding", "update_enrichment", "success", fmt.Sprintf("编辑漏洞 #%d 的富化字段", id), map[string]any{"finding_id": id})
	f, _ := s.m.pg.GetFinding(id)
	e, _ := s.m.pg.GetFindingEnrichment(id)
	writeJSON(w, 200, map[string]any{"enrichment": toEnrichmentDTO(e, f)})
}

// pathIntOr 取路径里的整数参数（缺省 0）。
func pathIntOr(r *http.Request, name string) int64 {
	v, err := strconv.ParseInt(strings.TrimSpace(r.PathValue(name)), 10, 64)
	if err != nil {
		return 0
	}
	return v
}
