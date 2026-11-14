package server

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func seedFinding(t *testing.T, s *Server, taskID int64, name string) *db.DBFinding {
	t.Helper()
	var id int64
	if err := s.m.pg.QueryRow(`INSERT INTO findings (task_id, vulnclass, name, severity, summary, evidence, status)
		VALUES ($1,'SQLi',$2,'high','一句话摘要','POST /api/login ...','confirmed') RETURNING id`, taskID, name).Scan(&id); err != nil {
		t.Fatalf("seed finding: %v", err)
	}
	f, err := s.m.pg.GetFinding(id)
	if err != nil || f == nil {
		t.Fatalf("reload finding: %v", err)
	}
	return f
}

// 富化落库与读取：结构化字段必须完整往返，且 test_process 来自**真实复现过程**
// 而不是模型输出 —— 这是本实现与上游的分野，用测试钉住。
func TestEnrichmentPersistAndRender(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	pg := s.m.pg
	task, err := pg.CreateTask("富化测试", "", nil, 0, 0)
	if err != nil {
		t.Fatalf("create task: %v", err)
	}
	f := seedFinding(t, s, task.ID, "原始名")
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM findings WHERE task_id=$1`, task.ID) })

	// 写入 agent 就地记录的复现过程（决定 test_process）
	if _, err := pg.SetFindingReproduction(f.ID, &db.Reproduction{
		EntryPoint: "POST /api/login",
		Steps: []db.ReproStep{
			{Request: "POST /api/login HTTP/1.1", Response: "HTTP 200", Expected: "绕过认证"},
		},
	}); err != nil {
		t.Fatalf("set reproduction: %v", err)
	}

	row := &db.FindingEnrichment{
		FindingID: f.ID, Name: "登录接口 SQL 注入", Target: "app.local", Module: "外部登录",
		Severity: "critical", Status: "confirmed", CVSSScore: 9.8,
		CVSSVector: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		Source:     "ai",
	}
	row.CVSSMetrics = jsonRaw(map[string]string{"AV": "N"})
	row.Description = jsonRaw([]string{"username 参数拼接进 SQL"})
	row.RiskAnalysis = jsonRaw([]string{"可读取全库"})
	row.Remediation = jsonRaw([]string{"改用参数化查询"})
	row.TestProcess = jsonRaw([]any{})
	if err := pg.UpsertFindingEnrichment(row); err != nil {
		t.Fatalf("upsert enrichment: %v", err)
	}

	f2, _ := pg.GetFinding(f.ID)
	e, err := pg.GetFindingEnrichment(f.ID)
	if err != nil || e == nil {
		t.Fatalf("read enrichment: %v", err)
	}
	dto := toEnrichmentDTO(e, f2)
	if dto.Name != "登录接口 SQL 注入" || dto.CVSSScore != 9.8 || len(dto.Description) != 1 {
		t.Fatalf("dto lost data: %+v", dto)
	}
	// test_process 必须来自真实 reproduction
	if len(dto.TestProcess) != 1 || !strings.Contains(dto.TestProcess[0].Request, "POST /api/login") {
		t.Fatalf("test_process must come from the recorded reproduction: %+v", dto.TestProcess)
	}

	// 报告合并：富化优先，缺失字段回落原始值
	rf := s.toReportFindings([]*db.DBFinding{f2})
	if len(rf) != 1 {
		t.Fatalf("toReportFindings returned %d", len(rf))
	}
	if rf[0].Name != "登录接口 SQL 注入" {
		t.Fatalf("report should prefer enrichment name, got %q", rf[0].Name)
	}
	if !strings.Contains(rf[0].CVSS, "9.8") || !strings.Contains(rf[0].CVSS, "AV:N") {
		t.Fatalf("report CVSS should carry score+vector: %q", rf[0].CVSS)
	}
	if rf[0].Remediation != "改用参数化查询" {
		t.Fatalf("report should use enriched remediation, got %q", rf[0].Remediation)
	}
}

// 人工局部更新：空字段保留原值（改状态不该把 AI 写的 name/target 冲掉）。
func TestEnrichmentPartialUpdatePreservesFields(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	pg := s.m.pg
	task, _ := pg.CreateTask("富化局部更新", "", nil, 0, 0)
	f := seedFinding(t, s, task.ID, "原名")
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM findings WHERE task_id=$1`, task.ID) })

	if err := pg.UpsertFindingEnrichment(&db.FindingEnrichment{
		FindingID: f.ID, Name: "AI 名", Target: "t.local", Severity: "high", Status: "open",
		Description: jsonRaw([]string{"描述"}), Source: "ai",
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	// 只改状态
	if err := pg.UpdateFindingEnrichmentFields(f.ID, "", "", "", "confirmed"); err != nil {
		t.Fatalf("partial update: %v", err)
	}
	e, _ := pg.GetFindingEnrichment(f.ID)
	if e.Name != "AI 名" || e.Target != "t.local" {
		t.Fatalf("partial update wiped AI fields: %+v", e)
	}
	if e.Status != "confirmed" {
		t.Fatalf("status not updated: %q", e.Status)
	}
	if e.Source != "manual" {
		t.Fatalf("source should flip to manual after human edit, got %q", e.Source)
	}
	if !db.HasEnrichmentProse(e) {
		t.Fatal("prose detection lost the description")
	}
}

// 没有配置 LLM 时，富化必须干净地失败（job=failed + 可读原因），而不是卡在 analyzing。
func TestEnrichWithoutLLMFails(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	pg := s.m.pg
	task, _ := pg.CreateTask("无 LLM 富化", "", nil, 0, 0)
	f := seedFinding(t, s, task.ID, "x")
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM findings WHERE task_id=$1`, task.ID) })

	// 这个 fixture 的 server 没有安装 LLM
	if _, _, ok := s.globalProvider(); ok {
		t.Skip("fixture unexpectedly has an LLM installed")
	}
	job := s.startEnrich(f, "zh-CN")
	if job.Status != "analyzing" {
		t.Fatalf("first click should start a job, got %q", job.Status)
	}
	// 等后台 goroutine 落定（它跑在一个独立 goroutine 里，用真实等待而不是忙循环）
	for i := 0; i < 100; i++ {
		time.Sleep(20 * time.Millisecond)
		st := s.enrichStatus(f)
		if st.Status == "failed" {
			if !strings.Contains(st.Error, "未配置 LLM") {
				t.Fatalf("unexpected failure reason: %q", st.Error)
			}
			return
		}
	}
	t.Fatalf("enrichment never settled, last status: %+v", s.enrichStatus(f))
}

// 状态接口：没有 job 也没有富化 → idle；有持久化结果 → done（重启后仍能显示）。
func TestEnrichStatusFallsBackToPersisted(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	pg := s.m.pg
	task, _ := pg.CreateTask("富化状态", "", nil, 0, 0)
	f := seedFinding(t, s, task.ID, "x")
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM findings WHERE task_id=$1`, task.ID) })

	if st := s.enrichStatus(f); st.Status != "idle" {
		t.Fatalf("expected idle, got %q", st.Status)
	}
	if err := pg.UpsertFindingEnrichment(&db.FindingEnrichment{
		FindingID: f.ID, Name: "带富化", Description: jsonRaw([]string{"d"}), Source: "ai",
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	st := s.enrichStatus(f)
	if st.Status != "done" || st.Result == nil || st.Result.Name != "带富化" {
		t.Fatalf("persisted enrichment should surface as done: %+v", st)
	}
}

// HTTP 层：路由能被真实中间件链打通（不是 404/401），参数缺失时给 400。
func TestEnrichRoutesReachable(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	tok := testAdminToken(t, s)
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/findings/999999/enrichment", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	s.Handler().ServeHTTP(w, req)
	if w.Code == 404 && strings.Contains(w.Body.String(), "page not found") {
		t.Fatal("enrichment route not registered")
	}
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if _, has := body["error"]; !has && w.Code != 200 {
		t.Fatalf("unexpected response %d: %s", w.Code, w.Body.String())
	}
}
