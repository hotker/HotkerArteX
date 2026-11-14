package server

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// 去重键必须忽略空白与大小写：同一个漏洞不该因为"SQL注入 / SQL 注入"被补两遍。
func TestDedupKeyNormalizes(t *testing.T) {
	pairs := [][2]string{
		{"SQL注入", "SQL 注入"},
		{"sql注入", "SQL注入"},
		{"越权\u3000访问", "越权访问"},
	}
	for _, p := range pairs {
		a := dedupKey(p[0], "登录接口注入")
		b := dedupKey(p[1], "登录接口 注入")
		if a != b {
			t.Fatalf("dedupKey should treat %q and %q alike: %q vs %q", p[0], p[1], a, b)
		}
	}
	if dedupKey("SQL注入", "A") == dedupKey("越权", "A") {
		t.Fatal("different classes must not collide")
	}
}

// 已有漏洞清单要能读到（去重的依据），且事实/转录为空时给出明确 400 而不是空跑。
func TestExtractGuardsEmptyTask(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	task, _ := s.m.pg.CreateTask("空任务", "", nil, 0, 0)
	t.Cleanup(func() { _, _ = s.m.pg.Exec(`DELETE FROM tasks WHERE id=$1`, task.ID) })

	req := httptest.NewRequest("POST", fmt.Sprintf("/api/tasks/%d/extract-findings", task.ID), nil)
	req.SetPathValue("id", fmt.Sprint(task.ID))
	rec := httptest.NewRecorder()
	s.extractFindings(rec, req)
	// 空内容 与 未配置 LLM 都是 400，但要给出**说得清**的原因（不是空跑）。
	if rec.Code != 400 {
		t.Fatalf("empty task should be rejected with 400, got %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "暂无可分析") && !strings.Contains(body, "未配置 LLM") {
		t.Fatalf("error should explain why: %s", body)
	}
}

// existingFindingDigest 要把该任务的漏洞列出来（模型据此不重复补），并且键归一。
func TestExistingFindingDigest(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	pg := s.m.pg
	task, _ := pg.CreateTask("有漏洞的任务", "", nil, 0, 0)
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM findings WHERE task_id=$1`, task.ID); _, _ = pg.Exec(`DELETE FROM tasks WHERE id=$1`, task.ID) })

	if _, err := pg.AddFinding(task.ID, 0, "SQL注入", "登录接口注入", "high", "摘要", "证据", "worker", nil); err != nil {
		t.Fatalf("add finding: %v", err)
	}
	text, keys := s.existingFindingDigest(task.ID)
	if !strings.Contains(text, "登录接口注入") {
		t.Fatalf("digest should list existing findings: %q", text)
	}
	if !keys[dedupKey("SQL注入", "登录接口注入")] {
		t.Fatalf("dedup key missing for existing finding: %v", keys)
	}
	if len(keys) != 1 {
		t.Fatalf("expected exactly one key, got %d", len(keys))
	}
}

// 事实摘要要把 explore 图里未升级的 fact 带出来（那是"漏记"的主要来源）。
func TestTaskFactDigestIncludesFacts(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	pg := s.m.pg
	task, _ := pg.CreateTask("带事实的任务", "", nil, 0, 0)
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM tasks WHERE id=$1`, task.ID) })

	es := pg.Exploration(task.ExplorationID)
	if _, err := es.AddNode(db.KindFact, map[string]any{
		"summary": "发现 /admin 未授权可访问",
		"detail":  "/admin 直接 200，含用户列表",
	}, 0, "confirmed", "worker", nil); err != nil {
		t.Fatalf("add fact node: %v", err)
	}
	digest := s.taskFactDigest(task.ID)
	if !strings.Contains(digest, "未授权") {
		t.Fatalf("fact digest should include recorded facts: %q", digest)
	}
}

// 转录必须能真的读到 activity 表的内容 —— 这条测试盯着真实表名与列名。
// （首版把表名写成了 exploration_activities，单测没覆盖到，实机联调才暴露：
// 转录永远为空，补录对"没落 fact 的漏洞"完全失效。）
func TestTaskTranscriptReadsActivities(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	pg := s.m.pg
	task, _ := pg.CreateTask("有转录", "", nil, 0, 0)
	t.Cleanup(func() {
		_, _ = pg.Exec(`DELETE FROM activity WHERE exploration_id=$1`, task.ExplorationID)
		_, _ = pg.Exec(`DELETE FROM tasks WHERE id=$1`, task.ID)
	})

	if _, err := pg.Exec(`INSERT INTO activity (exploration_id, kind, tool, detail)
		VALUES ($1,'tool_use','http_request','POST /api/login HTTP/1.1 -> 500 SQL syntax error')`,
		task.ExplorationID); err != nil {
		t.Fatalf("seed activity: %v", err)
	}
	tr := s.taskTranscript(task.ID)
	if !strings.Contains(tr, "SQL syntax error") {
		t.Fatalf("transcript should read the activity table, got %q", tr)
	}
	if !strings.Contains(tr, "http_request") {
		t.Fatalf("transcript should label the tool, got %q", tr)
	}
}

// 转录为空但事实存在时，不该因为转录空就判定"无内容"。
func TestTaskTranscriptEmptyIsNotAnError(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	pg := s.m.pg
	task, _ := pg.CreateTask("空转录", "", nil, 0, 0)
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM tasks WHERE id=$1`, task.ID) })
	if tr := s.taskTranscript(task.ID); tr != "" {
		t.Fatalf("expected empty transcript, got %q", tr)
	}
}
