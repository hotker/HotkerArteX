package server

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// 知识库端到端：建文档 → 关键词检索（无 embedder 时的降级路径）→ 分类 → 删除。
// 关键契约是【没有 pgvector / 没有 embedder 也照常能查】——那是绝大多数部署的现状。
func TestKnowledgeKeywordFallbackEndToEnd(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	pg := s.m.pg
	kb := s.kb()

	// 确保语义层是关的（本测试专门验证降级路径）
	_ = pg.SaveKnowledgeConfig(false, "", "", "", 0)
	if kb.SemanticReady() {
		t.Skip("embedder unexpectedly ready; keyword fallback path not exercised")
	}

	global, err := pg.AddKnowledgeDoc(&db.KnowledgeDoc{
		Scope: "global", Category: "越权", Title: "IDOR 测试要点",
		Content: "把别人对象的 id 替换成自己的 id，观察是否返回他人数据。注意区分 200 与 403。",
	})
	if err != nil {
		t.Fatalf("add global doc: %v", err)
	}
	other, err := pg.AddKnowledgeDoc(&db.KnowledgeDoc{
		Scope: "global", Category: "注入", Title: "SQL 注入判别",
		Content: "单引号 + 布尔对比是最快的判别方式。",
	})
	if err != nil {
		t.Fatalf("add doc2: %v", err)
	}
	t.Cleanup(func() {
		_ = pg.DeleteKnowledgeDoc(global)
		_ = pg.DeleteKnowledgeDoc(other)
	})

	hits, mode, err := kb.Search(context.Background(), "IDOR", 0, 5)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if mode != "keyword" {
		t.Fatalf("mode = %q, want keyword (no embedder)", mode)
	}
	if len(hits) == 0 || hits[0].Title != "IDOR 测试要点" {
		t.Fatalf("keyword search did not rank the right doc: %+v", hits)
	}
	// 标题命中应高于正文命中（打分规则：title 1.0 / category 0.8 / else 0.5）
	hits2, _, _ := kb.Search(context.Background(), "越权", 0, 5)
	if len(hits2) > 0 && hits2[0].Title != "IDOR 测试要点" {
		t.Fatalf("category match should rank the IDOR doc first: %+v", hits2)
	}

	cats, err := kb.Categories(0)
	if err != nil {
		t.Fatalf("categories: %v", err)
	}
	if !strings.Contains(strings.Join(cats, ","), "越权") {
		t.Fatalf("category missing: %v", cats)
	}

	// 空 query 不该报错，返回空结果
	if h, _, err := kb.Search(context.Background(), "   ", 0, 5); err != nil || len(h) != 0 {
		t.Fatalf("blank query should be a no-op: %v %v", h, err)
	}
}

// 任务范围：全局文档对任何任务可见；别的任务的文档不可见。
func TestKnowledgeTaskScopeIsolation(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	pg := s.m.pg

	taskA, err := pg.CreateTask("知识A", "", nil, 0, 0)
	if err != nil {
		t.Fatalf("create task A: %v", err)
	}
	taskB, _ := pg.CreateTask("知识B", "", nil, 0, 0)

	mk := func(taskID int64, title, content string) int64 {
		id := taskID
		docID, err := pg.AddKnowledgeDoc(&db.KnowledgeDoc{
			Scope: "task", TaskID: &id, Category: "范围", Title: title, Content: content,
		})
		if err != nil {
			t.Fatalf("add task doc: %v", err)
		}
		return docID
	}
	a := mk(taskA.ID, "A 任务授权范围", "只允许测试 10.0.0.0/24")
	b := mk(taskB.ID, "B 任务授权范围", "只允许测试 192.168.0.0/24")
	t.Cleanup(func() {
		_ = pg.DeleteKnowledgeDoc(a)
		_ = pg.DeleteKnowledgeDoc(b)
	})

	hits, _, err := s.kb().Search(context.Background(), "授权范围", taskA.ID, 10)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	sawA, sawB := false, false
	for _, h := range hits {
		if h.DocID == a {
			sawA = true
		}
		if h.DocID == b {
			sawB = true
		}
	}
	if !sawA {
		t.Fatal("task A should see its own knowledge")
	}
	if sawB {
		t.Fatal("task A must NOT see task B's knowledge")
	}
}

// 上传接口：任务范围但没给 task_id 必须被拒（否则会静默落成孤儿）。
func TestKnowledgeCreateRejectsTaskScopeWithoutTask(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	_ = s
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/knowledge", strings.NewReader(`{"scope":"task","title":"x","content":"y"}`))
	req.Header.Set("Content-Type", "application/json")
	s.createKnowledge(rec, req)
	if rec.Code != 400 {
		t.Fatalf("expected 400 for task scope without task_id, got %d: %s", rec.Code, rec.Body.String())
	}
}
