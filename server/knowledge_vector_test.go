package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// 假 embedder：把文本映射成 3 维词袋向量，保证"同一主题的文本向量相近"。
// 用它代替真供应商，测试才能断言"语义检索把相关的那篇排在第一"。
func fakeEmbedder(t *testing.T) *httptest.Server {
	t.Helper()
	vocab := []string{"越权", "注入", "上传"}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Input []string `json:"input"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		data := make([]map[string]any, len(req.Input))
		for i, s := range req.Input {
			vec := []float32{0.01, 0.01, 0.01}
			for d, kw := range vocab {
				if strings.Contains(s, kw) {
					vec[d] = 1
				}
			}
			data[i] = map[string]any{"index": i, "embedding": vec}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
	}))
}

// 语义链路（含真实 pgvector）：
// 建文档 → 建索引 → 向量检索把语义相近的那篇排第一 → 检索审计留痕。
//
// 若本机没有 pgvector，本用例 skip 而不是失败 —— 那条路径已有
// TestKnowledgeKeywordFallbackEndToEnd 覆盖（降级也必须能用）。
func TestKnowledgeSemanticEndToEnd(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	pg := s.m.pg
	if !pg.KnowledgeVectorAvailable() {
		t.Skip("pgvector 不可用，语义链路跳过（关键词降级路径由另一用例覆盖）")
	}

	emb := fakeEmbedder(t)
	defer emb.Close()

	if err := pg.SaveKnowledgeConfig(true, emb.URL, "fake-embed", "test-key", 3); err != nil {
		t.Fatalf("save config: %v", err)
	}
	t.Cleanup(func() { _ = pg.SaveKnowledgeConfig(false, emb.URL, "fake-embed", "", 3) })
	if !s.kb().SemanticReady() {
		t.Fatal("semantic should be ready with pgvector + enabled + key")
	}

	mk := func(title, cat, body string) int64 {
		id, err := pg.AddKnowledgeDoc(&db.KnowledgeDoc{
			Scope: "global", Category: cat, Title: title, Content: body,
		})
		if err != nil {
			t.Fatalf("add doc: %v", err)
		}
		if err := s.kb().IndexDoc(context.Background(), id); err != nil {
			t.Fatalf("index doc: %v", err)
		}
		return id
	}
	idor := mk("IDOR 越权要点", "越权", "替换对象 id 看能否读到他人数据。越权 越权")
	sqli := mk("SQL 注入判别", "注入", "单引号布尔对比。注入 注入")

	hits, mode, err := s.kb().Search(context.Background(), "越权 怎么测", 0, 5)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if mode != "semantic" {
		t.Fatalf("mode = %q, want semantic", mode)
	}
	if len(hits) == 0 || hits[0].DocID != idor {
		t.Fatalf("semantic search did not rank the on-topic doc first: %+v", hits)
	}
	// 不相关那篇不应排在前面
	if len(hits) > 1 && hits[0].DocID == sqli {
		t.Fatal("off-topic doc ranked first")
	}

	// 换模型后旧向量必须被忽略（防止换 embedder 串味）
	if err := pg.ReplaceKnowledgeChunks(idor, "other-model", 3, []db.KnowledgeChunkInsert{
		{Index: 0, Content: "越权", Embedding: []float32{1, 0, 0}},
	}); err != nil {
		t.Fatalf("re-write chunks with another model: %v", err)
	}
	hits2, _, err := s.kb().Search(context.Background(), "越权 怎么测", 0, 5)
	if err != nil {
		t.Fatalf("search after model swap: %v", err)
	}
	for _, h := range hits2 {
		if h.DocID == idor {
			t.Fatal("chunks from another embed model must be skipped")
		}
	}

	// 审计：SearchAndLog 应留下一条 semantic 记录
	_, _, _ = s.kb().SearchAndLog(context.Background(), "越权 怎么测", 0, 5, "worker")
	logs, err := pg.ListKnowledgeRetrievalLogs(5)
	if err != nil {
		t.Fatalf("logs: %v", err)
	}
	if len(logs) == 0 || logs[0].Mode != "semantic" || logs[0].AgentKey != "worker" {
		t.Fatalf("retrieval log not recorded: %+v", logs)
	}
}

// 重建索引：清空旧向量并把全部文档重新向量化。
func TestKnowledgeReindexRebuilds(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	pg := s.m.pg
	if !pg.KnowledgeVectorAvailable() {
		t.Skip("pgvector 不可用")
	}
	emb := fakeEmbedder(t)
	defer emb.Close()
	_ = pg.SaveKnowledgeConfig(true, emb.URL, "fake-embed", "test-key", 3)
	t.Cleanup(func() { _ = pg.SaveKnowledgeConfig(false, emb.URL, "fake-embed", "", 3) })

	id, _ := pg.AddKnowledgeDoc(&db.KnowledgeDoc{Scope: "global", Category: "越权", Title: "重建测试", Content: "越权测试内容"})
	t.Cleanup(func() { _ = pg.DeleteKnowledgeDoc(id) })

	n, err := s.kb().Reindex(context.Background())
	if err != nil {
		t.Fatalf("reindex: %v", err)
	}
	if n < 1 {
		t.Fatalf("reindex should cover at least one doc, got %d", n)
	}
	doc, _ := pg.GetKnowledgeDoc(id)
	if doc == nil || !doc.Indexed {
		t.Fatalf("doc not marked indexed after reindex: %+v", doc)
	}
}
