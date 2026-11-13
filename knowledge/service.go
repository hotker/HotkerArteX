package knowledge

import (
	"context"
	"fmt"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// Service 编排知识库的接入（分块 → 向量化 → 落库）与检索。
// 它只持有 *db.DB；embedder 配置每次调用现读，所以改配置不需要重启。
type Service struct{ pg *db.DB }

func NewService(pg *db.DB) *Service { return &Service{pg: pg} }

const (
	chunkChars   = 700
	chunkOverlap = 80
	embedBatch   = 16 // 每次 /embeddings 的输入条数（跨供应商的安全值）
)

// SemanticReady 报告能否跑向量检索：pgvector 存在 + 已启用 + 配了 key。
// false 时检索走关键词 —— 功能不消失，只是召回变弱。
func (s *Service) SemanticReady() bool {
	if s == nil || s.pg == nil || !s.pg.KnowledgeVectorAvailable() {
		return false
	}
	cfg, err := s.pg.GetKnowledgeConfig()
	if err != nil || cfg == nil {
		return false
	}
	return cfg.Enabled && strings.TrimSpace(cfg.APIKey) != ""
}

// Categories 列出可见分类（全局 + 给定任务）。
func (s *Service) Categories(taskID int64) ([]string, error) { return s.pg.ListKnowledgeCategories(taskID) }

func (s *Service) embedConfig() (EmbedConfig, error) {
	cfg, err := s.pg.GetKnowledgeConfig()
	if err != nil {
		return EmbedConfig{}, err
	}
	return EmbedConfig{BaseURL: cfg.BaseURL, Model: cfg.Model, APIKey: cfg.APIKey, Dim: cfg.Dim}, nil
}

// IndexDoc 分块 + 向量化一篇文档。语义检索未就绪时是空操作（关键词模式直接读正文，
// 不需要分块）。
func (s *Service) IndexDoc(ctx context.Context, docID int64) error {
	if !s.SemanticReady() {
		return nil
	}
	doc, err := s.pg.GetKnowledgeDoc(docID)
	if err != nil || doc == nil {
		return err
	}
	chunks := ChunkText(doc.Content, chunkChars, chunkOverlap)
	if len(chunks) == 0 {
		return s.pg.ReplaceKnowledgeChunks(docID, "", 0, nil) // 清空并标记已索引
	}
	cfg, err := s.embedConfig()
	if err != nil {
		return err
	}
	inputs := make([]string, len(chunks))
	for i, c := range chunks {
		inputs[i] = embedInput(doc.Category, doc.Title, c)
	}
	vecs := make([][]float32, 0, len(inputs))
	for i := 0; i < len(inputs); i += embedBatch {
		j := i + embedBatch
		if j > len(inputs) {
			j = len(inputs)
		}
		part, err := EmbedTexts(ctx, cfg, inputs[i:j])
		if err != nil {
			return err
		}
		vecs = append(vecs, part...)
	}
	ins := make([]db.KnowledgeChunkInsert, len(chunks))
	for i := range chunks {
		ins[i] = db.KnowledgeChunkInsert{Index: i, Content: chunks[i], Embedding: vecs[i]}
	}
	return s.pg.ReplaceKnowledgeChunks(docID, cfg.Model, cfg.Dim, ins)
}

// Search 取 top-k 相关片段，返回命中与所用模式（"semantic" | "keyword"）。
//
// 语义路径任何一步失败（嵌查询失败 / 向量查询报错）都静默降级到关键词：
// 用户要的是"能不能查到东西"，而不是"为什么没用向量"。
func (s *Service) Search(ctx context.Context, query string, taskID int64, topK int) ([]db.KnowledgeHit, string, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, "keyword", nil
	}
	if s.SemanticReady() {
		if cfg, err := s.embedConfig(); err == nil {
			if vecs, err := EmbedTexts(ctx, cfg, []string{query}); err == nil && len(vecs) == 1 {
				if hits, err := s.pg.SearchKnowledgeVector(vecs[0], cfg.Model, taskID, topK); err == nil {
					return hits, "semantic", nil
				}
			}
		}
	}
	hits, err := s.pg.SearchKnowledgeKeyword(query, taskID, topK)
	return hits, "keyword", err
}

// SearchAndLog 检索并记一条审计（agent 工具用）：回答"它到底查没查、命中哪几篇"。
func (s *Service) SearchAndLog(ctx context.Context, query string, taskID int64, topK int, agentKey string) ([]db.KnowledgeHit, string, error) {
	hits, mode, err := s.Search(ctx, query, taskID, topK)
	if err == nil {
		scope := "global"
		if taskID > 0 {
			scope = "global+task"
		}
		ids := make([]int64, 0, len(hits))
		for _, h := range hits {
			ids = append(ids, h.DocID)
		}
		s.pg.AddKnowledgeRetrievalLog(taskID, agentKey, query, scope, mode, topK, len(hits), ids)
	}
	return hits, mode, err
}

// Reindex 重建全部文档的向量（换 embedder/模型后必做）。要求语义检索就绪。
func (s *Service) Reindex(ctx context.Context) (int, error) {
	if !s.SemanticReady() {
		return 0, fmt.Errorf("语义检索未就绪：需 pgvector + 启用 embedder + 配置 api_key")
	}
	if err := s.pg.ClearKnowledgeChunks(); err != nil {
		return 0, err
	}
	docs, err := s.pg.ListKnowledgeDocs("", 0)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, doc := range docs {
		if err := s.IndexDoc(ctx, doc.ID); err != nil {
			return n, fmt.Errorf("文档 #%d(%s) 索引失败: %w", doc.ID, doc.Title, err)
		}
		n++
	}
	return n, nil
}

// TestEmbedder 探测 embedder 是否可用，返回实际返回的向量维度。
// 之所以返回维度：用户配 1024 而供应商给 1536 时，这里能立刻看出来。
func (s *Service) TestEmbedder(ctx context.Context) (int, error) {
	cfg, err := s.embedConfig()
	if err != nil {
		return 0, err
	}
	if strings.TrimSpace(cfg.APIKey) == "" {
		return 0, fmt.Errorf("未配置 api_key")
	}
	vecs, err := EmbedTexts(ctx, cfg, []string{"知识库连通性测试 knowledge base connectivity test"})
	if err != nil {
		return 0, err
	}
	if len(vecs) != 1 || len(vecs[0]) == 0 {
		return 0, fmt.Errorf("embedder 返回空向量")
	}
	return len(vecs[0]), nil
}
