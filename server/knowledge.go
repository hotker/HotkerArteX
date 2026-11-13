package server

import (
	"context"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/knowledge"
)

// 知识库 HTTP 层：文档 CRUD + 上传 + 检索 + embedder 配置/测试/重建索引。
//
// 与上游的差别在于【抽取与降级】：
//   - 抽取不用 python 子进程（.docx 直接用 archive/zip + encoding/xml 读），
//     所以上传路径没有任何外部依赖；
//   - 语义检索未就绪时不是报错，而是整体降级为关键词检索 —— 知识库永远可用，
//     只是没有向量召回时召回质量弱一些。前端据此显示"语义/关键词"模式。

func (s *Server) kb() *knowledge.Service { return knowledge.NewService(s.m.pg) }

// indexKnowledgeAsync 后台建索引：上传接口不该被 embeddings 的往返拖住。
// 失败只记日志 —— 文档已落库，用户可以稍后点「重建索引」。
func (s *Server) indexKnowledgeAsync(id int64) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := s.kb().IndexDoc(ctx, id); err != nil {
		selectLog("knowledge", "index doc %d: %v", id, err)
	}
}

// selectLog 只做一件事：拼上 "[knowledge]" 前缀后转给标准日志。
func selectLog(prefix, format string, args ...any) {
	log.Printf("["+prefix+"] "+format, args...)
}

// GET /api/knowledge?scope=&task=
func (s *Server) listKnowledge(w http.ResponseWriter, r *http.Request) {
	scope := strings.TrimSpace(r.URL.Query().Get("scope"))
	taskID, _ := strconv.ParseInt(r.URL.Query().Get("task"), 10, 64)
	if scope != "global" && scope != "task" {
		scope = ""
	}
	docs, err := s.m.pg.ListKnowledgeDocs(scope, taskID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	globalN, taskN, _ := s.m.pg.KnowledgeDocCount()
	writeJSON(w, 200, map[string]any{
		"docs":         docs,
		"global_count": globalN,
		"task_count":   taskN,
		"vector_ready": s.m.pg.KnowledgeVectorAvailable(),
		"semantic":     s.kb().SemanticReady(),
	})
}

// GET /api/knowledge/{id} — 含正文。
func (s *Server) getKnowledge(w http.ResponseWriter, r *http.Request) {
	id, _ := pathInt(r, "id")
	doc, err := s.m.pg.GetKnowledgeDoc(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if doc == nil {
		writeErr(w, 404, "文档不存在")
		return
	}
	writeJSON(w, 200, doc)
}

type knowledgeDocReq struct {
	Scope    string `json:"scope"`
	TaskID   int64  `json:"task_id"`
	Category string `json:"category"`
	Title    string `json:"title"`
	Content  string `json:"content"`
}

// POST /api/knowledge — 手写一篇。
func (s *Server) createKnowledge(w http.ResponseWriter, r *http.Request) {
	var req knowledgeDocReq
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	if strings.TrimSpace(req.Title) == "" || strings.TrimSpace(req.Content) == "" {
		writeErr(w, 400, "标题与正文必填")
		return
	}
	// 任务知识必须指明任务：否则会静默落成孤儿（scope=task 但 task_id 为空），
	// 读回来又像全局文档 —— 直接拒绝比事后排查便宜。
	if req.Scope == "task" && req.TaskID <= 0 {
		writeErr(w, 400, "任务知识需指定所属任务")
		return
	}
	doc := &db.KnowledgeDoc{Scope: req.Scope, Category: req.Category, Title: req.Title, Content: req.Content, Source: "manual"}
	if req.Scope == "task" && req.TaskID > 0 {
		id := req.TaskID
		doc.TaskID = &id
	}
	id, err := s.m.pg.AddKnowledgeDoc(doc)
	if err != nil {
		writeErr(w, 500, "保存失败: "+err.Error())
		return
	}
	go s.indexKnowledgeAsync(id)
	out, _ := s.m.pg.GetKnowledgeDoc(id)
	writeJSON(w, 200, out)
}

// PUT /api/knowledge/{id}
func (s *Server) updateKnowledge(w http.ResponseWriter, r *http.Request) {
	id, _ := pathInt(r, "id")
	var req knowledgeDocReq
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	if err := s.m.pg.UpdateKnowledgeDoc(id, req.Category, req.Title, req.Content); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	go s.indexKnowledgeAsync(id) // 内容变了，旧向量作废
	out, _ := s.m.pg.GetKnowledgeDoc(id)
	writeJSON(w, 200, out)
}

// DELETE /api/knowledge/{id}
func (s *Server) deleteKnowledge(w http.ResponseWriter, r *http.Request) {
	id, _ := pathInt(r, "id")
	if err := s.m.pg.DeleteKnowledgeDoc(id); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// POST /api/knowledge/upload — multipart：file + scope + task_id + category。
func (s *Server) uploadKnowledge(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeErr(w, 400, "上传解析失败")
		return
	}
	file, hdr, err := r.FormFile("file")
	if err != nil {
		writeErr(w, 400, "缺少文件")
		return
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 32<<20))
	if err != nil {
		writeErr(w, 400, "读取失败")
		return
	}
	text, err := knowledge.ExtractText(hdr.Filename, raw)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if strings.TrimSpace(text) == "" {
		writeErr(w, 400, "文档内容为空或无法抽取文本")
		return
	}
	scope := r.FormValue("scope")
	taskID, _ := strconv.ParseInt(r.FormValue("task_id"), 10, 64)
	if scope == "task" && taskID <= 0 {
		writeErr(w, 400, "任务知识需指定所属任务：请选择要归属的任务")
		return
	}
	doc := &db.KnowledgeDoc{
		Scope:    scope,
		Category: r.FormValue("category"),
		Title:    strings.TrimSuffix(hdr.Filename, filepath.Ext(hdr.Filename)),
		Content:  text,
		Source:   "upload",
		FileName: hdr.Filename,
		Bytes:    int64(len(raw)),
	}
	if scope == "task" && taskID > 0 {
		doc.TaskID = &taskID
	}
	id, err := s.m.pg.AddKnowledgeDoc(doc)
	if err != nil {
		writeErr(w, 500, "保存失败: "+err.Error())
		return
	}
	go s.indexKnowledgeAsync(id)
	out, _ := s.m.pg.GetKnowledgeDoc(id)
	writeJSON(w, 200, out)
}

// GET /api/knowledge/categories?task=
func (s *Server) knowledgeCategories(w http.ResponseWriter, r *http.Request) {
	taskID, _ := strconv.ParseInt(r.URL.Query().Get("task"), 10, 64)
	cats, err := s.m.pg.ListKnowledgeCategories(taskID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"categories": cats})
}

// POST /api/knowledge/search — 页面上的"试检索"（不写审计，那是 agent 的事）。
func (s *Server) searchKnowledge(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Query string `json:"query"`
		Task  int64  `json:"task_id"`
		TopK  int    `json:"top_k"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	if strings.TrimSpace(req.Query) == "" {
		writeErr(w, 400, "query 不能为空")
		return
	}
	if req.TopK <= 0 {
		req.TopK = 5
	}
	hits, mode, err := s.kb().Search(r.Context(), req.Query, req.Task, req.TopK)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"hits": hits, "mode": mode})
}

// GET /api/knowledge/logs
func (s *Server) knowledgeLogs(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	logs, err := s.m.pg.ListKnowledgeRetrievalLogs(limit)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"logs": logs})
}

// GET /api/knowledge/config
func (s *Server) getKnowledgeConfig(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.m.pg.GetKnowledgeConfig()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"enabled":      cfg.Enabled,
		"base_url":     cfg.BaseURL,
		"model":        cfg.Model,
		"dim":          cfg.Dim,
		"has_key":      cfg.HasKey,
		"vector_ready": s.m.pg.KnowledgeVectorAvailable(),
		"semantic":     s.kb().SemanticReady(),
	})
}

// PUT /api/knowledge/config — api_key 留空表示保留现有 key。
func (s *Server) saveKnowledgeConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool   `json:"enabled"`
		BaseURL string `json:"base_url"`
		Model   string `json:"model"`
		APIKey  string `json:"api_key"`
		Dim     int    `json:"dim"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	if strings.TrimSpace(req.BaseURL) == "" || strings.TrimSpace(req.Model) == "" {
		writeErr(w, 400, "Base URL 与模型必填")
		return
	}
	if err := s.m.pg.SaveKnowledgeConfig(req.Enabled, req.BaseURL, req.Model, req.APIKey, req.Dim); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "semantic": s.kb().SemanticReady()})
}

// POST /api/knowledge/config/test — 探测 embedder，返回实际维度。
func (s *Server) testKnowledgeEmbedder(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	dim, err := s.kb().TestEmbedder(ctx)
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "dim": dim})
}

// POST /api/knowledge/reindex — 重建全部向量（换模型后必做）。同步执行：
// 文档量级在人工知识库范围内，且用户需要"重建了几篇"的确定答复。
func (s *Server) reindexKnowledge(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	n, err := s.kb().Reindex(ctx)
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "indexed": n, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "indexed": n})
}
