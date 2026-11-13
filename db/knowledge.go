package db

import (
	"database/sql"
	"errors"
	"strconv"
	"strings"
	"time"
)

// 知识库（两层 RAG）：全局库 + 任务库。
//
// 文档存在 knowledge_docs（scope=global|task）。语义检索另有一层 knowledge_chunks
// （pgvector 的 vector 列，由 ensureKnowledgeVectorSchema 守卫式创建）；pgvector 不可用时
// 整条链路降级为对文档的关键词检索（ILIKE），功能不消失、只是召回变弱。
//
// 设计取舍：向量列用【不定维 vector】+ 每 chunk 记 embed_model/dim，检索时按当前模型过滤。
// 换 embedder 时旧模型的行自动被忽略，重建索引后统一 —— 不需要 ALTER TABLE 改维度
// （向量列一旦固定维度，换模型就得重建整张表）。

// KnowledgeDoc 是一篇知识文档。
type KnowledgeDoc struct {
	ID        int64     `json:"id"`
	Scope     string    `json:"scope"` // global | task
	TaskID    *int64    `json:"task_id,omitempty"`
	Category  string    `json:"category"`
	Title     string    `json:"title"`
	Content   string    `json:"content,omitempty"` // 列表视图不返回正文
	Source    string    `json:"source"`            // manual | upload | migrated
	FileName  string    `json:"file_name,omitempty"`
	Bytes     int64     `json:"bytes"`
	Indexed   bool      `json:"indexed"`
	Chunks    int       `json:"chunks"` // 向量分块数（关键词模式下为 0）
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// KnowledgeConfig 是 embedder 配置（单例）。
type KnowledgeConfig struct {
	Enabled bool   `json:"enabled"`
	BaseURL string `json:"base_url"`
	Model   string `json:"model"`
	APIKey  string `json:"-"` // 永不序列化给 UI
	HasKey  bool   `json:"has_key"`
	Dim     int    `json:"dim"`
}

// KnowledgeHit 是一条检索结果（语义模式是命中的分块，关键词模式是文档片段）。
type KnowledgeHit struct {
	DocID    int64   `json:"doc_id"`
	Title    string  `json:"title"`
	Category string  `json:"category"`
	Scope    string  `json:"scope"`
	Content  string  `json:"content"`
	Score    float64 `json:"score"`
}

// KnowledgeChunkInsert 是一个待写入的分块及其向量。
type KnowledgeChunkInsert struct {
	Index     int
	Content   string
	Embedding []float32
}

// KnowledgeRetrievalLog 是一次检索审计。
type KnowledgeRetrievalLog struct {
	ID        int64     `json:"id"`
	TaskID    *int64    `json:"task_id,omitempty"`
	AgentKey  string    `json:"agent_key"`
	Query     string    `json:"query"`
	Scope     string    `json:"scope"`
	Mode      string    `json:"mode"`
	TopK      int       `json:"top_k"`
	Hits      int       `json:"hits"`
	CreatedAt time.Time `json:"created_at"`
}

// KnowledgeVectorAvailable 报告 pgvector 语义层是否就绪。
func (d *DB) KnowledgeVectorAvailable() bool { return d.GetBool("knowledge.vector_available", false) }

// ensureKnowledgeVectorSchema 创建 pgvector 扩展 + knowledge_chunks。
// best-effort：失败只记日志并把开关置 false，绝不返回错误（不能让缺扩展把程序起不来）。
func (d *DB) ensureKnowledgeVectorSchema() {
	if _, err := d.Exec(`CREATE EXTENSION IF NOT EXISTS vector`); err != nil {
		_ = d.SetBool("knowledge.vector_available", false)
		return
	}
	if _, err := d.Exec(`
CREATE TABLE IF NOT EXISTS knowledge_chunks (
    id          BIGSERIAL PRIMARY KEY,
    doc_id      BIGINT NOT NULL REFERENCES knowledge_docs(id) ON DELETE CASCADE,
    chunk_index INT NOT NULL DEFAULT 0,
    content     TEXT NOT NULL DEFAULT '',
    embedding   vector,
    embed_model TEXT NOT NULL DEFAULT '',
    embed_dim   INT NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_knowledge_chunks_doc ON knowledge_chunks(doc_id);
CREATE INDEX IF NOT EXISTS idx_knowledge_chunks_model ON knowledge_chunks(embed_model);`); err != nil {
		_ = d.SetBool("knowledge.vector_available", false)
		return
	}
	_ = d.SetBool("knowledge.vector_available", true)
}

// ---------- embedder 配置 ----------

// GetKnowledgeConfig 返回切 embedder 配置；没有行时返回默认值（智谱 embedding-3）。
func (d *DB) GetKnowledgeConfig() (*KnowledgeConfig, error) {
	var c KnowledgeConfig
	err := d.QueryRow(`SELECT enabled, base_url, model, COALESCE(api_key,''), dim FROM knowledge_config WHERE id=1`).
		Scan(&c.Enabled, &c.BaseURL, &c.Model, &c.APIKey, &c.Dim)
	if errors.Is(err, sql.ErrNoRows) {
		return &KnowledgeConfig{BaseURL: "https://open.bigmodel.cn/api/paas/v4", Model: "embedding-3", Dim: 1024}, nil
	}
	if err != nil {
		return nil, err
	}
	c.HasKey = strings.TrimSpace(c.APIKey) != ""
	return &c, nil
}

// SaveKnowledgeConfig 覆盖 embedder 配置。api_key 留空表示"保留现有 key" ——
// 前端永远拿不到 key，回填时不可能填对，所以空值必须解释为"不改"。
func (d *DB) SaveKnowledgeConfig(enabled bool, baseURL, model, apiKey string, dim int) error {
	if dim <= 0 {
		dim = 1024
	}
	if strings.TrimSpace(apiKey) == "" {
		_, err := d.Exec(`UPDATE knowledge_config SET enabled=$1, base_url=$2, model=$3, dim=$4, updated_at=now() WHERE id=1`,
			enabled, strings.TrimSpace(baseURL), strings.TrimSpace(model), dim)
		return err
	}
	_, err := d.Exec(`UPDATE knowledge_config SET enabled=$1, base_url=$2, model=$3, api_key=$4, dim=$5, updated_at=now() WHERE id=1`,
		enabled, strings.TrimSpace(baseURL), strings.TrimSpace(model), apiKey, dim)
	return err
}

// AdoptKnowledgeKeyFromProfile 把某个 LLM 配置的 api_key 复制到 embedder（仅当 embedder
// 还没有 key 时）。方便复用已经配好的供应商（例如同一个智谱 key）。
func (d *DB) AdoptKnowledgeKeyFromProfile(profileID int64) (bool, error) {
	res, err := d.Exec(`UPDATE knowledge_config
		SET api_key = p.api_key, updated_at = now()
		FROM llm_profiles p
		WHERE knowledge_config.id = 1
		  AND COALESCE(knowledge_config.api_key,'') = ''
		  AND p.id = $1 AND COALESCE(p.api_key,'') <> ''`, profileID)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ---------- 文档 ----------

// AddKnowledgeDoc 新增文档。scope=task 但 task_id 缺失时落为 global —— 调用方
// （HTTP 层）应当先拒绝这种上传，这里只做兜底。
func (d *DB) AddKnowledgeDoc(doc *KnowledgeDoc) (int64, error) {
	scope := "global"
	var tid *int64
	if doc.Scope == "task" && doc.TaskID != nil && *doc.TaskID > 0 {
		scope, tid = "task", doc.TaskID
	}
	source := doc.Source
	if source == "" {
		source = "manual"
	}
	bytes := doc.Bytes
	if bytes == 0 {
		bytes = int64(len(doc.Content))
	}
	var id int64
	err := d.QueryRow(`INSERT INTO knowledge_docs (scope, task_id, category, title, content, source, file_name, bytes)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
		scope, tid, strings.TrimSpace(doc.Category), strings.TrimSpace(doc.Title),
		doc.Content, source, doc.FileName, bytes).Scan(&id)
	return id, err
}

// UpdateKnowledgeDoc 改正文/标题/分类，并把 indexed 复位（内容变了旧向量就作废）。
func (d *DB) UpdateKnowledgeDoc(id int64, category, title, content string) error {
	_, err := d.Exec(`UPDATE knowledge_docs SET category=$2, title=$3, content=$4, bytes=$5, indexed=false, updated_at=now() WHERE id=$1`,
		id, strings.TrimSpace(category), strings.TrimSpace(title), content, int64(len(content)))
	return err
}

// GetKnowledgeDoc 取单篇（含正文）；不存在返回 nil, nil。
func (d *DB) GetKnowledgeDoc(id int64) (*KnowledgeDoc, error) {
	var doc KnowledgeDoc
	var tid sql.NullInt64
	err := d.QueryRow(`SELECT id, scope, task_id, category, title, content, source, file_name, bytes, indexed, created_at, updated_at
		FROM knowledge_docs WHERE id=$1`, id).
		Scan(&doc.ID, &doc.Scope, &tid, &doc.Category, &doc.Title, &doc.Content, &doc.Source, &doc.FileName, &doc.Bytes, &doc.Indexed, &doc.CreatedAt, &doc.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if tid.Valid {
		v := tid.Int64
		doc.TaskID = &v
	}
	return &doc, nil
}

// ListKnowledgeDocs 按范围列文档（不带正文）：
//   - scope="global" → 只要全局
//   - scope="task" + taskID → 只要该任务
//   - taskID>0 且 scope 空 → 全局 + 该任务（agent 视角）
//   - 否则全部
func (d *DB) ListKnowledgeDocs(scope string, taskID int64) ([]*KnowledgeDoc, error) {
	var where string
	var args []any
	switch {
	case scope == "global":
		where = "WHERE scope='global'"
	case scope == "task" && taskID > 0:
		where = "WHERE scope='task' AND task_id=$1"
		args = append(args, taskID)
	case taskID > 0:
		where = "WHERE scope='global' OR (scope='task' AND task_id=$1)"
		args = append(args, taskID)
	}
	q := `SELECT id, scope, task_id, category, title, source, file_name, bytes, indexed, created_at, updated_at
		FROM knowledge_docs ` + where + ` ORDER BY scope, category, created_at DESC`
	rows, err := d.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*KnowledgeDoc{}
	for rows.Next() {
		var doc KnowledgeDoc
		var tid sql.NullInt64
		if err := rows.Scan(&doc.ID, &doc.Scope, &tid, &doc.Category, &doc.Title, &doc.Source,
			&doc.FileName, &doc.Bytes, &doc.Indexed, &doc.CreatedAt, &doc.UpdatedAt); err != nil {
			return nil, err
		}
		if tid.Valid {
			v := tid.Int64
			doc.TaskID = &v
		}
		out = append(out, &doc)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// 附上向量分块数（best-effort：只在语义层存在时查）
	if d.KnowledgeVectorAvailable() && len(out) > 0 {
		if cr, e := d.Query(`SELECT doc_id, count(*) FROM knowledge_chunks GROUP BY doc_id`); e == nil {
			counts := map[int64]int{}
			for cr.Next() {
				var id int64
				var n int
				if cr.Scan(&id, &n) == nil {
					counts[id] = n
				}
			}
			cr.Close()
			for _, doc := range out {
				doc.Chunks = counts[doc.ID]
			}
		}
	}
	return out, nil
}

// DeleteKnowledgeDoc 删除文档（chunks 级联删除）。
func (d *DB) DeleteKnowledgeDoc(id int64) error {
	_, err := d.Exec(`DELETE FROM knowledge_docs WHERE id=$1`, id)
	return err
}

// ListKnowledgeCategories 列出可见范围内的非空分类（全局恒可见 + 给定任务）。
func (d *DB) ListKnowledgeCategories(taskID int64) ([]string, error) {
	q := `SELECT DISTINCT category FROM knowledge_docs WHERE category<>'' AND (scope='global'`
	var args []any
	if taskID > 0 {
		q += ` OR (scope='task' AND task_id=$1)`
		args = append(args, taskID)
	}
	q += `) ORDER BY category`
	rows, err := d.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// KnowledgeDocCount 返回文档数（统计卡片/空状态用）。
func (d *DB) KnowledgeDocCount() (global int, task int, err error) {
	err = d.QueryRow(`SELECT count(*) FILTER (WHERE scope='global'), count(*) FILTER (WHERE scope='task') FROM knowledge_docs`).
		Scan(&global, &task)
	return
}

// ---------- 分块（语义层） ----------

// ReplaceKnowledgeChunks 重建一篇文档的分块：先删旧的再写新的，最后标记 indexed。
func (d *DB) ReplaceKnowledgeChunks(docID int64, model string, dim int, chunks []KnowledgeChunkInsert) error {
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.Exec(`DELETE FROM knowledge_chunks WHERE doc_id=$1`, docID); err != nil {
		return err
	}
	for _, c := range chunks {
		if _, err := tx.Exec(`INSERT INTO knowledge_chunks (doc_id, chunk_index, content, embedding, embed_model, embed_dim)
			VALUES ($1,$2,$3,$4::vector,$5,$6)`,
			docID, c.Index, c.Content, vecLiteral(c.Embedding), model, dim); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`UPDATE knowledge_docs SET indexed=true, updated_at=now() WHERE id=$1`, docID); err != nil {
		return err
	}
	return tx.Commit()
}

// ClearKnowledgeChunks 清空全部分块并把文档标记为未索引（重建索引用）。
func (d *DB) ClearKnowledgeChunks() error {
	if !d.KnowledgeVectorAvailable() {
		return nil
	}
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.Exec(`TRUNCATE knowledge_chunks`); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE knowledge_docs SET indexed=false`); err != nil {
		return err
	}
	return tx.Commit()
}

// SearchKnowledgeVector 对分块做余弦相似度检索，只比较同一 embed_model 的行
// （换模型后旧向量自动被忽略 —— 模型切换的安全阀），范围是全局 + 给定任务。
func (d *DB) SearchKnowledgeVector(queryVec []float32, model string, taskID int64, topK int) ([]KnowledgeHit, error) {
	if topK <= 0 {
		topK = 5
	}
	scopeClause := "(dc.scope='global'"
	args := []any{vecLiteral(queryVec), model}
	if taskID > 0 {
		scopeClause += " OR (dc.scope='task' AND dc.task_id=$3)"
		args = append(args, taskID)
	}
	scopeClause += ")"
	q := `SELECT dc.id, dc.title, dc.category, dc.scope, kc.content,
		1 - (kc.embedding <=> $1::vector) AS score
		FROM knowledge_chunks kc JOIN knowledge_docs dc ON dc.id = kc.doc_id
		WHERE kc.embed_model = $2 AND ` + scopeClause + `
		ORDER BY kc.embedding <=> $1::vector
		LIMIT ` + strconv.Itoa(topK)
	rows, err := d.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanKnowledgeHits(rows)
}

// SearchKnowledgeKeyword 是无 embedder 时的降级路径：title/content/category 上做 ILIKE，
// 范围同上。返回文档片段而不是分块。
func (d *DB) SearchKnowledgeKeyword(query string, taskID int64, topK int) ([]KnowledgeHit, error) {
	if topK <= 0 {
		topK = 5
	}
	like := "%" + strings.TrimSpace(query) + "%"
	scopeClause := "(scope='global'"
	args := []any{like}
	if taskID > 0 {
		scopeClause += " OR (scope='task' AND task_id=$2)"
		args = append(args, taskID)
	}
	scopeClause += ")"
	q := `SELECT id, title, category, scope, LEFT(content, 1200) AS content,
		(CASE WHEN title ILIKE $1 THEN 1.0 WHEN category ILIKE $1 THEN 0.8 ELSE 0.5 END) AS score
		FROM knowledge_docs
		WHERE (title ILIKE $1 OR content ILIKE $1 OR category ILIKE $1) AND ` + scopeClause + `
		ORDER BY score DESC, updated_at DESC
		LIMIT ` + strconv.Itoa(topK)
	rows, err := d.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanKnowledgeHits(rows)
}

func scanKnowledgeHits(rows *sql.Rows) ([]KnowledgeHit, error) {
	out := []KnowledgeHit{}
	for rows.Next() {
		var h KnowledgeHit
		if err := rows.Scan(&h.DocID, &h.Title, &h.Category, &h.Scope, &h.Content, &h.Score); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// ---------- 检索日志 ----------

// AddKnowledgeRetrievalLog 记一次检索（失败静默：审计不该影响检索本身）。
func (d *DB) AddKnowledgeRetrievalLog(taskID int64, agentKey, query, scope, mode string, topK, hits int, docIDs []int64) {
	var tid *int64
	if taskID > 0 {
		tid = &taskID
	}
	ids := make([]string, 0, len(docIDs))
	for _, id := range docIDs {
		ids = append(ids, strconv.FormatInt(id, 10))
	}
	arrLit := "{" + strings.Join(ids, ",") + "}" // 全是整数，可安全内联
	_, _ = d.Exec(`INSERT INTO knowledge_retrieval_logs (task_id, agent_key, query, scope, mode, top_k, hits, doc_ids)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8::bigint[])`, tid, agentKey, query, scope, mode, topK, hits, arrLit)
}

// ListKnowledgeRetrievalLogs 返回最近的检索记录。
func (d *DB) ListKnowledgeRetrievalLogs(limit int) ([]*KnowledgeRetrievalLog, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := d.Query(`SELECT id, task_id, agent_key, query, scope, mode, top_k, hits, created_at
		FROM knowledge_retrieval_logs ORDER BY id DESC LIMIT ` + strconv.Itoa(limit))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*KnowledgeRetrievalLog{}
	for rows.Next() {
		var l KnowledgeRetrievalLog
		var tid sql.NullInt64
		if err := rows.Scan(&l.ID, &tid, &l.AgentKey, &l.Query, &l.Scope, &l.Mode, &l.TopK, &l.Hits, &l.CreatedAt); err != nil {
			return nil, err
		}
		if tid.Valid {
			v := tid.Int64
			l.TaskID = &v
		}
		out = append(out, &l)
	}
	return out, rows.Err()
}

// vecLiteral 把向量渲染成 pgvector 的字面量 [1,2,3]。
func vecLiteral(v []float32) string {
	var b strings.Builder
	b.WriteByte('[')
	for i, x := range v {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.FormatFloat(float64(x), 'f', -1, 32))
	}
	b.WriteByte(']')
	return b.String()
}
