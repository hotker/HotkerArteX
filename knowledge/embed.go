// Package knowledge 实现两层 RAG 知识库（全局库 + 任务库）：文档接入（分块 → 向量化）、
// 语义 + 关键词检索，以及 OpenAI 兼容的 embeddings 客户端。
//
// 设计原则是【永不让程序因为知识库而不可用】：没配 embedder / 没有 pgvector 时全链路
// 降级为关键词检索，而不是报错或拒绝启动。
package knowledge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// EmbedConfig 是一个 OpenAI 兼容 embeddings 端点（智谱/硅基流动/OpenAI/Ollama
// 都提供 POST {base}/embeddings）。
type EmbedConfig struct {
	BaseURL string
	Model   string
	APIKey  string
	Dim     int
}

type embedReq struct {
	Model      string   `json:"model"`
	Input      []string `json:"input"`
	Dimensions int      `json:"dimensions,omitempty"`
}

type embedResp struct {
	Data []struct {
		Index     int       `json:"index"`
		Embedding []float32 `json:"embedding"`
	} `json:"data"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// EmbedTexts 对一组文本调用一次 /embeddings。批量不宜过大（调用方自行分片）：
// 部分供应商单请求有上限，且一次失败会连累整批。
//
// 返回顺序按响应里的 index 对齐，而不是假象地相信数组顺序 —— 有供应商会乱序返回。
func EmbedTexts(ctx context.Context, cfg EmbedConfig, texts []string) ([][]float32, error) {
	if strings.TrimSpace(cfg.APIKey) == "" {
		return nil, fmt.Errorf("embedder 未配置 api_key")
	}
	if strings.TrimSpace(cfg.Model) == "" {
		return nil, fmt.Errorf("embedder 未配置 model")
	}
	if len(texts) == 0 {
		return nil, nil
	}
	url := strings.TrimRight(cfg.BaseURL, "/") + "/embeddings"
	payload := embedReq{Model: cfg.Model, Input: texts}
	if cfg.Dim > 0 {
		payload.Dimensions = cfg.Dim
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	resp, err := (&http.Client{Timeout: 90 * time.Second}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("embeddings 请求失败: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	var out embedResp
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("embeddings 响应解析失败 (HTTP %d): %s", resp.StatusCode, snippet(raw))
	}
	if out.Error != nil && out.Error.Message != "" {
		return nil, fmt.Errorf("embeddings 错误: %s", out.Error.Message)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("embeddings HTTP %d: %s", resp.StatusCode, snippet(raw))
	}
	if len(out.Data) != len(texts) {
		return nil, fmt.Errorf("embeddings 数量不符: got %d want %d", len(out.Data), len(texts))
	}
	res := make([][]float32, len(texts))
	for _, d := range out.Data {
		if d.Index >= 0 && d.Index < len(res) {
			res[d.Index] = d.Embedding
		}
	}
	// 供应商没给 index（全 0）时退回按位置对齐；否则保持按 index 的结果。
	missing := false
	for _, v := range res {
		if v == nil {
			missing = true
			break
		}
	}
	if missing {
		for i := range out.Data {
			if i < len(res) {
				res[i] = out.Data[i].Embedding
			}
		}
	}
	var dims = map[int]bool{}
	for _, v := range res {
		if len(v) == 0 {
			return nil, fmt.Errorf("embeddings 返回空向量")
		}
		dims[len(v)] = true
	}
	if len(dims) > 1 {
		return nil, fmt.Errorf("embeddings 返回的向量维度不一致（同一批 %d 种）", len(dims))
	}
	return res, nil
}

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}
