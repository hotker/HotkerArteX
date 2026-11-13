package knowledge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// 真实端点会乱序返回 index；必须按 index 对齐而不是按数组顺序。
func TestEmbedTextsAlignsByIndex(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/embeddings" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer k" {
			t.Errorf("auth header missing: %q", r.Header.Get("Authorization"))
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		// 故意把顺序倒过来返回
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{
				{"index": 1, "embedding": []float32{0, 1}},
				{"index": 0, "embedding": []float32{1, 0}},
			},
		})
	}))
	defer srv.Close()

	cfg := EmbedConfig{BaseURL: srv.URL + "/v1", Model: "m", APIKey: "k", Dim: 2}
	vecs, err := EmbedTexts(context.Background(), cfg, []string{"a", "b"})
	if err != nil {
		t.Fatalf("embed: %v", err)
	}
	if len(vecs) != 2 || vecs[0][0] != 1 || vecs[1][1] != 1 {
		t.Fatalf("vectors not aligned by index: %v", vecs)
	}
	if got["model"] != "m" {
		t.Fatalf("model not sent: %v", got["model"])
	}
	if d, ok := got["dimensions"]; !ok || d.(float64) != 2 {
		t.Fatalf("dimensions not sent: %v", got["dimensions"])
	}
}

func TestEmbedTextsErrors(t *testing.T) {
	// 无 key / 无 model：本地就拒，不发请求
	if _, err := EmbedTexts(context.Background(), EmbedConfig{Model: "m"}, []string{"x"}); err == nil {
		t.Fatal("missing api_key must fail")
	}
	if _, err := EmbedTexts(context.Background(), EmbedConfig{APIKey: "k"}, []string{"x"}); err == nil {
		t.Fatal("missing model must fail")
	}

	// 服务端 error 字段要透出可读信息
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"message": "额度不足"}})
	}))
	defer srv.Close()
	_, err := EmbedTexts(context.Background(), EmbedConfig{BaseURL: srv.URL, Model: "m", APIKey: "k"}, []string{"x"})
	if err == nil || !contains(err.Error(), "额度不足") {
		t.Fatalf("provider error not surfaced: %v", err)
	}

	// 数量不符
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{{"index": 0, "embedding": []float32{1}}}})
	}))
	defer srv2.Close()
	_, err = EmbedTexts(context.Background(), EmbedConfig{BaseURL: srv2.URL, Model: "m", APIKey: "k"}, []string{"a", "b"})
	if err == nil || !contains(err.Error(), "数量不符") {
		t.Fatalf("count mismatch not detected: %v", err)
	}

	// 同一批维度不一致
	srv3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{
			{"index": 0, "embedding": []float32{1}},
			{"index": 1, "embedding": []float32{1, 2}},
		}})
	}))
	defer srv3.Close()
	_, err = EmbedTexts(context.Background(), EmbedConfig{BaseURL: srv3.URL, Model: "m", APIKey: "k"}, []string{"a", "b"})
	if err == nil || !contains(err.Error(), "维度不一致") {
		t.Fatalf("mixed dims not detected: %v", err)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
