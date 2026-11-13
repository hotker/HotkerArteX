package db

import (
	"database/sql"
	"strings"
	"testing"
	"unicode/utf8"
)

// Normalize 是入库前的唯一闸门：模型给的复现结构经常带空对象、超长 HTML、
// 上千条步骤 —— 这些必须在落库前收敛，不能等报告渲染时才发现。
func TestReproductionNormalize(t *testing.T) {
	r := &Reproduction{
		EntryPoint:    "  POST /api/login  ",
		Prerequisites: "\n需要 admin 账号\n",
		Steps: []ReproStep{
			{}, // 空步：模型占位，必须丢
			{Request: "POST /a HTTP/1.1", Response: "HTTP 200"},
			{Expected: "登录成功"}, // 只有预期也算一步
		},
		Provenance: "从事实 #12 串上来",
	}
	n := r.Normalize()
	if n == nil {
		t.Fatal("should keep the reproduction")
	}
	if n.EntryPoint != "POST /api/login" {
		t.Fatalf("entry point not trimmed: %q", n.EntryPoint)
	}
	if len(n.Steps) != 2 {
		t.Fatalf("empty step must be dropped, got %d steps", len(n.Steps))
	}

	// 全空 → nil（调用方存 NULL，而不是一个空对象）
	if (&Reproduction{}).Normalize() != nil {
		t.Fatal("empty reproduction must normalize to nil")
	}

	// 超长字段被截断并留标记
	huge := &Reproduction{Steps: []ReproStep{{Request: strings.Repeat("A", StepFieldCap*2)}}}
	hn := huge.Normalize()
	if len(hn.Steps[0].Request) > StepFieldCap+200 {
		t.Fatalf("request not clipped: %d", len(hn.Steps[0].Request))
	}
	if !strings.Contains(hn.Steps[0].Request, "已截断") {
		t.Fatal("clipped field must say so")
	}

	// 步骤条数上限
	many := &Reproduction{}
	for i := 0; i < MaxSteps*3; i++ {
		many.Steps = append(many.Steps, ReproStep{Request: "x"})
	}
	if got := len(many.Normalize().Steps); got != MaxSteps {
		t.Fatalf("step cap not applied: %d", got)
	}
}

// 多字节字符不能被截断劈开（劈开就是乱码，报告里最显眼）。
func TestReproductionClipKeepsRuneBoundary(t *testing.T) {
	body := strings.Repeat("测试", StepFieldCap) // 每个汉字 3 字节
	n := (&Reproduction{Steps: []ReproStep{{Request: body}}}).Normalize()
	got := n.Steps[0].Request
	if !utf8.ValidString(got) {
		t.Fatal("clipped field is not valid UTF-8 (cut mid-rune)")
	}
	if !strings.HasPrefix(got, "测试") {
		t.Fatal("content should start intact")
	}
	if !strings.Contains(got, "已截断") {
		t.Fatal("clipped field must carry the marker")
	}
}

// Encode/Decode 往返：NULL 与坏数据都还原成 nil，不 panic。
func TestReproductionEncodeDecode(t *testing.T) {
	var nilRepro *Reproduction
	val, err := nilRepro.Encode()
	if err != nil || val.Valid {
		t.Fatalf("nil should encode to NULL: %v %v", val, err)
	}
	if DecodeReproduction(val) != nil {
		t.Fatal("NULL must decode to nil")
	}

	src := &Reproduction{EntryPoint: "GET /x", Steps: []ReproStep{{Request: "GET /x HTTP/1.1"}}}
	val2, err := src.Encode()
	if err != nil || !val2.Valid {
		t.Fatalf("encode failed: %v", err)
	}
	back := DecodeReproduction(val2)
	if back == nil || back.EntryPoint != "GET /x" || len(back.Steps) != 1 {
		t.Fatalf("round-trip lost data: %+v", back)
	}

	if DecodeReproduction(sqlNull(`{"broken":`)) != nil {
		t.Fatal("broken JSON must decode to nil (treated as no reproduction)")
	}
	if DecodeReproduction(sqlNull(`{}`)) != nil {
		t.Fatal("empty object must decode to nil")
	}
}

// sqlNull 造一个 Valid 的 sql.NullString（测试用）。
func sqlNull(s string) sql.NullString {
	return sql.NullString{String: s, Valid: true}
}
