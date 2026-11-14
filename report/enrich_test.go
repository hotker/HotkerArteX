package report

import (
	"strings"
	"testing"
)

// 模型输出的常见形态都要能解析：裸 JSON、```json 围栏、前后夹带解释文字。
func TestParseEnrichmentToleratesFences(t *testing.T) {
	body := `{"title":"登录接口 SQL 注入","target":"app.local","module":"外部登录",
		"description":["用户名参数拼接进 SQL"],"risk_analysis":["可读取全库"],
		"remediation":["改用参数化查询"],"cvss_score":9.8,
		"cvss_vector":"AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","cvss_metrics":{"AV":"N"}}`
	for _, raw := range []string{
		body,
		"```json\n" + body + "\n```",
		"好的，以下是改写结果：\n" + body + "\n希望有帮助。",
		"```\n" + body + "\n```",
	} {
		e, err := ParseEnrichment(raw)
		if err != nil {
			t.Fatalf("parse failed for %q: %v", raw[:20], err)
		}
		if e.Title != "登录接口 SQL 注入" || e.CVSSScore != 9.8 || len(e.Description) != 1 {
			t.Fatalf("wrong parse: %+v", e)
		}
		if e.Empty() {
			t.Fatal("should not be empty")
		}
	}
}

// CVSS 向量形状不对时必须丢弃 —— 报告里出现一句假的 CVSS 比没有更糟。
func TestParseEnrichmentRejectsFakeVector(t *testing.T) {
	e, err := ParseEnrichment(`{"title":"x","cvss_score":7.5,"cvss_vector":"高危向量"}`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.CVSSVector != "" {
		t.Fatalf("bogus vector should be dropped, got %q", e.CVSSVector)
	}
	if e.CVSSScore != 7.5 {
		t.Fatalf("score should survive: %v", e.CVSSScore)
	}
	// 超界分数夹到 0..10
	e2, _ := ParseEnrichment(`{"title":"x","cvss_score":42}`)
	if e2.CVSSScore != 10 {
		t.Fatalf("score should clamp to 10, got %v", e2.CVSSScore)
	}
}

func TestParseEnrichmentGarbage(t *testing.T) {
	if _, err := ParseEnrichment("这完全不是 JSON"); err == nil {
		t.Fatal("garbage should error so caller keeps the original fields")
	}
	e, err := ParseEnrichment(`{"title":"","description":[],"risk_analysis":[],"remediation":[]}`)
	if err != nil {
		t.Fatalf("empty JSON should parse: %v", err)
	}
	if !e.Empty() {
		t.Fatal("all-empty result must report Empty() so the caller can fall back")
	}
}

// 提示里必须明确"不要生成测试步骤" —— 这是本实现与上游的关键分野：
// 步骤由真实证据渲染，让模型复述请求/响应既慢又容易编。
func TestEnrichPromptForbidsFabricatedSteps(t *testing.T) {
	u := EnrichUserPrompt(EnrichInput{VulnClass: "SQLi", Severity: "critical", Summary: "s", Evidence: "e"}, "zh-CN")
	if !strings.Contains(u, "test_process") || !strings.Contains(u, "由平台用真实证据直接渲染") {
		t.Fatalf("prompt must tell the model not to fabricate steps:\n%s", u)
	}
	for _, want := range []string{"title", "description", "risk_analysis", "remediation", "cvss_vector"} {
		if !strings.Contains(u, want) {
			t.Fatalf("prompt missing field %q", want)
		}
	}
	if !strings.Contains(u, "使用简体中文") {
		t.Fatal("language directive missing")
	}
	// 繁体 / 英文切换
	if got := EnrichUserPrompt(EnrichInput{}, "en-US"); !strings.Contains(got, "Write in English") {
		t.Fatal("english directive missing")
	}
}

// 证据过长要按 rune 截断，不能把汉字劈成乱码再喂给模型。
func TestEnrichPromptClipsEvidence(t *testing.T) {
	long := strings.Repeat("测试", 5000)
	u := EnrichUserPrompt(EnrichInput{Summary: "s", Evidence: long}, "zh-CN")
	if len([]rune(u)) > 15000 {
		t.Fatalf("prompt not clipped: %d runes", len([]rune(u)))
	}
	if !strings.Contains(u, "…") {
		t.Fatal("clip marker missing")
	}
}
