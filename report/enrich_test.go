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

// 补录：没有 evidence 的条目必须被丢弃 —— "不许推测"写在提示里不算，代码里才算。
func TestParseExtractedDropsUnsupported(t *testing.T) {
	raw := `{"findings":[
		{"vulnclass":"SQL注入","name":"登录接口SQL注入","severity":"严重","summary":"s","evidence":"POST /api/login -> 500 报错","target":"app.local"},
		{"vulnclass":"越权","name":"越权访问订单","severity":"high","summary":"s","evidence":"","target":"app.local"},
		{"vulnclass":"","name":"","severity":"high","summary":"无类型无名","evidence":"库里只有一条空记录"}
	]}`
	got, err := ParseExtracted(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("only the supported entry should survive, got %d: %+v", len(got), got)
	}
	if got[0].Severity != "critical" {
		t.Fatalf("severity should normalize 严重→critical, got %q", got[0].Severity)
	}
	if got[0].Name != "登录接口SQL注入" || got[0].Target != "app.local" {
		t.Fatalf("fields lost: %+v", got[0])
	}
}

// 空结果必须被当作合法的"没东西可补"，而不是解析失败。
func TestParseExtractedEmptyIsFine(t *testing.T) {
	got, err := ParseExtracted(`{"findings":[]}`)
	if err != nil {
		t.Fatalf("empty findings should parse: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected none, got %+v", got)
	}
	if _, err := ParseExtracted("这不是 JSON"); err == nil {
		t.Fatal("garbage should error")
	}
}

// 严重度归一：模型的自由写法（中文/大小写/未知）都要落到四档之一。
func TestNormalizeSeverityAI(t *testing.T) {
	cases := map[string]string{
		"严重": "critical", "Critical": "critical", "高危": "high",
		"medium": "medium", "低": "low", "info": "low", "不清楚": "medium", "": "medium",
	}
	for in, want := range cases {
		if got := normalizeSeverityAI(in); got != want {
			t.Fatalf("normalizeSeverityAI(%q) = %q, want %q", in, got, want)
		}
	}
}

// 提示里必须明确"只补已验证的、evidence 要引用真实片段"，否则模型会大面积推测。
func TestExtractPromptConstrains(t *testing.T) {
	p := ExtractUserPrompt("转录内容", "事实清单", "- [high] SQL注入：登录", "zh-CN")
	for _, want := range []string{"已被实际验证", "evidence", "不要重复补录", "不要自己编造"} {
		if !strings.Contains(p, want) {
			t.Fatalf("prompt missing constraint %q", want)
		}
	}
	if !strings.Contains(p, "转录内容") || !strings.Contains(p, "事实清单") {
		t.Fatal("prompt must carry both transcript and facts")
	}
	if !strings.Contains(p, "已经记录的漏洞") {
		t.Fatal("prompt must carry the dedup list")
	}
}
