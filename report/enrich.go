package report

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// 漏洞富化：把「一句话 summary + 原始证据」改写成交付级结构化数据。
//
// 与上游的差别在于**不生成测试过程**。上游把 test_process 也交给模型（后来又改成
// "只写散文、步骤由真实证据生成"，但字段仍留在模型输出结构里）。这里直接把它从
// 模型职责里拿掉：报告的「复现过程」由 findings.reproduction（agent 就地落库的真实
// 步骤）或原始 PoC 渲染 —— 让模型复述一遍请求/响应，既慢又容易编。
//
// 所以模型只负责四件事：规范标题、描述、影响、修复建议 + CVSS 三要素。
// 这些都是"改写"，不是"回忆"，模型做得好且快。

// Enrichment 是一条漏洞的富化结果。
type Enrichment struct {
	Title        string            `json:"title"`
	Target       string            `json:"target"`
	Module       string            `json:"module"`
	Description  []string          `json:"description"`
	RiskAnalysis []string          `json:"risk_analysis"`
	Remediation  []string          `json:"remediation"`
	CVSSScore    float64           `json:"cvss_score"`
	CVSSVector   string            `json:"cvss_vector"`
	CVSSMetrics  map[string]string `json:"cvss_metrics"`
}

// EnrichInput 是富化的输入（全部来自库里已有的事实）。
type EnrichInput struct {
	VulnClass string
	Severity  string
	Summary   string
	Evidence  string // 原始证据 / PoC 原文
	// Reproduction 是 agent 就地记录的结构化复现过程（JSON 原文）；给模型做上下文，
	// 但它不需要复述，只用来把描述/影响写准。
	Reproduction string
	// Transcript 是发现该漏洞时的真实工作转录（可选，截断后喂入）。
	Transcript string
}

// EnrichSystemPrompt 是系统提示。公司名由调用方注入（报告封面用同一套称呼）。
func EnrichSystemPrompt(company string) string {
	if strings.TrimSpace(company) == "" {
		company = "安全服务团队"
	}
	return "你是" + company + "的资深渗透测试报告撰写专家。把漏洞原始记录改写为【交付级】报告正文——" +
		"像资深顾问亲笔写给客户：精炼、具体、克制。严格只输出 JSON，不要 markdown 代码块，不要客套话与免责声明。" +
		"证据里的请求/命令/响应原文必须如实引用，不得编造。"
}

// enrichUserPrompt 拼出改写指令。逐条要求都对应报告里的一个字段，避免"写得多但没用"。
func EnrichUserPrompt(in EnrichInput, lang string) string {
	var b strings.Builder
	b.WriteString("把下面这条漏洞改写成报告正文。核心要求：精炼、具体、克制——宁缺毋滥，不凑条数、不注水。\n\n")
	fmt.Fprintf(&b, "漏洞类型/原始名称：%s\n严重程度：%s\n原始摘要：\n%s\n\n原始证据/PoC：\n%s\n",
		coalesce(in.VulnClass, "-"), coalesce(in.Severity, "-"), coalesce(in.Summary, "-"), clipRunes(coalesce(in.Evidence, "-"), 6000))
	if strings.TrimSpace(in.Reproduction) != "" {
		fmt.Fprintf(&b, "\n=== 复现过程（已由测试引擎就地记录，无需你复述）===\n%s\n", clipRunes(in.Reproduction, 4000))
	}
	if strings.TrimSpace(in.Transcript) != "" {
		fmt.Fprintf(&b, "\n=== 发现该漏洞时的真实工作转录（描述与影响要依据这里的真实现象，不得编造）===\n%s\n",
			clipRunes(in.Transcript, 12000))
	}
	b.WriteString(`
字段要求：
- title：规范、专业的漏洞名称（10-26 字）。原始名已规范（含 CVE 等）就保留或微调，不要照抄摘要。
- target：受影响主机或 URL，从摘要/证据中提取；无法确定留空字符串。
- module：所属功能模块（简短，如"外部账户登录 / 未授权接口"）。
- description：1 段 2-3 句，只说清这是什么漏洞、出在哪个点、本质成因。不堆 OWASP 分类、不复述修复。
- risk_analysis：2-4 条，每条一句，必须是针对本目标本漏洞的具体后果（谁、能做什么、拿到什么数据或权限），不要套话。
- remediation：2-4 条，每条一句，具体可落地（改哪个点、怎么改、校验什么）。
- CVSS 3.1：cvss_score（数字）、cvss_vector（如 "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"）、cvss_metrics（八项英文取值，键为 AV/AC/PR/UI/S/C/I/A）。

不要输出测试步骤（test_process）——报告的复现过程由平台用真实证据直接渲染。
只输出 JSON：{"title":"...","target":"...","module":"...","description":["..."],"risk_analysis":["..."],"remediation":["..."],"cvss_score":0,"cvss_vector":"...","cvss_metrics":{"AV":"N"}}`)
	if dir := langDirective(lang); dir != "" {
		b.WriteString("\n\n输出语言要求：" + dir)
	}
	return b.String()
}

// langDirective 给出目标语言的一句指令（简/繁/英）；未知语言不追加。
func langDirective(lang string) string {
	switch NormalizeLang(lang) {
	case LangZHTW:
		return "使用繁体中文（台灣用語）。"
	case LangENUS:
		return "Write in English."
	default:
		return "使用简体中文。"
	}
}

// ParseEnrichment 解析模型输出。容忍 ```json 围栏与前后废话（模型常见）。
//
// 解析失败返回零值 + error：调用方据此保留原始字段，而不是拿半个结果覆盖库里已有的富化。
func ParseEnrichment(raw string) (Enrichment, error) {
	var out Enrichment
	s := strings.TrimSpace(raw)
	s = strings.TrimPrefix(s, "```json")
	s = strings.TrimPrefix(s, "```")
	s = strings.TrimSuffix(s, "```")
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "{"); i >= 0 {
		if j := strings.LastIndex(s, "}"); j > i {
			s = s[i : j+1]
		}
	}
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return Enrichment{}, fmt.Errorf("富化结果解析失败: %w", err)
	}
	out.Title = strings.TrimSpace(out.Title)
	out.Target = strings.TrimSpace(out.Target)
	out.Module = strings.TrimSpace(out.Module)
	out.CVSSVector = strings.TrimSpace(out.CVSSVector)
	out.Description = trimList(out.Description)
	out.RiskAnalysis = trimList(out.RiskAnalysis)
	out.Remediation = trimList(out.Remediation)
	if out.CVSSScore < 0 {
		out.CVSSScore = 0
	}
	if out.CVSSScore > 10 {
		out.CVSSScore = 10
	}
	// 向量必须像 CVSS 向量（AV:…/AC:…）：形状不对就当没给，免得报告里出现一句假的 CVSS。
	if out.CVSSVector != "" && !looksLikeCVSSVector(out.CVSSVector) {
		out.CVSSVector = ""
	}
	return out, nil
}

// Empty 报告这次富化是否什么也没拿到（调用方据此保留原始字段并回"失败"）。
func (e Enrichment) Empty() bool {
	return e.Title == "" && len(e.Description) == 0 && len(e.RiskAnalysis) == 0 && len(e.Remediation) == 0
}

func looksLikeCVSSVector(v string) bool {
	parts := strings.Split(v, "/")
	if len(parts) < 3 {
		return false
	}
	for _, p := range parts {
		if !strings.Contains(p, ":") {
			return false
		}
	}
	return strings.HasPrefix(v, "AV:")
}

func trimList(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if t := strings.TrimSpace(s); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// coalesce 返回第一个非空值（report 包里已有同名 nz，这里用不同的名字避免冲突）。
func coalesce(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

// clipRunes 按 rune 截断，避免把多字节字符劈开（喂给模型的内容也不能是乱码）。
func clipRunes(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "…"
}

// CompleteText 是富化 / 报告叙述共用的"一次性文本补全"。
// 用接口而不是具体 provider，让 report 包不依赖 server 的选路逻辑。
type CompleteFunc func(ctx context.Context, system, user string, maxTokens int) (string, error)
