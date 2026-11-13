package report

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// 本文件把「任务 + 已确认漏洞 + 组织设置」翻成 doc（docx.go 的渲染结构），
// 三语（简体 / 繁体 / 英文）共用同一套结构，只换词表。
//
// 与上游的差别不在版式，在信息来源：上游报告正文由 AI 叙述生成，因此每次出报告
// 都要一次 LLM 调用、内容不稳定、且没法离线复现；这里只用【已经落库的事实】
// （漏洞字段、复现步骤、关联流量、资产），同一份数据任何时候渲染出来都一样 ——
// 交付件要的是可追溯，不是文采。AI 富化如果做过，其结果本来就已写进这些字段。

// Lang 是报告语言。
type Lang string

const (
	LangZHCN Lang = "zh-CN"
	LangZHTW Lang = "zh-TW"
	LangENUS Lang = "en-US"
)

// NormalizeLang 把任意输入收敛到支持的三语之一（默认简体）。
func NormalizeLang(s string) Lang {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "zh-tw", "zh-hant", "tw":
		return LangZHTW
	case "en", "en-us", "english":
		return LangENUS
	default:
		return LangZHCN
	}
}

// langSet 是一套报告用词。键集合必须与 renderText 引用的键一致。
type langSet struct {
	ReportTitle   string
	DefaultClient string
	Confidential  string
	TOC           string
	MetaClient    string
	MetaProject   string
	MetaScope     string
	MetaWindow    string
	MetaIssuedBy  string
	MetaGenerated string
	MetaVersion   string
	MetaPeople    string

	SecOverview   string
	SecScope      string
	SecSummary    string
	SecFindings   string
	SecAppendix   string
	IntroDefault  string
	ScopeMethods  string
	SummaryLead   string
	AppendixLead  string

	ThID       string
	ThName     string
	ThSeverity string
	ThAsset    string
	ThStatus   string
	ThCount    string

	SevCritical string
	SevHigh     string
	SevMedium   string
	SevLow      string
	SevUnknown  string

	StPending      string
	StConfirmed    string
	StResolved     string
	StFalsePos     string
	StIgnored      string
	StInProgress   string
	StRiskAccepted string
	StDuplicate    string
	StFixed        string

	LblVulnClass    string
	LblSeverity     string
	LblCVSS         string
	LblAssets       string
	LblStatus       string
	LblSummary      string
	LblImpact       string
	LblRepro        string
	LblEvidence     string
	LblRemediation  string
	LblDetail       string
	LblEntry        string
	LblPrereq       string
	LblStepN        string
	LblRequest      string
	LblResponse     string
	LblExpected     string
	LblTraffic      string
	LblNoFinding    string
	LblNoStep       string
	LblTruncated    string
	FooterPrefix    string
	TotalFindings   string
	ReportedAtFmt   string
}

var langs = map[Lang]langSet{
	LangZHCN: {
		ReportTitle: "渗透测试报告", DefaultClient: "（未指定客户）", Confidential: "密级：机密",
		TOC: "目录", MetaClient: "客户", MetaProject: "项目", MetaScope: "测试范围",
		MetaWindow: "测试窗口", MetaIssuedBy: "出具方", MetaGenerated: "出具日期",
		MetaVersion: "版本", MetaPeople: "测试人员",
		SecOverview: "1. 项目概述", SecScope: "2. 测试范围与方法", SecSummary: "3. 风险统计",
		SecFindings: "4. 漏洞详情", SecAppendix: "5. 附录",
		IntroDefault: "本次测试对目标系统实施了黑盒视角的安全测试，覆盖信息收集、攻击面枚举、漏洞验证与影响评估。以下内容仅记录已实际触发并可复现的问题。",
		ScopeMethods: "测试方法：主动扫描、手工验证、业务逻辑分析；所有验证均在实际可达范围内执行，并对每一步保留可复现的请求/响应证据。",
		SummaryLead:  "本次测试共确认漏洞 %d 个，按严重程度分布如下；详细描述见第 4 章。",
		AppendixLead: "附录汇总本次测试涉及的资产与关联证据，便于复核。",
		ThID: "编号", ThName: "漏洞", ThSeverity: "等级", ThAsset: "资产", ThStatus: "状态", ThCount: "数量",
		SevCritical: "严重", SevHigh: "高危", SevMedium: "中危", SevLow: "低危", SevUnknown: "未评级",
		StPending: "待处理", StConfirmed: "已确认", StResolved: "已处理", StFalsePos: "误报",
		StIgnored: "忽略", StInProgress: "处理中", StRiskAccepted: "风险接受", StDuplicate: "重复", StFixed: "已修复",
		LblVulnClass: "漏洞类型", LblSeverity: "风险等级", LblCVSS: "CVSS", LblAssets: "影响资产",
		LblStatus: "处置状态", LblSummary: "漏洞描述", LblImpact: "影响", LblRepro: "复现过程",
		LblEvidence: "验证证据", LblRemediation: "修复建议", LblDetail: "详细说明",
		LblEntry: "入口点", LblPrereq: "前置条件", LblStepN: "步骤 %d",
		LblRequest: "请求", LblResponse: "响应", LblExpected: "预期", LblTraffic: "关联流量",
		LblNoFinding: "本次测试未确认可利用漏洞。", LblNoStep: "（未登记结构化复现步骤）",
		LblTruncated: "（报告内容过长，已截断）", FooterPrefix: "渗透测试报告",
		TotalFindings: "确认漏洞总数", ReportedAtFmt: "2006-01-02",
	},
	LangZHTW: {
		ReportTitle: "滲透測試報告", DefaultClient: "（未指定客戶）", Confidential: "密級：機密",
		TOC: "目錄", MetaClient: "客戶", MetaProject: "專案", MetaScope: "測試範圍",
		MetaWindow: "測試期間", MetaIssuedBy: "出具方", MetaGenerated: "出具日期",
		MetaVersion: "版本", MetaPeople: "測試人員",
		SecOverview: "1. 專案概述", SecScope: "2. 測試範圍與方法", SecSummary: "3. 風險統計",
		SecFindings: "4. 漏洞詳情", SecAppendix: "5. 附錄",
		IntroDefault: "本次測試對目標系統實施黑箱視角的安全測試，涵蓋資訊收集、攻擊面列舉、漏洞驗證與影響評估。以下僅記錄已實際觸發且可重現的問題。",
		ScopeMethods: "測試方法：主動掃描、手工驗證、業務邏輯分析；所有驗證均於實際可達範圍內執行，並保留可重現的請求／回應證據。",
		SummaryLead:  "本次測試共確認漏洞 %d 個，依嚴重程度分布如下；詳細描述見第 4 章。",
		AppendixLead: "附錄彙整本次測試涉及的資產與關聯證據，便於複核。",
		ThID: "編號", ThName: "漏洞", ThSeverity: "等級", ThAsset: "資產", ThStatus: "狀態", ThCount: "數量",
		SevCritical: "嚴重", SevHigh: "高風險", SevMedium: "中風險", SevLow: "低風險", SevUnknown: "未評級",
		StPending: "待處理", StConfirmed: "已確認", StResolved: "已處理", StFalsePos: "誤報",
		StIgnored: "忽略", StInProgress: "處理中", StRiskAccepted: "風險接受", StDuplicate: "重複", StFixed: "已修復",
		LblVulnClass: "漏洞類型", LblSeverity: "風險等級", LblCVSS: "CVSS", LblAssets: "影響資產",
		LblStatus: "處置狀態", LblSummary: "漏洞描述", LblImpact: "影響", LblRepro: "重現過程",
		LblEvidence: "驗證證據", LblRemediation: "修復建議", LblDetail: "詳細說明",
		LblEntry: "入口點", LblPrereq: "前置條件", LblStepN: "步驟 %d",
		LblRequest: "請求", LblResponse: "回應", LblExpected: "預期", LblTraffic: "關聯流量",
		LblNoFinding: "本次測試未確認可利用漏洞。", LblNoStep: "（未登錄結構化重現步驟）",
		LblTruncated: "（報告內容過長，已截斷）", FooterPrefix: "滲透測試報告",
		TotalFindings: "確認漏洞總數", ReportedAtFmt: "2006-01-02",
	},
	LangENUS: {
		ReportTitle: "Penetration Test Report", DefaultClient: "(client unspecified)", Confidential: "CONFIDENTIAL",
		TOC: "Contents", MetaClient: "Client", MetaProject: "Project", MetaScope: "Scope",
		MetaWindow: "Test window", MetaIssuedBy: "Issued by", MetaGenerated: "Issued on",
		MetaVersion: "Version", MetaPeople: "Testers",
		SecOverview: "1. Project Overview", SecScope: "2. Scope and Methodology", SecSummary: "3. Risk Summary",
		SecFindings: "4. Findings", SecAppendix: "5. Appendix",
		IntroDefault: "This engagement assessed the target system from a black-box perspective, covering reconnaissance, attack-surface enumeration, exploitation and impact assessment. Only issues that were actually triggered and can be reproduced are recorded below.",
		ScopeMethods: "Methodology: active scanning, manual verification and business-logic analysis. Every verification was performed within the reachable scope, with reproducible request/response evidence retained.",
		SummaryLead:  "%d confirmed findings, distributed by severity below; see Chapter 4 for details.",
		AppendixLead: "The appendix consolidates the assets and evidence involved, for review.",
		ThID: "ID", ThName: "Finding", ThSeverity: "Severity", ThAsset: "Asset", ThStatus: "Status", ThCount: "Count",
		SevCritical: "Critical", SevHigh: "High", SevMedium: "Medium", SevLow: "Low", SevUnknown: "Unrated",
		StPending: "Pending", StConfirmed: "Confirmed", StResolved: "Resolved", StFalsePos: "False positive",
		StIgnored: "Ignored", StInProgress: "In progress", StRiskAccepted: "Risk accepted", StDuplicate: "Duplicate", StFixed: "Fixed",
		LblVulnClass: "Class", LblSeverity: "Severity", LblCVSS: "CVSS", LblAssets: "Affected assets",
		LblStatus: "Status", LblSummary: "Description", LblImpact: "Impact", LblRepro: "Reproduction",
		LblEvidence: "Evidence", LblRemediation: "Remediation", LblDetail: "Details",
		LblEntry: "Entry point", LblPrereq: "Prerequisites", LblStepN: "Step %d",
		LblRequest: "Request", LblResponse: "Response", LblExpected: "Expected", LblTraffic: "Related traffic",
		LblNoFinding: "No exploitable findings were confirmed in this engagement.",
		LblNoStep:    "(no structured reproduction steps recorded)",
		LblTruncated: "(report too long, truncated)", FooterPrefix: "Penetration Test Report",
		TotalFindings: "Total findings", ReportedAtFmt: "2006-01-02",
	},
}

// Person 是一名测试人员。
type Person struct {
	Name    string `json:"name"`
	Role    string `json:"role"`
	Contact string `json:"contact"`
}

// Settings 是组织级报告设置（出具方/客户/人员/默认语言）。存在 settings 表的一行里。
type Settings struct {
	Company      string   `json:"company"`       // 出具方
	Client       string   `json:"client"`        // 默认客户
	Confidential string   `json:"confidential"`  // 封面密级文本；空 = 用语言默认
	Lang         string   `json:"lang"`          // 默认语言
	People       []Person `json:"people"`
	Version      string   `json:"version"`       // 报告版本，如 v1.0
}

// Step 是一个复现步骤（与 finding 的 reproduction 结构对齐）。
type Step struct {
	Request  string `json:"request"`
	Response string `json:"response"`
	Expected string `json:"expected"`
	Proves   string `json:"proves"`
}

// Finding 是报告里的一条漏洞（由 db.DBFinding + 复现结构拼成）。
type Finding struct {
	ID          int64
	Name        string
	VulnClass   string
	Severity    string
	Status      string
	CVSS        string
	Summary     string
	Impact      string
	Remediation string
	Evidence    string
	Detail      string // 详细报告（Markdown 原文，尽量原样搬运）
	Assets      []string
	EntryPoint  string
	Prereq      string
	Steps       []Step
	Traffic     []string // 形如 "GET https://host/path → 200"
}

// DocInput 是渲染一份报告所需的全部数据。
type DocInput struct {
	TaskTitle   string
	Goal        string
	Scope       string
	StartedAt   time.Time
	FinishedAt  time.Time
	GeneratedAt time.Time
	AssetCount  int
	Assets      []string
	Settings    Settings
	Findings    []Finding
}

// Build 把数据翻成 doc 结构（纯函数，便于测试与将来的 HTML/PDF 复用）。
func Build(in DocInput) *doc {
	ls := langs[NormalizeLang(in.Settings.Lang)]
	d := &doc{
		Title:    ls.ReportTitle,
		Subtitle: firstNonEmpty(in.TaskTitle, in.Goal),
		Footer:   ls.FooterPrefix + " · " + firstNonEmpty(in.Settings.Client, ls.DefaultClient),
	}

	conf := firstNonEmpty(in.Settings.Confidential, ls.Confidential)
	d.Meta = append(d.Meta,
		metaRow{ls.MetaClient, firstNonEmpty(in.Settings.Client, ls.DefaultClient)},
		metaRow{ls.MetaProject, firstNonEmpty(in.TaskTitle, in.Goal)},
		metaRow{ls.MetaScope, firstNonEmpty(in.Scope, "—")},
		metaRow{ls.MetaWindow, windowText(in.StartedAt, in.FinishedAt)},
		metaRow{ls.MetaIssuedBy, firstNonEmpty(in.Settings.Company, "—")},
		metaRow{ls.MetaGenerated, in.GeneratedAt.Format(ls.ReportedAtFmt)},
		metaRow{ls.MetaVersion, firstNonEmpty(in.Settings.Version, "v1.0")},
		metaRow{conf, ""},
	)
	if len(in.Settings.People) > 0 {
		var names []string
		for _, p := range in.Settings.People {
			switch {
			case p.Name == "":
			case p.Role == "":
				names = append(names, p.Name)
			default:
				names = append(names, p.Name+"（"+p.Role+"）")
			}
		}
		if len(names) > 0 {
			d.Meta = append(d.Meta, metaRow{ls.MetaPeople, strings.Join(names, "、")})
		}
	}

	// 目录页（Word 更新域后展开）
	d.Blocks = append(d.Blocks,
		block{Kind: blockHeading, Level: 1, Text: ls.TOC},
		block{Kind: blockTOC},
		block{Kind: blockPageBreak},
	)

	// 1 概述
	d.Blocks = append(d.Blocks,
		block{Kind: blockHeading, Level: 1, Text: ls.SecOverview},
		block{Kind: blockPara, Text: ls.IntroDefault},
	)
	if g := strings.TrimSpace(in.Goal); g != "" {
		d.Blocks = append(d.Blocks, block{Kind: blockBullets, Items: []string{ls.MetaProject + "：" + g}})
	}

	// 2 范围与方法
	d.Blocks = append(d.Blocks,
		block{Kind: blockHeading, Level: 1, Text: ls.SecScope},
		block{Kind: blockPara, Text: ls.ScopeMethods},
	)
	if s := strings.TrimSpace(in.Scope); s != "" {
		d.Blocks = append(d.Blocks, block{Kind: blockCode, Code: s})
	}
	if len(in.Assets) > 0 {
		d.Blocks = append(d.Blocks, block{Kind: blockBullets, Items: clipList(in.Assets, 60)})
	}

	// 3 风险统计
	fs := append([]Finding(nil), in.Findings...)
	sort.SliceStable(fs, func(i, j int) bool {
		if docSevRank[normalizeSeverity(fs[i].Severity)] != docSevRank[normalizeSeverity(fs[j].Severity)] {
			return docSevRank[normalizeSeverity(fs[i].Severity)] < docSevRank[normalizeSeverity(fs[j].Severity)]
		}
		return fs[i].ID < fs[j].ID
	})
	d.Blocks = append(d.Blocks,
		block{Kind: blockHeading, Level: 1, Text: ls.SecSummary},
		block{Kind: blockPara, Text: fmt.Sprintf(ls.SummaryLead, len(fs))},
	)
	bySev := map[string]int{}
	for _, f := range fs {
		bySev[normalizeSeverity(f.Severity)]++
	}
	d.Blocks = append(d.Blocks, block{
		Kind:    blockTable,
		Headers: []string{ls.ThSeverity, ls.ThCount},
		Rows: [][]string{
			{ls.SevCritical, itoa(bySev["critical"])},
			{ls.SevHigh, itoa(bySev["high"])},
			{ls.SevMedium, itoa(bySev["medium"])},
			{ls.SevLow, itoa(bySev["low"])},
			{ls.SevUnknown, itoa(bySev[""])},
			{ls.TotalFindings, itoa(len(fs))},
		},
		Widths: []float64{6000, 3026},
	})
	if len(fs) > 0 {
		rows := make([][]string, 0, len(fs))
		for i, f := range fs {
			rows = append(rows, []string{
				fmt.Sprintf("F-%02d", i+1),
				firstNonEmpty(f.Name, f.VulnClass, "—"),
				severityLabel(ls, f.Severity),
				strings.Join(clipList(f.Assets, 3), "\n"),
				statusLabel(ls, f.Status),
			})
		}
		d.Blocks = append(d.Blocks, block{
			Kind:    blockTable,
			Headers: []string{ls.ThID, ls.ThName, ls.ThSeverity, ls.ThAsset, ls.ThStatus},
			Rows:    rows,
			Widths:  []float64{900, 3400, 1100, 2400, 1226},
		})
	}

	// 4 漏洞详情
	d.Blocks = append(d.Blocks, block{Kind: blockHeading, Level: 1, Text: ls.SecFindings})
	if len(fs) == 0 {
		d.Blocks = append(d.Blocks, block{Kind: blockPara, Text: ls.LblNoFinding})
	}
	for i, f := range fs {
		d.Blocks = append(d.Blocks, findingBlocks(ls, i+1, f)...)
	}

	// 5 附录
	d.Blocks = append(d.Blocks,
		block{Kind: blockHeading, Level: 1, Text: ls.SecAppendix},
		block{Kind: blockPara, Text: ls.AppendixLead},
	)
	if in.AssetCount > 0 || len(in.Assets) > 0 {
		d.Blocks = append(d.Blocks, block{
			Kind:    blockTable,
			Headers: []string{ls.ThAsset, ls.ThCount},
			Rows:    [][]string{{ls.ThAsset, itoa(max(in.AssetCount, len(in.Assets)))}},
			Widths:  []float64{6000, 3026},
		})
	}
	return d
}

// findingBlocks 渲染一条漏洞：属性表 + 描述/影响/复现/证据/修复。
func findingBlocks(ls langSet, n int, f Finding) []block {
	title := fmt.Sprintf("4.%d %s", n, firstNonEmpty(f.Name, f.VulnClass, "—"))
	out := []block{
		{Kind: blockHeading, Level: 2, Text: title},
		{
			Kind:    blockTable,
			Headers: []string{ls.ThID, ls.ThSeverity, ls.ThStatus, ls.LblCVSS},
			Rows: [][]string{{
				fmt.Sprintf("F-%02d", n),
				severityLabel(ls, f.Severity),
				statusLabel(ls, f.Status),
				firstNonEmpty(f.CVSS, "—"),
			}},
			Widths: []float64{1800, 2200, 2200, 2826},
		},
	}
	row := func(k, v string) block {
		return block{Kind: blockTable, Headers: nil, Rows: [][]string{{k, v}}, Widths: []float64{2200, 6626}}
	}
	if f.VulnClass != "" {
		out = append(out, row(ls.LblVulnClass, f.VulnClass))
	}
	if len(f.Assets) > 0 {
		out = append(out, row(ls.LblAssets, strings.Join(f.Assets, "\n")))
	}
	if f.EntryPoint != "" {
		out = append(out, row(ls.LblEntry, f.EntryPoint))
	}
	if f.Prereq != "" {
		out = append(out, row(ls.LblPrereq, f.Prereq))
	}

	section := func(label, body string) []block {
		body = strings.TrimSpace(body)
		if body == "" {
			return nil
		}
		return []block{
			{Kind: blockHeading, Level: 3, Text: label},
			{Kind: blockPara, Text: body},
		}
	}
	out = append(out, section(ls.LblSummary, f.Summary)...)
	out = append(out, section(ls.LblImpact, f.Impact)...)
	out = append(out, section(ls.LblDetail, f.Detail)...)

	// 复现：先给结构化步骤（每步请求/响应单独成为代码块），再退回自由文本证据。
	out = append(out, block{Kind: blockHeading, Level: 3, Text: ls.LblRepro})
	if len(f.Steps) == 0 {
		out = append(out, block{Kind: blockPara, Text: ls.LblNoStep})
	}
	for i, st := range f.Steps {
		out = append(out, block{Kind: blockHeading, Level: 3, Text: fmt.Sprintf(ls.LblStepN, i+1)})
		if st.Expected != "" {
			out = append(out, block{Kind: blockPara, Text: ls.LblExpected + "：" + st.Expected})
		}
		if st.Request != "" {
			out = append(out, block{Kind: blockPara, Text: ls.LblRequest + "："}, block{Kind: blockCode, Code: st.Request})
		}
		if st.Response != "" {
			out = append(out, block{Kind: blockPara, Text: ls.LblResponse + "："}, block{Kind: blockCode, Code: st.Response})
		}
		if st.Proves != "" {
			out = append(out, block{Kind: blockPara, Text: st.Proves})
		}
	}
	if len(f.Traffic) > 0 {
		out = append(out, block{Kind: blockHeading, Level: 3, Text: ls.LblTraffic},
			block{Kind: blockBullets, Items: clipList(f.Traffic, 20)})
	}
	out = append(out, section(ls.LblEvidence, f.Evidence)...)
	out = append(out, section(ls.LblRemediation, f.Remediation)...)
	out = append(out, block{Kind: blockPageBreak})
	return out
}

func severityLabel(ls langSet, sev string) string {
	switch normalizeSeverity(sev) {
	case "critical":
		return ls.SevCritical
	case "high":
		return ls.SevHigh
	case "medium":
		return ls.SevMedium
	case "low":
		return ls.SevLow
	}
	return ls.SevUnknown
}

func statusLabel(ls langSet, st string) string {
	switch strings.ToLower(strings.TrimSpace(st)) {
	case "confirmed":
		return ls.StConfirmed
	case "resolved":
		return ls.StResolved
	case "fixed":
		return ls.StFixed
	case "false_positive":
		return ls.StFalsePos
	case "ignored":
		return ls.StIgnored
	case "in_progress":
		return ls.StInProgress
	case "risk_accepted":
		return ls.StRiskAccepted
	case "duplicate":
		return ls.StDuplicate
	case "", "pending":
		return ls.StPending
	}
	return st
}

func normalizeSeverity(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "critical", "严重", "critical ":
		return "critical"
	case "high", "高", "高危":
		return "high"
	case "medium", "中", "中危":
		return "medium"
	case "low", "低", "低危":
		return "low"
	}
	return ""
}

var docSevRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "": 4}

func windowText(a, b time.Time) string {
	switch {
	case a.IsZero() && b.IsZero():
		return "—"
	case b.IsZero():
		return a.Format("2006-01-02")
	case a.IsZero():
		return b.Format("2006-01-02")
	}
	return a.Format("2006-01-02") + " ~ " + b.Format("2006-01-02")
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

// clipList 截断过长列表，并显式标注被截断（不假装列表是完整的）。
func clipList(in []string, max int) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if strings.TrimSpace(s) == "" {
			continue
		}
		if len(out) >= max {
			out = append(out, fmt.Sprintf("… (%d more)", len(in)-max))
			break
		}
		out = append(out, s)
	}
	return out
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }

// RenderReport 是给调用方的一站式入口：Build → RenderDocx。
func RenderReport(in DocInput) ([]byte, error) { return RenderDocx(Build(in)) }
