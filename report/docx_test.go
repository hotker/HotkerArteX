package report

import (
	"archive/zip"
	"bytes"
	"io"
	"strings"
	"testing"
	"time"
)

func sampleInput() DocInput {
	return DocInput{
		TaskTitle:   "Demo Pen Test",
		Goal:        "Get 3 flags",
		Scope:       "10.0.0.0/24",
		GeneratedAt: time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC),
		AssetCount:  3,
		Assets:      []string{"app.demo.local", "10.0.0.7"},
		Settings: Settings{
			Company: "Hotker Security", Client: "ACME", Lang: "zh-CN", Version: "v1.0",
			People: []Person{{Name: "张三", Role: "主测"}},
		},
		Findings: []Finding{{
			ID: 1, Name: "SQL 注入", VulnClass: "SQLi", Severity: "critical", Status: "confirmed",
			CVSS: "9.8", Summary: "参数拼接进 SQL", Impact: "全库可读", Remediation: "参数化查询",
			EntryPoint: "POST /api/login", Prereq: "无需登录",
			Steps: []Step{{
				Request:  "POST /api/login HTTP/1.1\nHost: app.demo.local\n\n{\"u\":\"a' OR 1=1--\"}",
				Response: "HTTP/1.1 200 OK\n{\"token\":\"x\"}",
				Expected: "绕过认证",
			}},
			Evidence: "sqlmap boolean-based blind",
			Traffic:  []string{"POST https://app.demo.local/api/login → 200"},
		}},
	}
}

// docx 必须是可被真实 Word/WPS/python-docx 打开的最小 OOXML：必要的部件齐全、
// 每个 zip 成员都能解析、正文里不出现未转义的 XML 元字符。
func TestRenderReportProducesValidDocx(t *testing.T) {
	blob, err := RenderReport(sampleInput())
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(blob), int64(len(blob)))
	if err != nil {
		t.Fatalf("not a zip: %v", err)
	}
	need := map[string]bool{
		"[Content_Types].xml": false, "_rels/.rels": false, "word/document.xml": false,
		"word/styles.xml": false, "word/numbering.xml": false,
		"word/_rels/document.xml.rels": false, "word/footer1.xml": false,
	}
	parts := map[string]string{}
	for _, f := range zr.File {
		if _, ok := need[f.Name]; ok {
			need[f.Name] = true
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open %s: %v", f.Name, err)
		}
		b, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("read %s: %v", f.Name, err)
		}
		parts[f.Name] = string(b)
	}
	for name, got := range need {
		if !got {
			t.Fatalf("missing part %s", name)
		}
	}

	doc := parts["word/document.xml"]
	for _, want := range []string{
		"渗透测试报告", // 标题
		"SQL 注入",  // 漏洞名
		"9.8",     // CVSS
		"POST /api/login",        // 入口点
		"a&apos; OR 1=1--",       // 单引号必须被转义
		"TOC \\o &quot;1-3&quot;", // 目录域
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("document.xml missing %q", want)
		}
	}
	// 表格必须有 tblGrid：python-docx / 部分编辑器缺它直接解析失败。
	if strings.Count(doc, "<w:tbl>") != strings.Count(doc, "<w:tblGrid>") {
		t.Fatalf("every table needs a tblGrid: %d tables, %d grids",
			strings.Count(doc, "<w:tbl>"), strings.Count(doc, "<w:tblGrid>"))
	}
	if strings.Contains(doc, `<w:tblGrid><w:gridCol`) && !strings.Contains(doc, `</w:tblGrid>`) {
		t.Fatal("unclosed tblGrid")
	}
	// 页码域在页脚部件里（document.xml 只引用它）
	if !strings.Contains(parts["word/footer1.xml"], "PAGE") {
		t.Fatalf("footer missing PAGE field: %s", parts["word/footer1.xml"])
	}
}

// 三语渲染：同一份数据在不同语言下都能出文件，且标题词表正确。
func TestRenderReportTrilingual(t *testing.T) {
	for _, tc := range []struct {
		lang Lang
		want string
	}{
		{LangZHCN, "渗透测试报告"},
		{LangZHTW, "滲透測試報告"},
		{LangENUS, "Penetration Test Report"},
	} {
		in := sampleInput()
		in.Settings.Lang = string(tc.lang)
		blob, err := RenderReport(in)
		if err != nil {
			t.Fatalf("%s: %v", tc.lang, err)
		}
		if len(blob) < 2000 {
			t.Fatalf("%s: suspiciously small docx (%d bytes)", tc.lang, len(blob))
		}
		d := Build(in)
		if d.Title != tc.want {
			t.Fatalf("%s: title %q, want %q", tc.lang, d.Title, tc.want)
		}
	}
}

// 空任务也要能出报告（客户常有"本次未确认漏洞"的交付）。
func TestRenderReportEmptyFindings(t *testing.T) {
	in := sampleInput()
	in.Findings = nil
	blob, err := RenderReport(in)
	if err != nil {
		t.Fatalf("render empty: %v", err)
	}
	d := Build(in)
	joined := ""
	for _, b := range d.Blocks {
		joined += b.Text + " " + strings.Join(b.Items, " ")
	}
	if !strings.Contains(joined, "未确认可利用漏洞") && !strings.Contains(joined, "No exploitable findings") {
		t.Fatalf("empty report should say so explicitly: %q", joined)
	}
	if len(blob) < 1500 {
		t.Fatalf("empty report too small: %d", len(blob))
	}
}

// 控制字符会让 Word 拒绝打开文件 —— 必须在渲染期剔除而不是交给用户去踩。
func TestRenderReportStripsControlChars(t *testing.T) {
	in := sampleInput()
	in.Findings[0].Summary = "bad\x00title\x07 with\x1b escapes"
	d := Build(in)
	found := false
	for _, b := range d.Blocks {
		if strings.Contains(b.Text, "bad") {
			found = true
		}
	}
	if !found {
		t.Fatal("summary should still be rendered")
	}
	blob, err := RenderReport(in)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	// 解压后逐个部件检查：zip 里偶有 0x00 是压缩流字节，不是内容。
	zr, err := zip.NewReader(bytes.NewReader(blob), int64(len(blob)))
	if err != nil {
		t.Fatalf("not a zip: %v", err)
	}
	for _, f := range zr.File {
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		if bytes.Contains(b, []byte{0x00}) {
			t.Fatalf("NUL byte leaked into %s", f.Name)
		}
	}
}
