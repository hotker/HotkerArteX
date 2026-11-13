package server

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// 报告生成的端到端契约：所选任务之外的漏洞不出现、显式勾选优先、文件真的落盘。
// 用真 PG + 真文件系统，不打桩 —— 这一层出错的后果是"客户拿到一份内容不对的报告"，
// 而这类静默失败最难发现。
func TestGenerateReportEndToEnd(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	pg := s.m.pg

	taskA, err := pg.CreateTask("报告A", "描述A", nil, 0, 0)
	if err != nil {
		t.Fatalf("create task A: %v", err)
	}
	taskB, err := pg.CreateTask("报告B", "描述B", nil, 0, 0)
	if err != nil {
		t.Fatalf("create task B: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pg.Exec(`DELETE FROM findings WHERE task_id IN ($1,$2)`, taskA.ID, taskB.ID)
	})

	ins := func(taskID int64, name string) int64 {
		var id int64
		if err := pg.QueryRow(`INSERT INTO findings (task_id, vulnclass, name, severity, summary, status, cvss, impact, remediation)
			VALUES ($1,'SQLi',$2,'critical','摘要','confirmed','9.8','影响','修复') RETURNING id`, taskID, name).Scan(&id); err != nil {
			t.Fatalf("seed finding: %v", err)
		}
		return id
	}
	fA := ins(taskA.ID, "A-注入")
	fB := ins(taskB.ID, "B-注入")

	if err := pg.SaveReportSettings(&db.ReportSettings{
		Company: "Hotker Security", Client: "示例客户", Lang: "zh-CN", Version: "v1.0",
	}); err != nil {
		t.Fatalf("save settings: %v", err)
	}

	// 1) 按任务生成：只含 A 的漏洞
	rec, err := s.buildReportForTask(taskA.ID, nil, "", "")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if rec.FindingsCount != 1 {
		t.Fatalf("expected 1 finding for task A, got %d", rec.FindingsCount)
	}
	body := readReportFile(t, s, rec.FilePath)
	assertDocxContains(t, body, "A-注入")
	assertDocxLacks(t, body, "B-注入")

	// 2) 显式勾选优先：任务 A + 只勾 B 的漏洞 → 报告里是 B
	rec2, err := s.buildReportForTask(taskA.ID, []int64{fB}, "", "")
	if err != nil {
		t.Fatalf("generate selected: %v", err)
	}
	assertDocxContains(t, readReportFile(t, s, rec2.FilePath), "B-注入")

	// 3) 显式语言覆盖设置
	rec3, err := s.buildReportForTask(taskA.ID, []int64{fA}, "en-US", "")
	if err != nil {
		t.Fatalf("generate en: %v", err)
	}
	if rec3.Lang != "en-US" {
		t.Fatalf("lang not applied: %q", rec3.Lang)
	}
	assertDocxContains(t, readReportFile(t, s, rec3.FilePath), "Penetration Test Report")

	// 4) 结构化复现：入口点/前置/逐步请求响应都要出现在报告里，且步骤按顺序
	if _, err := pg.SetFindingReproduction(fA, &db.Reproduction{
		EntryPoint:    "POST /api/login",
		Prerequisites: "需要 admin 账号（/register 自助注册）",
		Steps: []db.ReproStep{
			{Request: "POST /api/login HTTP/1.1\nHost: app.demo.local\n\n{\"u\":\"admin' OR 1=1--\"}", Response: "HTTP/1.1 200 OK", Expected: "绕过认证", Proves: "注入点可绕过认证"},
			{Request: "GET /api/admin/users HTTP/1.1", Response: "HTTP/1.1 200 OK\n[{...}]", Expected: "读到用户列表"},
		},
		Provenance: "从事实 #12 的报错指纹推来",
	}); err != nil {
		t.Fatalf("set reproduction: %v", err)
	}
	rec4, err := s.buildReportForTask(taskA.ID, []int64{fA}, "", "")
	if err != nil {
		t.Fatalf("generate with reproduction: %v", err)
	}
	body4 := readReportFile(t, s, rec4.FilePath)
	for _, want := range []string{
		"POST /api/login",          // 入口点
		"需要 admin 账号",            // 前置
		"从事实 #12",                 // 来源
		"步骤 1", "步骤 2",           // 有序步骤
		"GET /api/admin/users",     // 第 2 步的请求原文
		"绕过认证",                    // 预期
	} {
		assertDocxContains(t, body4, want)
	}
	// 没登记复现的漏洞要显式说明，而不是留空白让人以为漏了
	rec5, err := s.buildReportForTask(taskB.ID, nil, "", "")
	if err != nil {
		t.Fatalf("generate taskB: %v", err)
	}
	assertDocxContains(t, readReportFile(t, s, rec5.FilePath), "未登记结构化复现步骤")

	// 5) 落盘路径必须留在数据目录内（文件名来自用户可控的标题）
	if !filepath.IsLocal(rec.FilePath) {
		t.Fatalf("report path escaped the data dir: %q", rec.FilePath)
	}
	if got := safeFileToken("../../etc/passwd"); strings.ContainsAny(got, "/\\") {
		t.Fatalf("safeFileToken must strip separators: %q", got)
	}
}

func readReportFile(t *testing.T, s *Server, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(s.m.dir, rel))
	if err != nil {
		t.Fatalf("read report file %q: %v", rel, err)
	}
	return b
}

// docxText 解出 word/document.xml 正文（只用于断言关键词）。
func docxText(t *testing.T, blob []byte) string {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(blob), int64(len(blob)))
	if err != nil {
		t.Fatalf("docx is not a zip: %v", err)
	}
	for _, f := range zr.File {
		if f.Name != "word/document.xml" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open document.xml: %v", err)
		}
		b, _ := io.ReadAll(rc)
		rc.Close()
		return string(b)
	}
	t.Fatal("docx has no word/document.xml")
	return ""
}

func assertDocxContains(t *testing.T, blob []byte, want string) {
	t.Helper()
	if !strings.Contains(docxText(t, blob), want) {
		t.Fatalf("docx missing %q", want)
	}
}

func assertDocxLacks(t *testing.T, blob []byte, bad string) {
	t.Helper()
	if strings.Contains(docxText(t, blob), bad) {
		t.Fatalf("docx must not contain %q", bad)
	}
}
