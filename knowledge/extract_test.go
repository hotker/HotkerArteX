package knowledge

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"
)

// 造一个最小 .docx：只需要 word/document.xml 里的段落与表格结构。
func buildDocx(t *testing.T, body string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("word/document.xml")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>` + body + `</w:body></w:document>`))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestExtractTextDocx(t *testing.T) {
	body := `<w:p><w:r><w:t>第一段</w:t></w:r></w:p>` +
		`<w:p><w:r><w:t>带</w:t></w:r><w:r><w:t>多 run</w:t></w:r></w:p>` +
		`<w:tbl><w:tr><w:tc><w:p><w:r><w:t>单元格A</w:t></w:r></w:p></w:tc>` +
		`<w:tc><w:p><w:r><w:t>单元格B</w:t></w:r></w:p></w:tc></w:tr></w:tbl>`
	text, err := ExtractText("x.docx", buildDocx(t, body))
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	for _, want := range []string{"第一段", "带多 run", "单元格A", "单元格B"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in:\n%s", want, text)
		}
	}
	if strings.Contains(text, " | \n") {
		t.Fatalf("table separator leaked at line end:\n%s", text)
	}
}

func TestExtractTextPlainAndUnsupported(t *testing.T) {
	text, err := ExtractText("notes.md", []byte("# 标题\n正文"))
	if err != nil || !strings.Contains(text, "正文") {
		t.Fatalf("plain text extract: %v %q", err, text)
	}
	if _, err := ExtractText("a.pdf", []byte("%PDF-1.4")); err == nil {
		t.Fatal("pdf should be rejected with a clear message")
	} else if !strings.Contains(err.Error(), "PDF") {
		t.Fatalf("pdf error should mention PDF: %v", err)
	}
	// 假 docx：不是 zip
	if _, err := ExtractText("bad.docx", []byte("not a zip")); err == nil {
		t.Fatal("non-zip .docx must fail")
	}
}
