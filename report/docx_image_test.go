package report

import (
	"archive/zip"
	"bytes"
	"image"
	"image/color"
	"image/png"
	"io"
	"strings"
	"testing"
	"time"
)

// newTestPNG 生成一张纯色 PNG（宽高可指定），用于验证图片打包与 EMU 尺寸计算。
func newTestPNG(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, color.RGBA{R: 200, G: 120, B: 40, A: 255})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("encode png: %v", err)
	}
	return buf.Bytes()
}

// docx 里的图片必须：① 落成 word/media/* 部件 ② [Content_Types] 注册 png
// ③ document.xml.rels 有对应关系 ④ 正文有 <w:drawing> 且 EMU 宽高比正确。
// 这四件事缺任何一条，Word 都会报"内容有问题"。
func TestRenderReportEmbedsImages(t *testing.T) {
	pngBytes := newTestPNG(t, 800, 400) // 2:1
	in := sampleInput()
	in.Findings[0].Images = []Image{
		{Bytes: pngBytes, Ext: ".png", Width: 800, Height: 400, Caption: "登录绕过截图", StepIndex: 1},
		{Bytes: pngBytes, Ext: ".png", Width: 800, Height: 400, Caption: "总览图", StepIndex: 0},
	}
	blob, err := RenderReport(in)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(blob), int64(len(blob)))
	if err != nil {
		t.Fatalf("not a zip: %v", err)
	}
	parts := map[string][]byte{}
	for _, f := range zr.File {
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		parts[f.Name] = b
	}
	var media []string
	for name := range parts {
		if strings.HasPrefix(name, "word/media/") {
			media = append(media, name)
		}
	}
	if len(media) != 2 {
		t.Fatalf("expected 2 media parts, got %d: %v", len(media), media)
	}
	for _, m := range media {
		if !strings.HasSuffix(m, ".png") {
			t.Fatalf("media part should keep png extension: %s", m)
		}
		if len(parts[m]) == 0 {
			t.Fatalf("media part %s is empty", m)
		}
	}
	if !strings.Contains(string(parts["[Content_Types].xml"]), `Extension="png"`) {
		t.Fatal("png extension not registered in [Content_Types].xml")
	}
	rels := string(parts["word/_rels/document.xml.rels"])
	if strings.Count(rels, "relationships/image") != 2 {
		t.Fatalf("expected 2 image relationships:\n%s", rels)
	}
	doc := string(parts["word/document.xml"])
	if strings.Count(doc, "<w:drawing>") != 2 {
		t.Fatalf("expected 2 drawings in document.xml")
	}
	if !strings.Contains(doc, "登录绕过截图") || !strings.Contains(doc, "总览图") {
		t.Fatal("captions missing from document")
	}
	// EMU 宽高比：800x400 → cy 应为 cx 的一半（420pt 宽 → 210pt 高）
	if !strings.Contains(doc, `cx="5334000" cy="2667000"`) {
		t.Fatalf("EMU extent not proportional (420pt x 210pt expected): %s",
			excerptAround(doc, "wp:extent"))
	}
}

// 图片字节里的 XML 元字符不该破坏文档（二进制走独立部件，不进 XML）。
func TestImageBytesNeverEnterDocumentXML(t *testing.T) {
	pngBytes := newTestPNG(t, 40, 40)
	in := sampleInput()
	in.Findings[0].Images = []Image{{Bytes: pngBytes, Ext: ".png", Width: 40, Height: 40, Caption: "c", StepIndex: 1}}
	blob, err := RenderReport(in)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	zr, _ := zip.NewReader(bytes.NewReader(blob), int64(len(blob)))
	for _, f := range zr.File {
		if f.Name != "word/document.xml" {
			continue
		}
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		if bytes.Contains(b, pngBytes[:16]) {
			t.Fatal("raw image bytes leaked into document.xml")
		}
	}
}

// 没有图片时不应产生任何 media 部件（保持零依赖的最小 docx）。
func TestRenderReportWithoutImagesHasNoMedia(t *testing.T) {
	in := sampleInput()
	blob, err := RenderReport(in)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	zr, _ := zip.NewReader(bytes.NewReader(blob), int64(len(blob)))
	for _, f := range zr.File {
		if strings.HasPrefix(f.Name, "word/media/") {
			t.Fatalf("unexpected media part: %s", f.Name)
		}
	}
}

func excerptAround(s, marker string) string {
	i := strings.Index(s, marker)
	if i < 0 {
		return "(marker not found)"
	}
	end := i + 160
	if end > len(s) {
		end = len(s)
	}
	return s[i:end]
}

var _ = time.Now
