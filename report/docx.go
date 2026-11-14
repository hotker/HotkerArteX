// Package report 生成可交付的渗透测试报告：结构化数据 → 纯 Go 渲染的 .docx。
//
// 与上游的反差是刻意的：上游把 .docx 的排版交给 python-docx 子进程（封面/目录/
// 页码都靠 Python 侧拼），代价是交付环境必须装 python3 + python-docx，且渲染逻辑
// 与 Go 侧的数据结构分家、排障要跨语言。这里把渲染收进 Go：
//
//   - 零外部依赖：一个 .docx 就是 zip 里的若干 OOXML 部件，用 archive/zip + encoding/xml
//     直接写，任何跑得动本二进制的机器都能出报告；
//   - 结构即数据：doc 结构（封面/摘要/属性表/复现步骤/证据图注）与渲染器解耦，测试可以
//     只校验结构，不用开 Word；
//   - 失败可解释：没有 python 环境这类"环境缺失"不再是运行期错误。
//
// 版式保持工程师看得懂的最小集：A4 页边距、标题层级、表格、等宽代码块、页码、目录域。
package report

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"strings"
)

// doc 是报告的内存结构。渲染器只认它，不认业务结构 —— 业务侧（build.go）负责把
// 任务/漏洞数据翻成 doc，测试与未来的 PDF/HTML 导出可以复用同一份 doc。
type doc struct {
	Title    string
	Subtitle string
	// Meta 是封面上的属性行（客户、项目、测试窗口、出具方…），按序渲染。
	Meta []metaRow
	// Blocks 是正文：按序渲染，标题/段落/表格/代码块/分页符。
	Blocks []block
	// Footer 是页脚左侧文本（右侧是页码）。
	Footer string
	// Media 是正文引用的图片，按顺序打包进 word/media/。image rId 在渲染时确定。
	Media []*imageRef
}

type metaRow struct{ Key, Value string }

type blockKind int

const (
	blockHeading blockKind = iota // Level 1..3
	blockPara
	blockBullets
	blockTable
	blockCode
	blockPageBreak
	// blockImage 插入一张图片（证据截图）。Media 是图片在 docx 内的关系 id 与字节，
	// 由 RenderDocx 在打包阶段统一分配 rId 并写入 word/media/。
	blockImage
	// blockTOC 插一个目录域（TOC \o "1-3"）。Word 打开时提示更新域即生成目录 ——
	// 不预渲染页码，因为页数要到排版时才确定，硬编码只会给出错的页码。
	blockTOC
)

type block struct {
	Kind  blockKind
	Level int      // blockHeading: 1..3
	Text  string   // blockPara / blockHeading
	Items []string // blockBullets
	// blockTable
	Headers []string
	Rows    [][]string
	Widths  []float64 // 单位 pt；空 = 均分
	// blockCode：逐行渲染成等宽段落（不做语法高亮 —— 交付件要的是可复制，不是好看）
	Code string
	// blockImage：Media 指向 doc.Media 里的条目（由 Build 填入索引），Caption 渲染在图下方。
	Media   *imageRef
	Caption string
}

// imageRef 是一张待嵌入的图片。Bytes 已由调用方按内容校验并重编码（见 evidence.Sanitize），
// 这里只负责排版，不再信任任何元数据。
type imageRef struct {
	Name   string // 文件名（仅用于 word/media/ 内的名字与扩展名判定）
	Ext    string // ".png" | ".jpg"
	Bytes  []byte // 图片字节
	Width  int    // 像素
	Height int
	// 目标宽度（pt）。0 = 用默认 420pt（A4 版面内合适）。高度按像素比自动算，
	// 绝不拉伸 —— 截图被拉变形等于证据失真。
	TargetPT float64
	// rid 是打包时分配的关系 id（由 RenderDocx 写入，Build 阶段不填）。
	rid string
}

// mediaName 返回图片在 word/media/ 下的文件名（按序号派生，避免中文名与重名问题）。
func (m *imageRef) mediaName() string {
	ext := m.Ext
	if ext == "" {
		ext = ".png"
	}
	if ext != ".png" && ext != ".jpg" && ext != ".jpeg" {
		ext = ".png"
	}
	return sanitizeName(m.Name) + ext
}

// sanitizeName 把文件名压成安全的 ASCII 片段：OOXML 的部件名不该带中文与空格。
func sanitizeName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		}
	}
	out := b.String()
	if out == "" {
		out = "image"
	}
	if len(out) > 40 {
		out = out[:40]
	}
	return out
}

// statusWriter 把写失败攒起来，避免每处 WriteString 都判一次错。
type statusWriter struct {
	w   io.Writer
	err error
}

func (s *statusWriter) ws(strs ...string) {
	if s.err != nil {
		return
	}
	for _, v := range strs {
		if _, err := io.WriteString(s.w, v); err != nil {
			s.err = err
			return
		}
	}
}

// RenderDocx 把 doc 渲染成 .docx 字节。返回的错误只可能是编码/压缩失败，
// 不含任何"环境缺失"类错误。
func RenderDocx(d *doc) ([]byte, error) {
	// 图片 rId 在打包前统一分配：
	//   rId1 styles / rId2 numbering / rId3 footer（固定），图片从 rId100 起，
	//   这样 document.xml.rels 与正文引用一一对应，不会和固定关系撞号。
	for i, m := range d.Media {
		if m == nil {
			continue
		}
		m.rid = fmt.Sprintf("rId%d", 100+i)
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	parts := []struct {
		name string
		body func(*statusWriter)
	}{
		{"[Content_Types].xml", writeContentTypes},
		{"_rels/.rels", writeRootRels},
		{"docProps/core.xml", func(w *statusWriter) { writeCoreProps(w, d) }},
		{"docProps/app.xml", writeAppProps},
		{"word/document.xml", func(w *statusWriter) { writeDocument(w, d) }},
		{"word/styles.xml", writeStyles},
		{"word/numbering.xml", writeNumbering},
		{"word/_rels/document.xml.rels", func(w *statusWriter) { writeDocumentRels(w, d.Media) }},
		{"word/footer1.xml", func(w *statusWriter) { writeFooter(w, d) }},
	}
	// 图片字节作为独立 zip 部件写入（不压缩走默认 deflate 即可；PNG/JPG 本身已压缩）。
	for _, m := range d.Media {
		if m == nil || len(m.Bytes) == 0 {
			continue
		}
		f, err := zw.Create("word/media/" + m.mediaName())
		if err != nil {
			return nil, fmt.Errorf("创建图片部件失败: %w", err)
		}
		if _, err := f.Write(m.Bytes); err != nil {
			return nil, fmt.Errorf("写入图片 %s 失败: %w", m.Name, err)
		}
	}
	for _, p := range parts {
		f, err := zw.Create(p.name)
		if err != nil {
			return nil, fmt.Errorf("创建 docx 部件 %s 失败: %w", p.name, err)
		}
		w := &statusWriter{w: f}
		p.body(w)
		if w.err != nil {
			return nil, fmt.Errorf("写 docx 部件 %s 失败: %w", p.name, w.err)
		}
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("收尾 docx 失败: %w", err)
	}
	return buf.Bytes(), nil
}

const xmlHead = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` + "\n"

func writeContentTypes(w *statusWriter) {
	w.ws(xmlHead, `<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">`,
		`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>`,
		`<Default Extension="xml" ContentType="application/xml"/>`,
		`<Default Extension="png" ContentType="image/png"/>`,
		`<Default Extension="jpeg" ContentType="image/jpeg"/>`,
		`<Default Extension="jpg" ContentType="image/jpeg"/>`,
		`<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>`,
		`<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>`,
		`<Override PartName="/word/numbering.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.numbering+xml"/>`,
		`<Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/>`,
		`<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>`,
		`<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>`,
		`</Types>`)
}

func writeRootRels(w *statusWriter) {
	w.ws(xmlHead, `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">`,
		`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>`,
		`<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>`,
		`<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>`,
		`</Relationships>`)
}

func writeDocumentRels(w *statusWriter, media []*imageRef) {
	w.ws(xmlHead, `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">`,
		`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>`,
		`<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/numbering" Target="numbering.xml"/>`,
		`<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Target="footer1.xml"/>`)
	for _, m := range media {
		if m == nil || m.rid == "" {
			continue
		}
		w.ws(`<Relationship Id="` + m.rid + `" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="media/` + esc(m.mediaName()) + `"/>`)
	}
	w.ws(`</Relationships>`)
}

func writeCoreProps(w *statusWriter, d *doc) {
	w.ws(xmlHead, `<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"`,
		` xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/"`,
		` xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">`,
		`<dc:title>`, esc(d.Title), `</dc:title><dc:creator>HotkerArteX</dc:creator>`,
		`<cp:lastModifiedBy>HotkerArteX</cp:lastModifiedBy></cp:coreProperties>`)
}

func writeAppProps(w *statusWriter) {
	w.ws(xmlHead, `<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">`,
		`<Application>HotkerArteX</Application></Properties>`)
}

// writeDocument 拼正文。段落/表格按 Blocks 顺序输出，最后挂 footer 引用。
func writeDocument(w *statusWriter, d *doc) {
	w.ws(xmlHead,
		`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"`,
		` xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">`,
		`<w:body>`,
	)
	// 封面：大标题 + 副标题 + 属性表
	para(w, "Title", d.Title)
	para(w, "Subtitle", d.Subtitle)
	if len(d.Meta) > 0 {
		// 封面的属性表：必须带 tblGrid —— Word 容忍缺失，python-docx/部分编辑器会直接
		// 拒绝解析（required ``<w:tblGrid>`` child element not present）。
		w.ws(`<w:tbl><w:tblPr><w:tblStyle w:val="GridTable"/><w:tblW w:w="0" w:type="auto"/></w:tblPr>`,
			`<w:tblGrid><w:gridCol w:w="2400"/><w:gridCol w:w="6626"/></w:tblGrid>`)
		for _, m := range d.Meta {
			w.ws(`<w:tr>`)
			cell(w, m.Key, true, "MetaKey")
			cell(w, m.Value, false, "")
			w.ws(`</w:tr>`)
		}
		w.ws(`</w:tbl>`)
		para(w, "", "")
	}
	w.ws(`<w:p><w:r><w:br w:type="page"/></w:r></w:p>`) // 封面后分页

	for _, b := range d.Blocks {
		switch b.Kind {
		case blockHeading:
			lvl := b.Level
			if lvl < 1 {
				lvl = 1
			}
			if lvl > 3 {
				lvl = 3
			}
			para(w, fmt.Sprintf("Heading%d", lvl), b.Text)
		case blockPara:
			para(w, "", b.Text)
		case blockBullets:
			for _, it := range b.Items {
				w.ws(`<w:p><w:pPr><w:pStyle w:val="ListBullet"/><w:numPr><w:ilvl w:val="0"/><w:numId w:val="2"/></w:numPr></w:pPr>`)
				run(w, it)
				w.ws(`</w:p>`)
			}
		case blockTable:
			writeTable(w, b)
		case blockCode:
			for _, line := range strings.Split(strings.TrimRight(b.Code, "\n"), "\n") {
				para(w, "CodeBlock", line)
			}
		case blockPageBreak:
			w.ws(`<w:p><w:r><w:br w:type="page"/></w:r></w:p>`)
		case blockImage:
			writeImage(w, b.Media, b.Caption)
		case blockTOC:
			w.ws(`<w:p><w:pPr><w:pStyle w:val="Heading1"/></w:pPr></w:p>`,
				`<w:p><w:fldSimple w:instr=" TOC \o &quot;1-3&quot; \h \z \u ">`,
				`<w:r><w:t>更新域以生成目录</w:t></w:r></w:fldSimple></w:p>`)
		}
	}

	w.ws(`<w:sectPr>`,
		`<w:footerReference w:type="default" r:id="rId3"/>`,
		`<w:pgSz w:w="11906" w:h="16838"/>`, // A4 竖向（twips）
		`<w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" w:header="851" w:footer="992" w:gutter="0"/>`,
		`</w:sectPr></w:body></w:document>`)
}

// EMU 换算：1pt = 12700 EMU（OOXML 用 EMU 表示长度，1 英寸 = 914400 EMU）。
const emuPerPT = 12700

// writeImage 渲染一张内联图片 + 图注。
//
// 尺寸计算是关键：Word 里图片宽高都写 EMU，且必须保持像素宽高比 —— 一旦算错，图会被
// 拉扁或被裁。这里按 TargetPT（缺省 420pt，A4 正文宽度的合适值）等比缩放。
func writeImage(w *statusWriter, m *imageRef, caption string) {
	if m == nil || m.rid == "" {
		return
	}
	wpt := m.TargetPT
	if wpt <= 0 {
		wpt = 420
	}
	// 高度按像素比推出来；像素尺寸缺失时退回 3:2，绝不除零。
	hpt := wpt * 0.66
	if m.Width > 0 && m.Height > 0 {
		hpt = wpt * float64(m.Height) / float64(m.Width)
	}
	cx := int(wpt * emuPerPT)
	cy := int(hpt * emuPerPT)

	w.ws(`<w:p><w:pPr><w:jc w:val="center"/><w:spacing w:after="60"/></w:pPr><w:r><w:drawing>`,
		`<wp:inline xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing"`,
		` distT="0" distB="0" distL="0" distR="0">`,
		`<wp:extent cx="`, itoa(cx), `" cy="`, itoa(cy), `"/>`,
		`<wp:docPr id="1" name="`, esc(m.Name), `"/>`,
		// a:graphic 需要完整命名空间声明；缺任何一个，Word 都会报"内容有问题"。
		`<a:graphic xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">`,
		`<a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">`,
		`<pic:pic xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture">`,
		`<pic:nvPicPr><pic:cNvPr id="1" name="`, esc(m.Name), `"/><pic:cNvPicPr/></pic:nvPicPr>`,
		`<pic:blipFill><a:blip xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" r:embed="`, m.rid, `"/>`,
		`<a:stretch><a:fillRect/></a:stretch></pic:blipFill>`,
		`<pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="`, itoa(cx), `" cy="`, itoa(cy), `"/></a:xfrm>`,
		`<a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr>`,
		`</pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p>`)
	if strings.TrimSpace(caption) != "" {
		w.ws(`<w:p><w:pPr><w:jc w:val="center"/><w:spacing w:before="0" w:after="240"/></w:pPr>`)
		run(w, caption)
		w.ws(`</w:p>`)
	}
}

// writeTable 渲染表格：首行加粗底纹，列宽按 Widths（pt→twips）或均分。
func writeTable(w *statusWriter, b block) {
	ncol := len(b.Headers)
	if ncol == 0 {
		for _, r := range b.Rows {
			if len(r) > ncol {
				ncol = len(r)
			}
		}
	}
	if ncol == 0 {
		return
	}
	total := 9026.0 // A4 去掉两侧页边距后的可用宽度（twips）
	w.ws(`<w:tbl><w:tblPr><w:tblStyle w:val="GridTable"/><w:tblW w:w="`, fmt.Sprintf("%.0f", total), `" w:type="dxa"/>`,
		`<w:tblBorders>`,
		`<w:top w:val="single" w:sz="4" w:color="BFBFBF"/><w:left w:val="single" w:sz="4" w:color="BFBFBF"/>`,
		`<w:bottom w:val="single" w:sz="4" w:color="BFBFBF"/><w:right w:val="single" w:sz="4" w:color="BFBFBF"/>`,
		`<w:insideH w:val="single" w:sz="4" w:color="BFBFBF"/><w:insideV w:val="single" w:sz="4" w:color="BFBFBF"/>`,
		`</w:tblBorders></w:tblPr><w:tblGrid>`)
	widths := b.Widths
	if len(widths) != ncol {
		widths = make([]float64, ncol)
		for i := range widths {
			widths[i] = total / float64(ncol)
		}
	}
	for _, wd := range widths {
		w.ws(`<w:gridCol w:w="`, fmt.Sprintf("%.0f", wd), `"/>`)
	}
	w.ws(`</w:tblGrid>`)
	if len(b.Headers) > 0 {
		w.ws(`<w:tr><w:trPr><w:tblHeader/></w:trPr>`)
		for _, h := range b.Headers {
			cell(w, h, true, "TableHead")
		}
		w.ws(`</w:tr>`)
	}
	for _, r := range b.Rows {
		w.ws(`<w:tr>`)
		for i := 0; i < ncol; i++ {
			v := ""
			if i < len(r) {
				v = r[i]
			}
			cell(w, v, false, "")
		}
		w.ws(`</w:tr>`)
	}
	w.ws(`</w:tbl>`)
	para(w, "", "")
}

// cell 渲染一个表格单元（支持单元格内换行：按 \n 拆成多段）。直接写入 w：
// 早先的实现把片段当返回值传，漏传就静默丢内容 —— 这类"看起来渲染成功、其实少了一半
// 正文"的 bug 在文档生成里最难发现，所以这里让写动作只有一个出口。
func cell(w *statusWriter, text string, bold bool, style string) {
	w.ws(`<w:tc><w:tcPr><w:tcW w:w="0" w:type="auto"/></w:tcPr>`)
	for _, ln := range strings.Split(text, "\n") {
		w.ws(`<w:p>`)
		if style != "" {
			w.ws(`<w:pPr><w:pStyle w:val="` + style + `"/></w:pPr>`)
		}
		w.ws(`<w:r>`)
		if bold {
			w.ws(`<w:rPr><w:b/></w:rPr>`)
		}
		w.ws(`<w:t xml:space="preserve">` + esc(ln) + `</w:t></w:r></w:p>`)
	}
	w.ws(`</w:tc>`)
}

// para 渲染一个段落（style 为空 = 正文样式）。
func para(w *statusWriter, style, text string) {
	w.ws(`<w:p>`)
	if style != "" {
		w.ws(`<w:pPr><w:pStyle w:val="` + style + `"/></w:pPr>`)
	}
	if text != "" {
		run(w, text)
	}
	w.ws(`</w:p>`)
}

// run 渲染一个文本 run：\n 换行、\t 制表符会被拆成独立的 <w:br/> / <w:tab/>，
// 保证多行 evidence / PoC 粘贴进 Word 后行还是行。
func run(w *statusWriter, text string) {
	w.ws(`<w:r>`)
	first := true
	for _, seg := range strings.Split(text, "\n") {
		if !first {
			w.ws(`<w:br/>`)
		}
		first = false
		parts := strings.Split(seg, "\t")
		for i, p := range parts {
			if i > 0 {
				w.ws(`<w:tab/>`)
			}
			if p == "" {
				continue
			}
			w.ws(`<w:t xml:space="preserve">` + esc(p) + `</w:t>`)
		}
	}
	w.ws(`</w:r>`)
}

func writeFooter(w *statusWriter, d *doc) {
	label := d.Footer
	w.ws(xmlHead, `<w:ftr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">`,
		`<w:p><w:pPr><w:jc w:val="center"/></w:pPr><w:r><w:rPr><w:sz w:val="16"/></w:rPr><w:t xml:space="preserve">`,
		esc(label), `    </w:t></w:r>`,
		// PAGE 域：Word 打开时自动算页码
		`<w:fldSimple w:instr=" PAGE "><w:r><w:rPr><w:sz w:val="16"/></w:rPr><w:t>1</w:t></w:r></w:fldSimple>`,
		`</w:p></w:ftr>`)
}

func writeStyles(w *statusWriter) {
	w.ws(xmlHead, `<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">`,
		`<w:docDefaults><w:rPrDefault><w:rPr>`,
		`<w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:eastAsia="微软雅黑"/>`,
		`<w:sz w:val="21"/><w:szCs w:val="21"/><w:lang w:val="en-US" w:eastAsia="zh-CN"/>`,
		`</w:rPr></w:rPrDefault><w:pPrDefault><w:pPr><w:spacing w:after="120" w:line="300" w:lineRule="auto"/></w:pPr></w:pPrDefault></w:docDefaults>`,

		`<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/></w:style>`,

		`<w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:basedOn w:val="Normal"/>`,
		`<w:pPr><w:spacing w:before="2400" w:after="240"/><w:jc w:val="center"/></w:pPr>`,
		`<w:rPr><w:b/><w:sz w:val="52"/><w:szCs w:val="52"/></w:rPr></w:style>`,

		`<w:style w:type="paragraph" w:styleId="Subtitle"><w:name w:val="Subtitle"/><w:basedOn w:val="Normal"/>`,
		`<w:pPr><w:spacing w:after="720"/><w:jc w:val="center"/></w:pPr>`,
		`<w:rPr><w:color w:val="595959"/><w:sz w:val="26"/></w:rPr></w:style>`,

		`<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/>`,
		`<w:pPr><w:keepNext/><w:spacing w:before="360" w:after="120"/><w:outlineLvl w:val="0"/></w:pPr>`,
		`<w:rPr><w:b/><w:sz w:val="34"/><w:color w:val="1F3864"/></w:rPr></w:style>`,

		`<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/>`,
		`<w:pPr><w:keepNext/><w:spacing w:before="280" w:after="100"/><w:outlineLvl w:val="1"/></w:pPr>`,
		`<w:rPr><w:b/><w:sz w:val="28"/><w:color w:val="2E5395"/></w:rPr></w:style>`,

		`<w:style w:type="paragraph" w:styleId="Heading3"><w:name w:val="heading 3"/><w:basedOn w:val="Normal"/>`,
		`<w:pPr><w:keepNext/><w:spacing w:before="240" w:after="80"/><w:outlineLvl w:val="2"/></w:pPr>`,
		`<w:rPr><w:b/><w:sz w:val="24"/><w:color w:val="2E5395"/></w:rPr></w:style>`,

		`<w:style w:type="paragraph" w:styleId="CodeBlock"><w:name w:val="Code Block"/><w:basedOn w:val="Normal"/>`,
		`<w:pPr><w:shd w:val="clear" w:color="auto" w:fill="F4F4F4"/><w:spacing w:after="0" w:line="240" w:lineRule="auto"/>`,
		`<w:ind w:left="120" w:right="120"/></w:pPr>`,
		`<w:rPr><w:rFonts w:ascii="Consolas" w:hAnsi="Consolas" w:eastAsia="等线"/><w:sz w:val="18"/></w:rPr></w:style>`,

		`<w:style w:type="paragraph" w:styleId="ListBullet"><w:name w:val="List Bullet"/><w:basedOn w:val="Normal"/>`,
		`<w:pPr><w:spacing w:after="60"/></w:pPr></w:style>`,

		`<w:style w:type="paragraph" w:styleId="TableHead"><w:name w:val="Table Head"/><w:basedOn w:val="Normal"/>`,
		`<w:pPr><w:spacing w:after="0"/></w:pPr><w:rPr><w:b/></w:rPr></w:style>`,

		`<w:style w:type="paragraph" w:styleId="MetaKey"><w:name w:val="Meta Key"/><w:basedOn w:val="Normal"/>`,
		`<w:pPr><w:spacing w:after="0"/></w:pPr><w:rPr><w:b/></w:rPr></w:style>`,

		`<w:style w:type="table" w:styleId="GridTable"><w:name w:val="Grid Table"/>`,
		`<w:tblPr><w:tblCellMar><w:left w:w="108" w:type="dxa"/><w:right w:w="108" w:type="dxa"/></w:tblCellMar></w:tblPr>`,
		`</w:style>`,
		`</w:styles>`)
}

// writeNumbering 只定义一份项目符号编号（numId=2 被 ListBullet 段落引用）。
func writeNumbering(w *statusWriter) {
	w.ws(xmlHead, `<w:numbering xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">`,
		`<w:abstractNum w:abstractNumId="1">`,
		`<w:lvl w:ilvl="0"><w:start w:val="1"/><w:numFmt w:val="bullet"/><w:lvlText w:val="•"/>`,
		`<w:lvlJc w:val="left"/><w:pPr><w:ind w:left="420" w:hanging="360"/></w:pPr></w:lvl>`,
		`</w:abstractNum>`,
		`<w:num w:numId="2"><w:abstractNumId w:val="1"/></w:num>`,
		`</w:numbering>`)
}

// esc 转义 XML 文本。控制字符（除 \t\n\r）会让 Word 拒绝打开文件，一律剔除。
func esc(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 16)
	for _, r := range s {
		switch r {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '"':
			b.WriteString("&quot;")
		case '\'':
			b.WriteString("&apos;")
		default:
			if r < 0x20 && r != '\t' && r != '\n' && r != '\r' {
				continue
			}
			b.WriteRune(r)
		}
	}
	return b.String()
}
