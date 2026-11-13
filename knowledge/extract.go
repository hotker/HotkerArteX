package knowledge

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

// ExtractText 把上传的文档抽成纯文本。
//
// 与上游（调 python 子进程跑 python-docx / pdfplumber）不同：这里全部用标准库。
//   - .docx 就是一个 zip，正文在 word/document.xml，读 <w:p>/<w:t> 即可；
//   - PDF 的文本抽取需要完整解析字体/编码映射，标准库做不可靠，因此明确不支持 ——
//     让用户先导出成 .md/.txt 再上传，比"抽出一堆乱码"诚实。
//
// 这样知识库的上传路径没有任何外部依赖：跑得动本二进制的机器就能用。
func ExtractText(path string, raw []byte) (string, error) {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".md", ".markdown", ".txt", ".text", ".csv", ".json", ".log", ".yaml", ".yml", ".htm", ".html", "":
		return string(raw), nil
	case ".docx":
		return docxText(raw)
	default:
		return "", fmt.Errorf("暂不支持的文件类型（支持 .md/.txt/.csv/.json/.docx/.html；PDF 请先导出为文本）")
	}
}

// docxText 从 .docx 里抽段落文本（含表格单元格，逐格拼接）。
//
// 只认 <w:p> 段落边界与 <w:t> 文本节点：这是 Word/LibreOffice/WPS 导出 .docx 时
// 都会写的结构。删除线/修订标记里的文本也一并取出 —— 对知识库来说，宁可多给
// 上下文，也不要因为"这段被标记删除"就整段丢掉。
func docxText(raw []byte) (string, error) {
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return "", fmt.Errorf("不是合法的 .docx（zip 解析失败）：%w", err)
	}
	var doc []byte
	for _, f := range zr.File {
		if f.Name == "word/document.xml" {
			rc, err := f.Open()
			if err != nil {
				return "", err
			}
			doc, err = io.ReadAll(io.LimitReader(rc, 64<<20))
			rc.Close()
			if err != nil {
				return "", err
			}
			break
		}
	}
	if doc == nil {
		return "", fmt.Errorf("不是合法的 .docx（缺少 word/document.xml）")
	}

	dec := xml.NewDecoder(bytes.NewReader(doc))
	var (
		b      strings.Builder
		inText bool
		inTab  bool
	)
	// 只跟踪"当前是否在文本节点里"，结构信息由段落/单元格/行三个结束标签负责收尾。
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf(".docx 正文解析失败：%w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "t":
				inText = true
			case "tab":
				inTab = true
			case "tr":
				b.WriteString("\n")
			}
		case xml.CharData:
			if inText {
				b.Write(t)
			}
		case xml.EndElement:
			switch t.Name.Local {
			case "t":
				inText = false
			case "tab":
				if inTab {
					b.WriteString("\t")
					inTab = false
				}
			case "p":
				b.WriteString("\n")
			case "tc":
				b.WriteString(" | ")
			case "tr":
				b.WriteString("\n")
			}
		}
	}
	// 收拾表格拼接留下的尾巴与多余空行（但保留段落之间的单个空行，便于分块）
	out := strings.ReplaceAll(b.String(), " | \n", "\n")
	lines := strings.Split(out, "\n")
	for i := range lines {
		lines[i] = strings.TrimRight(lines[i], " \t")
	}
	out = strings.Join(lines, "\n")
	for strings.Contains(out, "\n\n\n") {
		out = strings.ReplaceAll(out, "\n\n\n", "\n\n")
	}
	return strings.TrimSpace(out), nil
}
