package knowledge

import "strings"

// ChunkText 把文档切成约 maxChars（按 rune 计）的分块：优先按整段聚合，保留语义单元；
// 只有单段超长时才硬切，并在硬切边界带 overlap 个 rune —— 免得一句话被切断后
// 既不在这块、也不在下块，检索两边都命中不到。
func ChunkText(text string, maxChars, overlap int) []string {
	if maxChars <= 0 {
		maxChars = 700
	}
	if overlap < 0 || overlap >= maxChars {
		overlap = 80
	}
	var chunks []string
	var cur strings.Builder
	curLen := 0
	push := func() {
		if s := strings.TrimSpace(cur.String()); s != "" {
			chunks = append(chunks, s)
		}
		cur.Reset()
		curLen = 0
	}
	add := func(p string) {
		pr := []rune(p)
		for len(pr) > maxChars {
			if curLen > 0 {
				push()
			}
			chunks = append(chunks, strings.TrimSpace(string(pr[:maxChars])))
			step := maxChars - overlap
			if step < 1 {
				step = maxChars
			}
			pr = pr[step:]
		}
		if len(pr) == 0 {
			return
		}
		if curLen > 0 && curLen+len(pr)+2 > maxChars {
			push()
		}
		if curLen > 0 {
			cur.WriteString("\n\n")
			curLen += 2
		}
		cur.WriteString(string(pr))
		curLen += len(pr)
	}
	for _, para := range strings.Split(text, "\n\n") {
		if s := strings.TrimSpace(para); s != "" {
			add(s)
		}
	}
	push()
	return chunks
}

// embedInput 拼出送进 embedder 的文本：分类 + 标题 + 正文。
// 带上分类与标题是有意的 —— 同一段正文在不同主题下的语义不同，标题是廉价而有效的
// 上下文。例如"权限校验"这类段落，挂在「越权」分类下和挂在「认证」分类下应当命中不同查询。
func embedInput(category, title, chunk string) string {
	var b strings.Builder
	if category != "" {
		b.WriteString("【分类】" + category + "\n")
	}
	if title != "" {
		b.WriteString("【标题】" + title + "\n")
	}
	b.WriteString("【正文】\n" + chunk)
	return b.String()
}
