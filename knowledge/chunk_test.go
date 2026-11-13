package knowledge

import (
	"strings"
	"testing"
)

func TestChunkTextPacksParagraphs(t *testing.T) {
	text := strings.Repeat("段落一内容。\n\n", 10) // 每段约 7 字
	chunks := ChunkText(text, 40, 8)
	if len(chunks) == 0 {
		t.Fatal("no chunks")
	}
	for _, c := range chunks {
		if n := len([]rune(c)); n > 40 {
			t.Fatalf("chunk exceeds maxChars: %d runes: %q", n, c)
		}
	}
}

// 超长单段必须硬切，且相邻块要有重叠：否则被切断的那句话两边都不含，检索两边都命中不到。
func TestChunkTextOverlapsOnHardSplit(t *testing.T) {
	text := strings.Repeat("あ", 100) // 单段 100 rune，无空行
	chunks := ChunkText(text, 30, 10)
	if len(chunks) < 3 {
		t.Fatalf("expected several chunks, got %d", len(chunks))
	}
	for i := 1; i < len(chunks); i++ {
		prevTail := []rune(chunks[i-1])
		curHead := []rune(chunks[i])
		if len(prevTail) < 10 || len(curHead) < 10 {
			continue
		}
		if string(prevTail[len(prevTail)-10:]) != string(curHead[:10]) {
			t.Fatalf("chunk %d does not overlap previous by 10 runes", i)
		}
	}
}

// 中文按 rune 计长：按字节切会把汉字劈成乱码。
func TestChunkTextCountsRunesNotBytes(t *testing.T) {
	text := strings.Repeat("测试", 50) // 100 rune / 300 bytes
	chunks := ChunkText(text, 20, 5)
	for _, c := range chunks {
		if len([]rune(c)) > 20 {
			t.Fatalf("chunk too long by runes: %d", len([]rune(c)))
		}
		if !isValidUTF8(c) {
			t.Fatalf("chunk is not valid UTF-8 (split mid-rune): %q", c)
		}
	}
}

func isValidUTF8(s string) bool {
	for i, r := range s {
		if r == 0xFFFD && i > 0 {
			return false
		}
	}
	return true
}

// embedInput 必须带上分类与标题：同一段正文在不同主题下语义不同。
func TestEmbedInputCarriesContext(t *testing.T) {
	got := embedInput("越权", "IDOR 测试要点", "把 id 换成别人的 id")
	for _, want := range []string{"【分类】越权", "【标题】IDOR 测试要点", "把 id 换成别人的 id"} {
		if !strings.Contains(got, want) {
			t.Fatalf("embed input missing %q: %q", want, got)
		}
	}
	// 分类/标题为空时不产生空标签
	if flat := embedInput("", "", "正文"); strings.Contains(flat, "【分类】") || strings.Contains(flat, "【标题】") {
		t.Fatalf("empty category/title should not emit headers: %q", flat)
	}
}
