package report

import (
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

// A report whose finding list is capped must say so instead of quietly
// presenting a partial list as complete.
func TestMarkdownReportsTruncation(t *testing.T) {
	in := Input{
		Title:         "t",
		Goal:          "g",
		GeneratedAt:   time.Now(),
		AssetCounts:   map[string]int{"endpoint": 3},
		Findings:      []*db.Node{},
		TotalFindings: 1500,
	}
	md := Markdown(in)
	if !strings.Contains(md, "本报告仅含最新") {
		t.Fatalf("truncated report must disclose the cap, got:\n%s", md)
	}
	if !strings.Contains(md, "1500 个未列出") {
		t.Fatalf("truncation note must carry the true and omitted counts, got:\n%s", md)
	}
}

func TestMarkdownNoTruncationNoteWhenComplete(t *testing.T) {
	in := Input{
		Title:       "t",
		Goal:        "g",
		GeneratedAt: time.Now(),
		Findings:    []*db.Node{},
		// TotalFindings 0 or == len(Findings) means the list is complete.
	}
	md := Markdown(in)
	if strings.Contains(md, "本报告仅含最新") {
		t.Fatalf("complete report must not carry a truncation note:\n%s", md)
	}
	if !strings.Contains(md, "确认发现：**0** 个\n") {
		t.Fatalf("expected the plain count line, got:\n%s", md)
	}
}
