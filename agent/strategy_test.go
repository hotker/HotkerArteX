package agent

import (
	"encoding/json"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func mkIntent(t *testing.T, id int64, summary, state string) *db.Node {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"summary": summary})
	return &db.Node{ID: id, Kind: db.KindIntent, State: state, Payload: b}
}

// TestIntentSimilarityCalibration pins the calibration the thresholds were tuned on:
// 逐字/缩句复述必须过闸门，真·不同机理必须远低于闸门，换词同指落在软提示区间。
func TestIntentSimilarityCalibration(t *testing.T) {
	base := "枚举 /api 下所有端点并测试未授权访问"
	cases := []struct {
		name, other string
		want        float64 // 期望分数的下界语义见断言
		cat         string
	}{
		{"逐字复述", base, 0.99, "dup"},
		{"缩句复述", "枚举 api 所有接口，测试未授权访问", dupIntentThreshold, "dup"},
		{"换词同指", "扫描 api 路径下的全部接口，检查是否存在未授权即可访问", nearIntentThreshold, "near"},
		{"不同机理", "对上传接口测试文件类型绕过（双扩展名 / .htaccess）", 0, "far"},
	}
	for _, c := range cases {
		got := intentSimilarity(base, c.other)
		switch c.cat {
		case "dup":
			if got < c.want {
				t.Fatalf("%s: %.2f < %.2f (must be caught by the dedup gate)", c.name, got, c.want)
			}
		case "near":
			if got < c.want || got >= dupIntentThreshold {
				t.Fatalf("%s: %.2f not in [%.2f, %.2f)", c.name, got, c.want, dupIntentThreshold)
			}
		case "far":
			if got >= nearIntentThreshold {
				t.Fatalf("%s: %.2f must stay below the advisory floor %.2f", c.name, got, nearIntentThreshold)
			}
		}
	}
}

func TestNearestLiveIntentSkipsDeadStates(t *testing.T) {
	nodes := []*db.Node{
		mkIntent(t, 1, "枚举 /api 下所有端点并测试未授权访问", "open"),
		mkIntent(t, 2, "枚举 /api 下所有端点并测试未授权访问", "done"), // 已跑过，不该拦新方向
		mkIntent(t, 3, "打 xss", "running"),
	}
	m := nearestLiveIntent("枚举 api 所有接口，测试未授权访问", nodes)
	if m.ID != 1 {
		t.Fatalf("expected live intent #1, got #%d (score %.2f)", m.ID, m.Score)
	}
	if m.Score < dupIntentThreshold {
		t.Fatalf("score %.2f should cross the dedup gate", m.Score)
	}
}

func TestStallTrackerCountsIdleRounds(t *testing.T) {
	st := &stallTracker{}
	ov := func(facts, findings, running int) map[string]any {
		rs := make([]map[string]any, running)
		return map[string]any{"facts": facts, "findings": findings, "running_intents": rs}
	}
	if r := st.observe(ov(2, 0, 0)); r != 0 {
		t.Fatalf("first observation is a baseline, got %d", r)
	}
	// 在跑 work 时不累加（等它是正当状态，不是停滞）
	for i := 0; i < 3; i++ {
		st.observe(ov(2, 0, 1))
	}
	if st.idleRounds != 0 {
		t.Fatalf("running work must reset the idle counter, got %d", st.idleRounds)
	}
	// 无在跑 work 且图不增长 → 逐轮累加
	for i := 0; i < 2; i++ {
		st.observe(ov(2, 0, 0))
	}
	if st.idleRounds != 2 {
		t.Fatalf("expected 2 idle rounds, got %d", st.idleRounds)
	}
	// 有新事实即清零
	st.observe(ov(5, 0, 0))
	if st.idleRounds != 0 {
		t.Fatalf("progress must reset idle counter, got %d", st.idleRounds)
	}
	// 新漏洞同样算推进
	st.observe(ov(5, 0, 0))
	st.observe(ov(5, 1, 0))
	if st.idleRounds != 0 {
		t.Fatalf("new finding must reset idle counter, got %d", st.idleRounds)
	}
}

func TestStallAdvisoryThreshold(t *testing.T) {
	if stallAdvisory(1) != "" || stallAdvisory(stallAdvisoryAfter-1) != "" {
		t.Fatal("advisory must stay silent before the threshold")
	}
	if got := stallAdvisory(stallAdvisoryAfter); got == "" {
		t.Fatal("advisory must fire at the threshold")
	}
}

func TestPriceTable(t *testing.T) {
	p, ok := PriceFor("claude-sonnet-4-5-20250929")
	if !ok || p.Out != 15 {
		t.Fatalf("sonnet pricing not matched: %+v ok=%v", p, ok)
	}
	if _, ok := PriceFor("some-unknown-model"); ok {
		t.Fatal("unknown model must not be priced (never invent a number)")
	}
	u := db.TokenUsage{InputTokens: 1_000_000, OutputTokens: 100_000}
	if c := CostUSD(p, u); c < 4 || c > 5.1 { // 3 + 1.5
		t.Fatalf("cost calc off: %.3f", c)
	}
}
