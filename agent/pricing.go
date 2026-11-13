package agent

import (
	"strings"

	"github.com/Autumn-27/artex/db"
)

// 本文件给「一次任务烧了多少钱」一个可计算的答案。上游只有 token 计数（
// db.TokenUsage），没有价格概念，于是 planner 在长回合里完全看不到自己的消耗——
// 一个方向打空、反复重抓大页面、或把预算烧在同义重试上，都不产生任何反馈。
//
// 做法：内置一张「模型前缀 → 单价（USD / 百万 token）」表，命中即按用量估算；未命中
// 的模型返回 known=false，调用方据此不渲染价格（绝不编一个假数字）。价格只是数量级
// 参考，真实账单以供应商为准 —— 所以数值只在态势里做"消耗感"提示，不进账务/报表。

// ModelPrice 是某模型族的四类用量单价（USD / 1M tokens）。
type ModelPrice struct {
	In  float64 // 普通输入
	Out float64 // 输出
	CR  float64 // cache read（命中缓存的输入）
	CW  float64 // cache write（写入缓存的输入）
}

// priceTable 按「模型 id 前缀」匹配，先长后短 —— 越具体的族放前面。数值取公开定价的
// 数量级（Claude 3.5/4 系、GPT-4o 系、DeepSeek 系），只用于消耗感提示。
var priceTable = []struct {
	prefix string
	price  ModelPrice
}{
	// Anthropic
	{"claude-opus-4", ModelPrice{In: 15, Out: 75, CR: 1.5, CW: 18.75}},
	{"claude-sonnet-4", ModelPrice{In: 3, Out: 15, CR: 0.3, CW: 3.75}},
	{"claude-3-7-sonnet", ModelPrice{In: 3, Out: 15, CR: 0.3, CW: 3.75}},
	{"claude-3-5-sonnet", ModelPrice{In: 3, Out: 15, CR: 0.3, CW: 3.75}},
	{"claude-3-5-haiku", ModelPrice{In: 0.8, Out: 4, CR: 0.08, CW: 1}},
	{"claude-3-opus", ModelPrice{In: 15, Out: 75, CR: 1.5, CW: 18.75}},
	{"claude", ModelPrice{In: 3, Out: 15, CR: 0.3, CW: 3.75}}, // 未知 claude 族取 sonnet 档
	// OpenAI
	{"gpt-4o-mini", ModelPrice{In: 0.15, Out: 0.6, CR: 0.075, CW: 0.15}},
	{"gpt-4o", ModelPrice{In: 2.5, Out: 10, CR: 1.25, CW: 2.5}},
	{"gpt-4.1-mini", ModelPrice{In: 0.4, Out: 1.6, CR: 0.1, CW: 0.4}},
	{"gpt-4.1", ModelPrice{In: 2, Out: 8, CR: 0.5, CW: 2}},
	{"o3-mini", ModelPrice{In: 1.1, Out: 4.4, CR: 0.55, CW: 1.1}},
	{"o3", ModelPrice{In: 2, Out: 8, CR: 0.5, CW: 2}},
	// DeepSeek / 国内常用
	{"deepseek-reasoner", ModelPrice{In: 0.55, Out: 2.19, CR: 0.14, CW: 0.55}},
	{"deepseek-chat", ModelPrice{In: 0.27, Out: 1.1, CR: 0.07, CW: 0.27}},
	{"deepseek", ModelPrice{In: 0.27, Out: 1.1, CR: 0.07, CW: 0.27}},
	{"qwen", ModelPrice{In: 0.4, Out: 1.2, CR: 0.08, CW: 0.4}},
	{"glm", ModelPrice{In: 0.6, Out: 2.2, CR: 0.1, CW: 0.6}},
	{"kimi", ModelPrice{In: 0.6, Out: 2.5, CR: 0.15, CW: 0.6}},
}

// PriceFor 返回模型单价与是否命中价格表（未命中 = 不估算，调用方不要渲染金额）。
func PriceFor(model string) (ModelPrice, bool) {
	m := strings.ToLower(strings.TrimSpace(model))
	if m == "" {
		return ModelPrice{}, false
	}
	for _, e := range priceTable {
		if strings.HasPrefix(m, e.prefix) {
			return e.price, true
		}
	}
	return ModelPrice{}, false
}

// CostUSD 用单价估算一次用量（四类 token 分别计价），单位美元。
func CostUSD(p ModelPrice, u db.TokenUsage) float64 {
	return (float64(u.InputTokens)*p.In +
		float64(u.OutputTokens)*p.Out +
		float64(u.CacheReadTokens)*p.CR +
		float64(u.CacheWriteTokens)*p.CW) / 1_000_000
}

// UsageTotal 是四类 token 的合计（用于"烧了多少"的量级提示）。
func UsageTotal(u db.TokenUsage) int {
	return u.InputTokens + u.OutputTokens + u.CacheReadTokens + u.CacheWriteTokens
}
