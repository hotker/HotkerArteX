package agent

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"unicode"

	"github.com/Autumn-27/artex/db"
)

// 本文件是 HotkerArteX 对「规划质量」的两处硬约束增强。原版把纪律写在提示词里
// （"不要重复已存在的意图"、"别空转"），全靠模型自律 —— 长回合 + compaction 之后
// 自律最容易失效。这里把两条纪律变成代码里的可计算信号：
//
//   1. intentSimilarity —— 新意图与「活着的意图（open/running）」做字符 bigram 相似度，
//      超过阈值直接拒收并回传最相似的意图 id，让模型当面看到"你正在重派 #12"。
//   2. stallTracker    —— 逐轮统计「新增事实/漏洞」的增量为 0 的连续轮数，命中阈值就把
//      告警塞进 planner 的本轮态势，逼它在"换机理"与"收官"之间二选一。

// ---- 意图相似度 ----

// dupIntentThreshold 是判定「同一条意图换措辞」的余弦相似度阈值。
//
// 校准（bigram 余弦，去停用字后实测）：逐字复述 ≈1.0；保留主干的缩句 ≈0.77；
// 换词但同指（"扫描 api 路径全部接口，检查是否存在未授权即可访问"）≈0.31；
// 真·不同机理（SQL 注入 vs 上传绕过）≈0.06。
//
// 0.75 是一道保守闸门：它拦得住近逐字/缩句重派，不会误杀换词复述 —— 后者本来就
// 是 planner 的正当行为（换个角度重述同一条路线），提示词层面另有约束。硬拦误杀
// 一条真方向，比漏过一条重复更贵（漏过最多多烧一轮，误杀可能永远丢掉一个洞）。
const dupIntentThreshold = 0.75

// nearIntentThreshold 是「值得提醒但放行」的余弦相似度下限，作为软提示回传给模型。
const nearIntentThreshold = 0.30

// 中文停用字：出现在几乎每个方向句里（枚举/测试/检查/所有/是否/存在…），把它们算进
// 相似度会把"换词复述"和"实质不同"一起拉高。做法是把它们从文本流里剔掉 —— 注意：
// 必须在【拼 bigram 之前】剔除，否则"测试注入"与"检查注入"仍会因共享"试注"而虚高。
var cnStop = map[rune]bool{
	'的': true, '了': true, '和': true, '与': true, '及': true, '或': true, '并': true,
	'在': true, '对': true, '把': true, '将': true, '是': true, '有': true, '无': true,
	'个': true, '些': true, '这': true, '那': true, '其': true, '以': true, '为': true,
	'所': true, '都': true, '也': true, '就': true, '而': true, '被': true, '从': true,
	'上': true, '下': true, '中': true, '里': true, '去': true, '来': true, '到': true,
	'做': true, '再': true, '又': true, '很': true, '更': true, '最': true, '要': true,
	'可': true, '能': true, '会': true, '想': true, '看': true, '用': true, '让': true,
	'一': true, '二': true, '三': true, '两': true, '每': true, '各': true, '该': true,
}

// enStop 是英文被动结构里的高频虚词（同样先剔后拼）。
var enStop = []string{" the ", " and ", " for ", " with ", " that ", " this ", " from "}

// intentVector 把一句话归一成字符 bigram 集合：
//  1. 转小写、去标点空白、剔停用字（中文逐字、英文整词，见 cnStop/enStop）；
//  2. 对剩下的实词字符流拼 bigram。
//
// 中文方向句短，分词器不稳定且各库结果不一致，bigram 是无依赖且够用的近似 ——
// 剔掉停用字之后，"枚举 api 端点" 与 "爆破上传点" 几乎不共享 bigram，而"扫描所有接口"
// 这种真·同义复述仍共享大量核心 bigram。
func intentVector(s string) map[string]struct{} {
	low := " " + strings.ToLower(s) + " "
	for _, w := range enStop {
		low = strings.ReplaceAll(low, w, " ")
	}
	var b strings.Builder
	for _, r := range low {
		if cnStop[r] {
			continue
		}
		switch {
		case unicode.IsLetter(r), unicode.IsDigit(r):
			b.WriteRune(r)
		}
	}
	runes := []rune(b.String())
	out := make(map[string]struct{}, len(runes))
	for i := 0; i+1 < len(runes); i++ {
		out[string(runes[i:i+2])] = struct{}{}
	}
	if len(runes) == 1 { // 单字方向（罕见）：退化为 unigram，避免空向量
		out[string(runes)] = struct{}{}
	}
	return out
}

// intentSimilarity 返回两组 bigram 的余弦相似度（|A∩B| / sqrt(|A|·|B|)，0..1）。
//
// 不用 Jaccard：planner 的重复几乎总是「短句被展开成更啰嗦的长句」（"枚举 api 端点"
// → "枚举 /api 下所有端点并逐个测试未授权访问"），Jaccard 会被长句新增的字稀释到
// 0.3 以下而漏判；纯 Overlap(min) 又会让短句对任何含它的长句直接判 1.0。几何平均
// 的余弦落在两者之间，是"包含式复述"与"长度差异"之间最稳的一档。
func intentSimilarity(a, b string) float64 {
	va, vb := intentVector(a), intentVector(b)
	if len(va) == 0 || len(vb) == 0 {
		return 0
	}
	inter := 0
	for k := range va {
		if _, ok := vb[k]; ok {
			inter++
		}
	}
	// 几何平均而不是 min：既不被长句稀释（包含式复述仍得高分），也不让"短句被
	// 短句包含"直接判满（避免一条两字的意图撞死所有含它的方向）。
	return float64(inter) / math.Sqrt(float64(len(va))*float64(len(vb)))
}

// liveIntentStates 是「还在占用这条方向」的意图状态集合 —— 只跟它们去重。
// done/blocked/exhausted 不参与：那些方向已经跑过，重派要交给 planner 用「新机理」
// 的显式理由来论证，而不是被相似度静默拦掉。
var liveIntentStates = map[string]bool{"open": true, "pending": true, "queued": true, "running": true}

// intentMatch 是一次相似度比中的结果。
type intentMatch struct {
	ID      int64
	Summary string
	Score   float64
}

// nearestLiveIntent 在 live 意图里找出与新方向最相似的一条（无候选时返回零值）。
func nearestLiveIntent(summary string, nodes []*db.Node) intentMatch {
	var best intentMatch
	for _, n := range nodes {
		if !liveIntentStates[n.State] {
			continue
		}
		s, _ := nodeIntentSummary(n)
		if s == "" {
			continue
		}
		if sc := intentSimilarity(summary, s); sc > best.Score {
			best = intentMatch{ID: n.ID, Summary: s, Score: sc}
		}
	}
	return best
}

func nodeIntentSummary(n *db.Node) (string, map[string]any) {
	var p map[string]any
	_ = json.Unmarshal(n.Payload, &p)
	s, _ := p["summary"].(string)
	return s, p
}

// checkIntentNovelty 是 add_intent 的去重闸门：撞上活意图（≥0.90）就拒收并说明
// 该往哪儿走；只是接近（≥0.62）则放行但在返回里点出来，让模型自己确认是否要合并。
// 返回 (错误, 软提示)。
func checkIntentNovelty(ts *db.ExplorationStore, summary string) (error, string) {
	if ts == nil {
		return nil, ""
	}
	nodes, err := ts.ListByKind(db.KindIntent, 200)
	if err != nil || len(nodes) == 0 {
		return nil, ""
	}
	m := nearestLiveIntent(summary, nodes)
	switch {
	case m.Score >= dupIntentThreshold:
		return fmt.Errorf("与在跑/待跑的意图 #%d 实质重复（相似度 %.2f）：%q。\n"+
			"这是同一方向的换措辞重派，已被拒收。请二选一：① 若该方向需要推进，用 steer_work(#%d, ...) 给在跑的 work 纠偏，或用 TodoWrite 记下后续步骤等它产出后派下一步；② 若你要的是【另一个】方向，把 summary 改写成实质不同的入口面/资产/机理（例如换利用链或换资产面），而不是同义改写。",
			m.ID, m.Score, m.Summary, m.ID), ""
	case m.Score >= nearIntentThreshold:
		return nil, fmt.Sprintf("（提示：本方向与在跑意图 #%d 相似度 %.2f —— %q。若其实是同一件事，请合并、不要并行重复打；若确有差异，在后续步骤里把差异写清楚。）",
			m.ID, m.Score, m.Summary)
	}
	return nil, ""
}

// sortMatches 仅用于测试/诊断输出，按分数降序。
func sortMatches(ms []intentMatch) []intentMatch {
	sort.Slice(ms, func(i, j int) bool { return ms[i].Score > ms[j].Score })
	return ms
}

// ---- 停滞检测 ----

// stallAdvisoryAfter 是「连续多少轮无新增」开始告警的阈值。planner 按图变化唤醒，
// 3 轮无增量基本已经说明这一批方向打空了（单轮之间通常有 worker 产出）。
const stallAdvisoryAfter = 3

// stallTracker 逐任务统计推进情况（planner 实例内保存，跨唤醒累计）。
type stallTracker struct {
	lastFacts    int  // 上一轮看到的事实总数
	lastFindings int  // 上一轮看到的漏洞总数
	idleRounds   int  // 连续「无新增且无在跑 work」的轮数
	seen         bool // 是否已有基线（首轮只记录不判断）
}

// observe 用本轮 graph_overview 的实测计数推进统计，返回当前停滞轮数。
// 判定口径刻意用【绝对值是否增长】而不是"本轮意图有没有跑完"：worker 跑完但没写回
// 任何东西（WriteCounts=0）同样不算推进，这正是最该被抓出来的空转。
func (s *stallTracker) observe(overview map[string]any) int {
	facts := intField(overview, "facts")
	findings := intField(overview, "findings")
	running := 0
	if rs, ok := overview["running_intents"].([]map[string]any); ok {
		running = len(rs)
	}
	advanced := facts > s.lastFacts || findings > s.lastFindings
	if !s.seen {
		s.seen = true // 首轮只立基线，不算停滞
	} else if advanced || running > 0 {
		s.idleRounds = 0
	} else {
		s.idleRounds++
	}
	s.lastFacts, s.lastFindings = facts, findings
	return s.idleRounds
}

// intField 从 overview 里取整数计数（JSON 解码后可能是 float64 / int）。
func intField(m map[string]any, key string) int {
	switch v := m[key].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	}
	return 0
}

// stallAdvisory 把停滞统计翻成本轮态势里的一段硬告警（未达阈值时返回空串）。
func stallAdvisory(rounds int) string {
	if rounds < stallAdvisoryAfter {
		return ""
	}
	return fmt.Sprintf("\n\n【停滞告警（代码统计，非主观判断）：已连续 %d 轮唤醒，图谱事实与漏洞总数没有任何增长，且当前没有在跑的 work】\n"+
		"这说明上一批方向已经打空，图上不再前进。本轮只有两条合法出路，必须选一条：\n"+
		"  (a) 派一条【机理不同】的新方向——换入口面、换资产、换利用链（例如从「再看一遍同一个接口」换成「打另一个未覆盖的资产面/协议层」）；\n"+
		"  (b) 若目标确实已经达成或所有合理路线都已探尽，用 prove_goal 逐个盖章并收官。\n"+
		"禁止：把已封锁路线换个措辞重派（会被去重闸门拒收）、为凑数量派注定空转的意图、以及把「目标未达成」当默认而不做任何决定。", rounds)
}

// drainIntentNotes 取走本轮累积的软提示（拼接成一段文本），并把缓冲清空。
func (t *ToolSet) drainIntentNotes() string {
	if len(t.intentNotes) == 0 {
		return ""
	}
	out := strings.Join(t.intentNotes, "\n")
	t.intentNotes = nil
	return out
}
