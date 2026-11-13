package server

import (
	"context"
	"log"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/llmpool"
	"github.com/Autumn-27/norma/llm"
)

// LLM 轮询(故障转移)的服务端接线。设计见 docs/LLM轮询设计.md：
//   - 全局激活配置这条路径(agent 未绑定、任务未 pin)才轮询;
//   - 绑定/pin 的路径默认独占该配置,失败即失败(可由 llm_pool_bind_fallback 打开兜底);
//   - 链序 = 激活配置 → 其余按 priority DESC,排除 pool_exclude 的;
//   - 熔断状态进程级共享(s.llmHealth),重建 pool 不清空。

// newLLMHealthRegistry builds the process-wide circuit-breaker registry, mirroring
// state into PG so a cooling-off window survives a restart. Writes are async and
// best-effort — the in-memory copy is authoritative.
func newLLMHealthRegistry(pg *db.DB) *llmpool.Registry {
	if pg == nil {
		return llmpool.NewRegistry(nil, nil)
	}
	persist := func(id int64, st llmpool.State) {
		h := db.LLMHealth{ProfileID: id, Fails: st.Fails, Trips: st.Trips, LastError: st.LastError}
		if !st.OpenUntil.IsZero() {
			t := st.OpenUntil
			h.OpenUntil = &t
		}
		go func() {
			if err := pg.SaveLLMHealth(h); err != nil {
				log.Printf("[llmpool] 熔断状态落库失败: %v", err)
			}
		}()
	}
	forget := func(id int64) {
		go func() { _ = pg.ClearLLMHealth(id) }()
	}
	reg := llmpool.NewRegistry(persist, forget)
	// Restore only windows that haven't expired (LoadLLMHealth filters), so a
	// profile that finished cooling while we were down comes back healthy.
	if rows, err := pg.LoadLLMHealth(); err == nil {
		for _, h := range rows {
			st := llmpool.State{Fails: h.Fails, Trips: h.Trips, LastError: h.LastError, LastAt: h.LastAt}
			if h.OpenUntil != nil {
				st.OpenUntil = *h.OpenUntil
			}
			reg.Restore(h.ProfileID, st)
			log.Printf("[llmpool] 恢复熔断状态: 配置 #%d 冷却至 %s", h.ProfileID, st.OpenUntil.Format(time.RFC3339))
		}
	}
	return reg
}

// poolMember builds one chain member from a profile, reusing the per-profile
// provider cache so every agent pointing at the same profile shares one provider
// (hence one rate limiter). Returns nil when the profile can't be built.
func (s *Server) poolMember(p *db.LLMProfile, rank int) *llmpool.Member {
	prov, cfg, ok := s.providerForProfile(p.ID)
	if !ok {
		return nil
	}
	return &llmpool.Member{
		ID: p.ID, Name: p.Name, Model: p.Model, Format: p.Format,
		Priority: p.Priority, Active: p.IsDefault, Rank: rank,
		WindowTokens: cfg.CompactionWindow(), Prov: prov,
		Quality: p.Quality, Economy: p.Economy,
	}
}

// poolChain reads the failover chain from the DB. headID/headProv/headCfg describe
// the member that must lead the chain — the globally active profile on the normal
// path, or an explicitly bound one when bound-profile fallback is on. The head is
// passed in (rather than resolved through the cache) so applyLLM's already-built
// provider is reused instead of duplicated.
//
// Returns nil when failover is off or the chain has fewer than two usable members
// — callers then use the bare provider, which is byte-for-byte the old behavior.
func (s *Server) poolChain(headID int64, headProv llm.Provider, headCfg agent.Config) *llmpool.Pool {
	if s.m == nil || s.m.pg == nil || !s.m.LLMPoolEnabled() {
		return nil
	}
	profs, err := s.m.pg.PoolProfiles()
	if err != nil {
		log.Printf("[llmpool] 读取轮询链失败: %v", err)
		return nil
	}
	var head *db.LLMProfile
	for _, p := range profs {
		if p.ID == headID {
			head = p
			break
		}
	}
	if head == nil { // head excluded from the chain (bound + pool_exclude) — still leads
		if p, err := s.m.pg.ProfileByID(headID); err == nil && p != nil {
			head = p
		} else {
			return nil
		}
	}
	headQuality, headEconomy := head.Quality, head.Economy
	members := []*llmpool.Member{{
		ID: head.ID, Name: head.Name, Model: head.Model, Format: head.Format,
		Priority: head.Priority, Active: head.IsDefault, Rank: llmpool.RankActive,
		WindowTokens: headCfg.CompactionWindow(), Prov: headProv,
		Quality: headQuality, Economy: headEconomy,
	}}
	for _, p := range profs {
		if p.ID == headID {
			continue
		}
		// The globally active profile outranks the others when it isn't the head
		// (bound-fallback chains), so it stays the first fallback tried.
		rank := p.Priority
		if p.IsDefault {
			rank = llmpool.RankActive - 1
		}
		if m := s.poolMember(p, rank); m != nil {
			members = append(members, m)
		}
	}
	if len(members) < 2 {
		return nil // nothing to fail over to
	}
	return llmpool.New(members, s.llmHealth)
}

// poolForActive wraps the globally-active provider in the failover chain. Returns
// prov unchanged when failover is off or there's nothing to fall back to.
func (s *Server) poolForActive(activeID int64, prov llm.Provider, cfg agent.Config) llm.Provider {
	pool := s.poolChain(activeID, prov, cfg)
	if pool == nil {
		return prov
	}
	names := make([]string, 0, len(pool.Members()))
	for _, m := range pool.Members() {
		names = append(names, m.Name+"/"+m.Model)
	}
	log.Printf("[llmpool] LLM 轮询已启用，链路(%d): %v", len(names), names)
	return pool
}

// poolForBinding wraps a BOUND profile's provider so it falls back to the chain.
// Only active when both the failover master switch and the bound-fallback switch
// are on; otherwise a bound profile stays exclusive (fails hard), which is the
// default and the documented precedence.
func (s *Server) poolForBinding(id int64, prov llm.Provider, cfg agent.Config) llm.Provider {
	if s.m == nil || !s.m.LLMPoolEnabled() || !s.m.LLMPoolBindFallback() {
		return prov
	}
	if pool := s.poolChain(id, prov, cfg); pool != nil {
		return pool
	}
	return prov
}

// roleMode 返回每个角色的默认路由意图（HotkerArteX）。mode 只改【同一条链内】的顺序，
// 所有健康配置在任何模式下都仍可被选中 —— 这正是它敢按角色下判断的原因：
//
//	planner / worker / pentest / mainagent / auto → deep（探索与利用依赖推理质量）
//	enrich（漏洞 AI 富化）/ summarize（压缩摘要）→ economy（量大、可容忍质量损失）
//	chat → balanced（不替用户做取舍）
func roleMode(role string) llmpool.Mode {
	switch role {
	case "planner", "worker", "pentest", "mainagent", "auto":
		return llmpool.ModeDeep
	case "enrich", "summarize":
		return llmpool.ModeEconomy
	default:
		return llmpool.ModeBalanced
	}
}

// poolWithRole 给已建好的 provider 套上角色模式；非 Pool（单配置）原样返回。
func poolWithRole(prov llm.Provider, role string) llm.Provider {
	if p, ok := prov.(*llmpool.Pool); ok && p != nil {
		return p.WithMode(roleMode(role))
	}
	return prov
}

// LLMPoolMemberStatus is one chain entry as shown in the UI.
type LLMPoolMemberStatus struct {
	ProfileID string `json:"profile_id"`
	Name      string `json:"name"`
	Model     string `json:"model"`
	Format    string `json:"format"`
	Priority  int    `json:"priority"`
	Active    bool   `json:"active"`   // is the globally-activated profile
	Excluded  bool   `json:"excluded"` // pool_exclude — not a failover target
	// Health: state is "ok" | "degraded" (failing but not tripped) | "tripped".
	State        string `json:"state"`
	Fails        int    `json:"fails"`
	Trips        int    `json:"trips"`
	CooldownSecs int    `json:"cooldown_secs"` // remaining cooling-off seconds; 0 = none
	LastError    string `json:"last_error,omitempty"`
	LastAt       string `json:"last_at,omitempty"`
}

// llmPoolStatus reports the whole picture for the LLM page: whether failover is
// on, the resolved chain order, and each profile's breaker state. Excluded
// profiles are listed too (flagged), so the user can see why one isn't in line.
func (s *Server) llmPoolStatus() map[string]any {
	out := map[string]any{
		"enabled":       false,
		"bind_fallback": false,
		"chain":         []LLMPoolMemberStatus{},
	}
	if s.m == nil || s.m.pg == nil {
		return out
	}
	out["enabled"] = s.m.LLMPoolEnabled()
	out["bind_fallback"] = s.m.LLMPoolBindFallback()

	all, err := s.m.pg.ListProfiles()
	if err != nil {
		return out
	}
	health := s.llmHealth.Snapshot()
	now := time.Now()
	// Chain order: active first, then priority DESC / id ASC — the same ordering
	// PoolProfiles applies, recomputed here so excluded ones can be shown in place.
	chain := make([]LLMPoolMemberStatus, 0, len(all))
	for _, p := range all {
		st := health[p.ID]
		m := LLMPoolMemberStatus{
			ProfileID: i64s(p.ID), Name: p.Name, Model: p.Model, Format: p.Format,
			Priority: p.Priority, Active: p.IsDefault, Excluded: p.PoolExclude,
			State: "ok", Fails: st.Fails, Trips: st.Trips,
			LastError: st.LastError,
		}
		if st.Open() {
			m.State = "tripped"
			m.CooldownSecs = int(st.OpenUntil.Sub(now).Seconds()) + 1
		} else if st.Fails > 0 {
			m.State = "degraded"
		}
		if !st.LastAt.IsZero() {
			m.LastAt = st.LastAt.Format(time.RFC3339)
		}
		chain = append(chain, m)
	}
	sortPoolStatus(chain)
	out["chain"] = chain
	return out
}

// sortPoolStatus orders the status rows exactly like the live chain: active first,
// then priority DESC, then id ASC (the incoming slice is already id-ordered, so a
// stable insertion sort on the first two keys is enough).
func sortPoolStatus(in []LLMPoolMemberStatus) {
	for i := 1; i < len(in); i++ {
		for j := i; j > 0 && poolLess(in[j], in[j-1]); j-- {
			in[j], in[j-1] = in[j-1], in[j]
		}
	}
}

func poolLess(a, b LLMPoolMemberStatus) bool {
	if a.Active != b.Active {
		return a.Active
	}
	return a.Priority > b.Priority
}

// 成本估算（HotkerArteX）：价格表住在 agent 包（agent.ModelPrice），这里薄薄地接一层
// —— 价格只在 planner 态势里做"消耗感"提示，不进账务/报表。
func priceForModel(model string) (agent.ModelPrice, bool) { return agent.PriceFor(model) }

// taskBudget 把任务累计 token 用量换算成金额，供 planner 的态势块展示。
// 价格按本轮 planner 实际使用的模型估算；未命中价格表 → known=true 但金额为 0
// （调用方只显示 token，绝不编一个假数字）。
func (s *Server) taskBudget(ctx context.Context, expID int64) (float64, int, bool) {
	if s == nil || s.m == nil || s.m.pg == nil {
		return 0, 0, false
	}
	u, err := s.m.pg.Exploration(expID).TokenTotal()
	if err != nil {
		return 0, 0, false
	}
	total := agent.UsageTotal(u)
	if total == 0 {
		return 0, 0, false
	}
	var model string
	s.cfgMu.Lock()
	model = s.llmCfg.Model
	s.cfgMu.Unlock()
	p, ok := priceForModel(model)
	if !ok {
		return 0, total, true // 知道 token，不知道价钱
	}
	return agent.CostUSD(p, u), total, true
}
