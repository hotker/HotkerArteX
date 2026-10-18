package server

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

// 任务级 LLM 成本预算熔断。消费既有的 llm_usage 记账（每次 LLM 调用都落一行，
// 成功/失败/中断都计），周期性求和该任务累计 token，超过预算即驱动有序收尾——
// 不需要改动 LLM 热路径，复用任务超时协调器已验证过的「等在跑 worker drain →
// 定终态(带守卫)」时序。
//
// 语义是「任务生命周期累计」而非「单次运行」：预算是花掉的上限，暂停/恢复/重启
// 都不清零——累计已落库(ledger)+预算在 settings，重启天然延续。因此一个因成本
// 被熔断、再被手动复活的会立即再次触发：这不是 bug，是「要让它继续跑，请调高
// 预算」的显式提示，避免用户靠暂停/复活把计费的表拧回去。
//
// 终态复用 timeout（「这次运行的预算资源已耗尽」与墙钟超时同属一类），不新造
// cost_limited 状态：终态枚举在 db.IsTerminal + 3 处 SQL 的 IN(...) + 前端
// TaskStatus 联合类型里写死，扩一个值会波及整条状态机。成本原因由活动记录 +
// 日志承载，UI 在「超时」徽章旁能看到这条 system 文案。

const (
	// 全局 settings key：单任务 LLM token 上限（0 = 不限）。
	settingTaskLLMBudgetTokens = "task_llm_budget_tokens"
	// 成本协调器轮询间隔。token 记账是每 LLM 调用落一行、低频写入，30s 足够及时
	// 又不给 DB 加轮询压力；最坏一个任务超支后约 30s 被收尾。
	costPollInterval = 30 * time.Second
)

// startCostCoordinator 为每个任务起一次成本预算协调器(幂等,与 deadline 协调器
// 同一批启动点)。预算未配置(<=0)或无 DB 时直接不起——省一个每任务的轮询 goroutine。
// 从 Run()、重启恢复、复活准入这几处调用,保证非活跃/重启后的任务也能被熔断。
func (e *Engine) startCostCoordinator(ctx context.Context, t *Task) {
	if t == nil {
		return
	}
	if e.m == nil || e.m.pg == nil {
		return
	}
	if e.TaskLLMBudget() <= 0 {
		return
	}
	e.deleteMu.RLock()
	if e.IsDeleting(t.ID) {
		e.deleteMu.RUnlock()
		return
	}
	if _, loaded := e.costCoordStarted.LoadOrStore(t.ID, true); loaded {
		e.deleteMu.RUnlock()
		return
	}
	rt := e.registerTaskRoutines(ctx, t.ID, 1)
	e.deleteMu.RUnlock()
	runTaskRoutine(rt, func(loopCtx context.Context) { e.costCoordinator(loopCtx, t) })
}

// costCoordinator 周期轮询该任务累计 token,超过生命周期预算即触发收尾。
// 用户暂停期间不熔断:暂停的任务在烧 0 token(在跑 run 已被 cancel),不应因历史
// 累计被收尾;恢复后重新判定。已终态/删除即退出。
func (e *Engine) costCoordinator(ctx context.Context, t *Task) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if isTerminalStatus(e.m.TaskStatus(t.ID)) {
			return
		}
		if e.IsDeleting(t.ID) {
			return
		}
		if e.IsPaused(t.ID) {
			// 暂停中:不烧 token,也不熔断。恢复后继续轮询。
			if sleepCtx(ctx, costPollInterval) {
				return
			}
			continue
		}
		if e.isSettling(t.ID) {
			return // 已在收尾(超时或成本),别再重复驱动
		}
		total, err := e.m.pg.TokenTotalByTask(t.ID)
		if err != nil {
			// 记账读取失败不该让协调器退出:下次轮询再试,别让一次抖动关掉熔断。
			log.Printf("[cost] task %s 读取累计 token 失败,本轮跳过: %v", t.ID, err)
			if sleepCtx(ctx, costPollInterval) {
				return
			}
			continue
		}
		if budget := e.TaskLLMBudget(); costOverBudget(total, budget) {
			log.Printf("[cost] task %s 累计 token %d 已达预算上限 %d,触发成本熔断收尾", t.ID, total, budget)
			e.emitActivity(t, db.Activity{Worker: "system", Kind: "text",
				Summary: fmt.Sprintf("成本预算已用完：本任务累计消耗 %d tokens（上限 %d），任务已停止。如需继续请调高「单任务 LLM token 上限」后复活任务。", total, budget)})
			e.settleCostOverrun(ctx, t)
			return
		}
		if sleepCtx(ctx, costPollInterval) {
			return
		}
	}
}

// settleCostOverrun 成本熔断的有序收尾:复用超时收尾的「等在跑 drain」时序,但
// **跳过终局 planner 轮**——预算熔断的本意就是别再花 LLM,再跑一轮 planner 判定
// 恰是最该停的那种开销。在跑 worker/planner 靠已夹逼的 run 预算自行收尾;超过
// grace 仍未清空则硬 cancel(意图走 exhausted 归类)。最后带守卫落 timeout 终态。
func (e *Engine) settleCostOverrun(ctx context.Context, t *Task) {
	if !e.markSettling(t.ID) {
		return // 超时收尾已先占位,尊重它
	}
	log.Printf("[cost] task %s 进入成本熔断收尾时序", t.ID)

	// 等在跑 worker/planner drain(在跑 run 因夹逼的 MaxDuration 自行收尾);
	// 超过 grace 仍未清空 → 硬 cancel 该任务 exec ctx(settling-aware 分支归 exhausted)。
	hardStop := time.Now().Add(settleDrainGrace)
	for e.inflightCount(t.ID) > 0 {
		if time.Now().After(hardStop) {
			log.Printf("[cost] task %s drain 超时(%s),硬取消在跑 run", t.ID, settleDrainGrace)
			e.cancelExec(t.ID, agent.AbortSettleDrainTimeout)
			_ = sleepCtx(ctx, 3*time.Second) // 给 worker 分支一点时间落库/归类
			break
		}
		if sleepCtx(ctx, 500*time.Millisecond) {
			return // 引擎整体关停
		}
	}

	// 定终态(带守卫):复用 timeout(终态枚举不扩,见文件头注释)。若常规路径已先落
	// done,守卫会拒绝覆盖,保留 completed 语义。
	if e.IsDeleting(t.ID) {
		return
	}
	if !e.beginTaskOperation(t.ID) {
		return
	}
	defer e.decInflight(t.ID)
	won, err := e.m.SetTaskStatusGuarded(t.ID, "timeout")
	switch {
	case err != nil:
		log.Printf("[cost] task %s 落终态失败: %v", t.ID, err)
	case won:
		log.Printf("[cost] task %s 成本熔断收尾完成,终态=timeout", t.ID)
	default:
		log.Printf("[cost] task %s 收尾时已是终态,保留原状态", t.ID)
	}
}

// TaskLLMBudget 读取全局单任务 LLM token 预算上限(0 = 不限)。每次轮询都读,
// 改预算对之后的判定即时生效,无需重启。
func (e *Engine) TaskLLMBudget() int64 {
	if e.m == nil || e.m.pg == nil {
		return 0
	}
	v, ok, _ := e.m.pg.GetSetting(settingTaskLLMBudgetTokens)
	if !ok {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n < 0 {
		return 0
	}
	return int64(n)
}

// costOverBudget 是熔断判定:累计 token >= 正数预算即触发。预算 <=0 表示未设置
// (不限),永不触发。抽成纯函数是为了让这条「什么时候该停」的核心语义能被单测,
// 而无需拉起 Postgres。
func costOverBudget(total, budget int64) bool {
	return budget > 0 && total >= budget
}
