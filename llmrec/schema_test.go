package llmrec

import (
	"fmt"
	"os"

	"github.com/Autumn-27/artex/db"
)

// ensureSchemaForTests 在隔离库里跑一遍 schema（幂等）。
//
// 必须幂等且能在库被重建后重跑：它由 TestMain 在【建完隔离库之后】调用，
// 而不是 init() —— init 早于 TestMain，那时 ARTEX_PG_DSN 还指向开发库，
// 建出的表会落在错误的库上（症状：单包过、全量挂 relation does not exist）。
// 失败时只提示，不 fatal：需要表的用例会各自报出真实错误。
func ensureSchemaForTests() {
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		return
	}
	pg, err := db.Open(dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[llmrec] 建表失败（需要 PG 的用例会各自 skip）：%v\n", err)
		return
	}
	// llm_usage 不在 schema.sql 里，由 db.EnsureLLMUsageTable 按需建（正式路径是
	// 服务启动时调用）。测试直接开表也得走同一个函数，别在这里手抄一份 DDL。
	if err := pg.EnsureLLMUsageTable(); err != nil {
		fmt.Fprintf(os.Stderr, "[llmrec] 建 llm_usage 表失败：%v\n", err)
	}
	_ = pg.Close()
}
