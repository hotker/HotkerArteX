package llmrec

import (
	"os"
	"testing"

	"github.com/Autumn-27/artex/dbtest"
)

// TestMain 走统一的测试隔离入口（dbtest.Main）：有 ARTEX_PG_DSN 且 PG 可达时，
// 先建临时库 artex_test_<pid>_<rand> 并把 DSN 指过去，包结束时 DROP —— 这样
// 本包的 schema 依赖不会和别的包互相踩，也不会写进开发库。
func TestMain(m *testing.M) {
	// dbtest.Main 内部会先建隔离库、改写 ARTEX_PG_DSN，再调 m.Run()。
	// 我们需要在那之后、用例之前建表 —— 所以不用 dbtest.Main 的便利入口，
	// 而是显式走 Setup/Run/Teardown 三段（见 dbtest 包）。
	dbtest.Setup()
	ensureSchemaForTests()
	code := dbtest.RunOnly(m)
	dbtest.Teardown()
	os.Exit(code)
}

// llmrec 的用例不经过 db.Open（它们直接 pg.QueryRow 查 llm_usage），所以 schema 得在这里
// 显式建一次。之前"单包过、全量挂"正是这个原因：单跑时开发库早就被别的包建好了表，
// 全量跑时它落在空库上。现在隔离库是全新的，必须在 TestMain 里自己 apply。
func init() { ensureSchemaForTests() }
