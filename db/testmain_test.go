package db

import (
	"testing"

	"github.com/Autumn-27/artex/dbtest"
)

// TestMain 走统一的测试隔离入口（dbtest.Main）：有 ARTEX_PG_DSN 且 PG 可达时，
// 先建一个临时库 artex_test_<pid>_<rand> 并把 DSN 指过去，包结束时 DROP。
// 测试因此不再写开发库，也不再需要靠一把全局 advisory lock 串行化（锁仍在 dbtest 内保留）。
// 没有 PG 配置时照旧直接跑，需要 DB 的用例各自 skip。
func TestMain(m *testing.M) { dbtest.Main(m) }
