package evidence

import (
	"database/sql"
	"os"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// 与其他 PG 包（db/agent/server/config/llmrec）一致：先拿 suite 锁，再初始化
// schema。此前这里先 db.Open（跑全量幂等 DDL）再拿锁，导致 evidence 二进制启动期
// 的 DDL 与持有锁的包（如 db 包正在跑的 TestActivityPageSessions 的 INSERT）并发，
// 撞出 40P01 死锁——CI 的 PG 日志里 Process 138 正是这段 schema DDL，Process 137
// 是被它撞成牺牲品的那条 activity INSERT。
func TestMain(m *testing.M) {
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		os.Exit(m.Run())
	}
	// 用独立的池拿锁，确保 db.Open 的 DDL 不会在拿锁前就并发执行。该池的连接靠
	// os.Exit 跳过 defer 存活到进程结束，从而全程持有锁（config/agent/llmrec 同一机制）。
	conn, err := sql.Open("pgx", dsn)
	if err != nil || conn.Ping() != nil {
		os.Exit(m.Run())
	}
	defer conn.Close()
	if _, err := conn.Exec(`SELECT pg_advisory_lock(7337741002)`); err != nil {
		os.Exit(m.Run())
	}
	defer conn.Exec(`SELECT pg_advisory_unlock(7337741002)`) //nolint:errcheck
	// 锁已持有，再初始化 schema（幂等 DDL），随后跑测试。
	pg, err := db.Open(dsn)
	if err != nil {
		panic(err)
	}
	defer pg.Close()
	os.Exit(m.Run())
}
