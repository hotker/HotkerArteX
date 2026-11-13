// Package dbtest 给「需要真实 PostgreSQL 的测试」提供隔离入口。
//
// 为什么需要它：原先测试直接连开发库（ARTEX_PG_DSN 指向哪就打到哪），跑一次
// `go test ./...` 就往同一个库里反复建 task/finding（task id 一路涨到三位数），
// 既污染开发数据，也让"两个包同时跑会互相 DELETE"只能靠一把 advisory lock 串行化。
//
// 现在的规则很简单：**测试永远不碰开发库**。进程启动时先在同一个 PG 实例里建一个
// 临时库 `artex_test_<pid>_<rand>`，把 ARTEX_PG_DSN 改写成它；包结束时把这个库 DROP
// 掉。schema 由 db.Open 照常 apply（schema.sql 是幂等的），所以隔离不影响任何行为。
//
// 调用方式（每个需要 PG 的测试包，在 TestMain 里一行）：
//
//	func TestMain(m *testing.M) { dbtest.Main(m) }
//
// 跳过条件照旧：没有 ARTEX_PG_DSN，或连不上 PG —— 需要 PG 的用例各自 skip。
package dbtest

import (
	"database/sql"
	"fmt"
	"math/rand"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// suiteLockKey 是跨包串行化用的 advisory lock。同一台 PG 上多个测试包并发时
// 各自有独立临时库，本来不会互相删数据；但共享同一个 PG 的其它资源（连接数、
// 系统目录）仍值得克制，且历史上有过 40P01 死锁，所以保留这把锁。
const suiteLockKey = 7337741002

// suiteDBEnv 记录本次进程建出来的临时库名（供诊断用）。
var (
	once     sync.Once
	suiteDB  string
	suiteAdm *sql.DB
	suiteErr error
)

// Main 是各包 TestMain 的便利入口：无 PG 配置/连不上 → 直接跑（用例自行 skip）；
// 否则建临时库、改写 ARTEX_PG_DSN、跑测试、DROP 库。
//
// 需要在用例之前做点事（比如自己建表）的包，用 Setup/RunOnly/Teardown 三段式：
//
//	dbtest.Setup()
//	ensureSchemaForTests()   // 此时 DSN 已指向隔离库
//	code := dbtest.RunOnly(m)
//	dbtest.Teardown()
//	os.Exit(code)
func Main(m *testing.M) { os.Exit(Run(m)) }

// Run 建库→跑测试→清库，返回退出码（不调用 os.Exit，便于 defer 收尾）。
func Run(m *testing.M) int {
	if !Setup() {
		return m.Run() // 没有可用 PG：原样跑，需要 DB 的用例各自 skip
	}
	code := m.Run()
	Teardown()
	return code
}

// Setup 建隔离库并把 ARTEX_PG_DSN 指过去。返回 false 表示没有可用 PG（保持原样）。
// 幂等：重复调用只做一次。
func Setup() bool {
	dsn := strings.TrimSpace(os.Getenv("ARTEX_PG_DSN"))
	if dsn == "" {
		return false
	}
	setup(dsn)
	return suiteErr == nil && suiteDB != ""
}

// RunOnly 只跑测试，不建/不清库 —— 配合 Setup/Teardown 使用。
func RunOnly(m *testing.M) int { return m.Run() }

// Teardown 删隔离库并解锁（未 Setup 时是空操作）。
func Teardown() { cleanup() }

// setup 建库并改写环境变量。只执行一次（同一进程内多个包不会共享进程，once 是防重复调用）。
func setup(dsn string) {
	once.Do(func() {
		u, err := url.Parse(dsn)
		if err != nil {
			suiteErr = err
			return
		}
		admURL := *u
		admURL.Path = "/postgres"
		adm, err := sql.Open("pgx", admURL.String())
		if err != nil {
			suiteErr = err
			return
		}
		if err := adm.Ping(); err != nil {
			adm.Close()
			suiteErr = err
			return
		}
		// 锁必须钉在一个连接上（session 级锁），所以独占一条 conn。
		if _, err := adm.Exec(`SELECT pg_advisory_lock($1)`, suiteLockKey); err != nil {
			adm.Close()
			suiteErr = err
			return
		}
		name := tempDBName(u)
		// 同名库理论上已被上次崩溃留下：先删再建（它一定是测试库，名字带 pid+随机段）。
		_, dropErr := adm.Exec(`DROP DATABASE IF EXISTS "` + name + `" WITH (FORCE)`)
		if dropErr != nil {
			// WITH (FORCE) 需要 PG13+；老版本回退到普通 DROP。
			_, err2 := adm.Exec(`DROP DATABASE IF EXISTS "` + name + `"`)
			if err2 != nil {
				_, _ = adm.Exec(`SELECT pg_advisory_unlock($1)`, suiteLockKey)
				adm.Close()
				suiteErr = err2
				return
			}
		}
		_, createErr := adm.Exec(`CREATE DATABASE "` + name + `"`)
		if createErr != nil {
			_, _ = adm.Exec(`SELECT pg_advisory_unlock($1)`, suiteLockKey)
			adm.Close()
			suiteErr = createErr
			return
		}
		testURL := *u
		testURL.Path = "/" + name
		os.Setenv("ARTEX_PG_DSN", testURL.String())
		suiteDB, suiteAdm = name, adm
		fmt.Fprintf(os.Stderr, "[dbtest] 隔离库 %s（原 DSN 的库不会被写入）\n", name)
	})
}

// tempDBName 生成 base_artex_test_<pid>_<rand> 形式的库名。
// 用原库名做前缀：一眼能看出是谁的临时库；限定 63 字符（PG 标识符上限）。
func tempDBName(u *url.URL) string {
	base := strings.TrimPrefix(u.Path, "/")
	base = sanitizeIdent(base)
	if base == "" {
		base = "artex"
	}
	name := fmt.Sprintf("%s_test_%d_%06d", truncIdent(base, 40), os.Getpid(), rand.Intn(1_000_000)) //nolint:gosec // 非安全用途
	return truncIdent(name, 63)
}

// sanitizeIdent 只保留 [a-z0-9_]，其余转 _（库名会进双引号，但仍保守处理）。
func sanitizeIdent(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return strings.Trim(b.String(), "_")
}

func truncIdent(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// cleanup 解锁并删库。删库失败只提示不 panic：测试结果已定，不该因为清理失败变成"失败"。
func cleanup() {
	if suiteAdm == nil || suiteDB == "" {
		return
	}
	if _, err := suiteAdm.Exec(`DROP DATABASE IF EXISTS "` + suiteDB + `" WITH (FORCE)`); err != nil {
		if _, err2 := suiteAdm.Exec(`DROP DATABASE IF EXISTS "` + suiteDB + `"`); err2 != nil {
			fmt.Fprintf(os.Stderr, "[dbtest] 清理隔离库 %s 失败（可手动 DROP）：%v\n", suiteDB, err2)
		}
	}
	_, _ = suiteAdm.Exec(`SELECT pg_advisory_unlock($1)`, suiteLockKey)
	_ = suiteAdm.Close()
}

// DSN 返回当前生效的 DSN（已指向隔离库）。需要自己开连接而不走 db.Open 的用例用它，
// 以免再去读一次可能已被改写的环境变量。
func DSN() (string, bool) {
	v := strings.TrimSpace(os.Getenv("ARTEX_PG_DSN"))
	return v, v != ""
}
