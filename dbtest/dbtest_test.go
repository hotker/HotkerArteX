package dbtest

import (
	"net/url"
	"strings"
	"testing"
)

// 隔离的关键是不变量：测试库名与开发库名永远不同，且落在一个安全的名字空间里。
// 这些是纯函数，不需要 PG 就能测。
func TestTempDBNameIsolatedAndSafe(t *testing.T) {
	u, _ := url.Parse("postgres://u:p@127.0.0.1:5432/artex_prod?sslmode=disable")
	name := tempDBName(u)

	if name == "artex_prod" {
		t.Fatal("test DB must never be the dev DB")
	}
	if !strings.HasPrefix(name, "artex_prod_test_") {
		t.Fatalf("name should carry the base as a prefix for traceability: %q", name)
	}
	if len(name) > 63 {
		t.Fatalf("identifier exceeds PostgreSQL's 63-byte limit: %d", len(name))
	}
	for _, r := range name {
		if !(r == '_' || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')) {
			t.Fatalf("unsafe identifier character %q in %q", r, name)
		}
	}
	// 两次调用必须不同（含 pid 与随机段），否则并发/重跑会撞库
	if again := tempDBName(u); again == name {
		t.Fatal("generated name should include randomness")
	}
}

// 库名带奇怪字符（大小写、连字符、中文）也要收敛成合法标识符。
func TestTempDBNameSanitizes(t *testing.T) {
	cases := []string{
		"postgres://h/My-DB", "postgres://h/库", "postgres://h/", "postgres://h/a.b-c",
	}
	for _, dsn := range cases {
		u, err := url.Parse(dsn)
		if err != nil {
			t.Fatalf("%s: %v", dsn, err)
		}
		name := tempDBName(u)
		if len(name) > 63 || len(name) == 0 {
			t.Fatalf("%s → %q (bad length)", dsn, name)
		}
		for _, r := range name {
			if !(r == '_' || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')) {
				t.Fatalf("%s → %q (unsafe %q)", dsn, name, r)
			}
		}
	}
}
