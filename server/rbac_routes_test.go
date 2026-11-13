package server

import (
	"go/ast"
	"io/fs"
	"go/parser"
	"go/token"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// 路由 → 权限映射必须覆盖所有已注册的 /api 路由。
//
// 这条测试存在的理由：permissionForRequest 按前缀匹配，一旦新增某个顶层模块却忘了映射，
// 它会静默返回 ""（放行）—— 也就是"少防一处"，而这类漏洞在代码评审里几乎看不见。
// 用测试把"未映射"变成红灯，比靠人记住可靠。
//
// 路由清单直接从源码 AST 里读 `mux.HandleFunc("METHOD /path", ...)`：http.ServeMux 不暴露
// 已注册模式，而维护一份手抄清单必然与 mux 脱节 —— 那正是这条测试要防的事。
func TestEveryAPIRouteMapsToAPermission(t *testing.T) {
	routes := registeredAPIRoutes(t)
	if len(routes) < 100 {
		t.Fatalf("only %d routes discovered — AST scan likely broke", len(routes))
	}
	var unmapped []string
	for _, spec := range routes {
		method, path, ok := strings.Cut(spec, " ")
		if !ok {
			continue
		}
		if strings.HasPrefix(path, "/api/auth/") || path == "/api/health" {
			continue // 鉴权前路径，不需要权限
		}
		if permissionForRequest(method, concretePath(path)) == "" {
			unmapped = append(unmapped, spec)
		}
	}
	sort.Strings(unmapped)
	if len(unmapped) > 0 {
		t.Fatalf("%d 条路由未映射到权限（等于放行）：\n  %s", len(unmapped), strings.Join(unmapped, "\n  "))
	}
}

// admin 必须持有目录里的每一项权限；否则新增模块后管理员会莫名其妙 403。
func TestAdminHoldsEveryCatalogPermission(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	acc, err := s.m.pg.ResolveRBACAccess("admin")
	if err != nil || acc == nil {
		t.Fatalf("resolve admin: %v", err)
	}
	for key := range db.RBACPermissions {
		if !acc.HasPermission(key) {
			t.Fatalf("admin missing permission %q", key)
		}
	}
}

// registeredAPIRoutes 扫 server 包的源码，抽出所有 mux.HandleFunc("METHOD /path", …)。
func registeredAPIRoutes(t *testing.T) []string {
	t.Helper()
	pkgs, err := parser.ParseDir(token.NewFileSet(), ".", func(fi fs.FileInfo) bool {
		return strings.HasSuffix(fi.Name(), ".go") && !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parse server package: %v", err)
	}
	seen := map[string]bool{}
	for _, pkg := range pkgs {
		for _, f := range pkg.Files {
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) == 0 {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "HandleFunc" {
					return true
				}
				lit, ok := call.Args[0].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				v, err := strconv.Unquote(lit.Value)
				if err != nil || !strings.Contains(v, "/api/") {
					return true
				}
				seen[v] = true
				return true
			})
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// concretePath 把 {id} 这类路径参数换成具体值，让前缀匹配走真实分支。
func concretePath(p string) string {
	parts := strings.Split(p, "/")
	for i, seg := range parts {
		if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") {
			parts[i] = "1"
		}
	}
	return strings.Join(parts, "/")
}
