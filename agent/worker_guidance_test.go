package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

// 段 [B2] 的核心契约：装了什么工具才提什么纪律；没装 http_request 时绝不能出现
// "用 http_request"这种指向不存在工具的指令（模型会照做然后报错空转）。
func TestWorkerEvidenceBlockMatchesToolset(t *testing.T) {
	both := workerEvidenceBlock(true, true)
	if !strings.Contains(both, "http_request") || !strings.Contains(both, "traffic_search") {
		t.Fatalf("both tools present should mention both:\n%s", both)
	}
	onlyTraffic := workerEvidenceBlock(true, false)
	if strings.Contains(onlyTraffic, "http_request") {
		t.Fatal("must not advertise http_request when it isn't installed")
	}
	if !strings.Contains(onlyTraffic, "先查流量") {
		t.Fatal("traffic discipline missing")
	}
	if got := workerEvidenceBlock(false, false); got != "" {
		t.Fatalf("no tools → no block, got %q", got)
	}
	// 复现闭环这条无论如何都必须在（它与工具无关，是报告能否成立的前提）
	if !strings.Contains(both, "逐字") || !strings.Contains(onlyTraffic, "逐字") {
		t.Fatal("verbatim reproduction rule must always be present")
	}
}

func TestWorkerHasTools(t *testing.T) {
	fake := actool.Build(actool.Spec{
		Name: "http_request",
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
	})
	if !workerHasTools([]actool.CoreTool{fake}, "http_request") {
		t.Fatal("should detect http_request")
	}
	if workerHasTools([]actool.CoreTool{fake}, "nope") {
		t.Fatal("should not detect an absent tool")
	}
}
