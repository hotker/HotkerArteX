package traffic

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	actool "github.com/Autumn-27/norma/tool"
)

// 端到端证据链：真实抓包（经记录代理）→ traffic_search 索引 → traffic_get 原文 →
// traffic_curl 可执行命令 → **命令真的能跑通**。这是"报告能否被复现"的地基，
// 所以整条链用真库、真代理、真执行，不打桩。
func TestEvidenceChainEndToEnd(t *testing.T) {
	// 目标：一个本地 echo 服务，返回可辨识的响应体。
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Echo", "yes")
		_, _ = w.Write([]byte("echo-body"))
	}))
	defer target.Close()

	// 记录代理必须监听一个【固定且空闲】的端口：ProxyAddr() 是
	// "http://127.0.0.1"+addr 的拼接，传 :0 会拼出 http://127.0.0.1:0（客户端连不上）。
	addr := freeLoopbackAddr(t)
	tr, err := Open(filepath.Join(t.TempDir(), "traffic"), addr)
	if err != nil {
		t.Fatalf("open traffic store: %v", err)
	}
	// 注意：go-mitmproxy 的 Start() 内部直接 Serve 并【阻塞】（不会自己返回），
	// 因此必须放到 goroutine 里跑 —— 在测试主协程里调用会挂死。
	go func() { _ = tr.Start() }()
	defer tr.Close()
	waitPort(t, addr)

	// 经记录代理发一条带 Cookie 与 JSON 正文的 POST。
	// ProxyAddr() 会返回 "http://127.0.0.1"+addr（addr 本身就带 127.0.0.1），
	// 传完整 host:port 时会拼成 127.0.0.1127.0.0.1。测试里直接拼出正确地址。
	pu, _ := url.Parse("http://" + addr)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}
	req, _ := http.NewRequest("POST", target.URL+"/api/v1/users?id=7", strings.NewReader(`{"role":"admin"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "sid=abc")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("send through proxy: %v", err)
	}
	resp.Body.Close()

	// 1) 索引：必须是轻量行（有 id/method/url/status，不含响应正文）
	// 抓包落库是异步的（sink 在响应完成后写索引），轮询到有记录为止。
	// 索引里的 host 是【去掉端口】的 hostname（record() 用 URL.Hostname()），
	// 而 traffic_search 是按 host 精确匹配 —— 所以这里也要用 hostname，不是 host:port。
	host := strings.TrimPrefix(target.URL, "http://")
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	var rows []map[string]any
	for i := 0; i < 100; i++ {
		if rows = evSearchRows(t, tr, host); len(rows) > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(rows) == 0 {
		t.Fatalf("recording produced no indexed exchange")
	}
	row := rows[0]
	id, _ := row["id"].(string)
	if id == "" {
		t.Fatalf("index row lacks id: %v", row)
	}
	for _, k := range []string{"method", "url", "status", "resp_len"} {
		if _, ok := row[k]; !ok {
			t.Fatalf("index row missing %q: %v", k, row)
		}
	}
	if _, leaked := row["resp"]; leaked {
		t.Fatal("traffic_search must never inline response bodies")
	}

	// 2) 原文：请求正文与 Cookie 都要能取回
	got := evCallStr(t, evToolByName(t, tr, "traffic_get"), map[string]any{"id": id})
	if !strings.Contains(got, "/api/v1/users?id=7") || !strings.Contains(got, `{"role":"admin"}`) {
		t.Fatalf("traffic_get lost the request body:\n%s", got)
	}

	// 3) 导出 curl：可执行、可复现
	cmd := evCallStr(t, evToolByName(t, tr, "traffic_curl"), map[string]any{"id": id, "https": false})
	t.Logf("导出的复现命令:\n%s", cmd)
	for _, want := range []string{"curl -i", "-X POST", "Cookie: sid=abc", `--data-binary '{"role":"admin"}'`,
		"'" + target.URL + "/api/v1/users?id=7'"} {
		if !strings.Contains(cmd, want) {
			t.Fatalf("curl export missing %q:\n%s", want, cmd)
		}
	}

	// 4) 命令真的能跑：执行它，检查服务端确实收到了（echo 响应体出现在输出里）。
	out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	if err != nil {
		t.Fatalf("exported command failed: %v\n%s\ncmd:\n%s", err, out, cmd)
	}
	if !strings.Contains(string(out), "echo-body") {
		t.Fatalf("exported command did not reproduce the request:\n%s", out)
	}
	if !strings.Contains(string(out), "X-Echo: yes") {
		t.Fatalf("response headers not shown (-i):\n%s", out)
	}
}

// freeLoopbackAddr 抢一个空闲的 127.0.0.1 端口（监听后立刻释放，交给记录代理用）。
func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("alloc port: %v", err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

// waitPort 等代理真正开始 accept（go-mitmproxy 的 Start 是异步的）。
func waitPort(t *testing.T, addr string) {
	t.Helper()
	for i := 0; i < 100; i++ {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("proxy never listened on %s", addr)
}

var evToolSeq atomic.Int64

func evToolByName(t *testing.T, tr *Traffic, name string) actool.CoreTool {
	t.Helper()
	evToolSeq.Add(1)
	for _, tool := range tr.Tools() {
		if tool.Name() == name {
			return tool
		}
	}
	t.Fatalf("tool %s not found", name)
	return nil
}

func evCallStr(t *testing.T, tool actool.CoreTool, args map[string]any) string {
	t.Helper()
	raw, _ := json.Marshal(args)
	res, err := tool.Call(context.Background(), raw, nil)
	if err != nil {
		t.Fatalf("%s call error: %v", tool.Name(), err)
	}
	if res.IsError {
		t.Fatalf("%s returned error: %s", tool.Name(), res.Flatten())
	}
	return res.Flatten()
}

func evSearchRows(t *testing.T, tr *Traffic, host string) []map[string]any {
	t.Helper()
	out := evCallStr(t, evToolByName(t, tr, "traffic_search"), map[string]any{"host": host})
	if strings.TrimSpace(out) == "无匹配流量。" {
		return nil
	}
	var rows []map[string]any
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		t.Fatalf("search output not JSON: %v\n%s", err, out)
	}
	return rows
}
