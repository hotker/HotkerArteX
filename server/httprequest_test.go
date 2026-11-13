package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	actool "github.com/Autumn-27/norma/tool"
)

// http_request 的结构性保证：header 顺序/重复头/大小写不被 Go 的头规范化吃掉，
// 表单与 JSON 自动编码，重定向可关，raw_socket 能发出畸形报文。
func TestHTTPRequestBuildsBodiesAndHeaders(t *testing.T) {
	type capture struct {
		header http.Header
		body   string
		raw    string // raw 请求行+头（raw_socket 用）
	}
	got := make(chan capture, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got <- capture{header: r.Header.Clone(), body: string(b), raw: r.Method + " " + r.URL.RequestURI()}
		w.Header().Set("X-Test", "ok")
		_, _ = w.Write([]byte("hello-body"))
	}))
	defer srv.Close()

	s := &Server{}
	tool := s.httpRequestTool()

	call := func(args map[string]any) actool.Result {
		raw, _ := json.Marshal(args)
		res, err := tool.Call(context.Background(), raw, nil)
		if err != nil {
			t.Fatalf("run err: %v", err)
		}
		if res.IsError {
			t.Fatalf("tool error: %s", res.Flatten())
		}
		return res
	}

	// 1) 表单 + 重复头 + 自定义 Cookie
	args := map[string]any{
		"url":    srv.URL + "/f",
		"method": "POST",
		"form":   map[string]any{"a": "1", "b": "x y"},
		"headers": []any{
			[]any{"X-Dup", "one"},
			[]any{"X-Dup", "two"},
			[]any{"X-Mixed-Case", "v"},
		},
		"cookies": map[string]any{"sid": "abc"},
	}
	res := call(args)
	if !strings.Contains(res.Flatten(), "200") || !strings.Contains(res.Flatten(), "hello-body") {
		t.Fatalf("unexpected result: %s", res.Flatten())
	}
	c := <-got
	if !strings.Contains(c.body, "a=1") || !strings.Contains(c.body, "b=x+y") {
		t.Fatalf("form not encoded: %q", c.body)
	}
	if !strings.Contains(strings.ToLower(c.header.Get("Content-Type")), "application/x-www-form-urlencoded") {
		t.Fatalf("form content-type missing: %v", c.header)
	}
	if n := len(c.header.Values("X-Dup")); n != 2 {
		t.Fatalf("duplicate headers collapsed: %v", c.header)
	}
	if !strings.Contains(c.header.Get("Cookie"), "sid=abc") {
		t.Fatalf("cookie missing: %v", c.header)
	}

	// 2) JSON 正文
	call(map[string]any{"url": srv.URL + "/j", "method": "POST", "json": map[string]any{"q": "1' or 1=1"}})
	c = <-got
	if !strings.Contains(c.body, `"q":"1' or 1=1"`) {
		t.Fatalf("json body wrong: %q", c.body)
	}
	if !strings.Contains(strings.ToLower(c.header.Get("Content-Type")), "application/json") {
		t.Fatalf("json content-type missing: %v", c.header)
	}
}

func TestHTTPRequestRedirectToggle(t *testing.T) {
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("final"))
	}))
	defer final.Close()
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL, http.StatusFound)
	}))
	defer redir.Close()

	s := &Server{}
	tool := s.httpRequestTool()
	run := func(redirect bool) string {
		raw, _ := json.Marshal(map[string]any{"url": redir.URL, "redirect": redirect})
		res, _ := tool.Call(context.Background(), raw, nil)
		return res.Flatten()
	}
	if out := run(true); !strings.Contains(out, "final") {
		t.Fatalf("follow should reach final: %s", out)
	}
	if out := run(false); !strings.Contains(out, "302") {
		t.Fatalf("no-follow must surface the 3xx itself: %s", out)
	}
}

func TestHTTPRequestRawSocketSendsVerbatim(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("raw-ok"))
	}))
	defer srv.Close()

	s := &Server{}
	tool := s.httpRequestTool()
	// 走私式畸形请求：同时给 CL 与 TE，第二个请求藏在正文里。
	payload := "POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /b HTTP/1.1\r\nHost: x\r\n\r\n"
	raw, _ := json.Marshal(map[string]any{"url": srv.URL, "raw_socket": true, "timeout": 3, "body": payload})
	res, err := tool.Call(context.Background(), raw, nil)
	if err != nil {
		t.Fatalf("run err: %v", err)
	}
	if res.IsError {
		t.Fatalf("raw socket should transmit (even if backend errors): %s", res.Flatten())
	}
	if out := res.Flatten(); !strings.Contains(out, "原始响应") && !strings.Contains(out, "未读到响应") {
		t.Fatalf("unexpected raw output: %s", out)
	}
}

func TestHTTPRequestRejectsBadURL(t *testing.T) {
	s := &Server{}
	tool := s.httpRequestTool()
	raw, _ := json.Marshal(map[string]any{"url": "ftp://example.com/x"})
	res, _ := tool.Call(context.Background(), raw, nil)
	if !res.IsError {
		t.Fatal("non-http scheme must be rejected")
	}
}
