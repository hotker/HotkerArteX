package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

// 本文件是 HotkerArteX 新增的平台武器库工具：http_request。
//
// 为什么需要它：agent 目前用 Bash+curl 打目标，但发包细节（编码、重定向、证书、
// 超时）全在模型手里，同一类探测在不同 worker 里写法各异，复现链常断在"这条请求
// 到底怎么发的"。http_request 把发包变成结构化调用：
//   - 默认走记录代理（MITM），每一条都自动落进流量库 → 证据链、复现步骤直接可用；
//   - 参数显式（method/url/headers/body/form/json/cookies/redirect/timeout/raw_socket），
//     头顺序与大小写由调用方控制 —— 走私/绕过类手法需要这个能力；
//   - 返回状态码、关键响应头、正文与耗时，并提示取证路径。
//
// 它不替代 Bash：判断链式操作（nc、多步管道、写脚本）仍走 Bash；http_request 负责
// 「一次请求、留下证据」这类高频动作。

const (
	httpReqDefaultTimeout = 30 * time.Second
	httpReqMaxTimeout     = 120 * time.Second
	httpReqBodyCap        = 20000 // 返回给模型的正文上限（更长的进流量库，用 traffic_blob/get 取）
)

func (s *Server) httpRequestTool() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "http_request",
		Description: "结构化发一次 HTTP 请求，默认经记录代理发出（自动落流量库，供 traffic_search/traffic_get 复查与报告取证）。" +
			"比 curl 更好控制：header 可精确指定大小写与顺序、重复头（走私/TE 类手法需要）、表单/JSON 自动编码、不发多余重试。" +
			"返回状态码、关键响应头、正文（超 20000 字符截断，全文在流量库）、耗时。",
		Prompt: "参数说明：\n" +
			"- url：完整 URL，必须 http:// 或 https:// 开头（可含 query）。\n" +
			"- method：默认 GET。\n" +
			"- headers：键值对数组，**按给定顺序**发送；同名头可重复（如两个 Transfer-Encoding）。\n" +
			"- body：原始正文字符串；form：键值对象（自动 application/x-www-form-urlencoded）；json：任意对象。三者只选一个。\n" +
			"- raw_socket：为 true 时不走标准库，直接把 body 原文按字节发到 host:port（用于构造畸形请求行/头、CL 与 TE 冲突、" +
			"半截请求等），此时 url 只用来取 host:port 与 https 判定。**注意 raw_socket 直连目标、不落流量库**。\n" +
			"- cookies：键值对象，自动拼 Cookie 头。\n" +
			"- redirect：默认跟随（false = 只看第一跳，重定向类漏洞必须 false）。\n" +
			"- timeout：秒，默认 30，上限 120。\n" +
			"- 重要证据请立刻用 traffic_search 定位那条流量（返回里带提示），别重复发包。",
		Schema: objSchema(map[string]any{
			"url":        strParam("完整 URL（http/https 开头）"),
			"method":     strParam("HTTP 方法，默认 GET"),
			"headers":    map[string]any{"type": "array", "description": "请求头，按顺序发送：[[\"Name\",\"value\"], ...]", "items": map[string]any{"type": "array", "items": map[string]any{"type": "string"}}},
			"body":       strParam("原始正文字符串（与 form/json 互斥）"),
			"form":       map[string]any{"type": "object", "description": "表单字段（与 body/json 互斥）"},
			"json":       map[string]any{"type": "object", "description": "JSON 正文对象（与 body/form 互斥）"},
			"cookies":    map[string]any{"type": "object", "description": "Cookie 键值（自动拼 Cookie 头）"},
			"redirect":   map[string]any{"type": "boolean", "description": "是否跟随重定向，默认 true"},
			"raw_socket": map[string]any{"type": "boolean", "description": "按字节发送原始请求（走私/畸形报文），默认 false"},
			"timeout":    map[string]any{"type": "integer", "description": "超时秒数，默认 30，上限 120"},
		}, "url"),
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			return s.runHTTPRequest(ctx, in)
		},
	})
}

type httpReqArgs struct {
	URL       string         `json:"url"`
	Method    string         `json:"method"`
	Headers   [][]string     `json:"headers"`
	Body      string         `json:"body"`
	Form      map[string]any `json:"form"`
	JSONBody  map[string]any `json:"json"`
	Cookies   map[string]any `json:"cookies"`
	Redirect  *bool          `json:"redirect"`
	RawSocket bool           `json:"raw_socket"`
	Timeout   int            `json:"timeout"`
}

func (s *Server) runHTTPRequest(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
	var a httpReqArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return actool.Errorf("参数解析失败: " + err.Error()), nil
	}
	if strings.TrimSpace(a.URL) == "" {
		return actool.Errorf("url 为必填"), nil
	}
	u, err := url.Parse(a.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return actool.Errorf("url 必须是完整的 http:// 或 https:// 地址: " + a.URL), nil
	}
	timeout := time.Duration(a.Timeout) * time.Second
	if timeout <= 0 {
		timeout = httpReqDefaultTimeout
	}
	if timeout > httpReqMaxTimeout {
		timeout = httpReqMaxTimeout
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	bodyBytes, ctype, err := buildRequestBody(&a)
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}

	if a.RawSocket {
		return s.rawSocketExchange(u, bodyBytes, timeout)
	}

	method := strings.ToUpper(strings.TrimSpace(a.Method))
	if method == "" {
		method = "GET"
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(bodyBytes))
	if err != nil {
		return actool.Errorf("构造请求失败: " + err.Error()), nil
	}
	// 头顺序/大小写由调用方决定：先按序写入显式 header，再补默认值（缺省才补）。
	hasCT := false
	for _, kv := range a.Headers {
		if len(kv) == 0 {
			continue
		}
		name := kv[0]
		val := ""
		if len(kv) > 1 {
			val = kv[1]
		}
		req.Header[name] = append(req.Header[name], val) // 保留大小写与重复头
		if strings.EqualFold(name, "Content-Type") {
			hasCT = true
		}
	}
	if len(a.Cookies) > 0 {
		req.Header.Set("Cookie", cookieHeader(a.Cookies))
	}
	if ctype != "" && !hasCT {
		req.Header.Set("Content-Type", ctype)
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "HotkerArteX/http_request")
	}

	client := s.httpReqClient(a.Redirect)
	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		hint := ""
		var ue *url.Error
		if errors.As(err, &ue) {
			hint = "（URL/连接层错误：" + ue.Err.Error() + "）"
		}
		return actool.Errorf(fmt.Sprintf("请求失败（%s）：%v%s\n检查：目标是否可达、是否需要正确的 Host、是否被前置代理拦掉。", elapsed.Round(time.Millisecond), err, hint)), nil
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	return httpReqResult(resp, respBody, elapsed), nil
}

// buildRequestBody 统一正文与 Content-Type 的构造（body 原样优先）。
func buildRequestBody(a *httpReqArgs) ([]byte, string, error) {
	switch {
	case a.Body != "":
		return []byte(a.Body), "", nil
	case len(a.JSONBody) > 0:
		b, err := json.Marshal(a.JSONBody)
		if err != nil {
			return nil, "", fmt.Errorf("json 序列化失败: %v", err)
		}
		return b, "application/json", nil
	case len(a.Form) > 0:
		vals := url.Values{}
		for k, v := range a.Form {
			vals.Set(k, stringifyAny(v))
		}
		return []byte(vals.Encode()), "application/x-www-form-urlencoded", nil
	}
	return nil, "", nil
}

// stringifyAny 把 JSON 里的标量转成表单值（数组用逗号拼，模拟常见多值提交）。
func stringifyAny(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		if t == float64(int64(t)) {
			return fmt.Sprintf("%d", int64(t))
		}
		return fmt.Sprintf("%v", t)
	case bool:
		return fmt.Sprintf("%v", t)
	case nil:
		return ""
	case []any:
		parts := make([]string, 0, len(t))
		for _, e := range t {
			parts = append(parts, stringifyAny(e))
		}
		return strings.Join(parts, ",")
	default:
		b, _ := json.Marshal(t)
		return string(b)
	}
}

func cookieHeader(c map[string]any) string {
	keys := make([]string, 0, len(c))
	for k := range c {
		keys = append(keys, k)
	}
	sort.Strings(keys) // 稳定输出，便于复现对比
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+stringifyAny(c[k]))
	}
	return strings.Join(parts, "; ")
}

// httpReqClient 构造带记录代理与 TLS 设置的客户端。redirect=false 时只走第一跳。
func (s *Server) httpReqClient(redirect *bool) *http.Client {
	tr := &http.Transport{
		// 渗透目标常年是自签/过期证书：这里关校验是刻意选择 —— 记录代理本身也会重签
		// 证书，目标证书链不可信时仍要把请求打出去并落库。
		TLSClientConfig:        &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:           16,
		IdleConnTimeout:        30 * time.Second,
		ForceAttemptHTTP2:      false, // 走私/降级类需要 h1 语义
		ExpectContinueTimeout:  time.Second,
		ResponseHeaderTimeout: 0,
	}
	if s != nil && s.m != nil {
		if addr := s.m.ProxyAddr(); addr != "" {
			if pu, err := url.Parse(addr); err == nil {
				tr.Proxy = http.ProxyURL(pu)
			}
		}
	}
	c := &http.Client{Transport: tr}
	if redirect == nil || *redirect {
		c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		}
	} else {
		c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	return c
}

// httpReqResult 把响应压成给模型看的一小块：状态、关键头、正文、耗时与取证提示。
func httpReqResult(resp *http.Response, body []byte, elapsed time.Duration) actool.Result {
	interesting := []string{
		"content-type", "content-length", "location", "set-cookie", "server",
		"x-powered-by", "www-authenticate", "allow", "access-control-allow-origin",
		"access-control-allow-credentials", "x-frame-options", "content-security-policy",
		"cache-control", "age", "x-cache", "via", "cf-ray", "vary",
	}
	var hdrs []string
	for _, k := range interesting {
		if vs, ok := resp.Header[http.CanonicalHeaderKey(k)]; ok && len(vs) > 0 {
			for _, v := range vs {
				hdrs = append(hdrs, k+": "+v)
			}
		}
	}
	txt := string(body)
	truncated := false
	if len(txt) > httpReqBodyCap {
		txt = txt[:httpReqBodyCap]
		truncated = true
	}
	var b strings.Builder
	note := ""
	if truncated {
		note = ", 已截断"
	}
	fmt.Fprintf(&b, "HTTP %d %s  (%s, %d bytes%s)\n", resp.StatusCode, http.StatusText(resp.StatusCode),
		elapsed.Round(time.Millisecond), len(body), note)
	if len(hdrs) > 0 {
		b.WriteString("--- 关键响应头 ---\n" + strings.Join(hdrs, "\n") + "\n")
	}
	b.WriteString("--- 响应正文 ---\n" + txt + "\n")
	if truncated {
		b.WriteString("\n（正文已截断，完整内容在流量库：用 traffic_search(host=...) 找这条 URL，再 traffic_get 取全文）\n")
	}
	b.WriteString("\n取证提示：本次请求已经记录代理落库。汇报漏洞时用 traffic_search 取该条 id，" +
		"把它写进 report_finding 的复现步骤 exchange_id —— 报告里的复现步骤会自动关联到真实报文；" +
		"需要可直接执行的命令时用 traffic_curl(id)。")
	return actool.Text(b.String())
}

// rawSocketExchange 在 host:port 上原样发送请求字节。用于标准库够不着的场景：
// CL/TE 冲突、请求行变形、半截请求（走私探测）、非 HTTP 方法的怪异 token。
// body 字段即【整段请求报文】（含请求行与空行）；url 只用于定位 host:port 与 TLS。
func (s *Server) rawSocketExchange(u *url.URL, payload []byte, timeout time.Duration) (actool.Result, error) {
	if len(payload) == 0 {
		return actool.Errorf("raw_socket 模式需要把完整请求报文写进 body（含请求行、头、空行、正文）"), nil
	}
	hostport := u.Host
	if u.Port() == "" {
		if u.Scheme == "https" {
			hostport += ":443"
		} else {
			hostport += ":80"
		}
	}
	notice := ""
	if s != nil && s.m != nil && s.m.ProxyAddr() != "" {
		notice = "\n注意：raw_socket 走【直连】不走记录代理，本次报文没有落流量库；复现证据请把这段原始报文本身存进 finding 的复现步骤。"
	}

	start := time.Now()
	conn, err := dialTarget(u.Scheme, hostport, timeout)
	if err != nil {
		return actool.Errorf("建立连接失败: " + err.Error()), nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(payload); err != nil {
		return actool.Errorf("发送失败: " + err.Error()), nil
	}
	respBytes, _ := io.ReadAll(io.LimitReader(conn, 2<<20))
	elapsed := time.Since(start)
	if len(respBytes) == 0 {
		return actool.Text(fmt.Sprintf("原始请求已发出，%s 内未读到响应（超时或后端在等待更多数据 —— 这在走私探测里是预期结果）。\npayload 摘要(base64): %s%s",
			elapsed.Round(time.Millisecond), base64.StdEncoding.EncodeToString(payload[:min(len(payload), 400)]), notice)), nil
	}
	txt := strings.ReplaceAll(string(respBytes), "\r\n", "\n")
	if len(txt) > httpReqBodyCap {
		txt = txt[:httpReqBodyCap] + "\n（已截断）"
	}
	return actool.Text(fmt.Sprintf("--- 原始响应（%s，%d 字节）---\n%s%s", elapsed.Round(time.Millisecond), len(respBytes), txt, notice)), nil
}

// dialTarget 建连并完成 TLS 握手（https 时跳过证书校验，理由见 httpReqClient）。
func dialTarget(scheme, hostport string, timeout time.Duration) (net.Conn, error) {
	d := &net.Dialer{Timeout: timeout}
	if scheme == "https" {
		return tls.DialWithDialer(d, "tcp", hostport, &tls.Config{InsecureSkipVerify: true, ServerName: hostOnly(hostport)})
	}
	return d.Dial("tcp", hostport)
}

// hostOnly 去掉 :port（TLS SNI 用）。
func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}
