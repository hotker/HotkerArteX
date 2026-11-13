package traffic

import (
	"strings"
	"testing"
)

// rawRequest 造一个与流量库同形的记录（请求头 CRLF、末段空行）。
func rawRequest(lines ...string) string {
	return strings.Join(lines, "\r\n") + "\r\n\r\n"
}

func TestCurlFromRequestOriginForm(t *testing.T) {
	raw := rawRequest(
		"POST /api/login HTTP/1.1",
		"Host: target.local:8443",
		"User-Agent: Mozilla/5.0",
		"Content-Type: application/x-www-form-urlencoded",
		"Content-Length: 21",
		"Cookie: sid=abc; role=user",
	) + "user=admin&pass=x"
	cmd, err := curlFromRequest(raw, false, true, "", "")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	for _, want := range []string{
		"curl -i -X POST -k",
		"-H 'User-Agent: Mozilla/5.0'",
		"-H 'Cookie: sid=abc; role=user'",
		"--data-binary 'user=admin&pass=x'",
		"'http://target.local:8443/api/login'",
	} {
		if !strings.Contains(cmd, want) {
			t.Fatalf("missing %q in:\n%s", want, cmd)
		}
	}
	// Host 头不能重复出现（curl 自行从 URL 推导）
	if strings.Contains(cmd, "-H 'Host:") {
		t.Fatalf("Host header must not be duplicated:\n%s", cmd)
	}
}

func TestCurlFromRequestAbsoluteFormAndHTTPS(t *testing.T) {
	raw := rawRequest("GET https://api.target/x?q=1 HTTP/1.1", "Host: api.target")
	cmd, err := curlFromRequest(raw, true, false, "http://127.0.0.1:8080", "")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !strings.Contains(cmd, "'https://api.target/x?q=1'") {
		t.Fatalf("absolute URL must be preserved:\n%s", cmd)
	}
	if strings.Contains(cmd, "-X GET") || strings.Contains(cmd, " -k") {
		t.Fatalf("GET without -X / no -k expected:\n%s", cmd)
	}
	if !strings.Contains(cmd, "-x 'http://127.0.0.1:8080'") {
		t.Fatalf("proxy flag missing:\n%s", cmd)
	}
}

func TestCurlFromRequestQuotesSingleQuote(t *testing.T) {
	raw := rawRequest("GET /search?q=it's HTTP/1.1", "Host: h", "X-Note: a'b")
	cmd, err := curlFromRequest(raw, true, true, "", "")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !strings.Contains(cmd, `'\''`) {
		t.Fatalf("single quote must be escaped for POSIX shells:\n%s", cmd)
	}
}

func TestCurlFromRequestBinaryBodySpillsToFile(t *testing.T) {
	raw := rawRequest("POST /up HTTP/1.1", "Host: h", "Content-Type: application/octet-stream") + "\x00\x01\x02binary"
	cmd, err := curlFromRequest(raw, true, true, "", "")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !strings.Contains(cmd, "--data-binary @") {
		t.Fatalf("binary body must be spilled to a file, got:\n%s", cmd)
	}
	if strings.Contains(cmd, "\x00") {
		t.Fatal("binary must never be inlined into the command")
	}
}

func TestCurlFromRequestNoHostFails(t *testing.T) {
	raw := rawRequest("GET /x HTTP/1.1", "Accept: */*")
	if _, err := curlFromRequest(raw, true, true, "", ""); err == nil {
		t.Fatal("origin-form without Host cannot be turned into a URL")
	}
}

// 真实抓包常常只有 origin-form、没有 Host 头（go-mitmproxy 自己知道往哪送）。
// 这时必须用索引里的 host 兜底，而不是报错丢结果。
func TestCurlFromRequestFallsBackToIndexHost(t *testing.T) {
	raw := rawRequest("POST /api/v1/users?id=7 HTTP/1.1", "Cookie: sid=abc") + `{"role":"admin"}`
	cmd, err := curlFromRequest(raw, false, true, "", "127.0.0.1:18080")
	if err != nil {
		t.Fatalf("fallback host should rescue a Host-less request: %v", err)
	}
	if !strings.Contains(cmd, "'http://127.0.0.1:18080/api/v1/users?id=7'") {
		t.Fatalf("fallback host not used:\n%s", cmd)
	}
}
