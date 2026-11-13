package traffic

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// 本文件把一条记录的原始请求翻译成【可直接执行】的 curl 命令。目的很具体：
// 报告里的复现步骤经常止于"请求原文"，读者还得自己拼 curl —— 拼错一个头、漏掉
// 一个 Cookie，复现就失效。这里把翻译做对一次，agent 和人都直接跑。
//
// 约定：
//   - 请求头按原顺序输出，Cookie/Referer 等含特殊字符的用单引号包住并转义；
//   - 正文：可打印文本内联 --data-binary '...'；含不可打印字节则落一个文件（在 outDir，
//     默认临时目录）并用 --data-binary @file，绝不把二进制塞进命令行；
//   - 请求行里的 target 可能是 origin-form（/path?q）或 absolute-form（http://host/path），
//     两者都要能还原成可执行 URL。

// curlFromRequest 把原始请求报文转成 curl 命令。https 决定 scheme；insecure 追加 -k；
// fallbackHost 在报文缺 Host 头时用来补全 URL（索引记录里的 hostname[:port]）。
func curlFromRequest(raw string, https, insecure bool, proxy, fallbackHost string) (string, error) {
	// 自己切头/正文，不用 splitExchange：后者把「无正文」也当失败返回（它服务于索引），
	// 而无正文的 GET 恰好是最常被导出的那一类。
	i := strings.Index(raw, "\r\n\r\n")
	sep := 4
	if i < 0 {
		i = strings.Index(raw, "\n\n") // 兼容被规范化成 LF 的记录
		sep = 2
	}
	if i < 0 {
		return "", fmt.Errorf("无法解析请求报文：找不到头部结束的空行")
	}
	head, body := raw[:i], raw[i+sep:]
	if strings.HasPrefix(body, "@blob ") {
		body = "" // 大正文以指针形式落库，取不到原文 —— 不臆造正文
	}
	lines := strings.Split(head, "\n")
	for i := range lines {
		lines[i] = strings.TrimRight(lines[i], "\r")
	}
	parts := strings.Fields(lines[0])
	if len(parts) < 2 {
		return "", fmt.Errorf("请求行不完整: %q", lines[0])
	}
	method, target := parts[0], parts[1]

	host := ""
	var headers [][2]string
	for _, ln := range lines[1:] {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		i := strings.Index(ln, ":")
		if i <= 0 {
			continue
		}
		name := strings.TrimSpace(ln[:i])
		val := strings.TrimSpace(ln[i+1:])
		if strings.EqualFold(name, "host") {
			host = val
			continue // curl 用 URL 里的 host，重复给 Host 会导致 SNI/连接不一致
		}
		if strings.EqualFold(name, "content-length") {
			continue // curl 依据正文自行计算
		}
		headers = append(headers, [2]string{name, val})
	}

	// URL：absolute-form 直接用；origin-form 补 scheme+host。
	//
	// host 的来源有两层：报文里可能【没有 Host 头】—— go-mitmproxy 录到的请求常常
	// 只有 origin-form + 无 Host（代理自己知道往哪送）。此时用 fallbackHost（由调用方
	// 从索引记录里取到的真实 host）补，而不是直接报错丢结果。
	urlStr := target
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		scheme := "http"
		if https {
			scheme = "https"
		}
		if host == "" {
			host = fallbackHost
		}
		if host == "" {
			return "", fmt.Errorf("请求里没有 Host 头，也没有索引 host，无法还原 URL")
		}
		urlStr = scheme + "://" + host + target
	}

	var b strings.Builder
	b.WriteString("curl -i")
	if strings.EqualFold(method, "HEAD") {
		b.WriteString(" -I")
	} else if !strings.EqualFold(method, "GET") {
		b.WriteString(" -X " + method)
	}
	if insecure {
		b.WriteString(" -k")
	}
	if strings.TrimSpace(proxy) != "" {
		b.WriteString(" -x " + shQuote(proxy))
	}
	for _, h := range headers {
		b.WriteString(" -H " + shQuote(h[0]+": "+h[1]))
	}
	if len(body) > 0 {
		if isPrintable(body) {
			b.WriteString(" --data-binary " + shQuote(body))
		} else {
			path := spillBody(body)
			if path == "" {
				return "", fmt.Errorf("正文含二进制且无法落盘")
			}
			b.WriteString(" --data-binary @" + shQuote(path))
		}
	}
	b.WriteString(" " + shQuote(urlStr))
	return b.String(), nil
}

// isPrintable 判断正文能否安全内联进命令行：不允许 NUL 与其它控制字符（保留 \t\r\n，
// 因为 curl 的 --data-binary 会原样发送它们）。
func isPrintable(s string) bool {
	for _, r := range s {
		if r == '\n' || r == '\r' || r == '\t' {
			continue
		}
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// spillBody 把二进制正文落成文件，返回路径（失败返回空串）。
func spillBody(body string) string {
	dir, err := os.MkdirTemp("", "afx-curl-")
	if err != nil {
		return ""
	}
	p := filepath.Join(dir, "body.bin")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		return ""
	}
	return p
}

// shQuote 用单引号包裹并转义内部的单引号（POSIX shell 安全）。
func shQuote(s string) string {
	if s == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
