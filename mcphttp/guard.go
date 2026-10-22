package mcphttp

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"syscall"
	"time"
)

// MCP servers are configured from the UI (and, via tools, from model output), and
// every request through them carries the configured headers — often an
// Authorization token. That makes the transport an outbound path an attacker can
// choose, so it gets the same dial-time guard as the notify webhooks: the check
// runs when the connection is established, so a redirect or DNS rebinding cannot
// step around it.
//
// Loopback and RFC1918 stay allowed: an MCP server on the operator's own machine
// or LAN is a normal setup. Link-local (including the cloud metadata address
// 169.254.169.254), unspecified and multicast have no legitimate use here.
func blockLinkLocalDial(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("无法解析 MCP 服务器地址 %q", host)
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return fmt.Errorf("拒绝连接链路本地/未指定地址 %s（可能是云元数据等敏感端点）", ip)
	}
	return nil
}

// newHTTPClient builds the client for one MCP server. insecure keeps its
// documented meaning (skip certificate verification for a self-signed server),
// but the dial guard applies either way.
func newHTTPClient(timeout time.Duration, insecure bool) *http.Client {
	tr := &http.Transport{
		DialContext: (&net.Dialer{Timeout: 30 * time.Second, Control: blockLinkLocalDial}).DialContext,
	}
	if insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &http.Client{Timeout: timeout, Transport: tr}
}

// sameOrigin reports whether candidate points at the same scheme/host/port as
// base. A legacy SSE server announces its POST endpoint in a data: line; without
// this check a hostile or compromised server could name an endpoint on another
// host and receive every subsequent request — including the configured
// Authorization header.
func sameOrigin(base, candidate string) bool {
	b, err := url.Parse(base)
	if err != nil {
		return false
	}
	c, err := url.Parse(candidate)
	if err != nil {
		return false
	}
	return b.Scheme == c.Scheme && sameHostPort(b) == sameHostPort(c)
}

func sameHostPort(u *url.URL) string {
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "https":
			port = "443"
		case "http":
			port = "80"
		}
	}
	return net.JoinHostPort(host, port)
}
