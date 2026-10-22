package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"syscall"
	"time"
)

// Outbound requests whose target is chosen by a user, the model, or a remote
// server (custom HTTP tools, LLM endpoint probes, MCP discovery) used to go out
// on a bare http.Client: any of them could be pointed at the cloud metadata
// endpoint (169.254.169.254) or another link-local service on the host and have
// the response read back into an API reply. These helpers put the same
// dial-time guard on those paths that the notify package already uses for
// webhooks — the check runs when the connection is actually established, so DNS
// rebinding and redirects cannot step around it.
//
// Scope of the block is deliberately narrow: loopback and RFC1918 are ALLOWED.
// A local llama.cpp/Ollama endpoint on 127.0.0.1 and routing through the
// recording proxy on 127.0.0.1 are both ordinary configurations, and blocking
// them would break working installs to defend against a target the caller can
// already reach. Link-local (including 169.254.169.254), unspecified and
// multicast have no legitimate use here.
func blockLinkLocalDial(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("无法解析目标地址 %q", host)
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

// guardedDialer is the dialer every user-influenced outbound client should use.
func guardedDialer() *net.Dialer {
	return &net.Dialer{Timeout: 15 * time.Second, Control: blockLinkLocalDial}
}

// guardRedirects refuses redirects that leave the origin the caller named.
//
// The dial guard only sees addresses the client actually connects to. That is
// enough for a direct request — every redirect hop dials afresh — but not for a
// proxied one: when the proxy is an HTTP proxy the client CONNECTs to the proxy
// itself and the proxy resolves the hop target, so the guard inspects the proxy's
// address, never the destination. A user-set proxy is often a remote tunnel, and
// a hostile or merely open proxy can send the request anywhere, including the
// metadata endpoint.
//
// Pinning every hop to the first URL's host:port closes that: the proxy still
// sees the request, but it cannot be steered to a host the caller did not name.
// Same-origin redirects (a trailing-slash fix, a login bounce) still work. This
// mirrors the notify webhook client, which pins for the same reason (credentials
// in the URL).
func guardRedirects(maxHops int) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxHops {
			return fmt.Errorf("重定向次数过多（%d）", len(via))
		}
		if len(via) == 0 {
			return nil
		}
		origin, next := via[0].URL, req.URL
		if !sameOriginURL(origin, next) {
			return fmt.Errorf("拒绝跨主机重定向（%s → %s）", origin.Host, next.Host)
		}
		return nil
	}
}

// sameOriginURL compares scheme + host:port with the default ports filled in, so
// http://a/x → http://a:80/y counts as same-origin.
func sameOriginURL(a, b *url.URL) bool {
	if a == nil || b == nil || a.Scheme != b.Scheme {
		return false
	}
	return authority(a) == authority(b)
}

func authority(u *url.URL) string {
	host, port := u.Hostname(), u.Port()
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

// refuseLinkLocalTarget rejects a target whose host resolves to a link-local or
// unspecified address. It is the proxied-path counterpart to blockLinkLocalDial:
// with an HTTP proxy the client connects to the proxy, so the dial guard never
// sees the destination. Resolution happens here so a name pointing at
// 169.254.169.254 is refused too, not just the literal IP.
//
// The check is best-effort by nature — a proxy resolves the name again, so a
// DNS-rebinding answer could differ — but combined with guardRedirects (which
// pins the target to the host the caller named) it removes the direct path to
// the metadata endpoint, and it costs one lookup on a call that is about to make
// a network round trip anyway.
func refuseLinkLocalTarget(ctx context.Context, u *url.URL) error {
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("目标地址为空")
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return fmt.Errorf("无法解析目标地址 %q: %w", host, err)
	}
	for _, entry := range ips {
		ip := entry.IP
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}
		if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
			ip.IsInterfaceLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
			return fmt.Errorf("拒绝连接链路本地/未指定地址 %s（%s，可能是云元数据等敏感端点）", ip, host)
		}
	}
	return nil
}
