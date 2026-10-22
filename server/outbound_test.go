package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestGuardRedirectsAllowsSameOrigin(t *testing.T) {
	guard := guardRedirects(5)
	first := &http.Request{URL: mustURL(t, "https://api.example.com/v1/models")}
	next := &http.Request{URL: mustURL(t, "https://api.example.com/v1/models/")}
	if err := guard(next, []*http.Request{first}); err != nil {
		t.Fatalf("same-origin redirect refused: %v", err)
	}
	// Default port equivalence.
	httpFirst := &http.Request{URL: mustURL(t, "http://api.example.com/x")}
	httpNext := &http.Request{URL: mustURL(t, "http://api.example.com:80/y")}
	if err := guard(httpNext, []*http.Request{httpFirst}); err != nil {
		t.Fatalf("default-port redirect refused: %v", err)
	}
}

func TestGuardRedirectsRefusesCrossHost(t *testing.T) {
	guard := guardRedirects(5)
	first := &http.Request{URL: mustURL(t, "https://api.example.com/v1/models")}
	// The classic metadata pivot: a caller-chosen proxy answers with a redirect to
	// the link-local endpoint, which the dial guard never inspects.
	for _, target := range []string{
		"http://169.254.169.254/latest/meta-data/",
		"https://evil.example.net/collect",
		"https://api.example.com:8443/v1/models",
		"http://api.example.com/v1/models", // scheme downgrade
	} {
		next := &http.Request{URL: mustURL(t, target)}
		if err := guard(next, []*http.Request{first}); err == nil {
			t.Fatalf("cross-origin redirect to %s was allowed", target)
		}
	}
}

func TestGuardRedirectsCapsHops(t *testing.T) {
	guard := guardRedirects(2)
	u := mustURL(t, "https://api.example.com/")
	via := []*http.Request{{URL: u}, {URL: u}}
	if err := guard(&http.Request{URL: u}, via); err == nil {
		t.Fatal("hop cap not enforced")
	}
}

func TestRefuseLinkLocalTargetBlocksMetadata(t *testing.T) {
	// 169.254.169.254 is a literal, so this needs no DNS.
	u := mustURL(t, "http://169.254.169.254/latest/meta-data/")
	if err := refuseLinkLocalTarget(context.Background(), u); err == nil {
		t.Fatal("link-local target accepted")
	}
	u = mustURL(t, "http://[::1]:8080/x")
	// ::1 is loopback, which the dial guard deliberately allows; the proxy-path
	// check must agree or a working local proxy setup would break.
	if err := refuseLinkLocalTarget(context.Background(), u); err != nil {
		t.Fatalf("loopback target refused: %v", err)
	}
}

func TestProviderErrorSummaryDoesNotEchoRawBody(t *testing.T) {
	// A caller-chosen base_url can answer with an arbitrary page. Only recognized
	// error fields may come back; the rest must be summarized, never echoed.
	raw := []byte(`<html><body>internal admin console: /etc/passwd contents...</body></html>`)
	if got := providerErrorSummary(raw); strings.Contains(got, "admin console") {
		t.Fatalf("raw body echoed back: %q", got)
	}
	if got := providerErrorSummary([]byte(`{"error":{"message":"invalid api key","code":"invalid_api_key"}}`)); !strings.Contains(got, "invalid api key") {
		t.Fatalf("provider message dropped: %q", got)
	}
	if got := providerErrorSummary([]byte(`{"message":"model not found"}`)); !strings.Contains(got, "model not found") {
		t.Fatalf("top-level message dropped: %q", got)
	}
	if got := providerErrorSummary(nil); got == "" {
		t.Fatal("empty body produced an empty summary")
	}
	long := make([]byte, 0, 2000)
	for i := 0; i < 2000; i++ {
		long = append(long, 'x')
	}
	payload, _ := json.Marshal(map[string]any{"error": map[string]any{"message": string(long)}})
	if got := providerErrorSummary(payload); len(got) > 400 {
		t.Fatalf("summary not bounded: %d bytes", len(got))
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// The custom HTTP tool's proxy path must refuse a link-local target before the
// request is handed to the proxy, which resolves the destination itself.
func TestRunHTTPToolRefusesLinkLocalThroughProxy(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("proxy was contacted for a refused target: %s", r.URL)
	}))
	defer proxy.Close()

	s := &Server{}
	execRaw, _ := json.Marshal(httpExec{
		Method: "GET",
		URL:    "http://169.254.169.254/latest/meta-data/",
		Proxy:  proxy.URL,
	})
	res, err := s.runHTTPTool(context.Background(), execRaw, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(res.Flatten(), "链路本地") {
		t.Fatalf("link-local target through proxy was not refused: error=%v %s", res.IsError, res.Flatten())
	}
}
