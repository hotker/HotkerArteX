package traffic

import (
	"bytes"
	"io"
	"strings"
	"testing"

	mproxy "github.com/lqqyt2423/go-mitmproxy/proxy"
)

// TestCaptureReaderKeepsHeadAndCountsTotal covers the bounded capture used for
// streamed bodies: only the first streamCaptureCap bytes are retained, while the
// total reflects everything the client actually received.
func TestCaptureReaderKeepsHeadAndCountsTotal(t *testing.T) {
	payload := bytes.Repeat([]byte("a"), streamCaptureCap+4096)
	cr := &captureReader{r: bytes.NewReader(payload)}

	got, err := io.ReadAll(cr)
	if err != nil {
		t.Fatalf("读取流失败: %v", err)
	}
	if len(got) != len(payload) {
		t.Fatalf("透传长度 = %d，期望 %d（捕获不得截断客户端收到的数据）", len(got), len(payload))
	}
	head, total := cr.snapshot()
	if len(head) != streamCaptureCap {
		t.Fatalf("保留的头部 = %d 字节，期望 %d", len(head), streamCaptureCap)
	}
	if total != int64(len(payload)) {
		t.Fatalf("总长度 = %d，期望 %d", total, len(payload))
	}
}

// TestCaptureReaderSmallBodyIsWhole keeps the common case exact: a streamed body
// below the cap is captured verbatim.
func TestCaptureReaderSmallBodyIsWhole(t *testing.T) {
	body := []byte("data: hello\n\n")
	cr := &captureReader{r: bytes.NewReader(body)}
	if _, err := io.Copy(io.Discard, cr); err != nil {
		t.Fatal(err)
	}
	head, total := cr.snapshot()
	if string(head) != string(body) || total != int64(len(body)) {
		t.Fatalf("head=%q total=%d，期望 %q/%d", head, total, body, len(body))
	}
}

// TestRecordExchangeUsesWireLengths is the regression test for streamed flows:
// the stored row must report the real body size even though only a prefix of the
// body is available, so a 10 MB download no longer appears as a tiny exchange
// (or vanishes entirely).
func TestRecordExchangeUsesWireLengths(t *testing.T) {
	tr, _ := openTraffic(t)

	f := newFlow("cdn.example.com", "GET", "/big.bin", nil, []byte("HEAD-ONLY"))
	tr.recordExchange(f, nil, []byte("HEAD-ONLY"), 0, 10<<20)

	var respLen int64
	var stored string
	if err := tr.DB().QueryRow(`SELECT resp_len FROM exchanges`).Scan(&respLen); err != nil {
		t.Fatalf("读取 resp_len: %v", err)
	}
	if respLen != 10<<20 {
		t.Fatalf("resp_len = %d，期望 %d（必须记录线上真实长度，而不是捕获到的头部长度）", respLen, 10<<20)
	}
	if err := tr.DB().QueryRow(`SELECT resp_body FROM exchange_bodies`).Scan(&stored); err != nil {
		t.Fatalf("读取 resp_body: %v", err)
	}
	if !strings.Contains(stored, "HEAD-ONLY") {
		t.Fatalf("resp_body = %q，期望保留捕获到的头部", stored)
	}
}

// TestSinkStreamResponseModifierCapturesBody checks the addon wiring: a flow the
// proxy marks as streamed gets a teeing reader, and draining it records the
// exchange once.
func TestSinkStreamResponseModifierCapturesBody(t *testing.T) {
	tr, _ := openTraffic(t)
	s := &sink{t: tr}

	f := newFlow("stream.example.com", "GET", "/events", nil, nil)
	f.Stream = true
	f.Response.Header.Set("Content-Type", "text/event-stream")

	body := "data: one\n\ndata: two\n\n"
	reqIn := strings.NewReader("")
	respIn := strings.NewReader(body)

	reqOut := s.StreamRequestModifier(f, reqIn)
	respOut := s.StreamResponseModifier(f, respIn)

	if _, err := io.Copy(io.Discard, reqOut); err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, respOut); err != nil {
		t.Fatal(err)
	}

	// recordStream normally fires when the proxy finishes the flow; newFlow has no
	// done channel, so drive the same completion path the addon uses.
	state, ok := s.pending.Load(f.Id)
	if !ok {
		t.Fatal("流式响应未被登记到 pending 表")
	}
	s.recordStream(f, state.(*streamState))

	var respLen int64
	var stored string
	if err := tr.DB().QueryRow(`SELECT resp_len FROM exchanges`).Scan(&respLen); err != nil {
		t.Fatalf("流式交换未被记录: %v", err)
	}
	if respLen != int64(len(body)) {
		t.Fatalf("resp_len = %d，期望 %d", respLen, len(body))
	}
	if err := tr.DB().QueryRow(`SELECT resp_body FROM exchange_bodies`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != body {
		t.Fatalf("resp_body = %q，期望 %q", stored, body)
	}
}

// TestSinkStreamSkipsWebSocket guards against wrapping the upgrade handshake: a
// websocket flow is not an HTTP exchange and must not produce a record.
func TestSinkStreamSkipsWebSocket(t *testing.T) {
	tr, _ := openTraffic(t)
	s := &sink{t: tr}

	f := newFlow("ws.example.com", "GET", "/socket", nil, nil)
	f.Stream = true
	f.WebScoket = &mproxy.WebSocketData{}

	in := strings.NewReader("raw")
	if out := s.StreamRequestModifier(f, in); out != io.Reader(in) {
		t.Fatal("websocket 流不应被包装")
	}
	if _, ok := s.pending.Load(f.Id); ok {
		t.Fatal("websocket 流不应登记到 pending 表")
	}
}
