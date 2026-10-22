package traffic

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/capture"
	actool "github.com/Autumn-27/norma/tool"
)

// newScopeTestTraffic opens a recorder with one recorded exchange per host, so
// the scoped-read tools have something to find and something to refuse.
func newScopeTestTraffic(t *testing.T, hosts ...string) *Traffic {
	t.Helper()
	dir := t.TempDir()
	tr, err := Open(dir, "")
	if err != nil {
		t.Fatalf("open traffic: %v", err)
	}
	t.Cleanup(func() { _ = tr.Close() })
	for i, host := range hosts {
		id := "ex-" + host
		if _, err := tr.db.Exec(`INSERT OR REPLACE INTO exchanges(id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path)
VALUES(?,?,?,?,?,?,?,?,?,?,'')`, id, 1700000000+i, host, "GET", "/", "http://"+host+"/", 200, "text/plain", 1, 2); err != nil {
			t.Fatalf("seed exchange %s: %v", host, err)
		}
		if _, err := tr.db.Exec(`INSERT OR REPLACE INTO exchange_bodies(id,req_head,req_body,resp_head,resp_body)
VALUES(?,?,?,?,?)`, id, "GET / HTTP/1.1", []byte("q"), "HTTP/1.1 200 OK", []byte("r")); err != nil {
			t.Fatalf("seed body %s: %v", host, err)
		}
	}
	return tr
}

func toolByName(tools []actool.CoreTool, name string) actool.CoreTool {
	for _, tl := range tools {
		if tl.Name() == name {
			return tl
		}
	}
	return nil
}

func runTool(t *testing.T, tl actool.CoreTool, ctx context.Context, input map[string]any) actool.Result {
	t.Helper()
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	res, err := tl.Call(ctx, raw, &actool.ToolContext{})
	if err != nil {
		t.Fatalf("%s: %v", tl.Name(), err)
	}
	return res
}

func TestTrafficSearchRefusesOutOfScopeHost(t *testing.T) {
	tr := newScopeTestTraffic(t, "in.example", "other.example")
	search := toolByName(tr.Tools(), "traffic_search")
	if search == nil {
		t.Fatal("traffic_search missing")
	}
	ctx := capture.WithScope(context.Background(), capture.Scope{Hosts: map[string]bool{"in.example": true}})

	if res := runTool(t, search, ctx, map[string]any{"host": "in.example"}); res.IsError {
		t.Fatalf("in-scope host refused: %s", res.Flatten())
	}
	res := runTool(t, search, ctx, map[string]any{"host": "other.example"})
	if !res.IsError || !strings.Contains(res.Flatten(), "拒绝读取") {
		t.Fatalf("out-of-scope host was readable: error=%v %s", res.IsError, res.Flatten())
	}
}

func TestTrafficGetRefusesOutOfScopeExchange(t *testing.T) {
	tr := newScopeTestTraffic(t, "in.example", "other.example")
	get := toolByName(tr.Tools(), "traffic_get")
	if get == nil {
		t.Fatal("traffic_get missing")
	}
	ctx := capture.WithScope(context.Background(), capture.Scope{Hosts: map[string]bool{"in.example": true}})

	if res := runTool(t, get, ctx, map[string]any{"id": "ex-in.example"}); res.IsError {
		t.Fatalf("in-scope exchange refused: %s", res.Flatten())
	}
	res := runTool(t, get, ctx, map[string]any{"id": "ex-other.example"})
	if !res.IsError || !strings.Contains(res.Flatten(), "拒绝读取") {
		t.Fatalf("out-of-scope exchange was readable: error=%v %s", res.IsError, res.Flatten())
	}
}

// An empty allowed set must read NOTHING. Deriving the restriction from "is the
// set non-empty" would turn a task with no assets yet into an unrestricted one.
func TestTrafficScopeEmptyAllowedRefusesEverything(t *testing.T) {
	tr := newScopeTestTraffic(t, "in.example")
	search := toolByName(tr.Tools(), "traffic_search")
	ctx := capture.WithScope(context.Background(), capture.Scope{Hosts: map[string]bool{}})

	res := runTool(t, search, ctx, map[string]any{"host": "in.example"})
	if !res.IsError {
		t.Fatalf("empty scope still read traffic: %s", res.Flatten())
	}
}

// Declared scope is matched by membership, not literal equality: a root_domain
// scope must admit a capture taken on one of its subdomains, otherwise a task
// could not read traffic for hosts it explicitly declared.
func TestTrafficScopeAdmitsDeclaredDomainAndCIDR(t *testing.T) {
	tr := newScopeTestTraffic(t, "api.example.com", "10.1.2.3", "elsewhere.net")
	search := toolByName(tr.Tools(), "traffic_search")
	if search == nil {
		t.Fatal("traffic_search missing")
	}
	_, ipnet, err := net.ParseCIDR("10.1.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	ctx := capture.WithScope(context.Background(), capture.Scope{
		Domains: []string{"example.com"},
		Nets:    []*net.IPNet{ipnet},
	})

	for _, host := range []string{"api.example.com", "10.1.2.3"} {
		if res := runTool(t, search, ctx, map[string]any{"host": host}); res.IsError {
			t.Fatalf("declared-scope host %s refused: %s", host, res.Flatten())
		}
	}
	if res := runTool(t, search, ctx, map[string]any{"host": "elsewhere.net"}); !res.IsError {
		t.Fatalf("host outside the declared scope was readable: %s", res.Flatten())
	}
}

func TestTrafficToolsUnrestrictedWithoutScope(t *testing.T) {
	tr := newScopeTestTraffic(t, "anything.example")
	search := toolByName(tr.Tools(), "traffic_search")
	res := runTool(t, search, context.Background(), map[string]any{"host": "anything.example"})
	if res.IsError {
		t.Fatalf("unscoped run refused a read: %s", res.Flatten())
	}
	if !strings.Contains(res.Flatten(), "anything.example") {
		t.Fatalf("unscoped run did not see the exchange: %s", res.Flatten())
	}
}

func TestBlobInScopeFollowsReferencingExchange(t *testing.T) {
	tr := newScopeTestTraffic(t, "in.example", "other.example")
	// One blob referenced by two exchanges: readable while any referrer is in scope.
	for _, id := range []string{"ex-in.example", "ex-other.example"} {
		if _, err := tr.db.Exec(`INSERT OR REPLACE INTO blob_refs(hash, exchange_id) VALUES(?,?)`, "deadbeef", id); err != nil {
			t.Fatal(err)
		}
	}
	ctx := capture.WithScope(context.Background(), capture.Scope{Hosts: map[string]bool{"in.example": true}})
	if msg, err := tr.blobInScope(ctx, "deadbeef"); err != nil || msg != "" {
		t.Fatalf("blob with an in-scope referrer was refused: msg=%q err=%v", msg, err)
	}
	// Narrow the scope to a host that does not reference it.
	ctx = capture.WithScope(context.Background(), capture.Scope{Hosts: map[string]bool{"third.example": true}})
	if msg, err := tr.blobInScope(ctx, "deadbeef"); err != nil || msg == "" {
		t.Fatalf("blob with no in-scope referrer was allowed: msg=%q err=%v", msg, err)
	}
}

// An orphaned blob (no referencing exchange) must not be readable by hash alone.
func TestBlobInScopeRefusesOrphan(t *testing.T) {
	tr := newScopeTestTraffic(t, "in.example")
	ctx := capture.WithScope(context.Background(), capture.Scope{Hosts: map[string]bool{"in.example": true}})
	if msg, err := tr.blobInScope(ctx, "nosuchhash"); err != nil || msg == "" {
		t.Fatalf("orphan blob readable: msg=%q err=%v", msg, err)
	}
}

// Blob reads on an index without the blob_refs table must fail closed.
func TestBlobInScopeUnknownIDFailsClosed(t *testing.T) {
	dir := t.TempDir()
	tr, err := Open(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	ctx := capture.WithScope(context.Background(), capture.Scope{Hosts: map[string]bool{"x": true}})
	msg, err := tr.blobInScope(ctx, "missing")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg == "" {
		t.Fatal("unknown blob allowed")
	}
}
