package capture

import (
	"context"
	"net"
	"testing"
)

func mustNet(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestScopeAllows(t *testing.T) {
	scope := Scope{
		Hosts:   map[string]bool{"exact.example.com": true},
		Domains: []string{"corp.example"},
		Nets:    []*net.IPNet{mustNet(t, "10.1.0.0/16"), mustNet(t, "2001:db8::/32")},
	}
	allowed := []string{
		"exact.example.com",
		"EXACT.Example.COM", // host keys are compared lowercased
		"corp.example",
		"a.corp.example",
		"deep.sub.corp.example",
		"10.1.2.3",
		"[2001:db8::1]", // URL.Hostname() strips brackets, but be lenient
	}
	for _, h := range allowed {
		if !scope.Allows(h) {
			t.Errorf("Allows(%q) = false, want true", h)
		}
	}
	refused := []string{
		"",
		"other.example",
		"notcorp.example",   // suffix match must be on a label boundary
		"corp.example.evil", // a prefix of a different name is not enough
		"10.2.0.1",          // outside the CIDR
		"2001:db9::1",       // outside the v6 CIDR
	}
	for _, h := range refused {
		if scope.Allows(h) {
			t.Errorf("Allows(%q) = true, want false", h)
		}
	}
}

// An empty scope still refuses everything: "no declared targets yet" must not
// degrade into "the whole process-wide capture index".
func TestEmptyScopeRefusesEverything(t *testing.T) {
	var scope Scope
	if !scope.Empty() {
		t.Fatal("zero scope reported non-empty")
	}
	if scope.Allows("anything.example") || scope.Allows("10.0.0.1") {
		t.Fatal("empty scope allowed a host")
	}
}

// A host that parses as an IP must never fall through to domain suffix matching.
func TestScopeIPHostDoesNotMatchDomain(t *testing.T) {
	scope := Scope{Domains: []string{"example.com"}}
	if scope.Allows("1.2.3.4") {
		t.Fatal("IP host matched a domain entry")
	}
}

func TestFromRequiresRestricted(t *testing.T) {
	if _, ok := From(context.Background()); ok {
		t.Fatal("bare context reported a scope")
	}
	// A value stored directly (not via WithScope) must stay unrestricted: the
	// Restricted flag is the switch, not the presence of the value.
	ctx := context.WithValue(context.Background(), scopeKey{}, Scope{Hosts: map[string]bool{"a": true}})
	if _, ok := From(ctx); ok {
		t.Fatal("unrestricted value treated as restricted")
	}
	ctx = WithScope(context.Background(), Scope{Hosts: map[string]bool{"a": true}})
	got, ok := From(ctx)
	if !ok || !got.Restricted || !got.Allows("a") {
		t.Fatal("attached scope not readable")
	}
}
