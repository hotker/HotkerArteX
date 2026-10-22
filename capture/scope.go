// Package capture carries the per-run restriction on which captured traffic a
// run may read. It lives on its own so both the recorder (traffic) and the agent
// layer can agree on the type without importing each other.
package capture

import (
	"context"
	"net"
	"strings"
)

// Scope is the set of targets a run is allowed to read captured traffic for.
//
// It is derived from the task's DECLARED scope (task_scope: company, root_domain,
// subdomain, ip, cidr, icp) plus the hosts its assets carry, so an agent cannot
// read captures belonging to a different engagement. A run with no scope attached
// (chat / Auto, no task) stays unrestricted, exactly as before.
//
// Declared scope is matched by membership, not literal equality: a root_domain
// scope admits every host under it, and an ip/cidr scope admits every address
// inside it. That matters because a capture's host is whatever URL the browser
// used, which is usually a subdomain or a specific port of a declared target.
type Scope struct {
	// Hosts are exact host keys (lowercased, no port).
	Hosts map[string]bool
	// Domains admit the domain itself and every subdomain of it.
	Domains []string
	// Nets admit any IP-literal host inside them.
	Nets []*net.IPNet
	// Restricted is the switch, not "is anything listed": a task that has declared
	// no scope yet must read nothing. Deriving the restriction from emptiness
	// would silently grant it the whole process-wide index.
	Restricted bool
	// Reason explains the restriction in the tool's error text, so the model can
	// tell "not captured yet" apart from "outside this task".
	Reason string
}

// Allows reports whether host (as recorded: URL.Hostname(), lowercased) is in
// scope. A host that parses as an IP is checked against Nets; otherwise against
// the exact set and the domain suffixes.
func (s Scope) Allows(host string) bool {
	h := strings.ToLower(strings.Trim(strings.TrimSpace(host), "[]"))
	if h == "" {
		return false
	}
	if s.Hosts[h] {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		for _, n := range s.Nets {
			if n.Contains(ip) {
				return true
			}
		}
		return false
	}
	for _, d := range s.Domains {
		if h == d || strings.HasSuffix(h, "."+d) {
			return true
		}
	}
	return false
}

// Empty reports whether the scope admits nothing at all.
func (s Scope) Empty() bool {
	return len(s.Hosts) == 0 && len(s.Domains) == 0 && len(s.Nets) == 0
}

type scopeKey struct{}

// WithScope attaches the run's traffic-read scope.
func WithScope(ctx context.Context, scope Scope) context.Context {
	scope.Restricted = true
	return context.WithValue(ctx, scopeKey{}, scope)
}

// From reads the attached scope; ok=false means unrestricted.
func From(ctx context.Context) (Scope, bool) {
	v, ok := ctx.Value(scopeKey{}).(Scope)
	if !ok || !v.Restricted {
		return Scope{}, false
	}
	return v, true
}
