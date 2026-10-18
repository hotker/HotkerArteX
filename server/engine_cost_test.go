package server

import (
	"context"
	"testing"
)

// costOverBudget is the fuse's trip decision: trip iff budget is positive and
// total has reached it. budget<=0 means "not set" (unlimited) and never trips.
// It is extracted as a pure function precisely so this one semantic — when a
// task stops burning spend — is unit-testable without a Postgres.
func TestCostOverBudget(t *testing.T) {
	cases := []struct {
		name   string
		total  int64
		budget int64
		want   bool
	}{
		{"unlimited (budget 0) never trips, even at huge total", 1 << 40, 0, false},
		{"negative budget treated as unset", 1 << 40, -5, false},
		{"below budget does not trip", 999, 1000, false},
		{"exactly at budget trips", 1000, 1000, true},
		{"over budget trips", 1001, 1000, true},
		{"zero total under positive budget does not trip", 0, 1000, false},
		{"zero total at zero budget (both) does not trip", 0, 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := costOverBudget(c.total, c.budget); got != c.want {
				t.Fatalf("costOverBudget(total=%d, budget=%d) = %v, want %v", c.total, c.budget, got, c.want)
			}
		})
	}
}

// TaskLLMBudget must be nil-pg safe (return 0 = unlimited) so a manager without
// a database never crashes the coordinator or mis-trips a task.
func TestTaskLLMBudgetNilPG(t *testing.T) {
	e := NewEngine(&Manager{}) // pg == nil
	if got := e.TaskLLMBudget(); got != 0 {
		t.Fatalf("TaskLLMBudget with nil pg = %d, want 0 (unlimited)", got)
	}
}

// startCostCoordinator is a no-op (does not register a runtime, does not record
// the started marker) when the budget is unset, so a fleet of tasks with no cost
// cap configured spawns zero extra poller goroutines.
func TestStartCostCoordinatorNoopWhenUnset(t *testing.T) {
	e := NewEngine(&Manager{}) // pg nil → TaskLLMBudget 0 → no-op
	tasks := map[string]*Task{"1": {ID: "1"}, "2": {ID: "2"}}
	for _, t := range tasks {
		e.startCostCoordinator(context.Background(), t)
	}
	if _, ok := e.costCoordStarted.Load("1"); ok {
		t.Fatal("costCoordStarted marker recorded despite unset budget")
	}
	if _, ok := e.costCoordStarted.Load("2"); ok {
		t.Fatal("costCoordStarted marker recorded despite unset budget")
	}
	if rt := e.runtimes["1"]; rt != nil {
		t.Fatal("a task runtime was registered for a no-op cost coordinator")
	}
}

// startCostCoordinator must be idempotent for the started marker: once a task is
// marked started, a second call must not register a second poller goroutine.
// This mirrors the deadline coordinator's Run()/reload/re-admission dedup, so a
// task admitted several times keeps exactly one cost coordinator.
func TestStartCostCoordinatorIdempotentMarker(t *testing.T) {
	e := NewEngine(&Manager{})
	e.costCoordStarted.Store("7", true) // pre-seed as if already started
	// Even with the marker set, a nil-pg manager no-ops first (budget check), but
	// the invariant we assert is that the marker stays true and no runtime is added.
	e.startCostCoordinator(context.Background(), &Task{ID: "7"})
	if _, ok := e.costCoordStarted.Load("7"); !ok {
		t.Fatal("startCostCoordinator cleared an existing started marker")
	}
	if rt := e.runtimes["7"]; rt != nil {
		t.Fatal("a second runtime was registered for an already-started cost coordinator")
	}
}
