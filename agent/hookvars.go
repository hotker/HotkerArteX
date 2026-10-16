package agent

// The runtime hooks (PromptOverride / ToolAugment / ToolResolve / Wrapup* /
// FindingTrafficBindingEnabled) are assigned by the server during setup and
// read from planner/worker goroutines on every turn. Plain package-level
// function vars are a data race (proven by the race detector: server.New()
// writing while a still-running planner loop read the prompt hook), so each
// hook lives behind a sync/atomic.Pointer with a Set/Get pair. Function types
// are not comparable, so each Set compares against nil itself before storing.
// Set(nil) clears a hook; Get returns the zero value when unset.
