package server

import (
	"context"
	"testing"
)

// newTestServer builds a Server whose background loops (engine task runtimes,
// scheduler, notifier, evidence GC, archive worker) are cancelled and drained
// when the test ends. Without this, restoreTaskRuntimes re-admits tasks
// persisted in the shared PG and the loops keep writing into a previous test's
// already-removed data dir ("TempDir RemoveAll cleanup: directory not empty").
// td is used for skillDir/dataDir/keyDir (callers that keep files across the
// test pass one dir; others may pass t.TempDir()).
func newTestServer(t *testing.T, m *Manager, td string) *Server {
	t.Helper()
	s := New(context.Background(), m, td, td, td)
	t.Cleanup(func() { s.Stop() })
	return s
}
