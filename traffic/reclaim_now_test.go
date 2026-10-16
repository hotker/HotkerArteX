package traffic

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeBlobFile(t *testing.T, root, hash string) string {
	t.Helper()
	path := filepath.Join(root, hash[:2], hash+".bin")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestReclaimNowSweepsOrphans verifies the /api/gc backend path: unreferenced
// blobs are removed and counted, referenced ones survive, and an empty store
// is a no-op rather than an error.
func TestReclaimNowSweepsOrphans(t *testing.T) {
	tr, err := Open(filepath.Join(t.TempDir(), "traffic"), ":0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tr.Close() })

	live := strings.Repeat("a", 64)
	dead1 := strings.Repeat("b", 64)
	dead2 := strings.Repeat("c", 64)
	if _, err := tr.db.Exec(`INSERT INTO blob_refs(hash,exchange_id) VALUES($1,1)`, live); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(tr.dir, "_blobs", "sha256")
	livePath := writeBlobFile(t, root, live)
	deadPath1 := writeBlobFile(t, root, dead1)
	deadPath2 := writeBlobFile(t, root, dead2)

	removed, err := tr.ReclaimNow()
	if err != nil {
		t.Fatal(err)
	}
	if removed != 2 {
		t.Fatalf("removed=%d want 2", removed)
	}
	if _, err := os.Stat(livePath); err != nil {
		t.Fatalf("referenced blob removed: %v", err)
	}
	for _, p := range []string{deadPath1, deadPath2} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("orphan %s still present", p)
		}
	}

	// Second run over an already-clean store.
	if removed, err := tr.ReclaimNow(); err != nil || removed != 0 {
		t.Fatalf("second run: removed=%d err=%v", removed, err)
	}
}
