package config

import (
	"database/sql"
	"os"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// TestMain acquires the same PostgreSQL advisory lock (7337741002) as the
// db/server/agent/evidence test suites so this package's DSN-backed tests do
// not run cross-package concurrent with them when running `go test ./...`.
//
// The DSN is read from ARTEX_PG_DSN directly: db.DSN() cannot be used here
// because db imports config, which would be an import cycle in a test file.
// Without the env var (pure unit-test runs) the suite proceeds unlocked, same
// as before this file existed.
func TestMain(m *testing.M) {
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		os.Exit(m.Run())
	}
	conn, err := sql.Open("pgx", dsn)
	if err != nil || conn.Ping() != nil {
		os.Exit(m.Run())
	}
	defer conn.Close()
	if _, err := conn.Exec(`SELECT pg_advisory_lock(7337741002)`); err != nil {
		os.Exit(m.Run())
	}
	defer conn.Exec(`SELECT pg_advisory_unlock(7337741002)`) //nolint:errcheck
	os.Exit(m.Run())
}
