// Package storetest provides a throwaway per-test SQLite store in the test's
// temporary directory.
package storetest

import (
	"path/filepath"
	"testing"

	"github.com/terragohan/mcptunnels/internal/store"
)

// Open opens a migrated store on a fresh SQLite database in t.TempDir() and
// registers a cleanup that closes it.
func Open(t testing.TB) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("storetest: store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}
