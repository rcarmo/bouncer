package session

import (
	"path/filepath"
	"testing"
)

// Profiles of full test suites include fixture I/O. These benchmarks isolate
// hot-path lookups and durable create/delete operations for B/op comparisons.
func BenchmarkSessionGet(b *testing.B) {
	store, err := NewStore(filepath.Join(b.TempDir(), "sessions.json"), 7)
	if err != nil {
		b.Fatal(err)
	}
	defer store.Stop()
	id, err := store.Create("default", "user", "credential")
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if store.Get(id) == nil {
			b.Fatal("missing session")
		}
	}
}

func BenchmarkSessionCreateDelete(b *testing.B) {
	store, err := NewStore(filepath.Join(b.TempDir(), "sessions.json"), 7)
	if err != nil {
		b.Fatal(err)
	}
	defer store.Stop()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		id, err := store.Create("default", "user", "credential")
		if err != nil {
			b.Fatal(err)
		}
		if err := store.Delete(id); err != nil {
			b.Fatal(err)
		}
	}
}
