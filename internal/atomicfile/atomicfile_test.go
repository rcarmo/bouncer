package atomicfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.json")

	data := []byte(`{"hello":"world"}`)
	if err := Write(path, data, 0600); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("got %q, want %q", got, data)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("got perm %o, want 0600", info.Mode().Perm())
	}
}

func TestWriteOverwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.json")

	if err := Write(path, []byte("first"), 0600); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := Write(path, []byte("second"), 0600); err != nil {
		t.Fatalf("second write: %v", err)
	}

	got, _ := os.ReadFile(path)
	if string(got) != "second" {
		t.Errorf("got %q, want %q", got, "second")
	}
}

func TestWriteNoTempLeftOnSuccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.json")
	_ = Write(path, []byte("ok"), 0600)

	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Name() != "test.json" {
			t.Errorf("unexpected file: %s", e.Name())
		}
	}
}

func TestWriteCreatesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "new.json")

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("file should not exist yet")
	}
	if err := Write(path, []byte("created"), 0644); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "created" {
		t.Errorf("got %q, want %q", got, "created")
	}
}

func TestWriteInvalidDir(t *testing.T) {
	err := Write("/nonexistent/dir/file.json", []byte("x"), 0600)
	if err == nil {
		t.Error("expected error for nonexistent dir")
	}
}

func TestWriteLargeData(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "large.json")

	data := make([]byte, 1<<20) // 1 MiB
	for i := range data {
		data[i] = byte('A' + (i % 26))
	}
	if err := Write(path, data, 0600); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, _ := os.ReadFile(path)
	if len(got) != len(data) {
		t.Errorf("expected %d bytes, got %d", len(data), len(got))
	}
}

func TestWritePermissions(t *testing.T) {
	dir := t.TempDir()

	tests := []os.FileMode{0600, 0644, 0400}
	for _, perm := range tests {
		path := filepath.Join(dir, "perm_test")
		os.Remove(path)
		if err := Write(path, []byte("x"), perm); err != nil {
			t.Fatalf("Write perm %o: %v", perm, err)
		}
		info, _ := os.Stat(path)
		if info.Mode().Perm() != perm {
			t.Errorf("expected perm %o, got %o", perm, info.Mode().Perm())
		}
	}
}
