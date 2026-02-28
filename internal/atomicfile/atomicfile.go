// Package atomicfile provides atomic file writes (temp + fsync + rename).
package atomicfile

import (
	"fmt"
	"os"
	"path/filepath"
)

// Write atomically writes data to path.
// It writes to a temp file in the same directory, fsyncs, then renames.
func Write(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".bouncer-*.tmp")
	if err != nil {
		return fmt.Errorf("atomicfile: create temp: %w", err)
	}
	tmpName := tmp.Name()

	defer func() {
		// Clean up on failure.
		if tmp != nil {
			if err := tmp.Close(); err != nil {
				_ = err // Best effort cleanup.
			}
			if err := os.Remove(tmpName); err != nil && !os.IsNotExist(err) {
				_ = err // Best effort cleanup.
			}
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("atomicfile: write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("atomicfile: sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("atomicfile: close: %w", err)
	}
	tmp = nil // Prevent defer cleanup.

	if err := os.Chmod(tmpName, perm); err != nil {
		if rmErr := os.Remove(tmpName); rmErr != nil && !os.IsNotExist(rmErr) {
			_ = rmErr // Best effort cleanup.
		}
		return fmt.Errorf("atomicfile: chmod: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		if rmErr := os.Remove(tmpName); rmErr != nil && !os.IsNotExist(rmErr) {
			_ = rmErr // Best effort cleanup.
		}
		return fmt.Errorf("atomicfile: rename: %w", err)
	}
	return nil
}
