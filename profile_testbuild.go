//go:build allocprofile

package main

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
)

// This file is linked only into test builds. No HTTP profiling endpoint exists.
func init() {
	dir := os.Getenv("BOUNCER_ALLOC_PROFILE_DIR")
	if dir == "" {
		return
	}
	runtime.MemProfileRate = 1
	finishAllocationProfile = func() {
		runtime.GC()
		path := filepath.Join(dir, fmt.Sprintf("server-%d.pprof", os.Getpid()))
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			slog.Error("allocation profile create", "error", err)
			return
		}
		if err = pprof.Lookup("allocs").WriteTo(f, 0); err != nil {
			slog.Error("allocation profile write", "error", err)
		}
		if err = f.Close(); err != nil {
			slog.Error("allocation profile close", "error", err)
		}
	}
}
