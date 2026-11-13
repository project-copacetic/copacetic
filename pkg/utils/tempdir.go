package utils

import (
	"fmt"
	"os"
	"path/filepath"
)

// MkdirTemp creates a new temporary directory in the default temporary
// directory, like os.MkdirTemp("", pattern), and returns its path with symbolic
// links resolved.
//
// os.MkdirTemp joins TMPDIR with the directory name lexically. When TMPDIR
// contains a symlink followed by "..", such as "/work/link/..", the directory is
// created where the kernel resolves that path, but callers that later clean the
// returned path with filepath.Join or filepath.Clean end up pointing at a
// different, non-existent directory. Returning the resolved path avoids that.
func MkdirTemp(pattern string) (string, error) {
	dir, err := os.MkdirTemp("", pattern)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		_ = os.RemoveAll(dir)
		return "", fmt.Errorf("failed to resolve temporary directory %s: %w", dir, err)
	}
	return resolved, nil
}
