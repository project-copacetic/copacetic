package imageloader

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPodmanLoader_Load_Success(t *testing.T) {
	ctx := context.Background()
	cleanup := makeFakePodman(t, 0)
	defer cleanup()

	ldr, err := New(ctx, Config{Loader: "podman"})
	if err != nil {
		t.Fatalf("New() with Select: \"podman\" failed unexpectedly: %v", err)
	}
	if _, ok := ldr.(*podmanLoader); !ok {
		t.Fatalf("expected a *podmanLoader, got %T", ldr)
	}

	err = ldr.Load(ctx, bytes.NewReader([]byte("dummy_tar_data")), "unused-image-ref")
	if err != nil {
		t.Fatalf("(*podmanLoader).Load failed with fake podman (exit 0): %v", err)
	}
}

func TestPodmanLoader_Load_Error(t *testing.T) {
	ctx := context.Background()
	cleanup := makeFakePodman(t, 1)
	defer cleanup()

	ldr, err := New(ctx, Config{Loader: "podman"})
	if err != nil {
		t.Fatalf("New() with Select: \"podman\" failed unexpectedly: %v", err)
	}
	if _, ok := ldr.(*podmanLoader); !ok {
		t.Fatalf("expected a *podmanLoader, got %T", ldr)
	}

	err = ldr.Load(ctx, bytes.NewReader([]byte("dummy_tar_data")), "unused-image-ref")
	if err == nil {
		t.Fatal("(*podmanLoader).Load succeeded with fake podman (exit 1), expected error")
	}
	if !strings.Contains(err.Error(), "podman load:") {
		t.Errorf("expected error to contain 'podman load:', got %v", err)
	}
}

func makeFakePodman(t *testing.T, exitCode int) (cleanup func()) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake shell script for podman not supported on Windows in this test setup")
	}
	dir := t.TempDir()

	scriptContent := fmt.Sprintf("#!/usr/bin/env sh\ncat >/dev/null\necho \"podman load invoked (exit %d)\"\nexit %d\n", exitCode, exitCode)
	fakePodmanPath := filepath.Join(dir, "podman")

	//nolint:gosec
	if err := os.WriteFile(fakePodmanPath, []byte(scriptContent), 0o755); err != nil {
		t.Fatalf("failed to write fake podman script: %v", err)
	}

	originalPath := os.Getenv("PATH")
	if err := os.Setenv("PATH", dir+string(os.PathListSeparator)+originalPath); err != nil {
		t.Fatalf("failed to set PATH: %v", err)
	}

	return func() {
		if err := os.Setenv("PATH", originalPath); err != nil {
			t.Logf("warning: failed to restore PATH: %v", err)
		}
	}
}
