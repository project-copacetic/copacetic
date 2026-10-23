package utils

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestMkdirTempResolvesSymlinkDotDot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("TMPDIR and symlink semantics differ on windows")
	}

	base := t.TempDir()
	child := filepath.Join(base, "external", "child")
	if err := os.MkdirAll(child, 0o755); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(base, "input")
	if err := os.MkdirAll(input, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(child, filepath.Join(input, "jump")); err != nil {
		t.Fatal(err)
	}
	// jump/.. resolves to base/external, not to base/input.
	t.Setenv("TMPDIR", filepath.Join(input, "jump")+string(filepath.Separator)+"..")

	dir, err := MkdirTemp("copa-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	resolvedBase, err := filepath.EvalSymlinks(base)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(resolvedBase, "external"); filepath.Dir(dir) != want {
		t.Fatalf("temporary directory parent = %q, want %q", filepath.Dir(dir), want)
	}

	// Paths built from the returned directory must exist after lexical cleaning.
	file := filepath.Join(dir, "platform-0.tar")
	f, err := os.Create(file)
	if err != nil {
		t.Fatalf("creating a file under the returned directory failed: %v", err)
	}
	f.Close()
}
