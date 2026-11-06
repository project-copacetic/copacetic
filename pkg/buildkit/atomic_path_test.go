package buildkit

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAtomicOCILayoutStagesBesideResolvedDestination uses an output path whose
// lexical parent is a protected directory but whose real parent is elsewhere.
func TestAtomicOCILayoutStagesBesideResolvedDestination(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	protected := filepath.Join(base, "input")
	external := filepath.Join(base, "external")
	require.NoError(t, os.MkdirAll(filepath.Join(external, "child"), 0o755))
	require.NoError(t, os.MkdirAll(protected, 0o755))
	require.NoError(t, os.Symlink(filepath.Join(external, "child"), filepath.Join(protected, "jump")))
	old := time.Unix(1_000_000_000, 0)
	require.NoError(t, os.Chtimes(protected, old, old))
	require.NoError(t, os.Chmod(protected, 0o555))
	t.Cleanup(func() { _ = os.Chmod(protected, 0o755) })

	output := protected + "/jump/../output"
	var staging string
	require.NoError(t, createAtomicOCILayout(t.Context(), output, func(dir string) error {
		staging = dir
		return os.WriteFile(filepath.Join(dir, "marker"), []byte("published"), 0o600)
	}))

	assert.Equal(t, external, filepath.Dir(staging), "staging is created beside the resolved destination")
	data, err := os.ReadFile(filepath.Join(external, "output", "marker"))
	require.NoError(t, err)
	assert.Equal(t, "published", string(data))
	info, err := os.Stat(protected)
	require.NoError(t, err)
	assert.True(t, info.ModTime().Equal(old), "the lexical parent was not modified")
	entries, err := os.ReadDir(protected)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "jump", entries[0].Name())

	// An existing link at the final component is still rejected, not followed.
	require.NoError(t, os.Symlink(filepath.Join(base, "missing-target"), filepath.Join(external, "dangling")))
	err = createAtomicOCILayout(t.Context(), protected+"/jump/../dangling", func(string) error {
		t.Fatal("an existing destination link must prevent any writes")
		return nil
	})
	require.ErrorContains(t, err, "already exists")
	_, err = os.Lstat(filepath.Join(base, "missing-target"))
	assert.True(t, os.IsNotExist(err))
}
