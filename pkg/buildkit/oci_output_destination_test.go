package buildkit

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newDirMode returns the mode os.MkdirAll(path, 0o755) gives a new directory
// under the current umask.
func newDirMode(t *testing.T) os.FileMode {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "reference")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	info, err := os.Stat(dir)
	require.NoError(t, err)
	return info.Mode().Perm()
}

func writeTestLayoutMarker(staging string) error {
	return os.WriteFile(filepath.Join(staging, ispec.ImageLayoutFile), []byte(`{"imageLayoutVersion":"1.0.0"}`), 0o600)
}

func stubRenameNoReplace(t *testing.T, rename func(string, string) error) {
	t.Helper()
	original := renameNoReplace
	t.Cleanup(func() { renameNoReplace = original })
	renameNoReplace = rename
}

func TestCanPublishOCILayoutAtomically(t *testing.T) {
	if runtime.GOOS != linux && runtime.GOOS != "darwin" {
		t.Skip("no-replace rename is supported only on Linux and macOS")
	}
	parent := t.TempDir()
	existing := filepath.Join(parent, "existing")
	require.NoError(t, os.Mkdir(existing, 0o755))

	staged, reason := CanPublishOCILayoutAtomically(filepath.Join(parent, "output"))
	require.True(t, staged, "%v", reason)
	assert.Equal(t, []string{"existing"}, dirEntryNames(t, parent), "the probe must remove what it created")

	for name, path := range map[string]string{
		"existing directory":    existing,
		"missing parent":        filepath.Join(parent, "missing", "output"),
		"current directory":     ".",
		"parent of a directory": existing + "/..",
	} {
		t.Run(name, func(t *testing.T) {
			staged, reason := CanPublishOCILayoutAtomically(path)
			assert.False(t, staged)
			assert.Error(t, reason)
			assert.Equal(t, []string{"existing"}, dirEntryNames(t, parent))
		})
	}
}

// A filesystem without a no-replace rename, such as a FUSE, 9p or NFS mount,
// fails the probe, so the export falls back to writing in place.
func TestCanPublishOCILayoutAtomicallyProbesRename(t *testing.T) {
	stubRenameNoReplace(t, func(string, string) error { return syscall.EINVAL })
	parent := t.TempDir()
	staged, reason := CanPublishOCILayoutAtomically(filepath.Join(parent, "output"))
	assert.False(t, staged)
	require.ErrorIs(t, reason, syscall.EINVAL)
	assertDirEmpty(t, parent, "the probe must remove what it created")
}

func TestNamedOCIExportFallsBackInPlaceWhenProbeFails(t *testing.T) {
	stubRenameNoReplace(t, func(string, string) error { return errors.ErrUnsupported })
	tmp := isolateTempDir(t)
	stubOCIExporter(t, nil)
	platforms := []ispec.Platform{ociExportAMD64, ociExportARM64}
	results, patchPlatforms := namedOCIExportResults(t, platforms)
	parent := t.TempDir()
	output := filepath.Join(parent, "output")

	staged, reason := CanPublishOCILayoutAtomically(output)
	require.False(t, staged)
	require.ErrorIs(t, reason, errors.ErrUnsupported)
	require.NoError(t, CreateOCILayoutFromResultsWithContext(t.Context(), output, results, patchPlatforms, namedOCIExportOptions(staged)))
	assertNamedOCILayout(t, output, platforms)
	assert.Equal(t, []string{"output"}, dirEntryNames(t, parent))
	assertDirEmpty(t, tmp, "temporary platform directories must be removed")
}

func TestAtomicOCILayoutPublishesWithDirectoryMode(t *testing.T) {
	output := filepath.Join(t.TempDir(), "output")
	require.NoError(t, createAtomicOCILayout(t.Context(), output, func(staging string) error {
		assertDirEmpty(t, staging, "the writer gets an empty staging directory")
		info, err := os.Stat(staging)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o700), info.Mode().Perm(), "staging stays private while it is written")
		return writeTestLayoutMarker(staging)
	}))
	info, err := os.Stat(output)
	require.NoError(t, err)
	assert.Equal(t, newDirMode(t), info.Mode().Perm())
	assert.Zero(t, info.Mode()&os.ModeSetgid)
	assert.FileExists(t, filepath.Join(output, ispec.ImageLayoutFile))
}

// In a setgid directory, a new directory inherits the bit, and so does the
// published layout.
func TestAtomicOCILayoutKeepsInheritedSetgid(t *testing.T) {
	if runtime.GOOS != linux {
		t.Skip("directories inherit setgid from their parent on Linux")
	}
	parent := t.TempDir()
	require.NoError(t, os.Chmod(parent, 0o755|os.ModeSetgid))
	output := filepath.Join(parent, "output")
	require.NoError(t, createAtomicOCILayout(t.Context(), output, writeTestLayoutMarker))
	info, err := os.Stat(output)
	require.NoError(t, err)
	assert.NotZero(t, info.Mode()&os.ModeSetgid, "the published layout keeps the setgid bit")
	assert.Equal(t, newDirMode(t), info.Mode().Perm())
}
