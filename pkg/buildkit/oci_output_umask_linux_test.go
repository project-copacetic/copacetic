//go:build linux

package buildkit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setUmask sets the process umask for one test. The umask is process-wide, so
// tests that use it must not call t.Parallel.
func setUmask(t *testing.T, mask int) {
	t.Helper()
	previous := syscall.Umask(mask)
	t.Cleanup(func() { syscall.Umask(previous) })
}

// fileMode returns the permissions of the file at path.
func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	require.NoError(t, err)
	return info.Mode().Perm()
}

// Files that an export writes through replaceFile get the mode that the
// os.Create (blobs) or os.WriteFile(0o600) (metadata) calls they replace gave
// them under the process umask.
func TestOCIExportFilesKeepUmaskedModes(t *testing.T) {
	for _, mask := range []int{0o077, 0o022, 0o002} {
		t.Run(fmt.Sprintf("umask %04o", mask), func(t *testing.T) {
			setUmask(t, mask)
			reference := t.TempDir()
			created, err := os.Create(filepath.Join(reference, "created"))
			require.NoError(t, err)
			require.NoError(t, created.Close())
			blobMode := fileMode(t, created.Name())
			require.NoError(t, os.WriteFile(filepath.Join(reference, "written"), nil, 0o600))
			metadataMode := fileMode(t, filepath.Join(reference, "written"))

			// An in-place multi-platform export into an existing directory
			// writes every blob and both metadata files with replaceFile.
			stubOCIExporter(t, nil)
			platforms := []ispec.Platform{ociExportAMD64, ociExportARM64}
			results, patchPlatforms := namedOCIExportResults(t, platforms)
			output := t.TempDir()
			require.NoError(t, CreateOCILayoutFromResultsWithContext(t.Context(), output, results, patchPlatforms, namedOCIExportOptions(false)))
			assertNamedOCILayout(t, output, platforms)

			assert.Equal(t, metadataMode, fileMode(t, filepath.Join(output, ispec.ImageIndexFile)))
			assert.Equal(t, metadataMode, fileMode(t, filepath.Join(output, ispec.ImageLayoutFile)))
			blobs, err := filepath.Glob(filepath.Join(output, "blobs", "sha256", "*"))
			require.NoError(t, err)
			require.NotEmpty(t, blobs)
			for _, blob := range blobs {
				assert.Equal(t, blobMode, fileMode(t, blob), filepath.Base(blob))
			}

			// Preserved blobs that main wrote with os.WriteFile(0o600) keep that.
			path := filepath.Join(t.TempDir(), "preserved")
			require.NoError(t, replaceFile(path, strings.NewReader("preserved"), 0o600))
			assert.Equal(t, metadataMode, fileMode(t, path))
		})
	}
}
