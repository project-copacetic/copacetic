//go:build unix

package buildkit

import (
	"archive/tar"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// BuildKit's OCI exporter writes only regular files and directories. A layout
// export holding anything else is rejected before it is read or copied: a
// symlink would be followed to a file outside the export, and opening a FIFO
// blocks.
func TestOCIExportRejectsNonRegularEntries(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "outside")
	require.NoError(t, os.WriteFile(outside, []byte("not part of the export"), 0o600))
	name := "blobs/sha256/" + digest.FromString("unreferenced").Encoded()
	entries := []struct {
		kind   string
		header tar.Header
	}{
		{kind: "symlink", header: tar.Header{Name: name, Typeflag: tar.TypeSymlink, Linkname: outside, Mode: 0o777}},
		{kind: "FIFO", header: tar.Header{Name: name, Typeflag: tar.TypeFifo, Mode: 0o644}},
	}
	paths := []struct {
		name               string
		patched, preserved []ispec.Platform
	}{
		{name: "single platform", patched: []ispec.Platform{ociExportAMD64}},
		{name: "multi-platform", patched: []ispec.Platform{ociExportAMD64, ociExportARM64}},
		{name: "mixed", patched: []ispec.Platform{ociExportAMD64}, preserved: []ispec.Platform{ociExportARM64}},
	}
	for _, entry := range entries {
		for _, path := range paths {
			t.Run(path.name+" export with a "+entry.kind, func(t *testing.T) {
				header := entry.header
				exports := map[string]fakeOCIExport{PlatformKey(ociExportAMD64): {extraEntry: &header}}
				// The multi-platform and mixed paths extract exports under
				// the temp directory.
				tmp := t.TempDir()
				t.Setenv("TMPDIR", tmp)
				released := releaseFIFOsAfter(tmp, 10*time.Second)
				run, err := runOCIExport(t, path.patched, path.preserved, exports)
				assert.False(t, released(), "the export blocked opening a FIFO")
				require.ErrorContains(t, err, "OCI export for platform linux/amd64 holds "+name+", which is not a regular file or directory")
				assertOCIOutputAbsent(t, run.output)
			})
		}
	}
}

// releaseFIFOsAfter opens every FIFO under root once delay has passed, so that
// an open blocked on one returns. The returned function stops the wait and
// reports whether the FIFOs had to be released.
func releaseFIFOsAfter(root string, delay time.Duration) func() bool {
	stop := make(chan struct{})
	released := make(chan bool, 1)
	go func() {
		select {
		case <-stop:
			released <- false
		case <-time.After(delay):
			_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
				if err == nil && entry.Type()&fs.ModeNamedPipe != 0 {
					if fifo, openErr := os.OpenFile(path, os.O_RDWR, 0); openErr == nil {
						_ = fifo.Close()
					}
				}
				return nil
			})
			released <- true
		}
	}()
	return func() bool {
		close(stop)
		return <-released
	}
}
