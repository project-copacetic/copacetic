package buildkit

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cancelingReader cancels its context after the first read, as a timeout
// arriving while a large blob is copied would.
type cancelingReader struct {
	reader io.Reader
	cancel context.CancelFunc
	reads  int
}

func (r *cancelingReader) Read(p []byte) (int, error) {
	r.reads++
	n, err := r.reader.Read(p)
	r.cancel()
	return n, err
}

func TestCopyWithContextStopsAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	source := &cancelingReader{reader: bytes.NewReader(bytes.Repeat([]byte("x"), 8<<20)), cancel: cancel}
	var copied bytes.Buffer
	err := copyWithContext(ctx, &copied, source)
	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, 1, source.reads, "no further reads after cancellation")
	assert.Less(t, copied.Len(), 8<<20)

	copied.Reset()
	require.NoError(t, copyWithContext(t.Context(), &copied, bytes.NewReader([]byte("complete"))))
	assert.Equal(t, "complete", copied.String())
}

func TestExportHelpersObserveCancellation(t *testing.T) {
	canceled, cancel := context.WithCancel(t.Context())
	cancel()

	source := t.TempDir()
	blob := filepath.Join(source, "blobs", "sha256", "0123")
	require.NoError(t, os.MkdirAll(filepath.Dir(blob), 0o755))
	require.NoError(t, os.WriteFile(blob, []byte("blob"), 0o600))
	destination := t.TempDir()
	copied := make(map[string]bool)
	require.ErrorIs(t, copyBlobs(canceled, filepath.Join(source, "blobs"), filepath.Join(destination, "blobs"), copied), context.Canceled)
	require.ErrorIs(t, copyBlobsToOutput(canceled, destination, source, copied), context.Canceled)
	assert.Empty(t, copied)
	_, err := os.Stat(filepath.Join(destination, "blobs", "sha256", "0123"))
	assert.True(t, os.IsNotExist(err), "a canceled copy writes no blob")

	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	require.NoError(t, writer.WriteHeader(&tar.Header{Name: "index.json", Mode: 0o644, Size: 2}))
	_, err = writer.Write([]byte("{}"))
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	tarPath := filepath.Join(t.TempDir(), "image.tar")
	require.NoError(t, os.WriteFile(tarPath, archive.Bytes(), 0o600))
	extractDir := filepath.Join(t.TempDir(), "extract")
	require.ErrorIs(t, extractTarToDirectory(canceled, tarPath, extractDir), context.Canceled)
	_, err = os.Stat(filepath.Join(extractDir, "index.json"))
	assert.True(t, os.IsNotExist(err), "a canceled extraction does not run tar")

	require.NoError(t, extractTarToDirectory(t.Context(), tarPath, extractDir))
	data, err := os.ReadFile(filepath.Join(extractDir, "index.json"))
	require.NoError(t, err)
	assert.Equal(t, "{}", string(data))
}
