//go:build unix

package ocilayout

import (
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
)

// A FIFO in blobs/ must be rejected without being opened: opening a FIFO
// blocks until a writer appears and does not observe the context.
func TestOpenRejectsFIFOBlob(t *testing.T) {
	fixture := newSingleLayout(t, nil)
	data, err := os.ReadFile(filepath.Join(fixture.path, "blobs", "sha256", fixture.manifests[0].Digest.Encoded()))
	require.NoError(t, err)
	var manifest ocispec.Manifest
	require.NoError(t, json.Unmarshal(data, &manifest))
	layer := filepath.Join(fixture.path, "blobs", "sha256", manifest.Layers[0].Digest.Encoded())
	require.NoError(t, os.Remove(layer))
	require.NoError(t, syscall.Mkfifo(layer, 0o600))
	t.Cleanup(func() {
		// Release an open that blocked on the FIFO, so a failing run still ends.
		if fifo, err := os.OpenFile(layer, os.O_RDWR, 0); err == nil {
			fifo.Close()
		}
	})

	ctx := t.Context()
	done := make(chan error, 1)
	go func() {
		_, err := Open(ctx, fixture.path, "", "")
		done <- err
	}()
	select {
	case err := <-done:
		require.ErrorContains(t, err, "is not a regular file")
	case <-time.After(5 * time.Second):
		t.Fatal("Open blocked opening a FIFO blob")
	}
}
