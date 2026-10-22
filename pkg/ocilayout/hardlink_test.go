package ocilayout

import (
	"os"
	"path/filepath"
	"testing"

	digest "github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateNotInputFile(t *testing.T) {
	fixture := newSingleLayout(t, nil)
	source, err := Open(t.Context(), fixture.path, "", "")
	require.NoError(t, err)
	external := t.TempDir()
	blob := filepath.Join(fixture.path, "blobs", fixture.manifests[0].Digest.Algorithm().String(), fixture.manifests[0].Digest.Encoded())

	indexLink := filepath.Join(external, "index-link.json")
	require.NoError(t, os.Link(filepath.Join(fixture.path, "index.json"), indexLink))
	blobLink := filepath.Join(external, "blob-link.json")
	require.NoError(t, os.Link(blob, blobLink))
	symlinkToHardLink := filepath.Join(external, "symlink.json")
	require.NoError(t, os.Symlink(blobLink, symlinkToHardLink))
	unrelated := filepath.Join(external, "existing.json")
	require.NoError(t, os.WriteFile(unrelated, []byte("{}"), 0o600))

	for _, path := range []string{indexLink, blobLink, symlinkToHardLink} {
		err := source.ValidateNotInputFile(path)
		require.ErrorContains(t, err, "is the same file as OCI layout input file", path)
	}
	for _, path := range []string{"", unrelated, filepath.Join(external, "missing.json"), os.DevNull} {
		require.NoError(t, source.ValidateNotInputFile(path), path)
	}
	data, err := os.ReadFile(blob)
	require.NoError(t, err)
	assert.Equal(t, fixture.manifests[0].Digest, digest.FromBytes(data), "validation does not modify the input")
}
