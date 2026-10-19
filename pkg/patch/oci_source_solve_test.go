package patch

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/moby/buildkit/client"
	digest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/project-copacetic/copacetic/pkg/ocilayout"
)

func writeSolveTestBlob(t *testing.T, root, mediaType string, data []byte) ispec.Descriptor {
	t.Helper()
	dgst := digest.FromBytes(data)
	path := filepath.Join(root, "blobs", dgst.Algorithm().String(), dgst.Encoded())
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return ispec.Descriptor{MediaType: mediaType, Digest: dgst, Size: int64(len(data))}
}

func openSolveTestSource(t *testing.T) *ocilayout.Source {
	t.Helper()
	root := t.TempDir()
	config := writeSolveTestBlob(t, root, ispec.MediaTypeImageConfig,
		[]byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}`))
	manifestData, err := json.Marshal(map[string]any{
		"schemaVersion": 2,
		"mediaType":     ispec.MediaTypeImageManifest,
		"config":        config,
		"layers":        []ispec.Descriptor{},
	})
	require.NoError(t, err)
	manifest := writeSolveTestBlob(t, root, ispec.MediaTypeImageManifest, manifestData)
	indexData, err := json.Marshal(map[string]any{
		"schemaVersion": 2,
		"mediaType":     ispec.MediaTypeImageIndex,
		"manifests":     []ispec.Descriptor{manifest},
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(root, ispec.ImageLayoutFile), []byte(`{"imageLayoutVersion":"1.0.0"}`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, ispec.ImageIndexFile), indexData, 0o600))
	source, err := ocilayout.Open(t.Context(), root, "", "")
	require.NoError(t, err)
	return source
}

func TestPrepareOCISourceSolveDoesNotNameWorkerImage(t *testing.T) {
	source := openSolveTestSource(t)
	_, pipeW := io.Pipe()
	defer pipeW.Close()
	buildConfig, err := createBuildConfig(
		"example.com/acme/app:1.0-patched", true, false, pipeW,
		map[string]string{"org.opencontainers.image.version": "1.0"}, "1.0-patched", "", false,
	)
	require.NoError(t, err)
	require.Equal(t, "example.com/acme/app:1.0-patched", buildConfig.SolveOpt.Exports[0].Attrs["name"])

	prepareOCISourceSolve(&buildConfig.SolveOpt, source)

	require.Len(t, buildConfig.SolveOpt.Exports, 1)
	export := buildConfig.SolveOpt.Exports[0]
	assert.Equal(t, client.ExporterImage, export.Type)
	assert.Nil(t, export.Output, "the patched result must not be streamed for a daemon load")
	assert.NotContains(t, export.Attrs, "name", "a named image export creates or replaces that tag in the worker image store")
	assert.NotContains(t, export.Attrs, "push")
	assert.Equal(t, "true", export.Attrs["oci-mediatypes"])
	assert.Contains(t, buildConfig.SolveOpt.OCIStores, source.StoreID, "the solve must read the layout through the session store")
}
