package ocilayout

import (
	"testing"

	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// An index child without a descriptor platform whose config is not an image
// config is a pre-OCI 1.1 artifact. It must be skipped, not rejected.
func TestIndexSkipsLegacyArtifactChildWithoutPlatform(t *testing.T) {
	root := t.TempDir()
	image := newImageManifest(t, root, &ocispec.Platform{OS: "linux", Architecture: "amd64"}, nil, nil)
	config := writeBlob(t, root, "application/vnd.cncf.helm.config.v1+json", []byte(`{"name":"chart","version":"1.0.0"}`))
	layer := writeBlob(t, root, "application/vnd.cncf.helm.chart.content.v1.tar+gzip", []byte("chart"))
	artifact := writeBlob(t, root, ocispec.MediaTypeImageManifest, marshalJSON(t, ocispec.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    config,
		Layers:    []ocispec.Descriptor{layer},
	}))
	index := writeBlob(t, root, ocispec.MediaTypeImageIndex, marshalJSON(t, ocispec.Index{
		Versioned: specs.Versioned{SchemaVersion: 2}, Manifests: []ocispec.Descriptor{image, artifact},
	}))
	newLayoutAt(t, root, []ocispec.Descriptor{index})
	source, err := Open(t.Context(), root, "", "")
	require.NoError(t, err)
	found, err := source.Platforms(t.Context())
	require.NoError(t, err)
	assert.Equal(t, []ocispec.Platform{{OS: "linux", Architecture: "amd64"}}, found)
}
