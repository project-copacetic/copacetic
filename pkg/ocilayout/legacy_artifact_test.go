package ocilayout

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// legacyHelmArtifact writes a pre-OCI 1.1 artifact: an image-manifest media
// type with a non-image config and no artifactType or platform.
func legacyHelmArtifact(t *testing.T, root string, annotations map[string]string) ocispec.Descriptor {
	t.Helper()
	config := writeBlob(t, root, "application/vnd.cncf.helm.config.v1+json", []byte(`{"name":"chart","version":"1.0.0"}`))
	layer := writeBlob(t, root, "application/vnd.cncf.helm.chart.content.v1.tar+gzip", []byte("chart"))
	desc := writeBlob(t, root, ocispec.MediaTypeImageManifest, marshalJSON(t, ocispec.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    config,
		Layers:    []ocispec.Descriptor{layer},
	}))
	desc.Annotations = annotations
	return desc
}

// An index child without a descriptor platform whose config is not an image
// config is a pre-OCI 1.1 artifact. It must be skipped, not rejected.
func TestIndexSkipsLegacyArtifactChildWithoutPlatform(t *testing.T) {
	root := t.TempDir()
	image := newImageManifest(t, root, &ocispec.Platform{OS: "linux", Architecture: "amd64"}, nil, nil)
	artifact := legacyHelmArtifact(t, root, nil)
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

// A top-level pre-OCI 1.1 artifact must not count as an image or make a shared
// selector ambiguous. Only a verified body establishes that; a corrupt body
// stays a candidate.
func TestTopLevelSelectionIgnoresLegacyArtifacts(t *testing.T) {
	shared := map[string]string{"io.containerd.image.name": "example.com/acme/app:1.0", ocispec.AnnotationRefName: "1.0"}
	for _, test := range []struct {
		name           string
		selector       string
		selectArtifact bool
		corrupt        bool
		wantError      string
	}{
		{name: "implicit selection"},
		{name: "shared image name", selector: "example.com/acme/app:1.0"},
		{name: "shared tag", selector: "1.0"},
		{name: "artifact digest is still rejected", selectArtifact: true, wantError: "unsupported config mediaType"},
		{name: "corrupt artifact body stays a candidate", corrupt: true, wantError: "2 top-level images"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			image := newImageManifest(t, root, &ocispec.Platform{OS: "linux", Architecture: "amd64"}, shared, nil)
			artifact := legacyHelmArtifact(t, root, shared)
			if test.corrupt {
				path := filepath.Join(root, "blobs", artifact.Digest.Algorithm().String(), artifact.Digest.Encoded())
				require.NoError(t, os.WriteFile(path, []byte("corrupt"), 0o600))
			}
			newLayoutAt(t, root, []ocispec.Descriptor{artifact, image})
			selector := test.selector
			if test.selectArtifact {
				selector = artifact.Digest.String()
			}
			source, err := Open(t.Context(), root, "", selector)
			if test.wantError != "" {
				require.ErrorContains(t, err, test.wantError)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, image.Digest, source.Descriptor.Digest)
		})
	}
}
