package ocilayout

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIndexInfersMissingDescriptorPlatforms(t *testing.T) {
	for _, count := range []int{1, 2} {
		for _, omitAll := range []bool{false, true} {
			t.Run(fmt.Sprintf("images=%d/omitAll=%v", count, omitAll), func(t *testing.T) {
				root := t.TempDir()
				platforms := []ocispec.Platform{
					{OS: "linux", Architecture: "amd64", OSVersion: "fixture.1", OSFeatures: []string{"a", "b"}},
					{OS: "linux", Architecture: "arm64", Variant: "v8"},
				}
				var manifests []ocispec.Descriptor
				for i := range count {
					desc := newImageManifest(t, root, &platforms[i], map[string]string{"example.descriptor": "kept"}, nil)
					if i == 0 || omitAll {
						desc.Platform = nil
					}
					manifests = append(manifests, desc)
				}
				index := writeBlob(t, root, ocispec.MediaTypeImageIndex, marshalJSON(t, ocispec.Index{
					Versioned: specs.Versioned{SchemaVersion: 2}, Manifests: manifests,
				}))
				fixture := newLayoutAt(t, root, []ocispec.Descriptor{index})
				before := snapshotLayout(t, root)
				source, err := Open(t.Context(), fixture.path, "", "")
				require.NoError(t, err)
				found, err := source.Platforms(t.Context())
				require.NoError(t, err)
				want := append([]ocispec.Platform(nil), platforms[:count]...)
				if count == 2 {
					want[1].Variant = ""
				}
				assert.Equal(t, want, found)

				output := t.TempDir()
				copied := make(map[string]bool)
				for i := range count {
					desc, err := source.PlatformDescriptor(t.Context(), &want[i])
					require.NoError(t, err)
					assert.Equal(t, manifests[i], *desc, "inference must not rewrite the source descriptor")
					desc, err = source.CopyPlatform(t.Context(), output, &want[i], copied)
					require.NoError(t, err)
					assert.Equal(t, manifests[i], *desc, "preserved descriptors retain omitted platform metadata")
				}
				for rel := range copied {
					original, err := os.ReadFile(filepath.Join(root, "blobs", rel))
					require.NoError(t, err)
					preserved, err := os.ReadFile(filepath.Join(output, "blobs", rel))
					require.NoError(t, err)
					assert.Equal(t, original, preserved)
				}
				assert.Equal(t, before, snapshotLayout(t, root))
			})
		}
	}
}

func TestIndexValidatesInferredPlatformLayers(t *testing.T) {
	root := t.TempDir()
	desc := newImageManifest(t, root, &ocispec.Platform{OS: "linux", Architecture: "amd64"}, nil, nil)
	desc.Platform = nil
	var manifest ocispec.Manifest
	data, err := os.ReadFile(filepath.Join(root, "blobs", desc.Digest.Algorithm().String(), desc.Digest.Encoded()))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, &manifest))
	layer := manifest.Layers[0].Digest
	require.NoError(t, os.WriteFile(filepath.Join(root, "blobs", layer.Algorithm().String(), layer.Encoded()), []byte("corrupt"), 0o600))
	index := writeBlob(t, root, ocispec.MediaTypeImageIndex, marshalJSON(t, ocispec.Index{
		Versioned: specs.Versioned{SchemaVersion: 2}, Manifests: []ocispec.Descriptor{desc},
	}))
	newLayoutAt(t, root, []ocispec.Descriptor{index})
	_, err = Open(t.Context(), root, "", "")
	require.ErrorContains(t, err, "layer")
}

func TestIndexInferenceStillFiltersArtifacts(t *testing.T) {
	root := t.TempDir()
	image := newImageManifest(t, root, &ocispec.Platform{OS: "linux", Architecture: "amd64"}, nil, nil)
	image.Platform = nil
	unknown := newImageManifest(t, root, &ocispec.Platform{OS: "unknown", Architecture: "unknown"}, nil, nil)
	unknown.Platform = nil
	artifact := writeBlob(t, root, ocispec.MediaTypeImageManifest, marshalJSON(t, ocispec.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2}, ArtifactType: nonImageMediaType,
	}))
	index := writeBlob(t, root, ocispec.MediaTypeImageIndex, marshalJSON(t, ocispec.Index{
		Versioned: specs.Versioned{SchemaVersion: 2}, Manifests: []ocispec.Descriptor{image, unknown, artifact},
	}))
	newLayoutAt(t, root, []ocispec.Descriptor{index})
	source, err := Open(t.Context(), root, "", "")
	require.NoError(t, err)
	found, err := source.Platforms(t.Context())
	require.NoError(t, err)
	assert.Equal(t, []ocispec.Platform{{OS: "linux", Architecture: "amd64"}}, found)
}
