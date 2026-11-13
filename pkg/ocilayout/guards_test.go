package ocilayout

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/moby/buildkit/solver/pb"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Open must reject an index or manifest that does not declare the version or
// media type it is read as, rather than interpret it as one.
func TestOpenRejectsUnsupportedIndexAndManifestVersions(t *testing.T) {
	platform := &ocispec.Platform{OS: "linux", Architecture: "amd64"}
	writeIndexJSON := func(t *testing.T, root string, index any) {
		t.Helper()
		require.NoError(t, os.WriteFile(filepath.Join(root, ocispec.ImageLayoutFile), marshalJSON(t, ocispec.ImageLayout{Version: ocispec.ImageLayoutVersion}), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(root, ocispec.ImageIndexFile), marshalJSON(t, index), 0o600))
	}
	for _, tc := range []struct {
		name    string
		write   func(t *testing.T, root string)
		wantErr string
	}{
		{
			name: "index.json schemaVersion",
			write: func(t *testing.T, root string) {
				desc := newImageManifest(t, root, platform, nil, nil)
				writeIndexJSON(t, root, ocispec.Index{Versioned: specs.Versioned{SchemaVersion: 1}, MediaType: ocispec.MediaTypeImageIndex, Manifests: []ocispec.Descriptor{desc}})
			},
			wantErr: "invalid index.json schemaVersion 1",
		},
		{
			name: "index.json mediaType",
			write: func(t *testing.T, root string) {
				desc := newImageManifest(t, root, platform, nil, nil)
				writeIndexJSON(t, root, ocispec.Index{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispec.MediaTypeImageManifest, Manifests: []ocispec.Descriptor{desc}})
			},
			wantErr: "invalid index.json mediaType",
		},
		{
			name: "image index body schemaVersion",
			write: func(t *testing.T, root string) {
				desc := newImageManifest(t, root, platform, nil, nil)
				child := writeBlob(t, root, ocispec.MediaTypeImageIndex, marshalJSON(t, ocispec.Index{
					Versioned: specs.Versioned{SchemaVersion: 1}, MediaType: ocispec.MediaTypeImageIndex, Manifests: []ocispec.Descriptor{desc},
				}))
				writeIndexJSON(t, root, ocispec.Index{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispec.MediaTypeImageIndex, Manifests: []ocispec.Descriptor{child}})
			},
			wantErr: "has schemaVersion 1 (expected 2)",
		},
		{
			name: "image manifest body schemaVersion",
			write: func(t *testing.T, root string) {
				config := writeBlob(t, root, ocispec.MediaTypeImageConfig, marshalJSON(t, ocispec.Image{Platform: *platform, RootFS: ocispec.RootFS{Type: "layers"}}))
				manifest := writeBlob(t, root, ocispec.MediaTypeImageManifest, marshalJSON(t, ocispec.Manifest{
					Versioned: specs.Versioned{SchemaVersion: 1}, MediaType: ocispec.MediaTypeImageManifest, Config: config, Layers: []ocispec.Descriptor{},
				}))
				writeIndexJSON(t, root, ocispec.Index{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispec.MediaTypeImageIndex, Manifests: []ocispec.Descriptor{manifest}})
			},
			wantErr: "has schemaVersion 1 (expected 2)",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			tc.write(t, root)
			_, err := Open(t.Context(), root, "", "")
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

// The state for a platform must read the layout through its content store and
// be bound to that platform's manifest, not resolved again by name or index.
func TestSourceStateUsesLayoutStoreAndPlatformManifest(t *testing.T) {
	root := t.TempDir()
	amd64 := newImageManifest(t, root, &ocispec.Platform{OS: "linux", Architecture: "amd64"}, nil, nil)
	arm64 := newImageManifest(t, root, &ocispec.Platform{OS: "linux", Architecture: "arm64"}, nil, nil)
	index := writeBlob(t, root, ocispec.MediaTypeImageIndex, marshalJSON(t, ocispec.Index{
		Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispec.MediaTypeImageIndex, Manifests: []ocispec.Descriptor{amd64, arm64},
	}))
	newLayoutAt(t, root, []ocispec.Descriptor{index})
	source, err := Open(t.Context(), root, "", "")
	require.NoError(t, err)

	state, err := source.State(t.Context(), arm64.Platform, []byte(`{"architecture":"arm64","os":"linux"}`))
	require.NoError(t, err)
	def, err := state.Marshal(t.Context())
	require.NoError(t, err)
	var sources []*pb.SourceOp
	for _, data := range def.Def {
		var op pb.Op
		require.NoError(t, op.UnmarshalVT(data))
		if op.GetSource() != nil {
			sources = append(sources, op.GetSource())
		}
	}
	require.Len(t, sources, 1)
	assert.Equal(t, "oci-layout://"+source.StoreID+"/image@"+arm64.Digest.String(), sources[0].Identifier)
	assert.Equal(t, source.StoreID, sources[0].Attrs[pb.AttrOCILayoutStoreID])
}

// cancelAfterCopyContext reports cancellation once the staged copy of a blob
// holds all of its bytes: after the copy completes and before it is published.
type cancelAfterCopyContext struct {
	context.Context
	dir         string
	destination string
	size        int64
}

func (c cancelAfterCopyContext) Err() error {
	entries, _ := os.ReadDir(c.dir)
	for _, entry := range entries {
		if entry.Name() == filepath.Base(c.destination) {
			continue
		}
		if info, err := entry.Info(); err == nil && info.Size() == c.size {
			return context.Canceled
		}
	}
	return c.Context.Err()
}

// A copy canceled after its bytes are staged must not be published.
func TestCopyBlobCanceledAfterCopyIsNotPublished(t *testing.T) {
	fixture := newSingleLayout(t, nil)
	source, err := Open(t.Context(), fixture.path, "", "")
	require.NoError(t, err)
	desc := fixture.manifests[0]
	output := t.TempDir()
	dir := filepath.Join(output, "blobs", desc.Digest.Algorithm().String())
	destination := filepath.Join(dir, desc.Digest.Encoded())
	require.NoError(t, os.MkdirAll(dir, 0o755))

	copied := make(map[string]bool)
	ctx := cancelAfterCopyContext{Context: t.Context(), dir: dir, destination: destination, size: desc.Size}
	err = source.copyBlob(ctx, output, &desc, copied)
	require.ErrorIs(t, err, context.Canceled)
	assert.NoFileExists(t, destination)
	assert.Empty(t, copied)
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Empty(t, entries, "the staged copy must be removed")
}
