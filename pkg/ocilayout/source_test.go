package ocilayout

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/moby/buildkit/client"
	"github.com/moby/buildkit/client/llb/sourceresolver"
	digest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type layoutFixture struct {
	path      string
	manifests []ocispec.Descriptor
}

type recordingResolver struct {
	ref string
	opt sourceresolver.Opt
}

func (r *recordingResolver) ResolveImageConfig(_ context.Context, ref string, opt sourceresolver.Opt) (string, digest.Digest, []byte, error) {
	r.ref = ref
	r.opt = opt
	return ref, digest.FromString(ref), []byte(`{"architecture":"amd64","os":"linux"}`), nil
}

func writeBlob(t *testing.T, root, mediaType string, data []byte) ocispec.Descriptor {
	t.Helper()
	dgst := digest.FromBytes(data)
	path := filepath.Join(root, "blobs", dgst.Algorithm().String(), dgst.Encoded())
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return ocispec.Descriptor{MediaType: mediaType, Digest: dgst, Size: int64(len(data))}
}

func marshalJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	require.NoError(t, err)
	return data
}

func snapshotLayout(t *testing.T, root string) []string {
	t.Helper()
	var snapshot []string
	require.NoError(t, filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		snapshot = append(snapshot, rel+":"+digest.FromBytes(data).String())
		return nil
	}))
	sort.Strings(snapshot)
	return snapshot
}

func newImageManifest(t *testing.T, root string, platform *ocispec.Platform, descriptorAnnotations, bodyAnnotations map[string]string) ocispec.Descriptor {
	t.Helper()
	config := ocispec.Image{
		Platform: *platform,
		RootFS: ocispec.RootFS{
			Type:    "layers",
			DiffIDs: []digest.Digest{digest.FromString("uncompressed-" + platform.Architecture)},
		},
	}
	configDesc := writeBlob(t, root, ocispec.MediaTypeImageConfig, marshalJSON(t, config))
	layerDesc := writeBlob(t, root, ocispec.MediaTypeImageLayer, []byte("layer-"+platform.Architecture))
	manifest := ocispec.Manifest{
		Versioned:   specs.Versioned{SchemaVersion: 2},
		MediaType:   ocispec.MediaTypeImageManifest,
		Config:      configDesc,
		Layers:      []ocispec.Descriptor{layerDesc},
		Annotations: bodyAnnotations,
	}
	desc := writeBlob(t, root, ocispec.MediaTypeImageManifest, marshalJSON(t, manifest))
	desc.Platform = platform
	desc.Annotations = descriptorAnnotations
	return desc
}

func newSingleLayout(t *testing.T, annotations map[string]string) layoutFixture {
	t.Helper()
	root := t.TempDir()
	desc := newImageManifest(t, root, &ocispec.Platform{OS: "linux", Architecture: "amd64"}, annotations, nil)
	require.NoError(t, os.WriteFile(
		filepath.Join(root, ocispec.ImageLayoutFile),
		marshalJSON(t, ocispec.ImageLayout{Version: ocispec.ImageLayoutVersion}),
		0o600,
	))
	index := ocispec.Index{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispec.MediaTypeImageIndex, Manifests: []ocispec.Descriptor{desc}}
	require.NoError(t, os.WriteFile(filepath.Join(root, ocispec.ImageIndexFile), marshalJSON(t, index), 0o600))
	return layoutFixture{path: root, manifests: []ocispec.Descriptor{desc}}
}

func TestOpenSelectsDescriptor(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
		selector    func(ocispec.Descriptor) string
	}{
		{
			name:        "full image name",
			annotations: map[string]string{annotationImageName: "registry.example.com/acme/app:1.0"},
			selector:    func(ocispec.Descriptor) string { return "registry.example.com/acme/app:1.0" },
		},
		{
			name:        "tag",
			annotations: map[string]string{ocispec.AnnotationRefName: "stable"},
			selector:    func(ocispec.Descriptor) string { return "registry.example.com/acme/app:stable" },
		},
		{
			name: "digest",
			selector: func(desc ocispec.Descriptor) string {
				return "registry.invalid/acme/app@" + desc.Digest.String()
			},
		},
		{
			name:     "single entry fallback",
			selector: func(ocispec.Descriptor) string { return "registry.invalid/unrelated:logical" },
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newSingleLayout(t, test.annotations)
			if test.name != "single entry fallback" {
				other := newImageManifest(
					t,
					fixture.path,
					&ocispec.Platform{OS: "linux", Architecture: "arm64"},
					map[string]string{
						annotationImageName:       "registry.example.com/acme/other:elsewhere",
						ocispec.AnnotationRefName: "elsewhere",
					},
					nil,
				)
				fixture = newLayoutAt(t, fixture.path, []ocispec.Descriptor{fixture.manifests[0], other})
			}
			source, err := Open(t.Context(), fixture.path, filepath.Join(t.TempDir(), "output"), test.selector(fixture.manifests[0]))
			require.NoError(t, err)
			assert.Equal(t, fixture.manifests[0].Digest, source.Descriptor.Digest)
		})
	}
}

func TestOpenRejectsMissingAndAmbiguousSelectors(t *testing.T) {
	root := t.TempDir()
	first := newImageManifest(t, root, &ocispec.Platform{OS: "linux", Architecture: "amd64"}, map[string]string{ocispec.AnnotationRefName: "one"}, nil)
	second := newImageManifest(t, root, &ocispec.Platform{OS: "linux", Architecture: "arm64"}, map[string]string{ocispec.AnnotationRefName: "two"}, nil)
	fixture := newLayoutAt(t, root, []ocispec.Descriptor{first, second})

	_, err := Open(t.Context(), fixture.path, filepath.Join(t.TempDir(), "output"), "registry.invalid/acme:missing")
	require.ErrorContains(t, err, "ambiguous or unavailable")
	assert.ErrorContains(t, err, first.Digest.String())
	assert.ErrorContains(t, err, "tag=two")

	first.Annotations[ocispec.AnnotationRefName] = "same"
	second.Annotations[ocispec.AnnotationRefName] = "same"
	fixture = newLayoutAt(t, root, []ocispec.Descriptor{first, second})
	_, err = Open(t.Context(), fixture.path, filepath.Join(t.TempDir(), "output"), "registry.invalid/acme:same")
	require.ErrorContains(t, err, "2 descriptors matching tag same")
}

func newLayoutAt(t *testing.T, root string, descriptors []ocispec.Descriptor) layoutFixture {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(root, ocispec.ImageLayoutFile), marshalJSON(t, ocispec.ImageLayout{Version: ocispec.ImageLayoutVersion}), 0o600))
	index := ocispec.Index{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispec.MediaTypeImageIndex, Manifests: descriptors}
	require.NoError(t, os.WriteFile(filepath.Join(root, ocispec.ImageIndexFile), marshalJSON(t, index), 0o600))
	return layoutFixture{path: root, manifests: descriptors}
}

func TestOpenRejectsInvalidLayoutAndBlobContent(t *testing.T) {
	t.Run("invalid layout version", func(t *testing.T) {
		fixture := newSingleLayout(t, nil)
		require.NoError(t, os.WriteFile(filepath.Join(fixture.path, ocispec.ImageLayoutFile), []byte(`{"imageLayoutVersion":"2.0.0"}`), 0o600))
		_, err := Open(t.Context(), fixture.path, filepath.Join(t.TempDir(), "output"), "example.com/app:latest")
		require.ErrorContains(t, err, "unsupported OCI image layout version")
	})

	t.Run("symlinked layout metadata", func(t *testing.T) {
		fixture := newSingleLayout(t, nil)
		metadataPath := filepath.Join(fixture.path, ocispec.ImageLayoutFile)
		externalPath := filepath.Join(t.TempDir(), ocispec.ImageLayoutFile)
		require.NoError(t, os.WriteFile(externalPath, []byte(`{"imageLayoutVersion":"1.0.0"}`), 0o600))
		require.NoError(t, os.Remove(metadataPath))
		require.NoError(t, os.Symlink(externalPath, metadataPath))
		_, err := Open(t.Context(), fixture.path, filepath.Join(t.TempDir(), "output"), "example.com/app:latest")
		require.ErrorContains(t, err, "must be a regular file")
	})

	t.Run("missing manifest blob", func(t *testing.T) {
		fixture := newSingleLayout(t, nil)
		require.NoError(t, os.Remove(filepath.Join(fixture.path, "blobs", "sha256", fixture.manifests[0].Digest.Encoded())))
		_, err := Open(t.Context(), fixture.path, filepath.Join(t.TempDir(), "output"), "example.com/app:latest")
		require.ErrorContains(t, err, "resolve blob path")
	})

	t.Run("corrupt layer blob", func(t *testing.T) {
		fixture := newSingleLayout(t, nil)
		var manifest ocispec.Manifest
		data, err := os.ReadFile(filepath.Join(fixture.path, "blobs", "sha256", fixture.manifests[0].Digest.Encoded()))
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(data, &manifest))
		require.NoError(t, os.WriteFile(filepath.Join(fixture.path, "blobs", "sha256", manifest.Layers[0].Digest.Encoded()), []byte("corrupt"), 0o600))
		_, err = Open(t.Context(), fixture.path, filepath.Join(t.TempDir(), "output"), "example.com/app:latest")
		require.ErrorContains(t, err, "size mismatch")
	})

	t.Run("same-size digest mismatch", func(t *testing.T) {
		fixture := newSingleLayout(t, nil)
		var manifest ocispec.Manifest
		data, err := os.ReadFile(filepath.Join(fixture.path, "blobs", "sha256", fixture.manifests[0].Digest.Encoded()))
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(data, &manifest))
		corrupt := []byte("layer-amd63")
		require.Equal(t, manifest.Layers[0].Size, int64(len(corrupt)))
		require.NoError(t, os.WriteFile(filepath.Join(fixture.path, "blobs", "sha256", manifest.Layers[0].Digest.Encoded()), corrupt, 0o600))
		_, err = Open(t.Context(), fixture.path, filepath.Join(t.TempDir(), "output"), "example.com/app:latest")
		require.ErrorContains(t, err, "digest mismatch")
	})

	t.Run("blob symlink escapes layout", func(t *testing.T) {
		fixture := newSingleLayout(t, nil)
		var manifest ocispec.Manifest
		data, err := os.ReadFile(filepath.Join(fixture.path, "blobs", "sha256", fixture.manifests[0].Digest.Encoded()))
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(data, &manifest))
		layerPath := filepath.Join(fixture.path, "blobs", "sha256", manifest.Layers[0].Digest.Encoded())
		externalPath := filepath.Join(t.TempDir(), "layer")
		require.NoError(t, os.WriteFile(externalPath, []byte("layer-amd64"), 0o600))
		require.NoError(t, os.Remove(layerPath))
		require.NoError(t, os.Symlink(externalPath, layerPath))
		_, err = Open(t.Context(), fixture.path, filepath.Join(t.TempDir(), "output"), "example.com/app:latest")
		require.ErrorContains(t, err, "resolves outside OCI layout")
	})
}

func TestOpenRejectsInputOutputOverlap(t *testing.T) {
	parent := t.TempDir()
	fixtureRoot := filepath.Join(parent, "input")
	require.NoError(t, os.Mkdir(fixtureRoot, 0o755))
	desc := newImageManifest(t, fixtureRoot, &ocispec.Platform{OS: "linux", Architecture: "amd64"}, nil, nil)
	fixture := newLayoutAt(t, fixtureRoot, []ocispec.Descriptor{desc})
	for _, output := range []string{fixture.path, filepath.Join(fixture.path, "patched"), parent} {
		_, err := Open(t.Context(), fixture.path, output, "example.com/app:latest")
		require.ErrorContains(t, err, "distinct, non-overlapping")
	}
}

func TestOpenAcceptsDockerMediaTypes(t *testing.T) {
	root := t.TempDir()
	platform := ocispec.Platform{OS: "linux", Architecture: "amd64"}
	config := ocispec.Image{Platform: platform, RootFS: ocispec.RootFS{Type: "layers", DiffIDs: []digest.Digest{digest.FromString("docker-layer")}}}
	configDesc := writeBlob(t, root, dockerMediaTypeConfig, marshalJSON(t, config))
	var layer bytes.Buffer
	writer := gzip.NewWriter(&layer)
	_, err := writer.Write([]byte("docker-layer"))
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	layerDesc := writeBlob(t, root, dockerMediaTypeLayer, layer.Bytes())
	manifest := ocispec.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: dockerMediaTypeManifest,
		Config:    configDesc,
		Layers:    []ocispec.Descriptor{layerDesc},
	}
	manifestDesc := writeBlob(t, root, dockerMediaTypeManifest, marshalJSON(t, manifest))
	manifestDesc.Platform = &platform
	fixture := newLayoutAt(t, root, []ocispec.Descriptor{manifestDesc})

	source, err := Open(t.Context(), fixture.path, filepath.Join(t.TempDir(), "output"), "example.com/acme/app:latest")
	require.NoError(t, err)
	available, err := source.Platforms(t.Context())
	require.NoError(t, err)
	require.Len(t, available, 1)
	assert.Equal(t, "amd64", available[0].Architecture)
}

func TestMultiPlatformMetadataCopyAndStoreBinding(t *testing.T) {
	root := t.TempDir()
	amd64 := newImageManifest(
		t,
		root,
		&ocispec.Platform{OS: "linux", Architecture: "amd64"},
		map[string]string{"descriptor.example": "kept"},
		map[string]string{"body.example": "kept"},
	)
	arm64 := newImageManifest(t, root, &ocispec.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}, nil, nil)
	unknown := arm64
	unknown.Platform = &ocispec.Platform{OS: "unknown", Architecture: "unknown"}
	artifact := ocispec.Descriptor{MediaType: "application/vnd.example.artifact", Digest: digest.FromString("artifact"), Size: 8}
	attestation := ocispec.Descriptor{
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: "application/vnd.example.attestation",
		Digest:       digest.FromString("attestation-not-present"),
		Size:         32,
		Platform:     &ocispec.Platform{OS: "unknown", Architecture: "unknown"},
	}
	imageIndex := ocispec.Index{
		Versioned:   specs.Versioned{SchemaVersion: 2},
		MediaType:   ocispec.MediaTypeImageIndex,
		Manifests:   []ocispec.Descriptor{amd64, arm64, unknown, artifact, attestation},
		Annotations: map[string]string{"index.example": "kept"},
	}
	indexDesc := writeBlob(t, root, ocispec.MediaTypeImageIndex, marshalJSON(t, imageIndex))
	indexDesc.Annotations = map[string]string{ocispec.AnnotationRefName: "stable"}
	fixture := newLayoutAt(t, root, []ocispec.Descriptor{indexDesc})
	before := snapshotLayout(t, fixture.path)

	source, err := Open(t.Context(), fixture.path, filepath.Join(t.TempDir(), "output"), "example.com/acme/app:stable")
	require.NoError(t, err)
	available, err := source.Platforms(t.Context())
	require.NoError(t, err)
	require.Len(t, available, 2)
	assert.Equal(t, "amd64", available[0].Architecture)
	assert.Equal(t, "", available[1].Variant)

	annotations, err := source.PlatformAnnotations(t.Context(), &ocispec.Platform{OS: "linux", Architecture: "amd64"})
	require.NoError(t, err)
	assert.Equal(t, "kept", annotations["body.example"])
	assert.Equal(t, "kept", annotations["descriptor.example"])
	indexAnnotations, err := source.IndexAnnotations(t.Context())
	require.NoError(t, err)
	assert.Equal(t, "kept", indexAnnotations["index.example"])

	output := t.TempDir()
	copied := make(map[string]bool)
	copiedDesc, err := source.CopyPlatform(t.Context(), output, &ocispec.Platform{OS: "linux", Architecture: "amd64"}, copied)
	require.NoError(t, err)
	assert.Equal(t, amd64, *copiedDesc)
	for rel := range copied {
		inputData, readErr := os.ReadFile(filepath.Join(root, "blobs", rel))
		require.NoError(t, readErr)
		outputData, readErr := os.ReadFile(filepath.Join(output, "blobs", rel))
		require.NoError(t, readErr)
		assert.Equal(t, inputData, outputData)
	}

	solveOpt := client.SolveOpt{}
	source.AddToSolveOpt(&solveOpt)
	assert.Same(t, source.store, solveOpt.OCIStores[source.StoreID])
	assert.Equal(t, before, snapshotLayout(t, fixture.path), "opening and copying from a source must not modify it")
}

func TestResolveReferenceUsesSelectedDigest(t *testing.T) {
	fixture := newSingleLayout(t, nil)
	source, err := Open(context.Background(), fixture.path, filepath.Join(t.TempDir(), "output"), "example.com/acme/app:stable")
	require.NoError(t, err)
	ref, err := source.ResolveReference()
	require.NoError(t, err)
	assert.Equal(t, "example.com/acme/app@"+fixture.manifests[0].Digest.String(), ref)

	resolver := &recordingResolver{}
	platform := &ocispec.Platform{OS: "linux", Architecture: "amd64"}
	_, err = source.ResolveImageConfig(t.Context(), resolver, platform)
	require.NoError(t, err)
	require.NotNil(t, resolver.opt.OCILayoutOpt)
	assert.Equal(t, source.StoreID, resolver.opt.OCILayoutOpt.Store.StoreID)
	assert.Empty(t, resolver.opt.OCILayoutOpt.Store.SessionID)
	assert.Equal(t, platform, resolver.opt.OCILayoutOpt.Platform)
	assert.Equal(t, ref, resolver.ref)
}
