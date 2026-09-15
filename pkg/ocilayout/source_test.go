package ocilayout

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/containerd/containerd/v2/core/content"
	containerdref "github.com/containerd/containerd/v2/pkg/reference"
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
			name:     "single entry without selector",
			selector: func(ocispec.Descriptor) string { return "" },
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newSingleLayout(t, test.annotations)
			if test.name != "single entry without selector" {
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
		_, err := Open(t.Context(), fixture.path, filepath.Join(t.TempDir(), "output"), "")
		require.ErrorContains(t, err, "unsupported OCI image layout version")
	})

	t.Run("symlinked layout metadata", func(t *testing.T) {
		fixture := newSingleLayout(t, nil)
		metadataPath := filepath.Join(fixture.path, ocispec.ImageLayoutFile)
		externalPath := filepath.Join(t.TempDir(), ocispec.ImageLayoutFile)
		require.NoError(t, os.WriteFile(externalPath, []byte(`{"imageLayoutVersion":"1.0.0"}`), 0o600))
		require.NoError(t, os.Remove(metadataPath))
		require.NoError(t, os.Symlink(externalPath, metadataPath))
		_, err := Open(t.Context(), fixture.path, filepath.Join(t.TempDir(), "output"), "")
		require.ErrorContains(t, err, "must be a regular file")
	})

	t.Run("missing manifest blob", func(t *testing.T) {
		fixture := newSingleLayout(t, nil)
		require.NoError(t, os.Remove(filepath.Join(fixture.path, "blobs", "sha256", fixture.manifests[0].Digest.Encoded())))
		_, err := Open(t.Context(), fixture.path, filepath.Join(t.TempDir(), "output"), "")
		require.ErrorContains(t, err, "resolve blob path")
	})

	t.Run("corrupt layer blob", func(t *testing.T) {
		fixture := newSingleLayout(t, nil)
		var manifest ocispec.Manifest
		data, err := os.ReadFile(filepath.Join(fixture.path, "blobs", "sha256", fixture.manifests[0].Digest.Encoded()))
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(data, &manifest))
		require.NoError(t, os.WriteFile(filepath.Join(fixture.path, "blobs", "sha256", manifest.Layers[0].Digest.Encoded()), []byte("corrupt"), 0o600))
		_, err = Open(t.Context(), fixture.path, filepath.Join(t.TempDir(), "output"), "")
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
		_, err = Open(t.Context(), fixture.path, filepath.Join(t.TempDir(), "output"), "")
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
		_, err = Open(t.Context(), fixture.path, filepath.Join(t.TempDir(), "output"), "")
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
		_, err := Open(t.Context(), fixture.path, output, "")
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

	source, err := Open(t.Context(), fixture.path, filepath.Join(t.TempDir(), "output"), "")
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
	assert.NotContains(t, annotations, "descriptor.example")
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
	source, err := Open(context.Background(), fixture.path, filepath.Join(t.TempDir(), "output"), "")
	require.NoError(t, err)
	ref, err := source.ResolveReference()
	require.NoError(t, err)
	assert.Equal(t, source.StoreID+"/image@"+fixture.manifests[0].Digest.String(), ref)

	parsed, err := containerdref.Parse(ref)
	require.NoError(t, err)
	assert.Equal(t, source.StoreID, parsed.Hostname())
	assert.Equal(t, fixture.manifests[0].Digest, parsed.Digest())

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

func TestOpenRejectsSelectedArtifacts(t *testing.T) {
	for _, index := range []bool{false, true} {
		for _, inBody := range []bool{false, true} {
			t.Run(fmt.Sprintf("index=%t/body=%t", index, inBody), func(t *testing.T) {
				fixture := newSingleLayout(t, nil)
				desc := fixture.manifests[0]
				if index {
					body := ocispec.Index{Versioned: specs.Versioned{SchemaVersion: 2}, Manifests: []ocispec.Descriptor{desc}}
					if inBody {
						body.ArtifactType = "application/example"
					}
					desc = writeBlob(t, fixture.path, ocispec.MediaTypeImageIndex, marshalJSON(t, body))
				} else if inBody {
					body := ocispec.Manifest{Versioned: specs.Versioned{SchemaVersion: 2}, ArtifactType: "application/example"}
					desc = writeBlob(t, fixture.path, ocispec.MediaTypeImageManifest, marshalJSON(t, body))
				}
				if !inBody {
					desc.ArtifactType = "application/example"
				}
				newLayoutAt(t, fixture.path, []ocispec.Descriptor{desc})
				before := snapshotLayout(t, fixture.path)
				_, err := Open(t.Context(), fixture.path, "", desc.Digest.String())
				require.ErrorContains(t, err, "unsupported artifact")
				assert.Equal(t, before, snapshotLayout(t, fixture.path))
			})
		}
	}
}

func TestPlatformArtifactFiltering(t *testing.T) {
	for _, inBody := range []bool{false, true} {
		t.Run(fmt.Sprintf("body=%t", inBody), func(t *testing.T) {
			fixture := newSingleLayout(t, nil)
			image := fixture.manifests[0]
			artifact := ocispec.Descriptor{
				MediaType:    ocispec.MediaTypeImageManifest,
				Digest:       digest.FromString("absent-artifact"),
				ArtifactType: "application/example",
				Platform:     image.Platform,
			}
			if inBody {
				artifact = writeBlob(t, fixture.path, ocispec.MediaTypeImageManifest, marshalJSON(t, ocispec.Manifest{
					Versioned: specs.Versioned{SchemaVersion: 2}, ArtifactType: "application/example",
				}))
				artifact.Platform = image.Platform
			}
			index := writeBlob(t, fixture.path, ocispec.MediaTypeImageIndex, marshalJSON(t, ocispec.Index{
				Versioned: specs.Versioned{SchemaVersion: 2}, Manifests: []ocispec.Descriptor{artifact, image},
			}))
			newLayoutAt(t, fixture.path, []ocispec.Descriptor{index})
			source, err := Open(t.Context(), fixture.path, "", "")
			require.NoError(t, err)
			found, err := source.Platforms(t.Context())
			require.NoError(t, err)
			require.Equal(t, []ocispec.Platform{*image.Platform}, found)
			desc, err := source.PlatformDescriptor(t.Context(), image.Platform)
			require.NoError(t, err)
			assert.Equal(t, image, *desc)
		})
	}
}

func TestSingleManifestPlatformComesFromConfig(t *testing.T) {
	fixture := newSingleLayout(t, nil)
	desc := fixture.manifests[0]
	desc.Platform = nil
	newLayoutAt(t, fixture.path, []ocispec.Descriptor{desc})
	source, err := Open(t.Context(), fixture.path, "", "")
	require.NoError(t, err)
	_, err = source.PlatformDescriptor(t.Context(), &ocispec.Platform{OS: "linux", Architecture: "arm64"})
	require.ErrorContains(t, err, "does not match requested platform")
	actual, err := source.PlatformDescriptor(t.Context(), nil)
	require.NoError(t, err)
	assert.Equal(t, fixture.manifests[0].Platform, actual.Platform)
	assert.Equal(t, desc.Digest, actual.Digest)
}

func TestOCIPlatformIdentity(t *testing.T) {
	root := t.TempDir()
	firstPlatform := ocispec.Platform{OS: "linux", Architecture: "arm64", Variant: "v8", OSVersion: "1", OSFeatures: []string{"b", "a"}}
	secondPlatform := firstPlatform
	secondPlatform.OSFeatures = []string{"c"}
	first := newImageManifest(t, root, &firstPlatform, nil, nil)
	second := newImageManifest(t, root, &secondPlatform, nil, nil)
	index := writeBlob(t, root, ocispec.MediaTypeImageIndex, marshalJSON(t, ocispec.Index{
		Versioned: specs.Versioned{SchemaVersion: 2}, Manifests: []ocispec.Descriptor{first, second},
	}))
	newLayoutAt(t, root, []ocispec.Descriptor{index})
	source, err := Open(t.Context(), root, "", "")
	require.NoError(t, err)
	found, err := source.Platforms(t.Context())
	require.NoError(t, err)
	require.Len(t, found, 2)
	target := firstPlatform
	target.Variant = ""
	target.OSFeatures = []string{"a", "b", "a"}
	desc, err := source.PlatformDescriptor(t.Context(), &target)
	require.NoError(t, err)
	assert.Equal(t, first.Digest, desc.Digest)
	target.OSVersion = "2"
	_, err = source.PlatformDescriptor(t.Context(), &target)
	require.ErrorContains(t, err, "no descriptor")

	index = writeBlob(t, root, ocispec.MediaTypeImageIndex, marshalJSON(t, ocispec.Index{
		Versioned: specs.Versioned{SchemaVersion: 2}, Manifests: []ocispec.Descriptor{first, first},
	}))
	newLayoutAt(t, root, []ocispec.Descriptor{index})
	source, err = Open(t.Context(), root, "", "")
	require.NoError(t, err)
	_, err = source.Platforms(t.Context())
	require.ErrorContains(t, err, "multiple descriptors")
}

func TestOptionalSelectorCountsImages(t *testing.T) {
	fixture := newSingleLayout(t, nil)
	image := fixture.manifests[0]
	artifact := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, ArtifactType: "application/example", Digest: digest.FromString("artifact")}
	unknown := ocispec.Descriptor{MediaType: "application/example", Digest: digest.FromString("unknown")}
	alias := image
	alias.Annotations = map[string]string{ocispec.AnnotationRefName: "alias"}
	newLayoutAt(t, fixture.path, []ocispec.Descriptor{artifact, unknown, image, alias})
	source, err := Open(t.Context(), fixture.path, "", "")
	require.NoError(t, err)
	assert.Equal(t, image.Digest, source.Descriptor.Digest)
	assert.Nil(t, source.Reference)
	_, err = Open(t.Context(), fixture.path, "", "unavailable")
	require.ErrorContains(t, err, "unavailable")
	source, err = Open(t.Context(), fixture.path, "", image.Digest.String())
	require.NoError(t, err)
	assert.Equal(t, image.Digest, source.Descriptor.Digest)
	source, err = Open(t.Context(), fixture.path, "", "alias")
	require.NoError(t, err)
	assert.Equal(t, image.Digest, source.Descriptor.Digest)

	other := newImageManifest(t, fixture.path, &ocispec.Platform{OS: "linux", Architecture: "arm64"}, nil, nil)
	newLayoutAt(t, fixture.path, []ocispec.Descriptor{image, other})
	_, err = Open(t.Context(), fixture.path, "", "")
	require.ErrorContains(t, err, "2 top-level images")
	source, err = Open(t.Context(), fixture.path, "", other.Digest.String())
	require.NoError(t, err)
	assert.Equal(t, other.Digest, source.Descriptor.Digest)
}

func TestOpenRejectsNestedImageIndex(t *testing.T) {
	fixture := newSingleLayout(t, nil)
	child := writeBlob(t, fixture.path, ocispec.MediaTypeImageIndex, marshalJSON(t, ocispec.Index{
		Versioned: specs.Versioned{SchemaVersion: 2}, Manifests: fixture.manifests,
	}))
	parent := writeBlob(t, fixture.path, ocispec.MediaTypeImageIndex, marshalJSON(t, ocispec.Index{
		Versioned: specs.Versioned{SchemaVersion: 2}, Manifests: append(fixture.manifests, child),
	}))
	newLayoutAt(t, fixture.path, []ocispec.Descriptor{parent})
	before := snapshotLayout(t, fixture.path)
	_, err := Open(t.Context(), fixture.path, "", "")
	require.ErrorContains(t, err, "nested child image index")
	assert.ErrorContains(t, err, child.Digest.String())
	assert.Equal(t, before, snapshotLayout(t, fixture.path))
}

func TestSourceNameIsIndependentOfSelector(t *testing.T) {
	for _, test := range []struct {
		name        string
		annotations map[string]string
		want        string
	}{
		{name: "unnamed"},
		{name: "bare ref name is only a tag", annotations: map[string]string{ocispec.AnnotationRefName: "stable"}},
		{name: "full image name", annotations: map[string]string{annotationImageName: "example.invalid/app:stable"}, want: "example.invalid/app:stable"},
		{name: "full ref name", annotations: map[string]string{ocispec.AnnotationRefName: "example.invalid/app:stable"}, want: "example.invalid/app:stable"},
		{name: "conflicting names", annotations: map[string]string{annotationImageName: "example.invalid/app:stable", ocispec.AnnotationRefName: "example.invalid/other:stable"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newSingleLayout(t, test.annotations)
			source, err := Open(t.Context(), fixture.path, "", fixture.manifests[0].Digest.String())
			require.NoError(t, err)
			if test.want == "" {
				assert.Nil(t, source.Reference)
			} else {
				require.NotNil(t, source.Reference)
				assert.Equal(t, test.want, source.Reference.String())
			}
		})
	}
}

func TestAuxiliaryWritePathsCannotMutateSource(t *testing.T) {
	fixture := newSingleLayout(t, nil)
	source, err := Open(t.Context(), fixture.path, "", "")
	require.NoError(t, err)
	require.NoError(t, source.ValidateWritePath(filepath.Join(t.TempDir(), "vex.json")))
	for _, path := range []string{fixture.path, filepath.Join(fixture.path, "vex.json")} {
		require.ErrorContains(t, source.ValidateWritePath(path), "must not overlap OCI layout input")
	}
	link := filepath.Join(t.TempDir(), "source-link")
	require.NoError(t, os.Symlink(fixture.path, link))
	require.ErrorContains(t, source.ValidateWritePath(filepath.Join(link, "vex.json")), "must not overlap OCI layout input")
}

func TestOpenRejectsPlatformConflictingWithConfig(t *testing.T) {
	fixture := newSingleLayout(t, nil)
	desc := fixture.manifests[0]
	desc.Platform = &ocispec.Platform{OS: "linux", Architecture: "arm64"}
	newLayoutAt(t, fixture.path, []ocispec.Descriptor{desc})
	_, err := Open(t.Context(), fixture.path, "", "")
	require.ErrorContains(t, err, "conflicts with image config platform")
}

func TestImageDescriptorConfigArtifactTypeMustMatchManifest(t *testing.T) {
	fixture := newSingleLayout(t, nil)
	desc := fixture.manifests[0]
	desc.ArtifactType = dockerMediaTypeConfig
	newLayoutAt(t, fixture.path, []ocispec.Descriptor{desc})
	_, err := Open(t.Context(), fixture.path, "", "")
	require.ErrorContains(t, err, "conflicts with config mediaType")

	body := ocispec.Manifest{Versioned: specs.Versioned{SchemaVersion: 2}, ArtifactType: "application/example"}
	desc = writeBlob(t, fixture.path, ocispec.MediaTypeImageManifest, marshalJSON(t, body))
	desc.ArtifactType = ocispec.MediaTypeImageConfig
	newLayoutAt(t, fixture.path, []ocispec.Descriptor{desc})
	_, err = Open(t.Context(), fixture.path, "", "")
	require.ErrorContains(t, err, "unsupported artifact")
}

func TestSelectorsIgnoreArtifactAliases(t *testing.T) {
	for _, test := range []struct {
		annotation string
		selector   string
	}{
		{annotationImageName, "example.com/app:stable"},
		{ocispec.AnnotationRefName, "stable"},
	} {
		t.Run(test.annotation, func(t *testing.T) {
			annotations := map[string]string{test.annotation: test.selector}
			fixture := newSingleLayout(t, annotations)
			image := fixture.manifests[0]
			artifact := ocispec.Descriptor{
				MediaType: ocispec.MediaTypeImageManifest, ArtifactType: "application/example",
				Digest: digest.FromString("absent-artifact"), Annotations: annotations,
			}
			newLayoutAt(t, fixture.path, []ocispec.Descriptor{artifact, image})
			source, err := Open(t.Context(), fixture.path, "", test.selector)
			require.NoError(t, err)
			assert.Equal(t, image.Digest, source.Descriptor.Digest)

			other := newImageManifest(t, fixture.path, &ocispec.Platform{OS: "linux", Architecture: "arm64"}, annotations, nil)
			newLayoutAt(t, fixture.path, []ocispec.Descriptor{artifact, image, other})
			_, err = Open(t.Context(), fixture.path, "", test.selector)
			require.ErrorContains(t, err, "2 descriptors matching")
		})
	}
}

type cancelingContentStore struct {
	content.Store
	target    digest.Digest
	onOpen    int
	opens     int
	bytesRead int
	cancel    context.CancelFunc
}

//nolint:gocritic // The content.Store interface passes descriptors by value.
func (s *cancelingContentStore) ReaderAt(ctx context.Context, desc ocispec.Descriptor) (content.ReaderAt, error) {
	ra, err := s.Store.ReaderAt(ctx, desc)
	if err != nil || desc.Digest != s.target {
		return ra, err
	}
	s.opens++
	if s.opens != s.onOpen {
		return ra, nil
	}
	return &cancelingBlobReader{ReaderAt: ra, store: s}, nil
}

type cancelingBlobReader struct {
	content.ReaderAt
	store *cancelingContentStore
}

func (r *cancelingBlobReader) ReadAt(p []byte, off int64) (int, error) {
	n, err := r.ReaderAt.ReadAt(p, off)
	r.store.bytesRead += n
	r.store.cancel()
	return n, err
}

func TestBlobOperationsObserveCancellation(t *testing.T) {
	for _, test := range []struct {
		name   string
		copy   bool
		json   bool
		onOpen int
	}{
		{name: "already canceled"},
		{name: "during validation", onOpen: 1},
		{name: "during preserved transfer", copy: true, onOpen: 2},
		{name: "during metadata read after validation", json: true, onOpen: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newSingleLayout(t, nil)
			source, err := Open(t.Context(), fixture.path, "", "")
			require.NoError(t, err)
			data := bytes.Repeat([]byte("blob"), 256*1024)
			desc := writeBlob(t, fixture.path, ocispec.MediaTypeImageLayer, data)
			before := snapshotLayout(t, fixture.path)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			store := &cancelingContentStore{Store: source.store, target: desc.Digest, onOpen: test.onOpen, cancel: cancel}
			source.store = store
			if test.onOpen == 0 {
				cancel()
			}
			switch {
			case test.copy:
				output := t.TempDir()
				destination := filepath.Join(output, "blobs", desc.Digest.Algorithm().String(), desc.Digest.Encoded())
				require.NoError(t, os.MkdirAll(filepath.Dir(destination), 0o755))
				require.NoError(t, os.WriteFile(destination, []byte("existing destination"), 0o600))
				beforeOutput := snapshotLayout(t, output)
				copied := make(map[string]bool)
				err = source.copyBlob(ctx, output, &desc, copied)
				assert.Empty(t, copied)
				assert.Equal(t, beforeOutput, snapshotLayout(t, output), "cancellation leaves existing blobs unchanged and removes temporary copies")
			case test.json:
				var metadata any
				err = source.readJSONBlob(ctx, &desc, &metadata)
			default:
				err = source.validateBlob(ctx, &desc)
			}
			require.ErrorIs(t, err, context.Canceled)
			assert.Less(t, store.bytesRead, len(data), "stop before reading the rest of a large blob")
			assert.Equal(t, before, snapshotLayout(t, fixture.path))
		})
	}
}

func TestTemporaryRootsStayOutsideSource(t *testing.T) {
	fixture := newSingleLayout(t, nil)
	source, err := Open(t.Context(), fixture.path, "", "")
	require.NoError(t, err)
	require.NoError(t, source.ValidateTempDir(filepath.Dir(fixture.path)), "shared ancestor temp roots are safe")
	require.NoError(t, source.ValidateTempDir(t.TempDir()))
	for _, root := range []string{fixture.path, filepath.Join(fixture.path, "tmp")} {
		require.ErrorContains(t, source.ValidateTempDir(root), "temporary directory")
	}
	link := filepath.Join(t.TempDir(), "input-link")
	require.NoError(t, os.Symlink(fixture.path, link))
	require.ErrorContains(t, source.ValidateTempDir(filepath.Join(link, "tmp")), "temporary directory")
}

func TestOpenValidatesCompletePlatformIdentity(t *testing.T) {
	actual := ocispec.Platform{OS: "linux", Architecture: "arm64", OSVersion: "fixture.1", OSFeatures: []string{"b", "a"}}
	for _, test := range []struct {
		name     string
		version  string
		features []string
		wantErr  bool
	}{
		{name: "normalized equivalent", version: "fixture.1", features: []string{"a", "b", "a"}},
		{name: "different OS version", version: "fixture.2", features: []string{"a", "b"}, wantErr: true},
		{name: "missing OS version", features: []string{"a", "b"}, wantErr: true},
		{name: "different OS features", version: "fixture.1", features: []string{"c"}, wantErr: true},
		{name: "missing OS features", version: "fixture.1", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			desc := newImageManifest(t, root, &actual, nil, nil)
			declared := actual
			declared.Variant = "v8"
			declared.OSVersion, declared.OSFeatures = test.version, test.features
			desc.Platform = &declared
			newLayoutAt(t, root, []ocispec.Descriptor{desc})
			before := snapshotLayout(t, root)
			_, err := Open(t.Context(), root, "", "")
			if test.wantErr {
				require.ErrorContains(t, err, "conflicts with image config platform")
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, before, snapshotLayout(t, root))
		})
	}
}
