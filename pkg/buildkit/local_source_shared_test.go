package buildkit

import (
	"context"
	"errors"
	"io"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	v1types "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
)

const sharedArchiveParent = "example.com/local:parent"

type sharedArchiveFixture struct {
	root     v1.Descriptor
	children []v1.Descriptor
	files    map[string][]byte
}

func (f *sharedArchiveFixture) rootDigest() digest.Digest {
	return digest.Digest(f.root.Digest.String())
}

// newSharedArchiveFixture saves a local index of three images, each with an
// original manifest and config.
func newSharedArchiveFixture(t *testing.T) *sharedArchiveFixture {
	t.Helper()
	f := &sharedArchiveFixture{files: map[string][]byte{"blobs/sha256/layer": []byte("image layer bytes, not retained")}}
	for _, arch := range []string{"amd64", "arm64", "386"} {
		config := []byte(`{"os":"linux","architecture":"` + arch + `","rootfs":{"type":"layers","diff_ids":[]},"config":{"Labels":{"com.example.arch":"` + arch + `"}}}`)
		configDesc := localMetadataDescriptor(t, config, v1types.OCIConfigJSON)
		child, body := archiveTestManifest(t, v1.Manifest{
			SchemaVersion: 2, MediaType: v1types.OCIManifestSchema1, Config: configDesc, Layers: []v1.Descriptor{},
			Annotations: map[string]string{"com.example.platform": arch},
		}, v1types.OCIManifestSchema1)
		child.Platform = &v1.Platform{OS: linux, Architecture: arch}
		f.files[archiveBlobPath(child.Digest)], f.files[archiveBlobPath(configDesc.Digest)] = body, config
		f.children = append(f.children, child)
	}
	root, index := archiveTestManifest(t, v1.IndexManifest{SchemaVersion: 2, MediaType: v1types.OCIImageIndex, Manifests: f.children}, v1types.OCIImageIndex)
	f.root = root
	f.files[localMetadataIndexFile], f.files[archiveBlobPath(root.Digest)] = localMetadataWrapper(t, &root), index
	return f
}

// mockSharedArchive serves the fixture as a native local image and counts saves.
func mockSharedArchive(t *testing.T, f *sharedArchiveFixture) *int {
	t.Helper()
	mockLocalMetadataArchive(t, sharedArchiveParent, &f.root, f.files)
	forbidLocalMetadataRegistry(t)
	saves := new(int)
	save := localImageArchive
	localImageArchive = func(ctx context.Context, image string) (io.ReadCloser, error) {
		*saves++
		return save(ctx, image)
	}
	return saves
}

type sharedArchiveLookup struct {
	annotations map[string]string
	descriptor  *remote.Descriptor
	config      []byte
}

// lookupAll reads every child's annotations and metadata, in either order.
func lookupAll(
	t *testing.T, f *sharedArchiveFixture, metadataFirst bool,
	annotations func(context.Context, string, digest.Digest) (map[string]string, error),
	metadata func(context.Context, string, digest.Digest) (*remote.Descriptor, []byte, error),
) []sharedArchiveLookup {
	t.Helper()
	got := make([]sharedArchiveLookup, len(f.children))
	readAnnotations := func() {
		for i := range f.children {
			child := &f.children[i]
			values, err := annotations(t.Context(), sharedArchiveParent, digest.Digest(child.Digest.String()))
			require.NoError(t, err)
			got[i].annotations = values
		}
	}
	readMetadata := func() {
		for i := range f.children {
			child := &f.children[i]
			desc, config, err := metadata(t.Context(), sharedArchiveParent, digest.Digest(child.Digest.String()))
			require.NoError(t, err)
			got[i].descriptor, got[i].config = desc, config
		}
	}
	if metadataFirst {
		readMetadata()
		readAnnotations()
	} else {
		readAnnotations()
		readMetadata()
	}
	return got
}

// One save of a local multi-platform source serves every platform's manifest
// annotations and metadata, with the same results as reading per lookup.
func TestLocalSourceArchiveReadsOnce(t *testing.T) {
	for _, metadataFirst := range []bool{false, true} {
		t.Run(map[bool]string{false: "annotations first", true: "metadata first"}[metadataFirst], func(t *testing.T) {
			f := newSharedArchiveFixture(t)
			saves := mockSharedArchive(t, f)
			shared := NewLocalSourceArchive(sharedArchiveParent, f.rootDigest())
			got := lookupAll(t, f, metadataFirst, shared.ManifestAnnotations, shared.Metadata)
			require.Equal(t, 1, *saves, "the source is saved once for every platform")

			want := lookupAll(t, f, metadataFirst, LocalImageManifestAnnotations, LocalImageMetadata)
			require.Equal(t, 1+2*len(f.children), *saves, "each separate lookup saves the source again")
			require.Equal(t, want, got)
			for i := range f.children {
				child := &f.children[i]
				require.Equal(t, map[string]string{"com.example.platform": child.Platform.Architecture}, got[i].annotations)
				require.Equal(t, f.files[archiveBlobPath(child.Digest)], got[i].descriptor.Manifest)
			}

			// Selections outside the captured root still fail without saving again.
			_, err := shared.ManifestAnnotations(t.Context(), sharedArchiveParent, digest.FromString("unrelated"))
			require.ErrorContains(t, err, "does not contain selected manifest")
			_, _, err = shared.Metadata(t.Context(), sharedArchiveParent, digest.FromString("unrelated"))
			require.ErrorContains(t, err, "does not contain selected manifest")
			_, err = shared.ManifestAnnotations(t.Context(), sharedArchiveParent, "sha256:bad")
			require.ErrorContains(t, err, "invalid selected local manifest")
			_, _, err = shared.Metadata(t.Context(), sharedArchiveParent, "sha256:bad")
			require.ErrorContains(t, err, "invalid selected local manifest")
			require.Equal(t, 1+2*len(f.children), *saves)

			canceled, cancel := context.WithCancel(t.Context())
			cancel()
			_, err = shared.ManifestAnnotations(canceled, sharedArchiveParent, digest.Digest(f.children[0].Digest.String()))
			require.ErrorIs(t, err, context.Canceled)
			_, _, err = shared.Metadata(canceled, sharedArchiveParent, digest.Digest(f.children[0].Digest.String()))
			require.ErrorIs(t, err, context.Canceled)
		})
	}
}

// Corrupt selected bytes fail verification from the shared save as they do
// from a separate one, without affecting the other platforms.
func TestLocalSourceArchiveVerifiesEachSelection(t *testing.T) {
	f := newSharedArchiveFixture(t)
	corrupt := archiveBlobPath(f.children[0].Digest)
	f.files[corrupt] = append(f.files[corrupt], ' ')
	saves := mockSharedArchive(t, f)
	shared := NewLocalSourceArchive(sharedArchiveParent, f.rootDigest())
	_, err := shared.ManifestAnnotations(t.Context(), sharedArchiveParent, digest.Digest(f.children[0].Digest.String()))
	require.ErrorContains(t, err, "does not match descriptor")
	_, _, err = shared.Metadata(t.Context(), sharedArchiveParent, digest.Digest(f.children[0].Digest.String()))
	require.ErrorContains(t, err, "does not match descriptor")
	for i := range f.children[1:] {
		child := &f.children[i+1]
		_, err := shared.ManifestAnnotations(t.Context(), sharedArchiveParent, digest.Digest(child.Digest.String()))
		require.NoError(t, err)
		_, _, err = shared.Metadata(t.Context(), sharedArchiveParent, digest.Digest(child.Digest.String()))
		require.NoError(t, err)
	}
	require.Equal(t, 1, *saves)
}

// Without a save of the captured root, every lookup reads for itself exactly
// as before: moved content and failed or classic saves are never reused.
func TestLocalSourceArchiveRereadsWithoutCapturedRoot(t *testing.T) {
	for _, scenario := range []string{"moved", "save-fails", "classic", "not-shared", "nil"} {
		t.Run(scenario, func(t *testing.T) {
			f := newSharedArchiveFixture(t)
			if scenario == "classic" {
				f.files = map[string][]byte{"manifest.json": []byte(`[]`)}
			}
			saves := mockSharedArchive(t, f)
			failure := errors.New("daemon unavailable")
			if scenario == "save-fails" {
				localImageArchive = func(context.Context, string) (io.ReadCloser, error) {
					*saves++
					return nil, failure
				}
			}
			root := f.rootDigest()
			if scenario == "moved" {
				root = digest.FromString("the captured root before the name moved")
			}
			shared := NewLocalSourceArchive(sharedArchiveParent, root)
			switch scenario {
			case "not-shared":
				shared = NewLocalSourceArchive("example.com/other:parent", f.rootDigest())
			case "nil":
				shared = nil
			}
			for i := range f.children {
				child := &f.children[i]
				selected := digest.Digest(child.Digest.String())
				annotations, err := shared.ManifestAnnotations(t.Context(), sharedArchiveParent, selected)
				want, wantErr := LocalImageManifestAnnotations(t.Context(), sharedArchiveParent, selected)
				require.Equal(t, wantErr, err)
				require.Equal(t, want, annotations)
				desc, config, err := shared.Metadata(t.Context(), sharedArchiveParent, selected)
				wantDesc, wantConfig, wantErr := LocalImageMetadata(t.Context(), sharedArchiveParent, selected)
				require.Equal(t, wantErr, err)
				require.Equal(t, wantDesc, desc)
				require.Equal(t, wantConfig, config)
				require.Equal(t, 4*(i+1), *saves, "each lookup saves the source")
				switch scenario {
				case "save-fails":
					require.ErrorIs(t, err, failure)
				case "classic":
					require.ErrorContains(t, err, "has no original manifest index")
					require.Nil(t, annotations)
				default:
					require.NoError(t, err)
					require.Equal(t, child.Platform.Architecture, annotations["com.example.platform"])
				}
			}
		})
	}
}

// Metadata lookups still detect an unavailable local source before any save.
func TestLocalSourceArchiveSkipsUnavailableSources(t *testing.T) {
	f := newSharedArchiveFixture(t)
	saves := mockSharedArchive(t, f)
	localImageIndex = func(context.Context, string) (*specs.Index, *specs.Descriptor, bool, bool, error) {
		return nil, nil, false, false, nil
	}
	shared := NewLocalSourceArchive(sharedArchiveParent, f.rootDigest())
	for i := range f.children {
		child := &f.children[i]
		desc, config, err := shared.Metadata(t.Context(), sharedArchiveParent, digest.Digest(child.Digest.String()))
		require.NoError(t, err)
		require.Nil(t, desc)
		require.Nil(t, config)
	}
	require.Zero(t, *saves)
}

func TestLocalSourceArchiveNames(t *testing.T) {
	root := digest.FromString("root")
	shared := NewLocalSourceArchive("alpine", root)
	require.True(t, shared.shares("docker.io/library/alpine:latest"))
	require.False(t, shared.shares("alpine:3.20"))
	require.False(t, shared.shares("docker.io/library/alpine@"+root.String()))
	require.False(t, NewLocalSourceArchive("alpine", "").shares("alpine"))
	require.False(t, NewLocalSourceArchive("Invalid:Name", root).shares("Invalid:Name"))
}
