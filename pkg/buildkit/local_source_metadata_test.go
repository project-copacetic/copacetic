package buildkit

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"testing"

	"github.com/containerd/errdefs"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	v1types "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
)

const (
	localMetadataInspectCase           = "inspect"
	localMetadataReadDeniedCase        = "read-denied"
	localMetadataOriginal              = "original"
	localMetadataManifestCase          = "manifest"
	localMetadataDeniedCase            = "denied"
	localMetadataIndexFile             = "index.json"
	localMetadataBodyAnnotation        = "com.example.body"
	localMetadataManifestMediaTypeCase = "manifest-media-type"
	localMetadataConfigCase            = "config"
	localMetadataCanceledCase          = "canceled"
)

type localMetadataFixture struct {
	root     v1.Descriptor
	child    v1.Descriptor
	config   v1.Descriptor
	index    []byte
	manifest []byte
	files    map[string][]byte
}

func newLocalMetadataFixture(t *testing.T) localMetadataFixture {
	t.Helper()
	// Deliberate whitespace and noncanonical key order detect re-marshaling.
	config := []byte("{ \"os\":\"linux\", \"architecture\":\"arm64\", \"rootfs\":{\"type\":\"layers\",\"diff_ids\":[]},\"config\":{} }\n")
	configDesc := localMetadataDescriptor(t, config, v1types.OCIConfigJSON)
	manifest, err := json.Marshal(v1.Manifest{
		SchemaVersion: 2, MediaType: v1types.OCIManifestSchema1, Config: configDesc,
		Layers: []v1.Descriptor{}, Annotations: map[string]string{localMetadataBodyAnnotation: localMetadataOriginal},
	})
	require.NoError(t, err)
	manifest = append([]byte(" \n"), manifest...)
	child := localMetadataDescriptor(t, manifest, v1types.OCIManifestSchema1)
	child.Platform = &v1.Platform{OS: linux, Architecture: arm64}
	child.Annotations = map[string]string{"com.example.descriptor": localMetadataOriginal}
	missing := child
	missing.Digest, err = v1.NewHash(digest.FromString("unavailable sibling").String())
	require.NoError(t, err)
	missing.Platform = &v1.Platform{OS: linux, Architecture: cancellationAMD64}
	index, err := json.Marshal(v1.IndexManifest{
		SchemaVersion: 2, MediaType: v1types.OCIImageIndex, Manifests: []v1.Descriptor{child, missing},
		Annotations: map[string]string{"com.example.index": localMetadataOriginal},
	})
	require.NoError(t, err)
	index = append(index, '\n', ' ')
	root := localMetadataDescriptor(t, index, v1types.OCIImageIndex)
	root.Annotations = map[string]string{"io.containerd.image.name": "example.com/local:parent"}
	return localMetadataFixture{
		root: root, child: child, config: configDesc, index: index, manifest: manifest,
		files: map[string][]byte{
			localMetadataIndexFile: localMetadataWrapper(t, &root), archiveBlobPath(root.Digest): index,
			archiveBlobPath(child.Digest): manifest, archiveBlobPath(configDesc.Digest): config,
			"blobs/sha256/layer": []byte("image layer bytes, not retained"),
		},
	}
}

func localMetadataDescriptor(t *testing.T, data []byte, mediaType v1types.MediaType) v1.Descriptor {
	t.Helper()
	hash, err := v1.NewHash(digest.FromBytes(data).String())
	require.NoError(t, err)
	return v1.Descriptor{Digest: hash, Size: int64(len(data)), MediaType: mediaType}
}

func localMetadataWrapper(t *testing.T, root *v1.Descriptor) []byte {
	t.Helper()
	data, err := json.Marshal(v1.IndexManifest{SchemaVersion: 2, Manifests: []v1.Descriptor{*root}})
	require.NoError(t, err)
	return data
}

func mockLocalMetadataArchive(t *testing.T, parent string, root *v1.Descriptor, files map[string][]byte) {
	t.Helper()
	oldIndex, oldStore, oldArchive := localImageIndex, localImageStoreKeepsManifests, localImageArchive
	t.Cleanup(func() {
		localImageIndex, localImageStoreKeepsManifests, localImageArchive = oldIndex, oldStore, oldArchive
	})
	localImageIndex = func(ctx context.Context, image string) (*specs.Index, *specs.Descriptor, bool, bool, error) {
		require.Equal(t, t.Context(), ctx)
		require.Equal(t, parent, image, "must save the named parent, not a synthesized child reference")
		if root == nil {
			return nil, nil, false, true, nil // Old native daemon without descriptor inspection.
		}
		return nil, &specs.Descriptor{Digest: digest.Digest(root.Digest.String()), Size: root.Size, MediaType: string(root.MediaType)}, false, true, nil
	}
	localImageStoreKeepsManifests = func(context.Context) (bool, error) { return true, nil }
	localImageArchive = func(ctx context.Context, image string) (io.ReadCloser, error) {
		require.Equal(t, t.Context(), ctx)
		require.Equal(t, parent, image)
		return io.NopCloser(archiveTestStream(t, files)), nil
	}
}

func forbidLocalMetadataRegistry(t *testing.T) {
	t.Helper()
	oldLocal, oldRemote := tryGetManifestFromLocal, getRemoteImageDescriptor
	t.Cleanup(func() { tryGetManifestFromLocal, getRemoteImageDescriptor = oldLocal, oldRemote })
	tryGetManifestFromLocal = func(context.Context, name.Reference) (*remote.Descriptor, v1.Hash, bool, error) {
		t.Fatal("local metadata must not call the reconstructed manifest/registry resolver")
		return nil, v1.Hash{}, false, nil
	}
	getRemoteImageDescriptor = func(name.Reference, ...remote.Option) (*remote.Descriptor, error) {
		t.Fatal("local metadata must not use host registry authentication")
		return nil, nil
	}
}

func TestLocalImageMetadataOriginalBytes(t *testing.T) {
	for _, nativeInspect := range []bool{true, false} {
		t.Run(map[bool]string{true: "native-inspect", false: "old-native-daemon"}[nativeInspect], func(t *testing.T) {
			fixture := newLocalMetadataFixture(t)
			var inspected *v1.Descriptor
			if nativeInspect {
				inspected = &fixture.root
			}
			const parent = "example.com/local:parent"
			mockLocalMetadataArchive(t, parent, inspected, fixture.files)
			forbidLocalMetadataRegistry(t)
			for _, selected := range []v1.Descriptor{fixture.child, fixture.root} {
				got, config, err := LocalImageMetadata(t.Context(), parent, digest.Digest(selected.Digest.String()))
				require.NoError(t, err)
				require.Equal(t, selected.Digest, got.Digest)
				require.Equal(t, selected.Size, got.Size)
				require.Equal(t, selected.MediaType, got.MediaType)
				if selected.MediaType.IsIndex() {
					require.Equal(t, fixture.index, got.Manifest, "never return the annotation-augmented index")
					require.Nil(t, config)
					require.Equal(t, map[string]string{"com.example.index": localMetadataOriginal}, got.Annotations)
				} else {
					require.Equal(t, fixture.manifest, got.Manifest)
					require.Equal(t, fixture.files[archiveBlobPath(fixture.config.Digest)], config)
					require.Equal(t, map[string]string{localMetadataBodyAnnotation: localMetadataOriginal}, got.Annotations)
				}
			}
			// Existing descriptor readers still enrich child annotations, but do not require configs.
			delete(fixture.files, archiveBlobPath(fixture.config.Digest))
			enriched, err := readArchiveDescriptor(t.Context(), archiveTestStream(t, fixture.files))
			require.NoError(t, err)
			require.NotEqual(t, fixture.index, enriched.Manifest)
			require.Equal(t, fixture.root.Digest, enriched.Digest)
		})
	}
}

func TestLocalImageMetadataSingleRoot(t *testing.T) {
	fixture := newLocalMetadataFixture(t)
	fixture.files[localMetadataIndexFile] = localMetadataWrapper(t, &fixture.child)
	mockLocalMetadataArchive(t, "local:single", &fixture.child, fixture.files)
	got, config, err := LocalImageMetadata(t.Context(), "local:single", digest.Digest(fixture.child.Digest.String()))
	require.NoError(t, err)
	require.Equal(t, fixture.manifest, got.Manifest)
	require.Equal(t, fixture.files[archiveBlobPath(fixture.config.Digest)], config)
}

func TestLocalImageMetadataRejectsInvalidNativeContent(t *testing.T) {
	for _, scenario := range []string{
		"manifest-digest", "manifest-size", localMetadataManifestMediaTypeCase, "config-digest", "config-size", "config-media-type",
		"config-invalid-json", "config-oversized", "root-digest", "root-size", "root-media-type", "inspect-mismatch", "not-a-member", "empty-native-archive",
	} {
		t.Run(scenario, func(t *testing.T) {
			fixture := newLocalMetadataFixture(t)
			selected := digest.Digest(fixture.child.Digest.String())
			switch scenario {
			case "manifest-digest":
				fixture.files[archiveBlobPath(fixture.child.Digest)] = bytes.ReplaceAll(fixture.manifest, []byte(localMetadataOriginal), []byte("modified"))
			case "manifest-size":
				fixture.files[archiveBlobPath(fixture.child.Digest)] = append(fixture.manifest, ' ')
			case "config-digest":
				key := archiveBlobPath(fixture.config.Digest)
				fixture.files[key] = bytes.ReplaceAll(fixture.files[key], []byte("linux"), []byte("other"))
			case "config-size":
				key := archiveBlobPath(fixture.config.Digest)
				fixture.files[key] = append(fixture.files[key], ' ')
			case "config-oversized":
				fixture.files[archiveBlobPath(fixture.config.Digest)] = bytes.Repeat([]byte("x"), (4<<20)+1)
			case "config-invalid-json":
				fixture.files[archiveBlobPath(fixture.config.Digest)] = []byte("{")
			case localMetadataManifestMediaTypeCase, "config-media-type":
				var manifest v1.Manifest
				require.NoError(t, json.Unmarshal(fixture.manifest, &manifest))
				if scenario == localMetadataManifestMediaTypeCase {
					manifest.MediaType = v1types.DockerManifestSchema2
				} else {
					manifest.Config.MediaType = v1types.OCILayer
				}
				data, err := json.Marshal(manifest)
				require.NoError(t, err)
				fixture.child = localMetadataDescriptor(t, data, v1types.OCIManifestSchema1)
				fixture.files[archiveBlobPath(fixture.child.Digest)] = data
				// Make the selected image the root so only the intended media-type mismatch remains.
				fixture.root = fixture.child
				fixture.files[localMetadataIndexFile] = localMetadataWrapper(t, &fixture.root)
				selected = digest.Digest(fixture.child.Digest.String())
			case "root-digest":
				fixture.files[archiveBlobPath(fixture.root.Digest)] = bytes.ReplaceAll(fixture.index, []byte(localMetadataOriginal), []byte("modified"))
			case "root-size":
				fixture.root.Size++
				fixture.files[localMetadataIndexFile] = localMetadataWrapper(t, &fixture.root)
			case "root-media-type":
				fixture.root.MediaType = v1types.DockerManifestList
				fixture.files[localMetadataIndexFile] = localMetadataWrapper(t, &fixture.root)
			case "inspect-mismatch":
				fixture.root.Size++
			case "not-a-member":
				// Valid image content is insufficient unless the root actually references it.
				data := bytes.Clone(fixture.manifest)
				data = append(data, ' ')
				unrelated := localMetadataDescriptor(t, data, fixture.child.MediaType)
				fixture.files[archiveBlobPath(unrelated.Digest)] = data
				selected = digest.Digest(unrelated.Digest.String())
			case "empty-native-archive":
				fixture.files = map[string][]byte{}
			}
			mockLocalMetadataArchive(t, "local:corrupt", &fixture.root, fixture.files)
			forbidLocalMetadataRegistry(t)
			got, config, err := LocalImageMetadata(t.Context(), "local:corrupt", selected)
			require.Error(t, err)
			require.Nil(t, got)
			require.Nil(t, config)
		})
	}
}

func TestLocalImageMetadataUnavailable(t *testing.T) {
	for _, scenario := range []string{"not-found", "daemon-unavailable", "daemon-unsupported", "classic-store", "unknown-store", "removed-during-save"} {
		t.Run(scenario, func(t *testing.T) {
			fixture := newLocalMetadataFixture(t)
			mockLocalMetadataArchive(t, "local:unavailable", nil, fixture.files)
			forbidLocalMetadataRegistry(t)
			localImageArchive = func(context.Context, string) (io.ReadCloser, error) {
				require.Equal(t, "removed-during-save", scenario, "unavailable/classic sources must not be saved")
				return nil, errdefs.ErrNotFound
			}
			localImageIndex = func(context.Context, string) (*specs.Index, *specs.Descriptor, bool, bool, error) {
				switch scenario {
				case "not-found":
					return nil, nil, false, false, nil
				case "daemon-unavailable", "daemon-unsupported":
					return nil, nil, false, false, errors.New(scenario)
				default:
					return nil, nil, true, true, nil
				}
			}
			localImageStoreKeepsManifests = func(context.Context) (bool, error) {
				switch scenario {
				case "unknown-store":
					return false, errors.New("unsupported daemon info")
				case "removed-during-save":
					return true, nil
				default:
					return false, nil
				}
			}
			got, config, err := LocalImageMetadata(t.Context(), "local:unavailable", digest.Digest(fixture.root.Digest.String()))
			require.NoError(t, err)
			require.Nil(t, got)
			require.Nil(t, config)
		})
	}
	// A classic archive may even contain a reconstructed OCI wrapper. The store
	// capability check above must keep it from establishing a source identity.
}

func TestLocalImageMetadataFoundInspectionError(t *testing.T) {
	fixture := newLocalMetadataFixture(t)
	mockLocalMetadataArchive(t, "local:invalid-inspect", &fixture.root, fixture.files)
	forbidLocalMetadataRegistry(t)
	invalid := errors.New("malformed native index in inspect response")
	localImageIndex = func(context.Context, string) (*specs.Index, *specs.Descriptor, bool, bool, error) {
		return nil, nil, false, true, invalid
	}
	localImageArchive = func(context.Context, string) (io.ReadCloser, error) {
		t.Fatal("invalid inspection metadata must fail before reading an archive")
		return nil, nil
	}
	got, config, err := LocalImageMetadata(t.Context(), "local:invalid-inspect", digest.Digest(fixture.root.Digest.String()))
	require.ErrorIs(t, err, invalid)
	require.Nil(t, got)
	require.Nil(t, config)
}

func TestLocalImageMetadataCancellation(t *testing.T) {
	for _, stage := range []string{"before-inspect", localMetadataInspectCase, "store", "save", "read"} {
		t.Run(stage, func(t *testing.T) {
			fixture := newLocalMetadataFixture(t)
			mockLocalMetadataArchive(t, "local:canceled", nil, fixture.files)
			ctx := t.Context()
			if stage == "before-inspect" {
				canceled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = canceled
			}
			localImageIndex = func(context.Context, string) (*specs.Index, *specs.Descriptor, bool, bool, error) {
				if stage == localMetadataInspectCase {
					return nil, nil, false, false, context.Canceled
				}
				return nil, nil, false, true, nil
			}
			localImageStoreKeepsManifests = func(context.Context) (bool, error) {
				if stage == "store" {
					return false, context.Canceled
				}
				return true, nil
			}
			localImageArchive = func(context.Context, string) (io.ReadCloser, error) {
				if stage == "save" {
					return nil, context.Canceled
				}
				return io.NopCloser(localMetadataErrorReader{context.Canceled}), nil
			}
			got, config, err := LocalImageMetadata(ctx, "local:canceled", digest.Digest(fixture.root.Digest.String()))
			require.ErrorIs(t, err, context.Canceled)
			require.Nil(t, got)
			require.Nil(t, config)
		})
	}
}

type localMetadataErrorReader struct{ err error }

func (r localMetadataErrorReader) Read([]byte) (int, error) { return 0, r.err }

func TestLocalImageMetadataArchiveBounds(t *testing.T) {
	fixture := newLocalMetadataFixture(t)
	archive, err := readLocalArchive(t.Context(), archiveTestStream(t, fixture.files), true)
	require.NoError(t, err)
	require.NotContains(t, archive.blobs, "blobs/sha256/layer")
	require.Contains(t, archive.blobs, archiveBlobPath(fixture.config.Digest))
	for _, scenario := range []string{"oversized-config", "total-config-metadata", "duplicate-config"} {
		t.Run(scenario, func(t *testing.T) {
			files := maps.Clone(fixture.files)
			padding := bytes.Repeat([]byte(" "), 4<<20)
			config := append([]byte(`{"os":"linux","architecture":"arm64"}`), padding...)
			if scenario == "oversized-config" {
				files[archiveBlobPath(fixture.config.Digest)] = config
				mockLocalMetadataArchive(t, "local:bounded", &fixture.root, files)
				_, _, err := LocalImageMetadata(t.Context(), "local:bounded", digest.Digest(fixture.child.Digest.String()))
				require.ErrorContains(t, err, "config does not match descriptor")
				return
			}
			if scenario == "total-config-metadata" {
				for i := range 9 {
					files["blobs/sha256/"+digest.FromBytes([]byte{byte(i)}).Encoded()] = config[:4<<20]
				}
				_, err := readLocalArchive(t.Context(), archiveTestStream(t, files), true)
				require.ErrorContains(t, err, "metadata exceeds")
				return
			}
			var buffer bytes.Buffer
			writer := tar.NewWriter(&buffer)
			for range 2 {
				data := fixture.files[archiveBlobPath(fixture.config.Digest)]
				require.NoError(t, writer.WriteHeader(&tar.Header{Name: archiveBlobPath(fixture.config.Digest), Mode: 0o600, Size: int64(len(data))}))
				_, err := writer.Write(data)
				require.NoError(t, err)
			}
			require.NoError(t, writer.Close())
			_, err := readLocalArchive(t.Context(), &buffer, true)
			require.ErrorContains(t, err, "duplicate manifest")
		})
	}
}

func TestLocalImageMetadataPartialSource(t *testing.T) {
	const parent = "local:partial"
	for _, scenario := range []string{"unpulled-child", "unpulled-config"} {
		t.Run(scenario, func(t *testing.T) {
			fixture := newLocalMetadataFixture(t)
			if scenario == "unpulled-child" {
				delete(fixture.files, archiveBlobPath(fixture.child.Digest))
			} else {
				delete(fixture.files, archiveBlobPath(fixture.config.Digest))
			}
			mockLocalMetadataArchive(t, parent, &fixture.root, fixture.files)
			forbidLocalMetadataRegistry(t)
			got, config, err := LocalImageMetadata(t.Context(), parent, digest.Digest(fixture.child.Digest.String()))
			require.NoError(t, err, "an unpulled blob must permit immutable recovery through the existing access path")
			require.Nil(t, got)
			require.Nil(t, config)
			root, _, err := LocalImageMetadata(t.Context(), parent, digest.Digest(fixture.root.Digest.String()))
			require.NoError(t, err)
			require.Equal(t, fixture.index, root.Manifest, "the exact local parent remains authoritative")
		})
	}
}
