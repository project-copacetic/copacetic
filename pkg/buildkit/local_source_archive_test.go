package buildkit

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	v1types "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/stretchr/testify/require"
)

func archiveTestManifest(t *testing.T, value any, mediaType v1types.MediaType) (v1.Descriptor, []byte) {
	t.Helper()
	data, err := json.Marshal(value)
	require.NoError(t, err)
	hash, err := v1.NewHash(digest.FromBytes(data).String())
	require.NoError(t, err)
	return v1.Descriptor{Digest: hash, Size: int64(len(data)), MediaType: mediaType}, data
}

func archiveTestStream(t *testing.T, files map[string][]byte) *bytes.Reader {
	t.Helper()
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for path, data := range files {
		require.NoError(t, writer.WriteHeader(&tar.Header{Name: path, Mode: 0o600, Size: int64(len(data))}))
		_, err := writer.Write(data)
		require.NoError(t, err)
	}
	require.NoError(t, writer.Close())
	return bytes.NewReader(buffer.Bytes())
}

func TestLocalArchiveDescriptor(t *testing.T) {
	annotations := map[string]string{"com.example.application": "preserved"}
	for _, mediaType := range []v1types.MediaType{v1types.OCIManifestSchema1, v1types.DockerManifestSchema2} {
		t.Run(string(mediaType), func(t *testing.T) {
			root, manifest := archiveTestManifest(t, v1.Manifest{SchemaVersion: 2, MediaType: mediaType, Annotations: annotations}, mediaType)
			root.Annotations = map[string]string{"io.containerd.image.name": "local/alias:source"}
			_, wrapper := archiveTestManifest(t, v1.IndexManifest{SchemaVersion: 2, Manifests: []v1.Descriptor{root}}, v1types.OCIImageIndex)
			files := map[string][]byte{"index.json": wrapper, archiveBlobPath(root.Digest): manifest, "manifest.json": []byte(`[{"Config":"legacy.json"}]`)}
			got, err := readArchiveDescriptor(t.Context(), archiveTestStream(t, files))
			require.NoError(t, err)
			require.Equal(t, root.Digest, got.Digest)
			require.Equal(t, manifest, got.Manifest)
			require.Equal(t, annotations, got.Annotations)
			files[archiveBlobPath(root.Digest)] = bytes.ReplaceAll(manifest, []byte("preserved"), []byte("different"))
			_, err = readArchiveDescriptor(t.Context(), archiveTestStream(t, files))
			require.ErrorContains(t, err, "does not match descriptor")
			files[archiveBlobPath(root.Digest)] = append(manifest, ' ')
			_, err = readArchiveDescriptor(t.Context(), archiveTestStream(t, files))
			require.ErrorContains(t, err, "does not match descriptor")
		})
	}
}

func TestLocalArchivePartialIndex(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		t.Run(map[bool]string{false: "available-child", true: "invalid-child-origin"}[invalid], func(t *testing.T) {
			annotations := map[string]string{"com.example.application": "preserved"}
			if invalid {
				annotations[types.AnnotationPatchOriginKind] = types.PatchOriginImage
			}
			child, manifest := archiveTestManifest(t, v1.Manifest{
				SchemaVersion: 2, MediaType: v1types.OCIManifestSchema1,
				Config:      v1.Descriptor{Digest: v1.Hash{Algorithm: "sha256", Hex: digest.FromString("config").Encoded()}},
				Annotations: annotations,
			}, v1types.OCIManifestSchema1)
			child.Platform = &v1.Platform{OS: "linux", Architecture: "amd64"}
			missing := child
			missing.Digest, _ = v1.NewHash(digest.FromString("unavailable sibling").String())
			missing.Platform = &v1.Platform{OS: "linux", Architecture: "arm64"}
			root, index := archiveTestManifest(t, v1.IndexManifest{SchemaVersion: 2, MediaType: v1types.OCIImageIndex, Manifests: []v1.Descriptor{child, missing}}, v1types.OCIImageIndex)
			_, wrapper := archiveTestManifest(t, v1.IndexManifest{SchemaVersion: 2, Manifests: []v1.Descriptor{root}}, v1types.OCIImageIndex)
			got, err := readArchiveDescriptor(t.Context(), archiveTestStream(t, map[string][]byte{"index.json": wrapper, archiveBlobPath(root.Digest): index, archiveBlobPath(child.Digest): manifest}))
			if invalid {
				require.ErrorContains(t, err, "invalid patch origin")
				return
			}
			require.NoError(t, err)
			require.Equal(t, root.Digest, got.Digest)
			var result v1.IndexManifest
			require.NoError(t, json.Unmarshal(got.Manifest, &result))
			require.Len(t, result.Manifests, 2)
			require.Equal(t, annotations, result.Manifests[0].Annotations)
			require.Equal(t, missing, result.Manifests[1])
		})
	}
}

func TestLocalArchiveInvalidMetadata(t *testing.T) {
	for _, raw := range []string{
		`{`, `{"schemaVersion":1}`, `{"schemaVersion":2,"manifests":[]}`, `{"schemaVersion":2,"manifests":[{},{}]}`,
		`{"schemaVersion":2,"manifests":[{"digest":"invalid"}]}`, `{"schemaVersion":2,"mediaType":"unsupported","manifests":[{}]}`,
	} {
		_, err := readArchiveDescriptor(t.Context(), archiveTestStream(t, map[string][]byte{"index.json": []byte(raw)}))
		require.Error(t, err)
	}
	got, err := readArchiveDescriptor(t.Context(), archiveTestStream(t, map[string][]byte{"manifest.json": []byte(`[]`)}))
	require.NoError(t, err)
	require.Nil(t, got)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = readArchiveDescriptor(ctx, bytes.NewReader(nil))
	require.ErrorIs(t, err, context.Canceled)
}

func TestInvalidLocalArchiveNeverFallsBackToRegistry(t *testing.T) {
	oldIndex, oldArchive, oldRemote := localImageIndex, localArchiveDescriptor, getRemoteImageDescriptor
	t.Cleanup(func() {
		localImageIndex, localArchiveDescriptor, getRemoteImageDescriptor = oldIndex, oldArchive, oldRemote
	})
	localImageIndex = func(context.Context, string) (*specs.Index, *specs.Descriptor, bool, bool, error) {
		return nil, nil, true, true, nil
	}
	localArchiveDescriptor = func(context.Context, string) (*remote.Descriptor, error) {
		return nil, errors.New("invalid captured archive")
	}
	getRemoteImageDescriptor = func(name.Reference, ...remote.Option) (*remote.Descriptor, error) {
		t.Fatal("must not replace a locally present source with registry content")
		return nil, nil
	}
	_, err := ResolveImageSource(t.Context(), "example.com/local:source")
	require.ErrorContains(t, err, "invalid captured archive")
}

func TestLocalArchiveOversizedAndDuplicateIndex(t *testing.T) {
	for _, scenario := range []string{"oversized", "duplicate", "invalid-then-valid"} {
		t.Run(scenario, func(t *testing.T) {
			var buffer bytes.Buffer
			writer := tar.NewWriter(&buffer)
			data := []byte(`{"schemaVersion":2,"manifests":[]}`)
			if scenario == "oversized" {
				body := bytes.Repeat([]byte(" "), 4<<20+1)
				copy(body, data)
				require.NoError(t, writer.WriteHeader(&tar.Header{Name: "index.json", Mode: 0o600, Size: int64(len(body))}))
				_, err := writer.Write(body)
				require.NoError(t, err)
				require.NoError(t, writer.Close())
			} else {
				for i := range 2 {
					body := data
					if i == 0 && scenario == "invalid-then-valid" {
						body = []byte(`{`)
					}
					require.NoError(t, writer.WriteHeader(&tar.Header{Name: "index.json", Mode: 0o600, Size: int64(len(body))}))
					_, err := writer.Write(body)
					require.NoError(t, err)
				}
				require.NoError(t, writer.Close())
			}
			_, err := readArchiveDescriptor(t.Context(), bytes.NewReader(buffer.Bytes()))
			expected := map[string]string{
				"oversized": "invalid index entry", "duplicate": "multiple indexes", "invalid-then-valid": "invalid index",
			}
			require.ErrorContains(t, err, expected[scenario])
		})
	}
}

func TestLocalArchiveUnsupportedWrapper(t *testing.T) {
	root, manifest := archiveTestManifest(t, v1.Manifest{SchemaVersion: 2, MediaType: v1types.OCIManifestSchema1}, v1types.OCIManifestSchema1)
	_, wrapper := archiveTestManifest(t, v1.IndexManifest{
		SchemaVersion: 2, MediaType: "unsupported", Manifests: []v1.Descriptor{root},
	}, v1types.OCIImageIndex)
	_, err := readArchiveDescriptor(t.Context(), archiveTestStream(t, map[string][]byte{
		"index.json": wrapper, archiveBlobPath(root.Digest): manifest,
	}))
	require.ErrorContains(t, err, "must identify exactly one source")
}
