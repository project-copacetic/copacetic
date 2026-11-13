package ocilayout

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/errdefs"
	"github.com/moby/buildkit/client"
	digest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// layoutTreeState records every entry, including directories and their
// modification times, so that creating and removing a temporary entry is
// visible even though no regular file changes.
func layoutTreeState(t *testing.T, root string) map[string]string {
	t.Helper()
	state := make(map[string]string)
	require.NoError(t, filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		value := info.Mode().String() + " " + info.ModTime().UTC().Format(time.RFC3339Nano)
		if info.Mode().IsRegular() {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			value += " " + digest.FromBytes(data).String()
		}
		state[rel] = value
		return nil
	}))
	return state
}

func ageLayoutTree(t *testing.T, root string) {
	t.Helper()
	old := time.Unix(1_000_000_000, 0)
	require.NoError(t, filepath.WalkDir(root, func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return os.Chtimes(path, old, old)
	}))
}

func TestSourceOperationsDoNotTouchInputDirectories(t *testing.T) {
	root := t.TempDir()
	amd64 := newImageManifest(t, root, &ocispec.Platform{OS: "linux", Architecture: "amd64"}, nil, map[string]string{"body.example": "kept"})
	arm64 := newImageManifest(t, root, &ocispec.Platform{OS: "linux", Architecture: "arm64"}, nil, nil)
	imageIndex := ocispec.Index{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ocispec.MediaTypeImageIndex,
		Manifests: []ocispec.Descriptor{amd64, arm64},
	}
	indexDesc := writeBlob(t, root, ocispec.MediaTypeImageIndex, marshalJSON(t, imageIndex))
	newLayoutAt(t, root, []ocispec.Descriptor{indexDesc})
	ageLayoutTree(t, root)
	before := layoutTreeState(t, root)

	source, err := Open(t.Context(), root, filepath.Join(t.TempDir(), "output"), "")
	require.NoError(t, err)
	found, err := source.Platforms(t.Context())
	require.NoError(t, err)
	require.Len(t, found, 2)
	_, err = source.IndexAnnotations(t.Context())
	require.NoError(t, err)
	output := t.TempDir()
	copied := make(map[string]bool)
	for i := range found {
		_, err = source.PlatformAnnotations(t.Context(), &found[i])
		require.NoError(t, err)
		_, err = source.CopyPlatform(t.Context(), output, &found[i], copied)
		require.NoError(t, err)
	}
	var solveOpt client.SolveOpt
	source.AddToSolveOpt(&solveOpt)
	store := solveOpt.OCIStores[source.StoreID]
	_, err = store.Info(t.Context(), amd64.Digest)
	require.NoError(t, err)
	_, err = content.ReadBlob(t.Context(), store, amd64)
	require.NoError(t, err)

	assert.Equal(t, before, layoutTreeState(t, root), "no entry or directory timestamp in the input may change")
}

func TestSessionStoreIsReadOnly(t *testing.T) {
	fixture := newSingleLayout(t, nil)
	source, err := Open(t.Context(), fixture.path, "", "")
	require.NoError(t, err)
	var solveOpt client.SolveOpt
	source.AddToSolveOpt(&solveOpt)
	store := solveOpt.OCIStores[source.StoreID]
	require.NotNil(t, store)
	desc := fixture.manifests[0]
	ageLayoutTree(t, fixture.path)
	before := layoutTreeState(t, fixture.path)
	ctx := t.Context()

	_, err = store.Writer(ctx, content.WithRef("copa-write-attempt"))
	assert.True(t, errdefs.IsPermissionDenied(err), "writer: %v", err)
	assert.True(t, errdefs.IsPermissionDenied(store.Delete(ctx, desc.Digest)), "a session peer must not delete input blobs")
	_, err = store.Update(ctx, content.Info{Digest: desc.Digest, Labels: map[string]string{"copa": "label"}}, "labels.copa")
	assert.True(t, errdefs.IsPermissionDenied(err), "update: %v", err)
	assert.True(t, errdefs.IsPermissionDenied(store.Abort(ctx, "copa-write-attempt")))
	_, err = store.Status(ctx, "copa-write-attempt")
	assert.True(t, errdefs.IsNotFound(err), "status: %v", err)
	statuses, err := store.ListStatuses(ctx)
	require.NoError(t, err)
	assert.Empty(t, statuses)

	info, err := store.Info(ctx, desc.Digest)
	require.NoError(t, err)
	assert.Equal(t, desc.Digest, info.Digest)
	assert.Equal(t, desc.Size, info.Size)
	data, err := content.ReadBlob(ctx, store, desc)
	require.NoError(t, err)
	assert.Equal(t, desc.Digest, digest.FromBytes(data))

	_, err = store.Info(ctx, digest.FromString("missing"))
	assert.True(t, errdefs.IsNotFound(err), "missing info: %v", err)
	_, err = store.ReaderAt(ctx, ocispec.Descriptor{Digest: digest.FromString("missing")})
	assert.True(t, errdefs.IsNotFound(err), "missing reader: %v", err)
	_, err = store.Info(ctx, digest.Digest("sha256:../../index.json"))
	assert.True(t, errdefs.IsInvalidArgument(err), "malformed digest: %v", err)

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	_, err = store.ReaderAt(canceled, desc)
	require.ErrorIs(t, err, context.Canceled)

	assert.Equal(t, before, layoutTreeState(t, fixture.path), "rejected writes leave the input unchanged")
}

func TestSessionStoreKeepsReadsInsideBlobDirectory(t *testing.T) {
	fixture := newSingleLayout(t, nil)
	source, err := Open(t.Context(), fixture.path, "", "")
	require.NoError(t, err)
	outside := filepath.Join(t.TempDir(), "outside")
	require.NoError(t, os.WriteFile(outside, []byte("outside"), 0o600))
	dgst := digest.FromString("outside")
	link := filepath.Join(fixture.path, "blobs", dgst.Algorithm().String(), dgst.Encoded())
	require.NoError(t, os.Symlink(outside, link))
	var solveOpt client.SolveOpt
	source.AddToSolveOpt(&solveOpt)
	_, err = solveOpt.OCIStores[source.StoreID].ReaderAt(t.Context(), ocispec.Descriptor{Digest: dgst, Size: 7})
	require.ErrorContains(t, err, "resolves outside OCI layout blob directory")
}
