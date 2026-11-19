package buildkit

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/distribution/reference"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/daemon"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	v1types "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"

	"github.com/project-copacetic/copacetic/pkg/types"
)

// A complete local multi-platform index in the containerd image store is named
// only by the index, so the daemon cannot resolve <repo>@<child digest>. The
// preserved child must be exported from one save of the index instead.
func TestExportPreservedPlatformsFromLocalIndexArchive(t *testing.T) {
	const parent = "example.com/local:parent"
	layer := []byte("original layer bytes")
	layerHash, err := v1.NewHash(digest.FromBytes(layer).String())
	require.NoError(t, err)
	layerDesc := v1.Descriptor{MediaType: v1types.OCILayer, Size: int64(len(layer)), Digest: layerHash}
	files := map[string][]byte{archiveBlobPath(layerDesc.Digest): layer}
	var children []v1.Descriptor
	var amd64Config string
	for _, arch := range []string{cancellationAMD64, "386"} {
		config := []byte(`{"os":"linux","architecture":"` + arch + `","rootfs":{"type":"layers","diff_ids":[]}}`)
		configDesc := localMetadataDescriptor(t, config, v1types.OCIConfigJSON)
		child, body := archiveTestManifest(t, v1.Manifest{
			SchemaVersion: 2, MediaType: v1types.OCIManifestSchema1, Config: configDesc, Layers: []v1.Descriptor{layerDesc},
		}, v1types.OCIManifestSchema1)
		child.Platform = &v1.Platform{OS: linux, Architecture: arch}
		files[archiveBlobPath(child.Digest)], files[archiveBlobPath(configDesc.Digest)] = body, config
		if arch == cancellationAMD64 {
			amd64Config = archiveBlobPath(configDesc.Digest)
		}
		children = append(children, child)
	}
	root, index := archiveTestManifest(t, v1.IndexManifest{SchemaVersion: 2, MediaType: v1types.OCIImageIndex, Manifests: children}, v1types.OCIImageIndex)
	files[localMetadataIndexFile], files[archiveBlobPath(root.Digest)] = localMetadataWrapper(t, &root), index

	mockLocalMetadataArchive(t, parent, &root, files)
	oldLocal, oldDaemon := tryGetManifestFromLocal, getImageFromDaemon
	t.Cleanup(func() { tryGetManifestFromLocal, getImageFromDaemon = oldLocal, oldDaemon })
	tryGetManifestFromLocal = func(context.Context, name.Reference) (*remote.Descriptor, v1.Hash, bool, error) {
		return &remote.Descriptor{Descriptor: root, Manifest: index}, root.Digest, true, nil
	}
	getImageFromDaemon = func(ref name.Reference, _ ...daemon.Option) (v1.Image, error) {
		return nil, errors.New("No such image: " + ref.String())
	}

	ref, err := reference.ParseNormalizedNamed(parent)
	require.NoError(t, err)
	outputDir := t.TempDir()
	preserved := []types.PatchPlatform{{Platform: specs.Platform{OS: linux, Architecture: "386"}}}
	manifests, err := exportPreservedPlatformsToOutput(t.Context(), outputDir, ref, preserved, map[string]bool{})
	require.NoError(t, err)
	require.Len(t, manifests, 1)
	require.Equal(t, children[1].Digest.String(), manifests[0]["digest"])

	// The original manifest, config and layer bytes land under their own digests.
	for path, want := range files {
		if path == localMetadataIndexFile || path == archiveBlobPath(root.Digest) || path == archiveBlobPath(children[0].Digest) || path == amd64Config {
			continue // the index and the patched platform are not preserved content
		}
		got, err := os.ReadFile(filepath.Join(outputDir, path))
		require.NoError(t, err, path)
		require.Equal(t, want, got, path)
	}
}
