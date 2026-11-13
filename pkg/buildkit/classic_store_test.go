package buildkit

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/daemon"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	v1types "github.com/google/go-containerregistry/pkg/v1/types"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
)

// Docker's classic graph-driver store has no inspect descriptor and keeps no
// manifests. Its `docker save` index and go-containerregistry's daemon image
// both describe a reconstruction whose digest no registry has served (the
// CI TestPatchBuiltOpenSSL failure).
func TestResolveImageSourceClassicStoreUsesRegistryIdentity(t *testing.T) {
	oldIndex, oldStore, oldArchive, oldDaemon, oldRemote := localImageIndex, localImageStoreKeepsManifests, localArchiveDescriptor, getImageFromDaemon, getRemoteImageDescriptor
	t.Cleanup(func() {
		localImageIndex, localImageStoreKeepsManifests, localArchiveDescriptor, getImageFromDaemon, getRemoteImageDescriptor = oldIndex, oldStore, oldArchive, oldDaemon, oldRemote
	})
	reconstructed, err := mutate.ConfigFile(empty.Image, &v1.ConfigFile{OS: "linux", Architecture: "amd64"})
	require.NoError(t, err)
	reconstructedDigest, err := reconstructed.Digest()
	require.NoError(t, err)
	published := v1.Hash{Algorithm: "sha256", Hex: strings.Repeat("d", 64)}
	require.NotEqual(t, published, reconstructedDigest)

	for _, tc := range []struct {
		name      string
		input     string
		remoteErr error
	}{
		{name: "immutable reference present locally", input: "127.0.0.1:5000/copa-openssl:test-debian12@" + published.String()},
		{name: "mutable tag present locally", input: "127.0.0.1:5000/copa-openssl:test-debian12"},
		{name: "registry unavailable", input: "127.0.0.1:5000/copa-openssl:test-debian12", remoteErr: errors.New("registry unavailable")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			localImageIndex = func(context.Context, string) (*specs.Index, *specs.Descriptor, bool, bool, error) {
				return nil, nil, true, true, nil // found, no descriptor
			}
			localImageStoreKeepsManifests = func(context.Context) (bool, error) { return false, nil }
			localArchiveDescriptor = func(context.Context, string) (*remote.Descriptor, error) {
				t.Fatal("a classic store's saved index must not identify the source")
				return nil, nil
			}
			getImageFromDaemon = func(name.Reference, ...daemon.Option) (v1.Image, error) { return reconstructed, nil }
			remoteReads := 0
			getRemoteImageDescriptor = func(ref name.Reference, _ ...remote.Option) (*remote.Descriptor, error) {
				remoteReads++
				if digestRef, ok := ref.(name.Digest); ok {
					require.Equal(t, published.String(), digestRef.DigestStr())
				}
				if tc.remoteErr != nil {
					return nil, tc.remoteErr
				}
				return &remote.Descriptor{Descriptor: v1.Descriptor{MediaType: v1types.DockerManifestSchema2, Digest: published, Size: 528}}, nil
			}

			source, err := ResolveImageSource(t.Context(), tc.input)
			require.Equal(t, 1, remoteReads)
			if tc.remoteErr != nil {
				require.ErrorIs(t, err, tc.remoteErr, "a reconstruction must never stand in for an unavailable registry identity")
				return
			}
			require.NoError(t, err)
			require.True(t, source.Registry)
			require.Nil(t, source.Index)
			require.Equal(t, published.String(), source.Descriptor.Digest.String())
		})
	}

	t.Run("discovery keeps the local reconstruction", func(t *testing.T) {
		localImageIndex = func(context.Context, string) (*specs.Index, *specs.Descriptor, bool, bool, error) {
			return nil, nil, true, true, nil
		}
		localImageStoreKeepsManifests = func(context.Context) (bool, error) { return false, nil }
		getImageFromDaemon = func(name.Reference, ...daemon.Option) (v1.Image, error) { return reconstructed, nil }
		getRemoteImageDescriptor = func(name.Reference, ...remote.Option) (*remote.Descriptor, error) {
			t.Fatal("platform discovery of a local image must stay local")
			return nil, nil
		}
		ref, err := name.ParseReference("127.0.0.1:5000/copa-openssl:test-debian12")
		require.NoError(t, err)
		desc, err := TryGetManifestFromLocalWithContext(t.Context(), ref)
		require.NoError(t, err)
		require.Equal(t, reconstructedDigest, desc.Digest)
	})

	t.Run("store detection failure is not an identity", func(t *testing.T) {
		localImageIndex = func(context.Context, string) (*specs.Index, *specs.Descriptor, bool, bool, error) {
			return nil, nil, true, true, nil
		}
		localImageStoreKeepsManifests = func(context.Context) (bool, error) { return false, errors.New("info unavailable") }
		localArchiveDescriptor = func(context.Context, string) (*remote.Descriptor, error) {
			t.Fatal("an unknown store must not be trusted to keep manifests")
			return nil, nil
		}
		getImageFromDaemon = func(name.Reference, ...daemon.Option) (v1.Image, error) { return reconstructed, nil }
		getRemoteImageDescriptor = func(name.Reference, ...remote.Option) (*remote.Descriptor, error) {
			return &remote.Descriptor{Descriptor: v1.Descriptor{MediaType: v1types.DockerManifestSchema2, Digest: published}}, nil
		}
		source, err := ResolveImageSource(t.Context(), "127.0.0.1:5000/copa-openssl:test-debian12")
		require.NoError(t, err)
		require.True(t, source.Registry)
		require.Equal(t, published.String(), source.Descriptor.Digest.String())
	})

	t.Run("containerd store keeps the local identity", func(t *testing.T) {
		localImageIndex = func(context.Context, string) (*specs.Index, *specs.Descriptor, bool, bool, error) {
			return nil, nil, true, true, nil // API < 1.48 omits the descriptor
		}
		localImageStoreKeepsManifests = func(context.Context) (bool, error) { return true, nil }
		local := v1.Hash{Algorithm: "sha256", Hex: strings.Repeat("e", 64)}
		localArchiveDescriptor = func(context.Context, string) (*remote.Descriptor, error) {
			return &remote.Descriptor{Descriptor: v1.Descriptor{MediaType: v1types.OCIManifestSchema1, Digest: local}}, nil
		}
		getImageFromDaemon = func(name.Reference, ...daemon.Option) (v1.Image, error) {
			t.Fatal("the original archive identity must be used")
			return nil, nil
		}
		getRemoteImageDescriptor = func(name.Reference, ...remote.Option) (*remote.Descriptor, error) {
			t.Fatal("a local mutable tag in a manifest-keeping store must not be replaced with registry content")
			return nil, nil
		}
		source, err := ResolveImageSource(t.Context(), "registry.invalid/app:local")
		require.NoError(t, err)
		require.False(t, source.Registry)
		require.Equal(t, local.String(), source.Descriptor.Digest.String())
	})
}
