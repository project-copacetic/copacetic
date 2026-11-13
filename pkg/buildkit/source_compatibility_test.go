package buildkit

import (
	"context"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	v1types "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/require"
)

func TestResolveImageSourceReconstructedManifest(t *testing.T) {
	oldLocal, oldRemote := tryGetManifestFromLocal, getRemoteImageDescriptor
	t.Cleanup(func() { tryGetManifestFromLocal, getRemoteImageDescriptor = oldLocal, oldRemote })
	original := v1.Hash{Algorithm: "sha256", Hex: strings.Repeat("a", 64)}
	reconstructed := v1.Hash{Algorithm: "sha256", Hex: strings.Repeat("b", 64)}
	for _, format := range []v1types.MediaType{v1types.OCIManifestSchema1, v1types.DockerManifestSchema2} {
		for _, changed := range []bool{false, true} {
			t.Run(string(format)+"/changed="+map[bool]string{false: "false", true: "true"}[changed], func(t *testing.T) {
				input := "example.com/app:source@" + original.String()
				tryGetManifestFromLocal = func(context.Context, name.Reference) (*remote.Descriptor, v1.Hash, bool, error) {
					return &remote.Descriptor{Descriptor: v1.Descriptor{MediaType: v1types.DockerManifestSchema2, Digest: reconstructed}}, original, true, nil
				}
				getRemoteImageDescriptor = func(ref name.Reference, _ ...remote.Option) (*remote.Descriptor, error) {
					require.Equal(t, original.String(), ref.Identifier())
					selected := original
					if changed {
						selected = reconstructed
					}
					return &remote.Descriptor{Descriptor: v1.Descriptor{MediaType: format, Digest: selected}}, nil
				}
				result, err := ResolveImageSource(t.Context(), input)
				if changed {
					require.ErrorContains(t, err, "does not match immutable reference")
					return
				}
				require.NoError(t, err)
				require.Nil(t, result.Index)
				require.Equal(t, original.String(), result.Descriptor.Digest.String())
				require.Equal(t, string(format), result.Descriptor.MediaType)
			})
		}
	}
}
