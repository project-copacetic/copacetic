package buildkit

import (
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	v1types "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
)

// Linux indexes can record an informational os.version, for example Azure
// Linux's "azurelinux-3.0". A target that names only OS and architecture, as a
// scanner report or --platform does, must still select that descriptor.
func TestPlatformDescriptorLinuxOSVersion(t *testing.T) {
	amd64 := specs.Platform{OS: linux, Architecture: "amd64", OSVersion: "azurelinux-3.0"}
	arm64 := specs.Platform{OS: linux, Architecture: "arm64", Variant: "v8", OSVersion: "azurelinux-3.0"}
	index := &specs.Index{Manifests: []specs.Descriptor{
		{MediaType: specs.MediaTypeImageManifest, Digest: digest.FromString("amd64"), Platform: &amd64},
		{MediaType: specs.MediaTypeImageManifest, Digest: digest.FromString("arm64"), Platform: &arm64},
	}}
	source := &ImageSource{Index: index}
	ggcr := &v1.IndexManifest{}
	for _, desc := range index.Manifests {
		hash, err := v1.NewHash(desc.Digest.String())
		require.NoError(t, err)
		ggcr.Manifests = append(ggcr.Manifests, v1.Descriptor{MediaType: v1types.MediaType(desc.MediaType), Digest: hash, Platform: &v1.Platform{
			OS: desc.Platform.OS, Architecture: desc.Platform.Architecture, Variant: desc.Platform.Variant, OSVersion: desc.Platform.OSVersion,
		}})
	}
	for _, tc := range []struct {
		name   string
		target specs.Platform
		want   digest.Digest
	}{
		{"report platform without os.version", specs.Platform{OS: linux, Architecture: "amd64"}, digest.FromString("amd64")},
		{"arm64 without variant or os.version", specs.Platform{OS: linux, Architecture: "arm64"}, digest.FromString("arm64")},
		{"discovered platform with os.version", amd64, digest.FromString("amd64")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := source.PlatformDescriptor(&tc.target)
			require.NoError(t, err)
			require.Equal(t, tc.want, got.Digest)
			match, err := matchingPlatformDescriptor(ggcr, &tc.target)
			require.NoError(t, err)
			require.Equal(t, tc.want.String(), match.Digest.String())
		})
	}
}
