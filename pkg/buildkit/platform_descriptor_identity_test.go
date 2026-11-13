package buildkit

import (
	"fmt"
	"testing"

	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
)

const descriptorWindowsFeature = "win32k"

func TestPlatformDescriptorExactIdentity(t *testing.T) {
	windows20348 := specs.Platform{OS: goosWindows, Architecture: cancellationAMD64, OSVersion: "10.0.20348.1"}
	windows26100 := specs.Platform{OS: goosWindows, Architecture: cancellationAMD64, OSVersion: "10.0.26100.1"}
	windowsRevision := windows20348
	windowsRevision.OSVersion = "10.0.20348.2"
	windowsFeatures := windows20348
	windowsFeatures.OSFeatures = []string{descriptorWindowsFeature}
	arm64 := specs.Platform{OS: linux, Architecture: arm64, Variant: "v8"}
	armAlias := specs.Platform{OS: linux, Architecture: "aarch64"}

	for _, tc := range []struct {
		name      string
		platforms []specs.Platform
		target    specs.Platform
		want      int
		wantErr   string
	}{
		{
			name: "Windows 20348 is not 26100", platforms: []specs.Platform{windows20348, windows26100},
			target: windows20348, want: 0,
		},
		{
			name: "Windows 26100 is not 20348", platforms: []specs.Platform{windows20348, windows26100},
			target: windows26100, want: 1,
		},
		{
			name: "Windows revision is part of identity", platforms: []specs.Platform{windows20348, windowsRevision},
			target: windowsRevision, want: 1,
		},
		{
			name: "Windows features are part of identity", platforms: []specs.Platform{windows20348, windowsFeatures},
			target: windowsFeatures, want: 1,
		},
		{
			name: "Windows features cannot be omitted", platforms: []specs.Platform{windowsFeatures},
			target: windows20348, wantErr: "no descriptor",
		},
		{
			name: "compatible Windows version is not identity", platforms: []specs.Platform{windows20348},
			target: windows26100, wantErr: "no descriptor",
		},
		{
			name: "normalized arm64 alias", platforms: []specs.Platform{armAlias},
			target: arm64, want: 0,
		},
		{
			name: "duplicate Windows identity", platforms: []specs.Platform{windows20348, windows20348},
			target: windows20348, wantErr: "multiple descriptors",
		},
		{
			name: "duplicate normalized arm64 identity", platforms: []specs.Platform{armAlias, arm64},
			target: arm64, wantErr: "multiple descriptors",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := &ImageSource{Index: &specs.Index{}}
			for i, platform := range tc.platforms {
				source.Index.Manifests = append(source.Index.Manifests, specs.Descriptor{
					MediaType: specs.MediaTypeImageManifest,
					Digest:    digest.FromString(fmt.Sprintf("%s/%d", tc.name, i)),
					Platform:  &platform,
				})
			}
			// An unqualified descriptor must never match a requested platform.
			source.Index.Manifests = append(source.Index.Manifests, specs.Descriptor{Digest: digest.FromString("no platform")})
			got, err := source.PlatformDescriptor(&tc.target)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				require.Nil(t, got)
				return
			}
			require.NoError(t, err)
			require.Equal(t, source.Index.Manifests[tc.want], *got)
		})
	}
}
