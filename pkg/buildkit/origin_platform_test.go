package buildkit

import (
	"encoding/json"
	"testing"

	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/project-copacetic/copacetic/mocks"
	"github.com/project-copacetic/copacetic/pkg/types"
)

// A recorded origin digest that names another platform's manifest must not be
// used as the re-patch base: a single-platform manifest resolves regardless of
// the requested platform, which would graft the patch onto a foreign rootfs.
func TestUpdateImageConfigDataRejectsCrossPlatformOrigin(t *testing.T) {
	const (
		original = "example.com/app:original"
		patched  = "example.com/app:patched"
	)
	recorded := digest.FromString("recorded original")
	lineage := &types.SourceLineage{Kind: types.PatchOriginImage, Name: original, Digest: recorded}

	imageConfig := func(t *testing.T, platform specs.Platform, labels map[string]string) []byte {
		t.Helper()
		config, err := json.Marshal(specs.Image{Platform: platform, Config: specs.ImageConfig{Labels: labels}})
		require.NoError(t, err)
		return originalTestConfig(t, config)
	}
	repatchInput := func(t *testing.T, platform specs.Platform) []byte {
		t.Helper()
		config, err := AddImageConfigLabels(imageConfig(t, platform, map[string]string{"BaseImage": original}), lineage.Annotations())
		require.NoError(t, err)
		return copaOutputTestConfig(t, config)
	}

	amd64 := specs.Platform{OS: "linux", Architecture: "amd64"}
	arm64 := specs.Platform{OS: "linux", Architecture: "arm64"}
	arm64v8 := specs.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}
	windows := specs.Platform{OS: "windows", Architecture: "amd64", OSVersion: "10.0.20348.2655"}
	otherWindows := specs.Platform{OS: "windows", Architecture: "amd64", OSVersion: "10.0.17763.6189"}

	for _, tc := range []struct {
		name      string
		input     []byte
		origin    []byte
		requested *specs.Platform
		wantErr   string
	}{
		{
			name:    "frontend default platform rejects foreign origin",
			input:   repatchInput(t, amd64),
			origin:  imageConfig(t, arm64, nil),
			wantErr: "does not match patched image platform",
		},
		{
			name:      "requested platform rejects foreign origin",
			input:     repatchInput(t, amd64),
			origin:    imageConfig(t, arm64, nil),
			requested: &amd64,
			wantErr:   "does not match patched image platform",
		},
		{
			name:      "requested platform checked when input omits its platform",
			input:     repatchInput(t, specs.Platform{}),
			origin:    imageConfig(t, arm64, nil),
			requested: &amd64,
			wantErr:   "does not match requested platform",
		},
		{
			name:    "frontend default platform cannot verify origin when input omits its platform",
			input:   repatchInput(t, specs.Platform{}),
			origin:  imageConfig(t, arm64, nil),
			wantErr: "no target platform was requested",
		},
		{
			name:    "frontend default platform rejects undeclared input and origin",
			input:   repatchInput(t, specs.Platform{}),
			origin:  imageConfig(t, specs.Platform{}, nil),
			wantErr: "no target platform was requested",
		},
		{
			name:    "origin without a declared platform cannot be verified",
			input:   repatchInput(t, amd64),
			origin:  imageConfig(t, specs.Platform{}, nil),
			wantErr: "does not declare its platform",
		},
		{
			name:    "windows origin must keep the exact os version",
			input:   repatchInput(t, windows),
			origin:  imageConfig(t, otherWindows, nil),
			wantErr: "does not match patched image platform",
		},
		{
			name:      "normalized arm64 variant matches",
			input:     repatchInput(t, arm64v8),
			origin:    imageConfig(t, arm64, nil),
			requested: &arm64,
		},
		{
			name:      "windows requested platform may omit os version",
			input:     repatchInput(t, windows),
			origin:    imageConfig(t, windows, nil),
			requested: &specs.Platform{OS: "windows", Architecture: "amd64"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &mocks.MockGWClient{}
			client.On("ResolveImageConfig", mock.Anything, mock.Anything, mock.Anything).Return(original, recorded, tc.origin, nil)

			_, _, _, origin, validated, err := updateImageConfigData(t.Context(), client, tc.input, patched, patched, digest.FromString("P1"), tc.requested)
			if tc.wantErr != "" {
				require.ErrorIs(t, err, ErrOriginIntegrity)
				require.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			require.True(t, validated)
			require.Equal(t, recorded, origin.Digest)
		})
	}
}

// A legacy BaseImage-only image has no recorded digest, so its mutable locator
// may now name an image for another platform. Copa must fall back to the
// current image instead of rebuilding the patch on that image's root filesystem.
func TestUpdateImageConfigDataChecksLegacyBaseImagePlatform(t *testing.T) {
	const (
		original = "example.com/app:original"
		patched  = "example.com/app:patched"
	)
	imageConfig := func(t *testing.T, platform specs.Platform, labels map[string]string) []byte {
		t.Helper()
		config, err := json.Marshal(specs.Image{Platform: platform, Config: specs.ImageConfig{Labels: labels}})
		require.NoError(t, err)
		return config
	}
	legacyInput := func(t *testing.T, platform specs.Platform) []byte {
		t.Helper()
		return imageConfig(t, platform, map[string]string{"BaseImage": original})
	}

	amd64 := specs.Platform{OS: "linux", Architecture: "amd64"}
	arm64 := specs.Platform{OS: "linux", Architecture: "arm64"}
	arm64v8 := specs.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}

	for _, tc := range []struct {
		name         string
		input        []byte
		base         []byte
		requested    *specs.Platform
		wantFallback bool
	}{
		{
			name:         "base for another platform falls back",
			input:        legacyInput(t, arm64),
			base:         imageConfig(t, amd64, nil),
			wantFallback: true,
		},
		{
			name:         "base for another platform than requested falls back",
			input:        legacyInput(t, specs.Platform{}),
			base:         imageConfig(t, amd64, nil),
			requested:    &arm64,
			wantFallback: true,
		},
		{
			name:         "base without a declared platform falls back",
			input:        legacyInput(t, arm64),
			base:         imageConfig(t, specs.Platform{}, nil),
			wantFallback: true,
		},
		{
			name:         "undeclared input with no requested platform falls back",
			input:        legacyInput(t, specs.Platform{}),
			base:         imageConfig(t, arm64, nil),
			wantFallback: true,
		},
		{
			name:  "matching base is used",
			input: legacyInput(t, arm64),
			base:  imageConfig(t, arm64, nil),
		},
		{
			name:      "normalized arm64 variant matches the requested platform",
			input:     legacyInput(t, arm64v8),
			base:      imageConfig(t, arm64, nil),
			requested: &arm64,
		},
		{
			name:      "undeclared input uses a base that matches the requested platform",
			input:     legacyInput(t, specs.Platform{}),
			base:      imageConfig(t, arm64, nil),
			requested: &arm64,
		},
		{
			// Some paths request the host's default platform rather than the image's.
			name:      "base matching the declared input platform is used when the request differs",
			input:     legacyInput(t, arm64),
			base:      imageConfig(t, arm64, nil),
			requested: &amd64,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &mocks.MockGWClient{}
			client.On("ResolveImageConfig", mock.Anything, original, mock.Anything).Return(original, digest.FromString("current tag"), tc.base, nil)

			config, patchedConfig, base, lineage, validated, err := updateImageConfigData(t.Context(), client, tc.input, patched, patched, digest.FromString("P1"), tc.requested)
			require.NoError(t, err)
			require.Nil(t, lineage)
			require.False(t, validated)
			if tc.wantFallback {
				require.Equal(t, patched, base, "a mismatched legacy BaseImage must not be used as the re-patch base")
				require.Nil(t, patchedConfig)
				var image specs.Image
				require.NoError(t, json.Unmarshal(config, &image))
				require.Equal(t, patched, image.Config.Labels["BaseImage"])
				return
			}
			require.Equal(t, original, base)
			require.NotNil(t, patchedConfig)
			var image specs.Image
			require.NoError(t, json.Unmarshal(config, &image))
			require.Equal(t, original, image.Config.Labels["BaseImage"])
			client.AssertExpectations(t)
		})
	}
}
