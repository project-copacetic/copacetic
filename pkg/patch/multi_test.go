package patch

import (
	"context"
	"testing"

	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildPatchingPlan(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		opts      *types.Options
		platforms []types.PatchPlatform
		expected  struct {
			targetPlatform     string
			patchedImageName   string
			preservedPlatforms []string
		}
	}{
		{
			name: "separates target and preserved platforms",
			opts: &types.Options{Image: "docker.io/library/nginx:1.25"},
			platforms: []types.PatchPlatform{
				{Platform: platformSpec("linux", "amd64", ""), ShouldPreserve: false},
				{Platform: platformSpec("linux", "arm64", "v8"), ShouldPreserve: true},
			},
			expected: struct {
				targetPlatform     string
				patchedImageName   string
				preservedPlatforms []string
			}{
				targetPlatform:     "linux/amd64",
				patchedImageName:   "docker.io/library/nginx:1.25-patched",
				preservedPlatforms: []string{"linux/arm64/v8"},
			},
		},
		{
			name: "uses all platforms label when every platform is preserved",
			opts: &types.Options{Image: "docker.io/library/alpine:3.20"},
			platforms: []types.PatchPlatform{
				{Platform: platformSpec("linux", "amd64", ""), ShouldPreserve: true},
				{Platform: platformSpec("linux", "arm64", ""), ShouldPreserve: true},
			},
			expected: struct {
				targetPlatform     string
				patchedImageName   string
				preservedPlatforms []string
			}{
				targetPlatform:     "all platforms",
				patchedImageName:   "docker.io/library/alpine:3.20-patched",
				preservedPlatforms: []string{"linux/amd64", "linux/arm64"},
			},
		},
		{
			name: "keeps explicit patched tag",
			opts: &types.Options{Image: "docker.io/library/busybox:1.36", PatchedTag: "qa-build"},
			platforms: []types.PatchPlatform{
				{Platform: platformSpec("linux", "amd64", ""), ShouldPreserve: false},
			},
			expected: struct {
				targetPlatform     string
				patchedImageName   string
				preservedPlatforms []string
			}{
				targetPlatform:     "linux/amd64",
				patchedImageName:   "docker.io/library/busybox:qa-build",
				preservedPlatforms: nil,
			},
		},
		{
			name: "supports explicit full image reference",
			opts: &types.Options{Image: "docker.io/library/httpd:2.4", PatchedTag: "registry.example.com/copa/httpd:stable"},
			platforms: []types.PatchPlatform{
				{Platform: platformSpec("linux", "amd64", ""), ShouldPreserve: false},
			},
			expected: struct {
				targetPlatform     string
				patchedImageName   string
				preservedPlatforms []string
			}{
				targetPlatform:     "linux/amd64",
				patchedImageName:   "registry.example.com/copa/httpd:stable",
				preservedPlatforms: nil,
			},
		},
		{
			name: "falls back to simple suffix when image reference is invalid",
			opts: &types.Options{Image: "not a valid reference"},
			platforms: []types.PatchPlatform{
				{Platform: platformSpec("linux", "amd64", ""), ShouldPreserve: false},
			},
			expected: struct {
				targetPlatform     string
				patchedImageName   string
				preservedPlatforms []string
			}{
				targetPlatform:     "linux/amd64",
				patchedImageName:   "not a valid reference-patched",
				preservedPlatforms: nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			plan := buildPatchingPlan(tt.opts, tt.platforms)

			assert.Equal(t, tt.expected.targetPlatform, plan.TargetPlatform)
			assert.Equal(t, tt.expected.patchedImageName, plan.PatchedImageName)
			assert.Equal(t, tt.expected.preservedPlatforms, plan.PreservedPlatforms)
		})
	}
}

func TestPatchMultiPlatformImageRejectsMissingDiscoveredPlatforms(t *testing.T) {
	t.Parallel()

	err := patchMultiPlatformImage(context.Background(), &types.Options{Image: "docker.io/library/nginx:1.25"}, nil)

	require.Error(t, err)
	assert.ErrorContains(t, err, "no platforms provided for image")
	assert.ErrorContains(t, err, "docker.io/library/nginx:1.25")
}

func TestPatchMultiPlatformImageRejectsUnavailableRequestedPlatforms(t *testing.T) {
	t.Parallel()

	platforms := []types.PatchPlatform{
		{Platform: platformSpec("linux", "amd64", "")},
		{Platform: platformSpec("linux", "arm64", "")},
	}

	err := patchMultiPlatformImage(context.Background(), &types.Options{
		Image:     "docker.io/library/nginx:1.25",
		Platforms: []string{"linux/s390x"},
	}, platforms)

	require.Error(t, err)
	assert.ErrorContains(t, err, "none of the specified platforms")
	assert.ErrorContains(t, err, "linux/s390x")
}

func TestPatchMultiPlatformImagePropagatesReportDiscoveryErrors(t *testing.T) {
	t.Parallel()

	err := patchMultiPlatformImage(context.Background(), &types.Options{
		Image:   "not a valid reference",
		Report:  t.TempDir(),
		Scanner: "trivy",
	}, nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "error parsing reference")
	assert.Contains(t, err.Error(), "not a valid reference")
}

func platformSpec(os, arch, variant string) v1.Platform {
	return v1.Platform{OS: os, Architecture: arch, Variant: variant}
}
