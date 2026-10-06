package patch

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
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

func TestMarkPlatformPreserved(t *testing.T) {
	t.Parallel()

	platforms := []types.PatchPlatform{
		{Platform: platformSpec("linux", "amd64", "")},
		{Platform: platformSpec("linux", "arm64", "v8")},
	}

	markPlatformPreserved(platforms, "linux/arm64/v8")

	assert.False(t, platforms[0].ShouldPreserve)
	assert.True(t, platforms[1].ShouldPreserve)
}

func TestPlatformBuildOptionsClearsSharedVEXOutput(t *testing.T) {
	t.Parallel()

	opts := &types.Options{
		Image:       "docker.io/library/nginx:1.25",
		Output:      "vex.json",
		Format:      "openvex",
		Report:      "reports",
		IgnoreError: true,
	}

	got := platformBuildOptions(opts, "reports/linux-amd64.json")

	require.NotNil(t, got)
	assert.Equal(t, "reports/linux-amd64.json", got.Report)
	assert.Empty(t, got.Output)
	assert.Equal(t, "openvex", got.Format)
	assert.True(t, got.IgnoreError)
	assert.Equal(t, "docker.io/library/nginx:1.25", got.Image)
	assert.Equal(t, "vex.json", opts.Output)
	assert.Equal(t, "reports", opts.Report)
}

func TestWriteMultiPlatformVEX(t *testing.T) {
	t.Parallel()

	amd64 := platformSpec("linux", "amd64", "")
	arm64 := platformSpec("linux", "arm64", "")
	ppc64le := platformSpec("linux", "ppc64le", "")
	platforms := []types.PatchPlatform{
		{Platform: amd64},
		{Platform: ppc64le, ShouldPreserve: true},
		{Platform: arm64},
	}
	// Filled in reverse completion order. ppc64le is preserved and has no entry.
	vexByPlatform := map[string]*types.PlatformVEX{
		buildkit.PlatformKey(arm64): platformVEX(t, "nginx@sha256:arm64", "arm64"),
		buildkit.PlatformKey(amd64): platformVEX(t, "nginx@sha256:amd64", "amd64"),
	}

	t.Run("writes one document in platform order", func(t *testing.T) {
		t.Parallel()

		outputPath := filepath.Join(t.TempDir(), "vex.json")
		err := writeMultiPlatformVEX(platforms, vexByPlatform, "openvex", outputPath)
		require.NoError(t, err)

		body, err := os.ReadFile(outputPath)
		require.NoError(t, err)

		var doc struct {
			Statements []struct {
				Products []struct {
					ID            string `json:"@id"`
					Subcomponents []struct {
						ID string `json:"@id"`
					} `json:"subcomponents"`
				} `json:"products"`
			} `json:"statements"`
		}
		require.NoError(t, json.Unmarshal(body, &doc))
		require.Len(t, doc.Statements, 1)
		require.Len(t, doc.Statements[0].Products, 2)
		assert.Equal(t, "pkg:oci/nginx@sha256:amd64", doc.Statements[0].Products[0].ID)
		assert.Equal(t, "pkg:oci/nginx@sha256:arm64", doc.Statements[0].Products[1].ID)
		require.NotEmpty(t, doc.Statements[0].Products[0].Subcomponents)
		require.NotEmpty(t, doc.Statements[0].Products[1].Subcomponents)
		assert.Contains(t, doc.Statements[0].Products[0].Subcomponents[0].ID, "arch=amd64")
		assert.Contains(t, doc.Statements[0].Products[1].Subcomponents[0].ID, "arch=arm64")
		assert.NotContains(t, string(body), "ppc64le")
	})

	t.Run("returns an error when the VEX file cannot be written", func(t *testing.T) {
		t.Parallel()

		outputPath := filepath.Join(t.TempDir(), "missing", "vex.json")
		err := writeMultiPlatformVEX(platforms, vexByPlatform, "openvex", outputPath)
		require.Error(t, err)
	})

	t.Run("writes nothing when no platform has VEX data", func(t *testing.T) {
		t.Parallel()

		outputPath := filepath.Join(t.TempDir(), "vex.json")
		err := writeMultiPlatformVEX(platforms, map[string]*types.PlatformVEX{}, "openvex", outputPath)
		require.NoError(t, err)
		_, err = os.Stat(outputPath)
		require.ErrorIs(t, err, os.ErrNotExist)
	})
}

func platformVEX(t *testing.T, nameDigest, arch string) *types.PlatformVEX {
	t.Helper()
	return &types.PlatformVEX{
		Updates: &unversioned.UpdateManifest{
			Metadata: unversioned.Metadata{
				OS:     unversioned.OS{Type: "debian", Version: "12"},
				Config: unversioned.Config{Arch: arch},
			},
			OSUpdates: []unversioned.UpdatePackage{{
				Name:             "openssl",
				InstalledVersion: "3.0.0",
				FixedVersion:     "3.0.1",
				VulnerabilityID:  "CVE-2024-1111",
			}},
		},
		PkgType:         "deb",
		NameDigestOrTag: nameDigest,
	}
}

func platformSpec(os, arch, variant string) v1.Platform {
	return v1.Platform{OS: os, Architecture: arch, Variant: variant}
}
