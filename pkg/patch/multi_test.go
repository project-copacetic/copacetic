package patch

import (
	"context"
	"errors"
	"testing"

	"github.com/distribution/reference"
	"github.com/opencontainers/go-digest"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
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

func TestCaptureMultiPlatformSourceSnapshotsMutableTag(t *testing.T) {
	const image = "registry.example.com/team/app:latest"
	indexDigest := digest.FromString("source-before-output")
	current := &buildkit.ImageSource{
		Name:       image,
		Descriptor: v1.Descriptor{Digest: indexDigest, MediaType: v1.MediaTypeImageIndex},
		Index:      &v1.Index{},
	}

	originalResolver := resolveImageSource
	t.Cleanup(func() { resolveImageSource = originalResolver })
	resolveCalls := 0
	resolveImageSource = func(_ context.Context, got string) (*buildkit.ImageSource, error) {
		resolveCalls++
		assert.Equal(t, image, got)
		return current, nil
	}

	source, err := captureMultiPlatformSource(t.Context(), image)
	require.NoError(t, err)
	assert.Equal(t, 1, resolveCalls, "the mutable tag must be captured once before output")
	assert.Equal(t, indexDigest, source.IndexLineage.Digest)
}

func TestCaptureMultiPlatformSourceUsesRecordedOriginalBase(t *testing.T) {
	const currentName = "registry.example.com/team/app:patched"
	baseDigest := digest.FromString("original-index")
	current := &buildkit.ImageSource{
		Name: currentName,
		Index: &v1.Index{Annotations: map[string]string{
			copaAnnotationKeyPrefix + ".patched": "2026-08-26T00:00:00Z",
			v1.AnnotationBaseImageName:           "registry.example.com/team/app:1.0",
			v1.AnnotationBaseImageDigest:         baseDigest.String(),
		}},
	}
	base := &buildkit.ImageSource{
		Name:       "registry.example.com/team/app@" + baseDigest.String(),
		Descriptor: v1.Descriptor{Digest: baseDigest, MediaType: v1.MediaTypeImageIndex},
		Index:      &v1.Index{},
	}

	originalResolver := resolveImageSource
	t.Cleanup(func() { resolveImageSource = originalResolver })
	resolveImageSource = func(_ context.Context, image string) (*buildkit.ImageSource, error) {
		switch image {
		case currentName:
			return current, nil
		case base.Name:
			return base, nil
		default:
			return nil, errors.New("unexpected source reference: " + image)
		}
	}

	source, err := captureMultiPlatformSource(t.Context(), currentName)
	require.NoError(t, err)
	assert.Same(t, current, source.Current)
	assert.Same(t, base, source.Base)
	assert.Equal(t, &types.SourceLineage{Name: "registry.example.com/team/app:1.0", Digest: baseDigest}, source.IndexLineage)
}

func TestCommonBaseIndexLineage(t *testing.T) {
	indexDigest := digest.FromString("source-index")
	amdDigest := digest.FromString("source-amd64")
	armDigest := digest.FromString("source-arm64")
	base := &buildkit.ImageSource{
		Name:       "registry.example.com/team/app:1.0",
		Descriptor: v1.Descriptor{Digest: indexDigest, MediaType: v1.MediaTypeImageIndex},
		Index: &v1.Index{Manifests: []v1.Descriptor{
			{Digest: amdDigest, Platform: &v1.Platform{OS: "linux", Architecture: "amd64"}},
			{Digest: armDigest, Platform: &v1.Platform{OS: "linux", Architecture: "arm64"}},
		}},
	}
	lineage := &types.SourceLineage{Name: base.Name, Digest: indexDigest}
	source := &multiPlatformSource{Current: base, Base: base, IndexLineage: lineage}
	originalRef, err := reference.ParseNormalizedNamed(base.Name)
	require.NoError(t, err)
	patchedRef, err := reference.ParseNormalizedNamed("registry.example.com/team/app:patched-amd64")
	require.NoError(t, err)

	items := []types.PatchResult{
		{
			OriginalRef:   originalRef,
			PatchedRef:    patchedRef,
			PatchedDesc:   &v1.Descriptor{Digest: digest.FromString("patched-amd64"), Platform: &v1.Platform{OS: "linux", Architecture: "amd64"}},
			SourceLineage: &types.SourceLineage{Name: base.Name, Digest: amdDigest},
		},
		{
			OriginalRef: originalRef,
			PatchedRef:  originalRef,
			PatchedDesc: &v1.Descriptor{Digest: armDigest, Platform: &v1.Platform{OS: "linux", Architecture: "arm64"}},
		},
	}

	assert.Equal(t, lineage, commonBaseIndexLineage(source, items))

	items[0].SourceLineage.Digest = digest.FromString("different-base")
	assert.Nil(t, commonBaseIndexLineage(source, items), "a child mismatch must omit index lineage")

	items[0].SourceLineage.Digest = amdDigest
	items[0].SourceLineage.Name = "registry.example.com/different/app:1.0"
	assert.Nil(t, commonBaseIndexLineage(source, items), "a base-name mismatch must omit index lineage")
}

func TestCommonBaseIndexLineageAcceptsPreservedPatchedChild(t *testing.T) {
	indexDigest := digest.FromString("source-index")
	childDigest := digest.FromString("source-amd64")
	base := &buildkit.ImageSource{
		Name:       "registry.example.com/team/app:1.0",
		Descriptor: v1.Descriptor{Digest: indexDigest, MediaType: v1.MediaTypeImageIndex},
		Index: &v1.Index{Manifests: []v1.Descriptor{{
			Digest: childDigest, Platform: &v1.Platform{OS: "linux", Architecture: "amd64"},
		}}},
	}
	lineage := &types.SourceLineage{Name: base.Name, Digest: indexDigest}
	originalRef, err := reference.ParseNormalizedNamed("registry.example.com/team/app:patched")
	require.NoError(t, err)
	item := types.PatchResult{
		OriginalRef: originalRef,
		PatchedRef:  originalRef,
		PatchedDesc: &v1.Descriptor{
			Digest:   digest.FromString("previously-patched-amd64"),
			Platform: &v1.Platform{OS: "linux", Architecture: "amd64"},
			Annotations: map[string]string{
				v1.AnnotationBaseImageName:   base.Name,
				v1.AnnotationBaseImageDigest: childDigest.String(),
			},
		},
	}

	assert.Equal(t, lineage, commonBaseIndexLineage(
		&multiPlatformSource{Current: base, Base: base, IndexLineage: lineage},
		[]types.PatchResult{item},
	))
}

func TestPlatformSourceReferencePinsSelectedChild(t *testing.T) {
	childDigest := digest.FromString("source-amd64")
	source := &buildkit.ImageSource{
		Name: "registry.example.com/team/app:1.0",
		Index: &v1.Index{Manifests: []v1.Descriptor{{
			Digest: childDigest, Platform: &v1.Platform{OS: "linux", Architecture: "amd64"},
		}}},
	}

	got, err := platformSourceReference(source, &v1.Platform{OS: "linux", Architecture: "amd64"})
	require.NoError(t, err)
	assert.Equal(t, "registry.example.com/team/app@"+childDigest.String(), got)
}

func platformSpec(os, arch, variant string) v1.Platform {
	return v1.Platform{OS: os, Architecture: arch, Variant: variant}
}
