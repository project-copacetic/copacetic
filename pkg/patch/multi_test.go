package patch

import (
	"context"
	"errors"
	"maps"
	"sync/atomic"
	"testing"

	"github.com/distribution/reference"
	"github.com/moby/buildkit/client"
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
			types.AnnotationPatchOriginKind:      types.PatchOriginImage,
			types.AnnotationPatchOriginName:      "registry.example.com/team/app:1.0",
			types.AnnotationPatchOriginDigest:    baseDigest.String(),
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
	assert.Equal(t, &types.SourceLineage{Kind: types.PatchOriginImage, Name: "registry.example.com/team/app:1.0", Digest: baseDigest}, source.IndexLineage)
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
	lineage := &types.SourceLineage{Kind: types.PatchOriginImage, Name: base.Name, Digest: indexDigest}
	source := &multiPlatformSource{Current: base, Base: base, IndexLineage: lineage}
	originalRef, err := reference.ParseNormalizedNamed(base.Name)
	require.NoError(t, err)
	patchedRef, err := reference.ParseNormalizedNamed("registry.example.com/team/app:patched-amd64")
	require.NoError(t, err)

	items := []types.PatchResult{
		{
			OriginalRef: originalRef,
			PatchedRef:  patchedRef,
			PatchedDesc: &v1.Descriptor{
				Digest: digest.FromString("patched-amd64"), Platform: &v1.Platform{OS: "linux", Architecture: "amd64"},
				Annotations: (&types.SourceLineage{Kind: types.PatchOriginImage, Name: base.Name, Digest: amdDigest}).Annotations(),
			},
		},
		{
			OriginalRef: originalRef,
			PatchedRef:  originalRef,
			PatchedDesc: &v1.Descriptor{Digest: armDigest, Platform: &v1.Platform{OS: "linux", Architecture: "arm64"}},
		},
	}

	assert.Equal(t, lineage, commonBaseIndexLineage(source, items))

	items[0].PatchedDesc.Annotations[types.AnnotationPatchOriginDigest] = indexDigest.String()
	assert.Equal(t, lineage, commonBaseIndexLineage(source, items), "a verified frontend index origin is also a common origin")

	items[0].PatchedDesc.Annotations[types.AnnotationPatchOriginDigest] = digest.FromString("different-base").String()
	assert.Nil(t, commonBaseIndexLineage(source, items), "a child mismatch must omit index lineage")

	items[0].PatchedDesc.Annotations[types.AnnotationPatchOriginDigest] = amdDigest.String()
	items[0].PatchedDesc.Annotations[types.AnnotationPatchOriginName] = "registry.example.com/different/app:1.0"
	assert.Nil(t, commonBaseIndexLineage(source, items), "a base-name mismatch must omit index lineage")
}

func TestCommonBaseIndexLineageOmitsUnverifiedPreservedAncestry(t *testing.T) {
	indexDigest := digest.FromString("source-index")
	childDigest := digest.FromString("source-amd64")
	base := &buildkit.ImageSource{
		Name:       "registry.example.com/team/app:1.0",
		Descriptor: v1.Descriptor{Digest: indexDigest, MediaType: v1.MediaTypeImageIndex},
		Index: &v1.Index{Manifests: []v1.Descriptor{{
			Digest: childDigest, Platform: &v1.Platform{OS: "linux", Architecture: "amd64"},
		}}},
	}
	lineage := &types.SourceLineage{Kind: types.PatchOriginImage, Name: base.Name, Digest: indexDigest}
	originalRef, err := reference.ParseNormalizedNamed("registry.example.com/team/app:patched")
	require.NoError(t, err)
	item := types.PatchResult{
		OriginalRef: originalRef,
		PatchedRef:  originalRef,
		PatchedDesc: &v1.Descriptor{
			Digest:   digest.FromString("previously-patched-amd64"),
			Platform: &v1.Platform{OS: "linux", Architecture: "amd64"},
			Annotations: map[string]string{
				types.AnnotationPatchOriginKind:   types.PatchOriginImage,
				types.AnnotationPatchOriginName:   base.Name,
				types.AnnotationPatchOriginDigest: childDigest.String(),
			},
		},
	}

	assert.Nil(t, commonBaseIndexLineage(
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

func TestImmutableCurrentIndexReferenceUsesCurrentSnapshotOnRepatch(t *testing.T) {
	currentDigest := digest.FromString("current-patched-index")
	baseDigest := digest.FromString("older-original-index")
	source := &multiPlatformSource{
		Current: &buildkit.ImageSource{
			Name:       "registry.example.com/team/app:patched",
			Descriptor: v1.Descriptor{Digest: currentDigest, MediaType: v1.MediaTypeImageIndex},
			Index:      &v1.Index{},
		},
		Base: &buildkit.ImageSource{
			Name:       "registry.example.com/team/app:1.0",
			Descriptor: v1.Descriptor{Digest: baseDigest, MediaType: v1.MediaTypeImageIndex},
			Index:      &v1.Index{},
		},
		IndexLineage: &types.SourceLineage{Kind: types.PatchOriginImage, Name: "registry.example.com/team/app:1.0", Digest: baseDigest},
	}

	got, err := immutableCurrentIndexReference(source)
	require.NoError(t, err)
	assert.Equal(t, "registry.example.com/team/app@"+currentDigest.String(), got.String())
	assert.NotContains(t, got.String(), baseDigest.String(), "preserved bytes come from the current snapshot, not its older lineage base")
}

func platformSpec(os, arch, variant string) v1.Platform {
	return v1.Platform{OS: os, Architecture: arch, Variant: variant}
}

func TestPatchMultiPlatformImageRejectsUnrecoverableIndexOrigin(t *testing.T) {
	const input = "registry.example.com/team/app:patched"
	originalDigest := digest.FromString("original index")
	origin := (&types.SourceLineage{Kind: types.PatchOriginImage, Name: "registry.example.com/team/app:original", Digest: originalDigest}).Annotations()
	origin[copaAnnotationKeyPrefix+".patched"] = "2026-09-15T00:00:00Z"
	resolverBefore := resolveImageSource
	builderBefore := bkNewClient
	t.Cleanup(func() { resolveImageSource, bkNewClient = resolverBefore, builderBefore })
	for _, tc := range []struct {
		name       string
		change     func(map[string]string)
		base       *buildkit.ImageSource
		resolveErr error
	}{
		{name: "missing original", resolveErr: errors.New("original index not found")},
		{name: "missing marker", change: func(a map[string]string) { delete(a, copaAnnotationKeyPrefix+".patched") }, resolveErr: errors.New("original index not found")},
		{name: "partial tuple", change: func(a map[string]string) { delete(a, types.AnnotationPatchOriginDigest) }},
		{name: "inconsistent name", change: func(a map[string]string) {
			a[types.AnnotationPatchOriginName] = "registry.example.com/team/app@" + digest.FromString("different index").String()
		}},
		{name: "unsupported recovery kind", change: func(a map[string]string) {
			a[types.AnnotationPatchOriginKind] = types.PatchOriginOCI
			delete(a, types.AnnotationPatchOriginName)
		}},
		{name: "original is not an index", base: &buildkit.ImageSource{Descriptor: v1.Descriptor{Digest: originalDigest}}},
		{name: "original digest mismatch", base: &buildkit.ImageSource{Descriptor: v1.Descriptor{Digest: digest.FromString("different index")}, Index: &v1.Index{}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			annotations := maps.Clone(origin)
			if tc.change != nil {
				tc.change(annotations)
			}
			resolveImageSource = func(_ context.Context, image string) (*buildkit.ImageSource, error) {
				if image == input {
					return &buildkit.ImageSource{Name: input, Index: &v1.Index{Annotations: annotations}}, nil
				}
				require.Equal(t, "registry.example.com/team/app@"+originalDigest.String(), image)
				return tc.base, tc.resolveErr
			}
			_, err := captureMultiPlatformSource(t.Context(), input)
			require.ErrorIs(t, err, errRecordedIndexOrigin, "recorded-origin failure must not become omitted ancestry")
			inputRef, err := reference.ParseNormalizedNamed(input)
			require.NoError(t, err)
			_, _, _, err = captureSinglePlatformSource(t.Context(), input, inputRef, &v1.Platform{OS: "linux", Architecture: "amd64"})
			require.ErrorIs(t, err, errRecordedIndexOrigin, "single-platform dispatch must validate the index too")
			var builds atomic.Int32
			bkNewClient = func(context.Context, buildkit.Opts) (*client.Client, error) {
				builds.Add(1)
				return nil, errors.New("unexpected BuildKit construction")
			}
			err = patchMultiPlatformImage(t.Context(), &types.Options{Image: input, IgnoreError: true}, []types.PatchPlatform{{Platform: platformSpec("linux", "amd64", "")}})
			require.ErrorContains(t, err, "restore the original index")
			require.Zero(t, builds.Load(), "recovery must fail before any patch or export")
		})
	}
}

func TestCaptureMultiPlatformSourceKeepsUnrecordedOriginOmitted(t *testing.T) {
	const input = "registry.example.com/team/app:patched"
	resolverBefore := resolveImageSource
	t.Cleanup(func() { resolveImageSource = resolverBefore })
	for _, annotations := range []map[string]string{
		{copaAnnotationKeyPrefix + ".patched": "2026-09-15T00:00:00Z"},
		{
			copaAnnotationKeyPrefix + ".patched": "2026-09-15T00:00:00Z",
			v1.AnnotationBaseImageName:           "example.com/application-base:stable",
			v1.AnnotationBaseImageDigest:         digest.FromString("application base").String(),
		},
	} {
		current := &buildkit.ImageSource{Name: input, Index: &v1.Index{Annotations: annotations}}
		resolveImageSource = func(_ context.Context, image string) (*buildkit.ImageSource, error) {
			require.Equal(t, input, image, "unrecorded ancestry must not trigger recovery")
			return current, nil
		}
		source, err := captureMultiPlatformSource(t.Context(), input)
		require.NoError(t, err)
		require.Same(t, current, source.Current)
		require.Nil(t, source.Base)
		require.Nil(t, source.IndexLineage)
	}
}
