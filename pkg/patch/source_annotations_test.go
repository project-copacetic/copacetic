package patch

import (
	"context"
	"errors"
	"maps"
	"testing"

	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/stretchr/testify/require"
)

const (
	sourceOriginMatching      = "matching"
	sourceOriginRepository    = "repository"
	sourceOriginDigest        = "digest"
	sourceOriginPartial       = "partial"
	sourceOriginAbsent        = "absent"
	sourceOriginDifferentTag  = "different tag"
	sourceAnnotationsCanceled = "canceled"
	sourceAnnotationsChanged  = "changed"
	sourceAnnotationKey       = "com.example.source"
)

func TestCaptureSourceAnnotationsUsesIndexedLocalSource(t *testing.T) {
	local := localPlatformDescriptor
	t.Cleanup(func() { localPlatformDescriptor = local })
	platform := &specs.Platform{OS: "linux", Architecture: "amd64"}
	child := digest.FromString("local child")
	annotations := map[string]string{sourceAnnotationKey: "captured"}
	for _, scenario := range []string{"local", sourceAnnotationsChanged, sourceAnnotationsCanceled} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			reads := 0
			localPlatformDescriptor = func(_ context.Context, image string, p *specs.Platform) (*specs.Descriptor, bool, error) {
				reads++
				require.Equal(t, "127.0.0.1:1/local:index", image)
				require.Equal(t, platform, p)
				if scenario == sourceAnnotationsCanceled {
					cancel()
					return nil, false, errors.New("interrupted daemon inspect")
				}
				selected := child
				if scenario == sourceAnnotationsChanged {
					selected = digest.FromString("replacement platform")
				}
				return &specs.Descriptor{Digest: selected}, true, nil
			}
			got, err := captureSourceAnnotations(ctx, "127.0.0.1:1/local:index", "127.0.0.1:1/local@"+child.String(), annotations, platform)
			switch scenario {
			case "local":
				require.NoError(t, err, "the child is not independently available from this registry")
				require.Equal(t, annotations, got)
				got[sourceAnnotationKey] = "changed result"
				require.Equal(t, "captured", annotations[sourceAnnotationKey])
			case sourceAnnotationsChanged:
				require.ErrorContains(t, err, "changed after capture")
			case sourceAnnotationsCanceled:
				require.ErrorIs(t, err, context.Canceled)
			}
			require.Equal(t, 1, reads)
		})
	}
}

func TestValidateSourceOriginAnnotations(t *testing.T) {
	expected := &types.SourceLineage{Kind: types.PatchOriginImage, Name: "example.com/app:original", Digest: digest.FromString("original")}
	for _, scenario := range []string{sourceOriginAbsent, sourceOriginMatching, sourceOriginDifferentTag, sourceOriginDigest, sourceOriginRepository, "kind", sourceOriginPartial, "unverified config"} {
		t.Run(scenario, func(t *testing.T) {
			values := maps.Clone(expected.Annotations())
			configOrigin := expected
			switch scenario {
			case sourceOriginAbsent:
				values = map[string]string{"org.opencontainers.image.base.name": "application-base"}
			case sourceOriginDifferentTag:
				values[types.AnnotationPatchOriginName] = "example.com/app:alias"
			case sourceOriginDigest:
				values[types.AnnotationPatchOriginDigest] = digest.FromString("other").String()
			case sourceOriginRepository:
				values[types.AnnotationPatchOriginName] = "example.com/another:original"
			case "kind":
				values[types.AnnotationPatchOriginKind] = types.PatchOriginOCI
			case sourceOriginPartial:
				delete(values, types.AnnotationPatchOriginDigest)
			case "unverified config":
				configOrigin = nil
			}
			before := maps.Clone(values)
			err := validateSourceOriginAnnotations(values, configOrigin)
			if scenario == sourceOriginAbsent || scenario == sourceOriginMatching || scenario == sourceOriginDifferentTag {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, "contradicts the recovered config origin")
			}
			require.Equal(t, before, values)
		})
	}
}
