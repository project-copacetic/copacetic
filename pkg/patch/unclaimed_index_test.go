package patch

import (
	"context"
	"errors"
	"testing"

	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestCommonOriginRequiresUnpatchedChildMetadata(t *testing.T) {
	reader := readIndexChildMetadata
	t.Cleanup(func() { readIndexChildMetadata = reader })
	platform := specs.Platform{OS: "linux", Architecture: originAMD64}
	for _, scenario := range []string{"original", "legacy", "empty legacy", "modern", "partial", "manifest", "descriptor origin", "patched marker", "unavailable", "canceled"} {
		t.Run(scenario, func(t *testing.T) {
			child := specs.Descriptor{Digest: digest.FromString("unchanged child"), Platform: &platform}
			var manifest, labels map[string]string
			var failure error
			switch scenario {
			case "legacy":
				labels = map[string]string{"BaseImage": "example.com/app:original"}
			case "empty legacy":
				labels = map[string]string{"BaseImage": ""}
			case "modern":
				labels = (&types.SourceLineage{Kind: types.PatchOriginImage, Name: "example.com/app:original", Digest: digest.FromString("original")}).Annotations()
			case "partial":
				labels = map[string]string{types.AnnotationPatchOriginKind: ""}
			case "manifest":
				manifest = map[string]string{types.AnnotationPatchOriginDigest: digest.FromString("original").String()}
			case "descriptor origin":
				child.Annotations = map[string]string{types.AnnotationPatchOriginName: "example.com/app:original"}
			case "patched marker":
				manifest = map[string]string{copaAnnotationKeyPrefix + ".image.patched": ""}
			case "unavailable":
				failure = errors.New("immutable child metadata inaccessible")
			case "canceled":
				failure = context.Canceled
			}
			current := &buildkit.ImageSource{
				Name:       "example.com/app:unannotated",
				Descriptor: specs.Descriptor{Digest: digest.FromString("current index")}, Index: &specs.Index{Manifests: []specs.Descriptor{child}},
			}
			source, err := captureIndexSource(t.Context(), current)
			require.NoError(t, err)
			readIndexChildMetadata = func(_ context.Context, ref string) (map[string]string, map[string]string, error) {
				require.Equal(t, "example.com/app@"+child.Digest.String(), ref)
				return manifest, labels, failure
			}
			got := commonBaseIndexLineage(t.Context(), source, []types.PatchResult{{PatchedDesc: &child}})
			if scenario == "original" {
				require.NotNil(t, got)
				require.Equal(t, current.Descriptor.Digest, got.Digest)
			} else {
				require.Nil(t, got, "unchanged content alone does not prove unpatched ancestry")
			}
		})
	}
}
