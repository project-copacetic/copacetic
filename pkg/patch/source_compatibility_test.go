package patch

import (
	"context"
	"errors"
	"testing"

	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/stretchr/testify/require"
)

func TestCaptureSourceAnnotationsWithoutPlatformMetadata(t *testing.T) {
	oldLocal, oldResolve, oldArchive := localPlatformDescriptor, resolveImageSource, localManifestAnnotations
	t.Cleanup(func() {
		localPlatformDescriptor, resolveImageSource, localManifestAnnotations = oldLocal, oldResolve, oldArchive
	})
	localManifestAnnotations = func(_ context.Context, image string, selected digest.Digest) (map[string]string, error) {
		require.Equal(t, "127.0.0.1:1/local:source", image)
		require.Equal(t, digest.FromString("original classic source"), selected)
		return nil, nil // Classic archives lack native manifest annotations.
	}
	original := digest.FromString("original classic source")
	platform := &specs.Platform{OS: "linux", Architecture: "amd64"}
	for _, scenario := range []string{"stable", "changed", "unavailable"} {
		t.Run(scenario, func(t *testing.T) {
			localPlatformDescriptor = func(context.Context, string, *specs.Platform) (*specs.Descriptor, bool, error) { return nil, true, nil }
			resolveImageSource = func(_ context.Context, ref string) (*buildkit.ImageSource, error) {
				require.Equal(t, "127.0.0.1:1/local:source", ref)
				if scenario == "unavailable" {
					return nil, errors.New("local identity unavailable")
				}
				selected := original
				if scenario == "changed" {
					selected = digest.FromString("replacement")
				}
				return &buildkit.ImageSource{Name: ref, Descriptor: specs.Descriptor{Digest: selected}}, nil
			}
			annotations := map[string]string{"com.example.application": "preserved"}
			got, err := captureSourceAnnotations(t.Context(), "127.0.0.1:1/local:source", "127.0.0.1:1/local@"+original.String(), annotations, platform)
			if scenario == "stable" {
				require.NoError(t, err)
				require.Equal(t, annotations, got)
			} else {
				require.Error(t, err)
			}
		})
	}
}
