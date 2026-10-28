package patch

import (
	"context"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	v1types "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/stretchr/testify/require"
)

// ConfigFile mutations derive their output manifest from this view, retaining
// actual P1 layers while removing the newer manifest origin tuple entirely.
type legacyOriginImage struct{ v1.Image }

func (i legacyOriginImage) Manifest() (*v1.Manifest, error) {
	manifest, err := i.Image.Manifest()
	if err != nil {
		return nil, err
	}
	manifest = manifest.DeepCopy()
	manifest.Annotations = withoutSourceLineageAnnotations(manifest.Annotations)
	return manifest, nil
}

func testLegacyOriginFallback(t *testing.T, ctx context.Context, addr, repo string, application map[string]string) {
	t.Helper()
	t.Run("legacy-missing-original-index", func(t *testing.T) {
		first, err := remote.Image(originTestReference(t, repo+":p1-amd64"), remote.WithContext(ctx))
		require.NoError(t, err)
		config, err := first.ConfigFile()
		require.NoError(t, err)
		config = config.DeepCopy()
		config.Config.Labels = withoutSourceLineageAnnotations(config.Config.Labels)
		config.Config.Labels["BaseImage"] = repo + ":unavailable-legacy-original"
		_, err = remote.Get(originTestReference(t, config.Config.Labels["BaseImage"]), remote.WithContext(ctx))
		require.Error(t, err, "legacy original must be unavailable")
		legacy, err := mutate.ConfigFile(legacyOriginImage{first}, config)
		require.NoError(t, err)
		manifest, err := legacy.Manifest()
		require.NoError(t, err)
		require.NotContains(t, manifest.Annotations, types.AnnotationPatchOriginKind)
		require.NotContains(t, manifest.Annotations, types.AnnotationPatchOriginName)
		require.NotContains(t, manifest.Annotations, types.AnnotationPatchOriginDigest)
		input, output := repo+":legacy-missing-index", repo+":legacy-missing-output"
		index := mutate.IndexMediaType(mutate.AppendManifests(empty.Index, mutate.IndexAddendum{
			Add: legacy, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: originAMD64}, Annotations: application},
		}), v1types.OCIImageIndex)
		require.NoError(t, remote.WriteIndex(originTestReference(t, input), index, remote.WithContext(ctx)))
		require.NoError(t, Patch(ctx, &types.Options{
			Image: input, Report: originTestReport(t, originAMD64), Scanner: "trivy", Push: true, PatchedTag: output,
			BkAddr: addr, PkgTypes: "os", Progress: "quiet", Timeout: 2 * time.Minute,
		}))
		patched, err := remote.Image(originTestReference(t, output), remote.WithContext(ctx))
		require.NoError(t, err)
		patchedManifest, err := patched.Manifest()
		require.NoError(t, err)
		patchedConfig, err := patched.ConfigFile()
		require.NoError(t, err)
		for _, values := range []map[string]string{patchedConfig.Config.Labels, patchedManifest.Annotations} {
			require.NotContains(t, values, types.AnnotationPatchOriginKind)
			require.NotContains(t, values, types.AnnotationPatchOriginName)
			require.NotContains(t, values, types.AnnotationPatchOriginDigest)
			for key, value := range application {
				require.Equal(t, value, values[key])
			}
		}
		require.GreaterOrEqual(t, len(patchedManifest.Layers), len(manifest.Layers))
		for i := range manifest.Layers {
			require.Equal(t, manifest.Layers[i].Digest, patchedManifest.Layers[i].Digest, "legacy fallback must retain existing patch layers")
		}
		verifyOriginBlobs(t, patched)
	})
}
