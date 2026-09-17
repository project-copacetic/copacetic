package patch

import (
	"context"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	v1types "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/opencontainers/go-digest"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/stretchr/testify/require"
)

func testSourceOriginSurfaces(t *testing.T, ctx context.Context, addr, repo string, application map[string]string) {
	t.Helper()
	t.Run("source-origin-surfaces", func(t *testing.T) {
		first, err := remote.Image(originTestReference(t, repo+":p1-amd64"), remote.WithContext(ctx))
		require.NoError(t, err)
		config, err := first.ConfigFile()
		require.NoError(t, err)
		origin := types.SourceLineageFromAnnotations(config.Config.Labels)
		require.True(t, origin.Valid())
		layers, err := first.Layers()
		require.NoError(t, err)
		// Reuse actual P1 config/layers with a fresh manifest annotation map so
		// partial tuples are not completed by the annotation fixture itself.
		bare, err := mutate.AppendLayers(empty.Image, layers...)
		require.NoError(t, err)
		bare, err = mutate.ConfigFile(bare, config)
		require.NoError(t, err)
		bare = mutate.MediaType(bare, v1types.OCIManifestSchema1)
		for _, route := range []string{"single", "multi", "gateway"} {
			t.Run(route, func(t *testing.T) {
				for _, scenario := range []string{"matching", "alias", "descriptor-partial", "descriptor-digest", "descriptor-repository", "manifest-partial", "split"} {
					t.Run(scenario, func(t *testing.T) {
						descriptorAnnotations := origin.Annotations()
						manifestAnnotations := origin.Annotations()
						descriptorAnnotations["com.example.surface-descriptor"] = "preserved"
						maps.Copy(manifestAnnotations, application)
						switch scenario {
						case "alias":
							descriptorAnnotations[types.AnnotationPatchOriginName] = repo + ":original-alias"
						case "descriptor-partial":
							delete(descriptorAnnotations, types.AnnotationPatchOriginDigest)
						case "descriptor-digest":
							descriptorAnnotations[types.AnnotationPatchOriginDigest] = digest.FromString("another original").String()
						case "descriptor-repository":
							descriptorAnnotations[types.AnnotationPatchOriginName] = sourceOriginOtherRepository
						case "manifest-partial":
							delete(manifestAnnotations, types.AnnotationPatchOriginDigest)
						case "split":
							delete(descriptorAnnotations, types.AnnotationPatchOriginDigest)
							delete(manifestAnnotations, types.AnnotationPatchOriginKind)
							delete(manifestAnnotations, types.AnnotationPatchOriginName)
						}
						image := originAnnotatedImage(t, bare, manifestAnnotations)
						input := repo + "-surfaces:" + route + "-" + scenario
						output := repo + ":surface-output-" + route + "-" + scenario
						index := mutate.IndexMediaType(mutate.AppendManifests(empty.Index, mutate.IndexAddendum{
							Add: image, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: originAMD64}, Annotations: descriptorAnnotations},
						}), v1types.OCIImageIndex)
						require.NoError(t, remote.WriteIndex(originTestReference(t, input), index, remote.WithContext(ctx)))
						if route == "gateway" {
							transport := remote.DefaultTransport
							t.Cleanup(func() { remote.DefaultTransport = transport })
							inputPath := "/v2/" + strings.SplitN(strings.SplitN(input, "/", 2)[1], ":", 2)[0] + "/"
							blocked := &sourceSessionTransport{RoundTripper: transport, inputPath: inputPath}
							remote.DefaultTransport = blocked
							t.Cleanup(func() { require.Positive(t, blocked.denied.Load()) })
						}
						report := originTestReport(t, originAMD64)
						resultRef := output
						if route == "multi" {
							data, err := os.ReadFile(report)
							require.NoError(t, err)
							report = t.TempDir()
							require.NoError(t, os.WriteFile(filepath.Join(report, "amd64.json"), data, 0o600))
							resultRef += "-amd64"
						}
						err := Patch(ctx, &types.Options{
							Image: input, Report: report, Scanner: "trivy", Push: true, PatchedTag: output, BkAddr: addr,
							PkgTypes: "os", IgnoreError: true, Progress: "quiet", Timeout: 2 * time.Minute,
						})
						if scenario != "matching" && scenario != "alias" {
							require.Error(t, err, "partial or contradictory raw origin tuples must not be hidden by a merge")
							require.Contains(t, err.Error(), "origin")
							for _, ref := range []string{output, resultRef} {
								_, readErr := remote.Get(originTestReference(t, ref), remote.WithContext(ctx))
								require.Error(t, readErr, "origin rejection must leave no output, including with IgnoreError")
							}
							return
						}
						require.NoError(t, err)
						result, err := remote.Image(originTestReference(t, resultRef), remote.WithContext(ctx))
						require.NoError(t, err)
						manifest, err := result.Manifest()
						require.NoError(t, err)
						require.Equal(t, origin.Digest.String(), manifest.Annotations[types.AnnotationPatchOriginDigest])
						require.Equal(t, "preserved", manifest.Annotations["com.example.surface-descriptor"])
						for key, value := range application {
							require.Equal(t, value, manifest.Annotations[key])
						}
						verifyOriginBlobs(t, result)
					})
				}
			})
		}
	})
}
