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
	"github.com/moby/buildkit/client"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/stretchr/testify/require"
)

func testCapturedSourceDigest(t *testing.T, ctx context.Context, bk *client.Client, addr, repo string, original v1.Image, application map[string]string) {
	t.Helper()
	hash, err := original.Digest()
	require.NoError(t, err)
	t.Run("captured-source-digest", func(t *testing.T) {
		for _, scenario := range []string{"matching", "missing", "mismatch"} {
			t.Run(scenario, func(t *testing.T) {
				expected := digest.Digest(hash.String())
				switch scenario {
				case "missing":
					expected = ""
				case "mismatch":
					expected = digest.FromString("different captured manifest")
				}
				output := repo + ":captured-digest-" + scenario
				config, err := createBuildConfig(output, true, true, nil, application, "p1", "", false)
				require.NoError(t, err)
				config.SolveOpt.Exports[0].Attrs["registry.insecure"] = attrValueTrue
				_, err = bk.Build(ctx, config.SolveOpt, "copa-captured-origin-test", func(ctx context.Context, c gwclient.Client) (*gwclient.Result, error) {
					result, err := ExecutePatchCore(&Context{Context: ctx, Client: c}, &Options{
						ImageName: repo + ":original-amd64", TargetPlatform: &types.PatchPlatform{Platform: specs.Platform{OS: "linux", Architecture: originAMD64}},
						WorkingFolder: t.TempDir(), IgnoreError: true, RequireBaseManifest: true, ExpectedSourceDigest: expected,
						Updates: &unversioned.UpdateManifest{
							Metadata:  unversioned.Metadata{OS: unversioned.OS{Type: "alpine", Version: "3.20.0"}, Config: unversioned.Config{Arch: originAMD64}},
							OSUpdates: unversioned.UpdatePackages{{Name: "busybox", InstalledVersion: "1.36.1-r29", FixedVersion: "1.36.1-r29"}},
						},
					})
					if err != nil {
						return nil, err
					}
					return result.Result, nil
				}, nil)
				if scenario != "matching" {
					require.ErrorContains(t, err, "captured source manifest")
					_, readErr := remote.Get(originTestReference(t, output), remote.WithContext(ctx))
					require.Error(t, readErr, "invalid capture must fail before export even with IgnoreError")
					return
				}
				require.NoError(t, err)
				image, err := remote.Image(originTestReference(t, output), remote.WithContext(ctx))
				require.NoError(t, err)
				configFile, err := image.ConfigFile()
				require.NoError(t, err)
				require.Equal(t, hash.String(), configFile.Config.Labels[types.AnnotationPatchOriginDigest])
				verifyOriginBlobs(t, image)
			})
		}
	})
	t.Run("mutable-single-index", func(t *testing.T) {
		for _, scenario := range []string{"stable", "moved"} {
			t.Run(scenario, func(t *testing.T) {
				input, output := repo+":single-index-"+scenario, repo+":single-index-output-"+scenario
				makeIndex := func(image v1.Image) v1.ImageIndex {
					return mutate.IndexMediaType(mutate.AppendManifests(empty.Index, mutate.IndexAddendum{
						Add: image, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: originAMD64}},
					}), v1types.OCIImageIndex)
				}
				require.NoError(t, remote.WriteIndex(originTestReference(t, input), makeIndex(original), remote.WithContext(ctx)))
				resolver := resolveImageSource
				t.Cleanup(func() { resolveImageSource = resolver })
				captures := 0
				resolveImageSource = func(ctx context.Context, image string) (*buildkit.ImageSource, error) {
					source, err := resolver(ctx, image)
					if err != nil || image != input {
						return source, err
					}
					captures++
					if scenario == "moved" {
						config, err := original.ConfigFile()
						require.NoError(t, err)
						config = config.DeepCopy()
						config.Config.Labels["com.example.snapshot"] = "replacement"
						replacement, err := mutate.ConfigFile(original, config)
						require.NoError(t, err)
						require.NoError(t, remote.WriteIndex(originTestReference(t, input), makeIndex(replacement), remote.WithContext(ctx)))
					}
					return source, nil
				}
				require.NoError(t, Patch(ctx, &types.Options{
					Image: input, Report: originTestReport(t, originAMD64), Scanner: "trivy", Push: true, PatchedTag: output,
					BkAddr: addr, PkgTypes: "os", Progress: "quiet", Timeout: 2 * time.Minute,
				}))
				require.Equal(t, 1, captures)
				image, err := remote.Image(originTestReference(t, output), remote.WithContext(ctx))
				require.NoError(t, err)
				config, err := image.ConfigFile()
				require.NoError(t, err)
				require.Equal(t, hash.String(), config.Config.Labels[types.AnnotationPatchOriginDigest])
				require.NotContains(t, config.Config.Labels, "com.example.snapshot", "patch must use the captured child")
				verifyOriginBlobs(t, image)
			})
		}
	})
}
