package patch

import (
	"context"
	"fmt"
	"io"
	"log"
	"maps"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	v1types "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOriginPreflightIntegrity(t *testing.T) {
	if os.Getenv("COPA_ORIGIN_BUILDKIT_ADDR") == "" {
		t.Skip("requires the serialized real Docker proof lane")
	}
	previous := bkNewClient
	bkNewClient = buildkit.NewClient
	t.Cleanup(func() { bkNewClient = previous })
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
	defer cancel()
	server := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	defer server.Close()
	repo := strings.TrimPrefix(server.URL, "http://") + "/copa-1678-preflight"
	t.Logf("Origin preflight test registry: %s", repo)
	application := map[string]string{specs.AnnotationBaseImageName: "example.com/application-base:stable", specs.AnnotationBaseImageDigest: digest.FromString("application B").String()}
	images := map[string]v1.Image{}
	for _, arch := range []string{originAMD64, "386"} {
		image, err := remote.Image(originTestReference(t, "alpine:3.20.0"), remote.WithContext(ctx), remote.WithPlatform(v1.Platform{OS: "linux", Architecture: arch}))
		require.NoError(t, err)
		cfg, err := image.ConfigFile()
		require.NoError(t, err)
		cfg.Config.Labels = maps.Clone(application)
		image, err = mutate.ConfigFile(image, cfg)
		require.NoError(t, err)
		images[arch] = mutate.MediaType(image, v1types.OCIManifestSchema1)
		require.NoError(t, remote.Write(originTestReference(t, repo+"-base:"+arch), images[arch], remote.WithContext(ctx)))
	}
	t.Run("local-manifest", func(t *testing.T) {
		for _, scenario := range []string{sourceOriginValid, sourceOriginPartial, "contradictory"} {
			t.Run(scenario, func(t *testing.T) {
				annotations := map[string]string{"com.example.manifest-only": "preserved"}
				if scenario != sourceOriginValid {
					annotations[types.AnnotationPatchOriginKind] = types.PatchOriginImage
				}
				if scenario == "contradictory" {
					annotations[types.AnnotationPatchOriginName] = repo + "-base:amd64"
					annotations[types.AnnotationPatchOriginDigest] = digest.FromString("contradictory origin").String()
				}
				image := originAnnotatedImage(t, images[originAMD64], annotations)
				input := repo + ":local-" + scenario
				index := mutate.IndexMediaType(mutate.AppendManifests(empty.Index, mutate.IndexAddendum{
					Add: image, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: originAMD64}},
				}), v1types.OCIImageIndex)
				require.NoError(t, remote.WriteIndex(originTestReference(t, input), index, remote.WithContext(ctx)))
				alias := fmt.Sprintf("127.0.0.1:1/copa-1678-preflight-%d:source", time.Now().UnixNano())
				for _, args := range [][]string{{"pull", "--platform=linux/amd64", input}, {"tag", input, alias}} {
					//nolint:gosec // Generated, task-owned image references.
					out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
					require.NoError(t, err, string(out))
				}
				t.Cleanup(func() {
					cleanupCtx, stop := context.WithTimeout(context.Background(), time.Minute)
					defer stop()
					//nolint:gosec // Remove only generated source names.
					out, err := exec.CommandContext(cleanupCtx, "docker", "image", "rm", input, alias).CombinedOutput()
					t.Logf("local preflight cleanup: %v %s", err, out)
				})
				local, found, err := utils.LocalPlatformDescriptor(ctx, alias, &specs.Platform{OS: "linux", Architecture: originAMD64})
				require.NoError(t, err)
				require.True(t, found)
				if os.Getenv("COPA_ORIGIN_EXPECT_LEGACY_INSPECT") == "1" {
					require.Nil(t, local)
				} else {
					require.NotNil(t, local)
				}
				output := repo + ":local-output-" + scenario
				err = Patch(ctx, &types.Options{
					Image: alias, Report: originTestReport(t, originAMD64), Scanner: "trivy", Push: true,
					PatchedTag: output, BkAddr: "docker://", PkgTypes: "os", IgnoreError: true, Progress: "quiet", Timeout: 2 * time.Minute,
				})
				result, readErr := remote.Image(originTestReference(t, output), remote.WithContext(ctx))
				if scenario != sourceOriginValid {
					assert.Error(t, err, "local manifest origins must be validated before export")
					assert.Error(t, readErr, "rejected local source must leave no output")
					return
				}
				require.NoError(t, err)
				require.NoError(t, readErr)
				cfg, err := result.ConfigFile()
				require.NoError(t, err)
				for key, value := range application {
					require.Equal(t, value, cfg.Config.Labels[key])
				}
				manifest, err := result.Manifest()
				require.NoError(t, err)
				if manifest.MediaType == v1types.OCIManifestSchema1 {
					assert.Equal(t, "preserved", manifest.Annotations["com.example.manifest-only"])
				}
				verifyOriginBlobs(t, result)
			})
		}
	})
	t.Run("multi-config", func(t *testing.T) {
		for _, scenario := range []string{sourceOriginValid, sourceOriginPartial, sourceOriginRepository, "missing-original"} {
			for _, ignore := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/ignore=%t", scenario, ignore), func(t *testing.T) {
					var children []mutate.IndexAddendum
					reports := t.TempDir()
					for _, arch := range []string{originAMD64, "386"} {
						image := images[arch]
						if arch == originAMD64 && scenario != sourceOriginValid {
							cfg, err := image.ConfigFile()
							require.NoError(t, err)
							cfg.Config.Labels["BaseImage"] = repo + "-base:" + arch
							cfg.Config.Labels[types.AnnotationPatchOriginKind] = types.PatchOriginImage
							if scenario != sourceOriginPartial {
								cfg.Config.Labels[types.AnnotationPatchOriginName] = repo + "-base:" + arch
								cfg.Config.Labels[types.AnnotationPatchOriginDigest] = digest.FromString("unavailable original").String()
							}
							if scenario == sourceOriginRepository {
								cfg.Config.Labels[types.AnnotationPatchOriginName] = sourceOriginOtherRepository
							}
							image, err = mutate.ConfigFile(image, cfg)
							require.NoError(t, err)
						}
						children = append(children, mutate.IndexAddendum{Add: image, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: arch}}})
						data, err := os.ReadFile(originTestReport(t, arch))
						require.NoError(t, err)
						require.NoError(t, os.WriteFile(filepath.Join(reports, arch+".json"), data, 0o600))
					}
					input := fmt.Sprintf("%s:multi-%s-%t", repo, scenario, ignore)
					output := fmt.Sprintf("%s:multi-output-%s-%t", repo, scenario, ignore)
					index := mutate.IndexMediaType(mutate.AppendManifests(empty.Index, children...), v1types.OCIImageIndex)
					require.NoError(t, remote.WriteIndex(originTestReference(t, input), index, remote.WithContext(ctx)))
					err := Patch(ctx, &types.Options{
						Image: input, Report: reports, Scanner: "trivy", Push: true, PatchedTag: output, BkAddr: "docker://",
						PkgTypes: "os", IgnoreError: ignore, Progress: "quiet", Timeout: 2 * time.Minute,
					})
					if scenario != sourceOriginValid {
						assert.Error(t, err, "invalid selected config must fail regardless of ignore-errors")
						for _, ref := range []string{output, output + "-amd64", output + "-386"} {
							_, readErr := remote.Get(originTestReference(t, ref), remote.WithContext(ctx))
							assert.Error(t, readErr, "no platform or index may export before every selected origin validates: %s", ref)
						}
						return
					}
					require.NoError(t, err)
					for _, arch := range []string{originAMD64, "386"} {
						image, err := remote.Image(originTestReference(t, output+"-"+arch), remote.WithContext(ctx))
						require.NoError(t, err)
						verifyOriginBlobs(t, image)
					}
				})
			}
		}
	})
}
