package patch

import (
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	v1types "github.com/google/go-containerregistry/pkg/v1/types"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/solver/pb"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/stretchr/testify/require"
)

func testLegacyGatewaySource(t *testing.T, ctx context.Context, original v1.Image, application map[string]string) {
	t.Helper()
	t.Run("legacy-gateway-source", func(t *testing.T) {
		bk, err := buildkit.NewClient(ctx, buildkit.Opts{Addr: "docker://"})
		require.NoError(t, err)
		defer bk.Close()
		var hasBlobSource bool
		_, err = bk.Build(ctx, authenticatedSolveOpt(), copaProduct, func(_ context.Context, c gwclient.Client) (*gwclient.Result, error) {
			opts := c.BuildOpts()
			hasBlobSource = opts.LLBCaps.Supports(pb.CapSourceImageBlob) == nil
			return gwclient.NewResult(), nil
		}, nil)
		require.NoError(t, err)
		if hasBlobSource {
			t.Skip("fixture requires older Docker-native gateway without image-blob support")
		}
		for _, format := range []string{originManifestSurface, "index"} {
			t.Run(format, func(t *testing.T) {
				var restricted atomic.Bool
				var denied, workerReads atomic.Int64
				handler := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if restricted.Load() && strings.HasPrefix(r.URL.Path, "/v2/worker-input/") {
						if !strings.Contains(strings.ToLower(r.UserAgent()), "buildkit") {
							denied.Add(1)
							http.Error(w, "source metadata is accessible only to BuildKit", http.StatusForbidden)
							return
						}
						workerReads.Add(1)
					}
					handler.ServeHTTP(w, r)
				}))
				defer server.Close()
				host := strings.TrimPrefix(server.URL, "http://")
				t.Logf("Legacy gateway test registry: %s", host)
				input := host + "/worker-input:source"
				config, err := original.ConfigFile()
				require.NoError(t, err)
				config = config.DeepCopy()
				config.Config.Labels["com.example.legacy-gateway"] = input
				image, err := mutate.ConfigFile(original, config)
				require.NoError(t, err)
				root, err := image.Digest()
				require.NoError(t, err)
				if format == originManifestSurface {
					require.NoError(t, remote.Write(originTestReference(t, input), image, remote.WithContext(ctx)))
				} else {
					index := mutate.IndexMediaType(mutate.AppendManifests(empty.Index, mutate.IndexAddendum{
						Add: image, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: originAMD64}},
					}), v1types.OCIImageIndex)
					root, err = index.Digest()
					require.NoError(t, err)
					require.NoError(t, remote.WriteIndex(originTestReference(t, input), index, remote.WithContext(ctx)))
				}
				restricted.Store(true)
				_, err = remote.Get(originTestReference(t, input), remote.WithContext(ctx))
				require.Error(t, err, "Copa-side registry reads must fail")
				report := originTestReport(t, originAMD64)
				if baseline := os.Getenv("COPA_ORIGIN_BASELINE_CLI"); baseline != "" {
					//nolint:gosec // An explicit local test binary and generated fixture references.
					cmd := exec.CommandContext(ctx, baseline, []string{
						"patch", "-i", input, "-r", report, "-t", host + "/baseline-output:p1", "-a", "docker://",
						"--push", "--timeout", "2m", "--progress", "quiet",
					}...)
					out, err := cmd.CombinedOutput()
					require.NoError(t, err, "canonical baseline failed: %s", out)
					t.Log("canonical baseline patches worker-only source on older Docker gateway")
				}
				for _, generation := range []string{"p1", "p2"} {
					output := host + "/patched-output:" + generation
					require.NoError(t, Patch(ctx, &types.Options{
						Image: input, Report: report, Scanner: "trivy", Push: true, PatchedTag: output,
						BkAddr: "docker://", PkgTypes: "os", Progress: "quiet", Timeout: 2 * time.Minute,
					}))
					patched, err := remote.Image(originTestReference(t, output), remote.WithContext(ctx))
					require.NoError(t, err)
					patchedConfig, err := patched.ConfigFile()
					require.NoError(t, err)
					require.Equal(t, root.String(), patchedConfig.Config.Labels[types.AnnotationPatchOriginDigest], "retain the exact native root, including an index root")
					for key, value := range application {
						require.Equal(t, value, patchedConfig.Config.Labels[key])
					}
					verifyOriginBlobs(t, patched)
					input = output
				}
				require.Positive(t, denied.Load())
				require.Positive(t, workerReads.Load())
			})
		}
	})
}
