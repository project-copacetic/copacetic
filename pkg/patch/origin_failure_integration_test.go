package patch

import (
	"context"
	"fmt"
	"io"
	"log"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	v1types "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/moby/buildkit/client"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Cross two real BuildKit sessions so a cache warmed by preflight cannot hide
// loss of the recorded original before the patch worker resolves it. Only the
// client factory selects the second actual builder; metadata and exports use
// their production transports and the registry changes availability in flight.
func TestOriginFailureAfterPreflight(t *testing.T) {
	workerAddr := os.Getenv("COPA_ORIGIN_BUILDKIT_ADDR")
	if workerAddr == "" || strings.HasPrefix(workerAddr, "docker://") {
		t.Skip("requires the serialized Docker and distinct BuildKit proof lane")
	}
	previous := bkNewClient
	t.Cleanup(func() { bkNewClient = previous })
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Minute)
	defer cancel()
	images := map[string]v1.Image{}
	for _, arch := range []string{originAMD64, "386"} {
		image, err := remote.Image(originTestReference(t, "alpine:3.20.0"), remote.WithContext(ctx), remote.WithPlatform(v1.Platform{OS: "linux", Architecture: arch}))
		require.NoError(t, err)
		images[arch] = image
	}
	const (
		stable = "stable"
		early  = "early"
		late   = "late"
	)
	for _, timing := range []string{stable, early, late} {
		for _, ignore := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/ignore=%t", timing, ignore), func(t *testing.T) {
				var unavailable atomic.Bool
				var rejected atomic.Int32
				var clients atomic.Int32
				healthyExported := make(chan struct{})
				var healthyOnce sync.Once
				handler := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if unavailable.Load() && strings.Contains(r.URL.Path, "/copa-1678-failure-base/manifests/") {
						rejected.Add(1)
						if timing == late {
							select {
							case <-healthyExported:
							case <-r.Context().Done():
								return
							}
						}
						http.NotFound(w, r)
						return
					}
					handler.ServeHTTP(w, r)
					if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/manifests/output-386") {
						healthyOnce.Do(func() { close(healthyExported) })
					}
				}))
				defer server.Close()
				repo := strings.TrimPrefix(server.URL, "http://") + "/copa-1678-failure"
				t.Logf("Origin failure test registry: %s", repo)
				original := images[originAMD64]
				cfg, err := original.ConfigFile()
				require.NoError(t, err)
				cfg.Config.Labels = maps.Clone(cfg.Config.Labels)
				if cfg.Config.Labels == nil {
					cfg.Config.Labels = map[string]string{}
				}
				cfg.Config.Labels["com.example.fixture"] = server.URL
				original, err = mutate.ConfigFile(original, cfg)
				require.NoError(t, err)
				original = mutate.MediaType(original, v1types.OCIManifestSchema1)
				require.NoError(t, remote.Write(originTestReference(t, repo+"-base:original"), original, remote.WithContext(ctx)))
				bkNewClient = buildkit.NewClient
				err = Patch(ctx, &types.Options{
					Image: repo + "-base:original", Report: originTestReport(t, originAMD64), Scanner: "trivy",
					Push: true, PatchedTag: repo + ":p1", BkAddr: "docker://", PkgTypes: "os", Progress: "quiet", Timeout: 2 * time.Minute,
				})
				require.NoError(t, err)
				patched, err := remote.Image(originTestReference(t, repo+":p1"), remote.WithContext(ctx))
				require.NoError(t, err)
				children := []mutate.IndexAddendum{
					{Add: patched, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: originAMD64}}},
					{Add: images["386"], Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "386"}}},
				}
				input := mutate.IndexMediaType(mutate.AppendManifests(empty.Index, children...), v1types.OCIImageIndex)
				require.NoError(t, remote.WriteIndex(originTestReference(t, repo+":source"), input, remote.WithContext(ctx)))
				reports := t.TempDir()
				for _, arch := range []string{originAMD64, "386"} {
					data, err := os.ReadFile(originTestReport(t, arch))
					require.NoError(t, err)
					require.NoError(t, os.WriteFile(reports+"/"+arch+".json", data, 0o600))
				}
				bkNewClient = func(ctx context.Context, opts buildkit.Opts) (*client.Client, error) {
					if clients.Add(1) == 1 {
						opts.Addr = "docker://"
					} else {
						unavailable.Store(timing != stable)
						opts.Addr = workerAddr
					}
					return buildkit.NewClient(ctx, opts)
				}
				err = Patch(ctx, &types.Options{
					Image: repo + ":source", Report: reports, Scanner: "trivy", Push: true, PatchedTag: repo + ":output",
					BkAddr: "docker://", PkgTypes: "os", IgnoreError: ignore, Progress: "quiet", Timeout: 2 * time.Minute,
				})
				bkNewClient = buildkit.NewClient
				require.GreaterOrEqual(t, clients.Load(), int32(2), "the real preflight and a worker ran")
				if timing != early {
					require.Equal(t, int32(3), clients.Load(), "the real preflight and both workers ran")
				}
				result, readErr := remote.Index(originTestReference(t, repo+":output"), remote.WithContext(ctx))
				if timing == stable {
					require.NoError(t, err)
					require.NoError(t, readErr)
					manifest, err := result.IndexManifest()
					require.NoError(t, err)
					require.Len(t, manifest.Manifests, 2)
					for i := range manifest.Manifests {
						desc := &manifest.Manifests[i]
						image, err := result.Image(desc.Digest)
						require.NoError(t, err)
						verifyOriginBlobs(t, image)
					}
					require.Zero(t, rejected.Load())
					return
				}
				require.Positive(t, rejected.Load(), "recorded original became unavailable only after successful preflight")
				assert.ErrorIs(t, err, errOriginIntegrity, "origin recovery failures must retain their type through the real BuildKit return and worker group")
				assert.Error(t, readErr, "no final index may publish after a worker loses its original")
				if timing == late {
					select {
					case <-healthyExported:
					default:
						t.Fatal("late failure must follow the healthy child export")
					}
					healthy, err := remote.Image(originTestReference(t, repo+":output-386"), remote.WithContext(ctx))
					require.NoError(t, err)
					verifyOriginBlobs(t, healthy)
				}
			})
		}
	}
}
