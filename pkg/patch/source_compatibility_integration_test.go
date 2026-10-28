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
	"github.com/stretchr/testify/require"
)

// Run against the actual Docker daemon selected by DOCKER_HOST. The owned
// runtime runner supplies either the current daemon or an isolated older one.
func TestSourceCaptureCompatibility(t *testing.T) {
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
	repo := strings.TrimPrefix(server.URL, "http://") + "/copa-1678-compat"
	t.Logf("Source compatibility test registry: %s", repo)
	original, err := remote.Image(originTestReference(t, "alpine:3.20.0"), remote.WithContext(ctx), remote.WithPlatform(v1.Platform{OS: "linux", Architecture: "amd64"}))
	require.NoError(t, err)
	config, err := original.ConfigFile()
	require.NoError(t, err)
	application := map[string]string{specs.AnnotationBaseImageName: "example.com/application-base:stable", specs.AnnotationBaseImageDigest: digest.FromString("application B").String()}
	config.Config.Labels = maps.Clone(application)
	original, err = mutate.ConfigFile(original, config)
	require.NoError(t, err)
	for _, scenario := range []string{"oci-digest", "docker-digest", "local-alias", "qualified-local-alias", "index-digest", "index-local-alias"} {
		t.Run(scenario, func(t *testing.T) {
			image := mutate.MediaType(original, v1types.OCIManifestSchema1)
			if scenario == "docker-digest" {
				image = mutate.MediaType(original, v1types.DockerManifestSchema2)
			}
			source := repo + ":" + scenario
			require.NoError(t, remote.Write(originTestReference(t, source), image, remote.WithContext(ctx)))
			hash, err := image.Digest()
			require.NoError(t, err)
			input := source + "@" + hash.String()
			if strings.HasPrefix(scenario, "index-") {
				otherConfig, err := image.ConfigFile()
				require.NoError(t, err)
				otherConfig.Architecture = ARM64
				other, err := mutate.ConfigFile(image, otherConfig)
				require.NoError(t, err)
				index := mutate.AppendManifests(empty.Index,
					mutate.IndexAddendum{Add: image, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "amd64"}}},
					mutate.IndexAddendum{Add: other, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: ARM64}}})
				require.NoError(t, remote.WriteIndex(originTestReference(t, source), index, remote.WithContext(ctx)))
				indexHash, err := index.Digest()
				require.NoError(t, err)
				input = source + "@" + indexHash.String()
			}
			dockerCommand := func(args ...string) {
				t.Helper()
				//nolint:gosec // All references and paths belong to this generated fixture.
				data, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
				require.NoError(t, err, string(data))
			}
			dockerCommand("pull", "--platform=linux/amd64", input)
			cleanup := []string{input}
			if scenario == "local-alias" || scenario == "qualified-local-alias" || scenario == "index-local-alias" {
				alias := fmt.Sprintf("local/copa-1678-%d:source", time.Now().UnixNano())
				if scenario == "qualified-local-alias" || scenario == "index-local-alias" {
					alias = "127.0.0.1:1/" + alias
				}
				dockerCommand("tag", input, alias)
				input = alias
				cleanup = append(cleanup, alias)
			}
			t.Cleanup(func() {
				cleanupCtx, stop := context.WithTimeout(context.Background(), time.Minute)
				defer stop()
				//nolint:gosec // Remove only this scenario's generated or digest-pulled names.
				data, err := exec.CommandContext(cleanupCtx, "docker", append([]string{"image", "rm"}, cleanup...)...).CombinedOutput()
				t.Logf("compatibility image cleanup: %v %s", err, data)
			})
			platform := &specs.Platform{OS: "linux", Architecture: "amd64"}
			desc, found, err := utils.LocalPlatformDescriptor(ctx, input, platform)
			require.NoError(t, err)
			require.True(t, found)
			if os.Getenv("COPA_ORIGIN_EXPECT_LEGACY_INSPECT") == "1" {
				require.Nil(t, desc, "exercise the actual older Docker inspect API")
			}
			for _, generation := range []string{"p1", "p2"} {
				output := repo + ":" + scenario + "-" + generation
				require.NoError(t, Patch(ctx, &types.Options{
					Image: input, Report: originTestReport(t, "amd64"), Scanner: "trivy", Push: true,
					PatchedTag: output, BkAddr: "docker://", PkgTypes: "os", Progress: "quiet", Timeout: 2 * time.Minute,
				}))
				patched, err := remote.Image(originTestReference(t, output), remote.WithContext(ctx))
				require.NoError(t, err)
				cfg, err := patched.ConfigFile()
				require.NoError(t, err)
				require.Equal(t, hash.String(), cfg.Config.Labels[types.AnnotationPatchOriginDigest])
				for key, value := range application {
					require.Equal(t, value, cfg.Config.Labels[key])
				}
				verifyOriginBlobs(t, patched)
				dockerCommand("pull", output)
				cleanup = append(cleanup, output)
				input = output
			}
		})
	}
}
