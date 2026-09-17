package patch

import (
	"context"
	"io"
	"log"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
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
	"github.com/opencontainers/go-digest"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/utils"
	"github.com/stretchr/testify/require"
)

func testSourceAnnotationFollowups(t *testing.T, ctx context.Context, addr, repo string, images map[string]v1.Image, application map[string]string) {
	t.Helper()
	t.Run("direct-source-origin", func(t *testing.T) {
		first, err := remote.Image(originTestReference(t, repo+":p1-amd64"), remote.WithContext(ctx))
		require.NoError(t, err)
		config, err := first.ConfigFile()
		require.NoError(t, err)
		origin := types.SourceLineageFromAnnotations(config.Config.Labels)
		require.True(t, origin.Valid())
		for _, scenario := range []string{sourceOriginMatching, sourceOriginDigest, sourceOriginRepository, "kind", sourceOriginPartial, "manifest-only"} {
			t.Run(scenario, func(t *testing.T) {
				annotations := maps.Clone(application)
				maps.Copy(annotations, origin.Annotations())
				inputImage := first
				switch scenario {
				case sourceOriginDigest:
					annotations[types.AnnotationPatchOriginDigest] = digest.FromString("different original").String()
				case sourceOriginRepository:
					annotations[types.AnnotationPatchOriginName] = "example.com/another:original"
				case "kind":
					annotations[types.AnnotationPatchOriginKind] = types.PatchOriginOCI
				case sourceOriginPartial:
					// mutate.Annotations merges existing values, so explicitly clear
					// the required digest to create an invalid partial tuple.
					annotations[types.AnnotationPatchOriginDigest] = ""
				case "manifest-only":
					changed := config.DeepCopy()
					changed.Config.Labels = withoutSourceLineageAnnotations(changed.Config.Labels)
					inputImage, err = mutate.ConfigFile(first, changed)
					require.NoError(t, err)
				}
				inputImage = originAnnotatedImage(t, inputImage, annotations)
				inputManifest, manifestErr := inputImage.Manifest()
				require.NoError(t, manifestErr)
				for key, value := range annotations {
					require.Equal(t, value, inputManifest.Annotations[key], "fixture annotation %s", key)
				}
				input := repo + ":direct-origin-" + scenario
				output := repo + ":direct-origin-output-" + scenario
				require.NoError(t, remote.Write(originTestReference(t, input), inputImage, remote.WithContext(ctx)))
				err = Patch(ctx, &types.Options{
					Image: input, Report: originTestReport(t, originAMD64), Scanner: "trivy", Push: true, PatchedTag: output,
					BkAddr: addr, PkgTypes: "os", IgnoreError: true, Progress: "quiet", Timeout: 2 * time.Minute,
				})
				if scenario == sourceOriginMatching {
					require.NoError(t, err)
					result, readErr := remote.Image(originTestReference(t, output), remote.WithContext(ctx))
					require.NoError(t, readErr)
					manifest, readErr := result.Manifest()
					require.NoError(t, readErr)
					require.Equal(t, origin.Digest.String(), manifest.Annotations[types.AnnotationPatchOriginDigest])
					verifyOriginBlobs(t, result)
				} else {
					require.ErrorContains(t, err, "contradicts the recovered config origin")
					_, readErr := remote.Get(originTestReference(t, output), remote.WithContext(ctx))
					require.Error(t, readErr, "inconsistent origin must fail before export even with IgnoreError")
				}
			})
		}
	})
	for _, scenario := range []string{"daemon-index-source", "daemon-partial-index-source", "daemon-single-index-source"} {
		t.Run(scenario, func(t *testing.T) {
			partial := scenario == "daemon-partial-index-source"
			single := scenario != "daemon-index-source"
			var offline atomic.Bool
			var deniedReads atomic.Int64
			handler := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if offline.Load() && strings.HasPrefix(r.URL.Path, "/v2/local-input/") {
					deniedReads.Add(1)
					http.Error(w, "input available only in daemon", http.StatusNotFound)
					return
				}
				handler.ServeHTTP(w, r)
			}))
			defer server.Close()
			host := strings.TrimPrefix(server.URL, "http://")
			input := host + "/local-input:source"
			output := host + "/patched-output:p1"
			t.Logf("Daemon index test registry: %s", host)
			var children []mutate.IndexAddendum
			expected := map[string]v1.Hash{}
			for _, arch := range []string{originAMD64, "386"} {
				if single && !partial && arch == "386" {
					continue
				}
				image := images[arch]
				if partial && arch == "386" {
					// Give the unpulled sibling a unique config so previous runtime
					// cases cannot make it available through shared daemon content.
					config, err := image.ConfigFile()
					require.NoError(t, err)
					config = config.DeepCopy()
					config.Config.Labels["com.example.unpulled"] = host
					image, err = mutate.ConfigFile(image, config)
					require.NoError(t, err)
				}
				annotations := maps.Clone(application)
				annotations["com.example.parent-capture"] = arch
				children = append(children, mutate.IndexAddendum{Add: image, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: arch}, Annotations: annotations}})
				hash, err := image.Digest()
				require.NoError(t, err)
				expected[arch] = hash
			}
			index := mutate.IndexMediaType(mutate.AppendManifests(empty.Index, children...), v1types.OCIImageIndex)
			require.NoError(t, remote.WriteIndex(originTestReference(t, input), index, remote.WithContext(ctx)))
			t.Cleanup(func() {
				cleanupCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				command := exec.CommandContext(cleanupCtx, "docker", "image", "rm", input)
				output, err := command.CombinedOutput()
				if err != nil {
					t.Logf("remove owned daemon index: %v: %s", err, output)
				}
			})
			pulled := []string{originAMD64, "386"}
			if single {
				pulled = pulled[:1]
			}
			for _, arch := range pulled {
				//nolint:gosec // Both architectures and the ephemeral input registry are owned by this fixture.
				command := exec.CommandContext(ctx, "docker", "pull", "--platform", "linux/"+arch, input)
				result, err := command.CombinedOutput()
				require.NoError(t, err, string(result))
			}
			if partial {
				captured, top, complete, found, err := utils.LocalImageIndex(ctx, input)
				require.NoError(t, err)
				require.True(t, found)
				require.False(t, complete, "unpulled sibling must remain unavailable")
				require.Len(t, captured.Manifests, 1)
				root, err := index.Digest()
				require.NoError(t, err)
				require.Equal(t, root.String(), top.Digest.String())
			} else {
				captured, err := buildkit.ResolveImageSource(ctx, input)
				require.NoError(t, err)
				require.Len(t, captured.Index.Manifests, len(pulled))
			}
			for _, hash := range expected {
				child := host + "/local-input@" + hash.String()
				result, err := exec.CommandContext(ctx, "docker", "image", "inspect", child).CombinedOutput()
				require.Error(t, err, "fixture requires only the parent index to be named: %s", result)
			}
			offline.Store(true)
			_, err := remote.Get(originTestReference(t, input), remote.WithContext(ctx))
			require.Error(t, err)
			reports := t.TempDir()
			for _, arch := range []string{originAMD64, "386"} {
				data, err := os.ReadFile(originTestReport(t, arch))
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(filepath.Join(reports, arch+".json"), data, 0o600))
			}
			reportInput := reports
			if single {
				reportInput = originTestReport(t, originAMD64)
			}
			require.NoError(t, Patch(ctx, &types.Options{
				Image: input, Report: reportInput, Scanner: "trivy", Push: true, PatchedTag: output,
				BkAddr: "docker://", PkgTypes: "os", Progress: "quiet", Timeout: 3 * time.Minute,
			}))
			if single {
				patched, err := remote.Image(originTestReference(t, output), remote.WithContext(ctx))
				require.NoError(t, err)
				config, err := patched.ConfigFile()
				require.NoError(t, err)
				require.Equal(t, expected[originAMD64].String(), config.Config.Labels[types.AnnotationPatchOriginDigest])
				manifest, err := patched.Manifest()
				require.NoError(t, err)
				require.Equal(t, expected[originAMD64].String(), manifest.Annotations[types.AnnotationPatchOriginDigest])
				require.Equal(t, originAMD64, manifest.Annotations["com.example.parent-capture"])
				for key, value := range application {
					require.Equal(t, value, config.Config.Labels[key])
					require.Equal(t, value, manifest.Annotations[key])
				}
				verifyOriginBlobs(t, patched)
				require.Positive(t, deniedReads.Load(), "remote control must be exercised")
				return
			}
			patched, err := remote.Index(originTestReference(t, output), remote.WithContext(ctx))
			require.NoError(t, err)
			manifest, err := patched.IndexManifest()
			require.NoError(t, err)
			require.Len(t, manifest.Manifests, 2)
			for i := range manifest.Manifests {
				descriptor := &manifest.Manifests[i]
				arch := descriptor.Platform.Architecture
				require.Equal(t, expected[arch].String(), descriptor.Annotations[types.AnnotationPatchOriginDigest])
				require.Equal(t, arch, descriptor.Annotations["com.example.parent-capture"])
				image, err := patched.Image(descriptor.Digest)
				require.NoError(t, err)
				verifyOriginBlobs(t, image)
			}
			require.Positive(t, deniedReads.Load(), "remote control must be exercised")
		})
	}
}
