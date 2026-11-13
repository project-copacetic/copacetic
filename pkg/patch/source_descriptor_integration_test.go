package patch

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	v1types "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/opencontainers/go-digest"
	specsgo "github.com/opencontainers/image-spec/specs-go"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const sourceDescriptorGateway = "gateway"

// Publish exact index bytes rather than letting an image library repair the
// malformed child descriptors. All capture/export transports are real; gateway
// cases deny host input access to require BuildKit metadata and blob capture.
func TestSourceChildDescriptor(t *testing.T) {
	for _, route := range []string{"registry-single", "registry-multi", sourceDescriptorGateway} {
		t.Run(route, func(t *testing.T) { testSourceChildDescriptorRoute(t, route) })
	}
}

func testSourceChildDescriptorRoute(t *testing.T, route string) {
	t.Helper()
	addr := os.Getenv("COPA_ORIGIN_BUILDKIT_ADDR")
	if addr == "" || strings.HasPrefix(addr, "docker://") {
		t.Skip("requires the serialized BuildKit proof lane with image-blob support")
	}
	previous := bkNewClient
	bkNewClient = buildkit.NewClient
	t.Cleanup(func() { bkNewClient = previous })
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Minute)
	defer cancel()
	server := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	defer server.Close()
	host := strings.TrimPrefix(server.URL, "http://")
	t.Logf("Gateway descriptor test registry: %s", host)
	inputRepo, outputRepo := host+"/source", host+"/output"
	original, err := remote.Image(originTestReference(t, "alpine:3.20.0"), remote.WithContext(ctx),
		remote.WithPlatform(v1.Platform{OS: "linux", Architecture: originAMD64}))
	require.NoError(t, err)
	config, err := original.ConfigFile()
	require.NoError(t, err)
	application := map[string]string{
		specs.AnnotationBaseImageName: "example.com/application-base:stable", specs.AnnotationBaseImageDigest: digest.FromString("application B").String(),
		"com.example.descriptor-fixture": inputRepo,
	}
	config.Config.Labels = application
	original, err = mutate.ConfigFile(original, config)
	require.NoError(t, err)
	original = originAnnotatedImage(t, mutate.MediaType(original, v1types.OCIManifestSchema1), application)
	require.NoError(t, remote.Write(originTestReference(t, inputRepo+":original"), original, remote.WithContext(ctx)))
	originalData, err := original.RawManifest()
	require.NoError(t, err)
	put := func(tag, mediaType string, data []byte) {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodPut, server.URL+"/v2/source/manifests/"+tag, bytes.NewReader(data))
		require.NoError(t, err)
		req.Header.Set("Content-Type", mediaType)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusCreated, resp.StatusCode)
	}
	const (
		docker           = "docker"
		omittedMediaType = "omitted-media-type"
		missingSize      = "missing-size"
	)
	// A successful first capture also warms the child in the real worker;
	// malformed later indexes must not be accepted from that cached child.
	for _, scenario := range []string{sourceOriginMatching, missingSize, "zero-size", "wrong-size", "negative-size", "wrong-media-type", docker, omittedMediaType} {
		t.Run(scenario, func(t *testing.T) {
			data := originalData
			mediaType := specs.MediaTypeImageManifest
			if scenario == docker || scenario == omittedMediaType {
				var manifest map[string]any
				require.NoError(t, json.Unmarshal(data, &manifest))
				if scenario == docker {
					mediaType = string(v1types.DockerManifestSchema2)
					manifest["mediaType"] = mediaType
				} else {
					delete(manifest, "mediaType")
				}
				data, err = json.Marshal(manifest)
				require.NoError(t, err)
				put("child-"+scenario, mediaType, data)
			}
			child := specs.Descriptor{
				Digest: digest.FromBytes(data), Size: int64(len(data)), MediaType: mediaType,
				Platform: &specs.Platform{OS: "linux", Architecture: originAMD64}, Annotations: map[string]string{"com.example.descriptor": "preserved"},
			}
			switch scenario {
			case missingSize, "zero-size":
				child.Size = 0
			case "wrong-size":
				child.Size++
			case "negative-size":
				child.Size = -1
			case "wrong-media-type":
				child.MediaType = string(v1types.DockerManifestSchema2)
			}
			index := specs.Index{Versioned: specsgo.Versioned{SchemaVersion: 2}, MediaType: specs.MediaTypeImageIndex, Manifests: []specs.Descriptor{child}}
			indexData, err := json.Marshal(index)
			require.NoError(t, err)
			if scenario == missingSize {
				var raw map[string]any
				require.NoError(t, json.Unmarshal(indexData, &raw))
				manifests, ok := raw["manifests"].([]any)
				require.True(t, ok)
				selected, ok := manifests[0].(map[string]any)
				require.True(t, ok)
				delete(selected, "size")
				indexData, err = json.Marshal(raw)
				require.NoError(t, err)
			}
			put(scenario, specs.MediaTypeImageIndex, indexData)
			input, output := inputRepo+":"+scenario, outputRepo+":"+scenario
			transport := remote.DefaultTransport
			t.Cleanup(func() { remote.DefaultTransport = transport })
			blocked := &sourceSessionTransport{RoundTripper: transport, inputPath: "/v2/source/"}
			if route == sourceDescriptorGateway {
				remote.DefaultTransport = blocked
			}
			report := originTestReport(t, originAMD64)
			if route == "registry-multi" {
				data, err := os.ReadFile(report)
				require.NoError(t, err)
				report = t.TempDir()
				require.NoError(t, os.WriteFile(report+"/amd64.json", data, 0o600))
			}
			err = Patch(ctx, &types.Options{
				Image: input, Report: report, Scanner: "trivy", Push: true, PatchedTag: output,
				BkAddr: addr, PkgTypes: "os", IgnoreError: true, Progress: "quiet", Timeout: 2 * time.Minute,
			})
			if route == sourceDescriptorGateway {
				require.Positive(t, blocked.denied.Load(), "capture must cross the actual gateway boundary")
			} else {
				require.Zero(t, blocked.denied.Load())
			}
			patched, readErr := remote.Image(originTestReference(t, output), remote.WithContext(ctx))
			if scenario != sourceOriginMatching && scenario != docker && scenario != omittedMediaType {
				assert.Error(t, err, "malformed selected descriptor must fail even when its child is cached")
				assert.Error(t, readErr, "invalid capture must leave no output")
				if route == "registry-multi" {
					_, childErr := remote.Get(originTestReference(t, output+"-amd64"), remote.WithContext(ctx))
					assert.Error(t, childErr, "invalid capture must leave no child output")
				}
				return
			}
			require.NoError(t, err)
			require.NoError(t, readErr)
			patchedConfig, err := patched.ConfigFile()
			require.NoError(t, err)
			manifest, err := patched.Manifest()
			require.NoError(t, err)
			for _, surface := range []map[string]string{patchedConfig.Config.Labels, manifest.Annotations} {
				require.Equal(t, child.Digest.String(), surface[types.AnnotationPatchOriginDigest])
				for key, value := range application {
					require.Equal(t, value, surface[key])
				}
			}
			require.Equal(t, "preserved", manifest.Annotations["com.example.descriptor"])
			verifyOriginBlobs(t, patched)
		})
	}
}
