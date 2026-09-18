package patch

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
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

type sourceSessionTransport struct {
	http.RoundTripper
	inputPath string
	denied    atomic.Int64
}

func (transport *sourceSessionTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if strings.HasPrefix(request.URL.Path, transport.inputPath) {
		transport.denied.Add(1)
		return nil, fmt.Errorf("input registry is reachable only from the BuildKit worker")
	}
	return transport.RoundTripper.RoundTrip(request)
}

func testRemoteBuilderSource(t *testing.T, ctx context.Context, addr, repo string, original v1.Image, application map[string]string) {
	t.Helper()
	t.Run("remote-builder-source", func(t *testing.T) {
		for _, format := range []string{originManifestSurface, "index"} {
			t.Run(format, func(t *testing.T) {
				input := repo + "-remote-input:" + format
				output := repo + ":remote-builder-" + format
				config, err := original.ConfigFile()
				require.NoError(t, err)
				config = config.DeepCopy()
				config.Config.Labels["com.example.remote-source"] = input
				image, err := mutate.ConfigFile(original, config)
				require.NoError(t, err)
				hash, err := image.Digest()
				require.NoError(t, err)
				if format == originManifestSurface {
					require.NoError(t, remote.Write(originTestReference(t, input), image, remote.WithContext(ctx)))
				} else {
					index := mutate.IndexMediaType(mutate.AppendManifests(empty.Index, mutate.IndexAddendum{
						Add: image, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: originAMD64}, Annotations: map[string]string{"com.example.remote-descriptor": "preserved"}},
					}), v1types.OCIImageIndex)
					require.NoError(t, remote.WriteIndex(originTestReference(t, input), index, remote.WithContext(ctx)))
				}
				transport := remote.DefaultTransport
				t.Cleanup(func() { remote.DefaultTransport = transport })
				inputPath := "/v2/" + strings.SplitN(strings.SplitN(input, "/", 2)[1], ":", 2)[0] + "/"
				blocked := &sourceSessionTransport{RoundTripper: transport, inputPath: inputPath}
				remote.DefaultTransport = blocked
				_, err = remote.Get(originTestReference(t, input), remote.WithContext(ctx))
				require.ErrorContains(t, err, "reachable only from the BuildKit worker")
				require.NoError(t, Patch(ctx, &types.Options{
					Image: input, Report: originTestReport(t, originAMD64), Scanner: "trivy", Push: true, PatchedTag: output,
					BkAddr: addr, PkgTypes: "os", Progress: "quiet", Timeout: 2 * time.Minute,
				}))
				require.Positive(t, blocked.denied.Load(), "client must be unable to read the input registry")
				patched, err := remote.Image(originTestReference(t, output), remote.WithContext(ctx))
				require.NoError(t, err)
				patchedConfig, err := patched.ConfigFile()
				require.NoError(t, err)
				require.Equal(t, hash.String(), patchedConfig.Config.Labels[types.AnnotationPatchOriginDigest])
				require.Equal(t, input, patchedConfig.Config.Labels["com.example.remote-source"])
				manifest, err := patched.Manifest()
				require.NoError(t, err)
				require.Equal(t, hash.String(), manifest.Annotations[types.AnnotationPatchOriginDigest])
				for key, value := range application {
					require.Equal(t, value, patchedConfig.Config.Labels[key])
					require.Equal(t, value, manifest.Annotations[key])
				}
				if format == "index" {
					require.Equal(t, "preserved", manifest.Annotations["com.example.remote-descriptor"])
				}
				verifyOriginBlobs(t, patched)
			})
		}
	})
}
