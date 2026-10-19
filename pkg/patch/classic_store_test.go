package patch

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/distribution/reference"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/imageloader"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/stretchr/testify/require"
)

// A classic Docker image store reports the image as local but cannot provide
// its manifest. The selected manifest is read from the registry, as the
// builder does, instead of from a reconstructed `docker save` archive.
func TestCaptureSourceAnnotationsClassicStoreReadsRegistryManifest(t *testing.T) {
	server := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	defer server.Close()
	host := strings.TrimPrefix(server.URL, "http://")
	image := host + "/copa-openssl:test-debian12"
	ref, err := name.ParseReference(image)
	require.NoError(t, err)
	img, err := mutate.ConfigFile(empty.Image, &v1.ConfigFile{OS: "linux", Architecture: "amd64"})
	require.NoError(t, err)
	img = originAnnotatedImage(t, img, map[string]string{"com.example.source": "registry manifest"})
	require.NoError(t, remote.Write(ref, img, remote.WithContext(t.Context())))
	hash, err := img.Digest()
	require.NoError(t, err)
	size, err := img.Size()
	require.NoError(t, err)
	mediaType, err := img.MediaType()
	require.NoError(t, err)
	selected := digest.Digest(hash.String())
	platform := &specs.Platform{OS: "linux", Architecture: "amd64"}

	resolver, local, archive := resolveImageSource, localPlatformDescriptor, localManifestAnnotations
	t.Cleanup(func() {
		resolveImageSource, localPlatformDescriptor, localManifestAnnotations = resolver, local, archive
	})
	localPlatformDescriptor = func(context.Context, string, *specs.Platform) (*specs.Descriptor, bool, error) {
		return nil, true, nil // present in a store without per-platform descriptors
	}
	descriptor := &specs.Descriptor{MediaType: string(mediaType), Digest: selected, Size: size, Annotations: map[string]string{"com.example.descriptor": "captured"}}
	child := host + "/copa-openssl@" + selected.String()

	for _, registrySource := range []bool{true, false} {
		t.Run(map[bool]string{true: "classic store", false: "manifest-keeping store"}[registrySource], func(t *testing.T) {
			resolveImageSource = func(_ context.Context, got string) (*buildkit.ImageSource, error) {
				require.Equal(t, image, got)
				return &buildkit.ImageSource{Name: got, Descriptor: *descriptor, Registry: registrySource}, nil
			}
			localManifestAnnotations = func(_ context.Context, _ string, got digest.Digest) (map[string]string, error) {
				if registrySource {
					t.Error("a classic store's archive cannot contain the selected manifest")
				}
				require.Equal(t, selected, got)
				return map[string]string{"com.example.source": "local archive"}, nil
			}
			annotations, err := captureSourceAnnotations(t.Context(), image, child, descriptor, platform)
			require.NoError(t, err)
			require.Equal(t, "captured", annotations["com.example.descriptor"])
			if registrySource {
				require.Equal(t, "registry manifest", annotations["com.example.source"])
				return
			}
			require.Equal(t, "local archive", annotations["com.example.source"])
		})
	}
}

// After loading a patched image into a classic store, Docker cannot report its
// descriptor. A same-named registry image is a different object and must not be
// used for final index assembly.
func TestCreatePatchResultClassicStoreDoesNotSubstituteRegistryDescriptor(t *testing.T) {
	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/images/") && strings.HasSuffix(r.URL.Path, "/json") {
			w.Header().Set("Content-Type", "application/json")
			require.NoError(t, json.NewEncoder(w).Encode(map[string]any{"Id": digest.FromString("config").String()}))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer daemon.Close()
	t.Setenv("DOCKER_HOST", "tcp://"+strings.TrimPrefix(daemon.URL, "http://"))
	t.Setenv("DOCKER_API_VERSION", "1.45")
	t.Setenv("DOCKER_TLS_VERIFY", "")

	resolver := resolveImageSource
	t.Cleanup(func() { resolveImageSource = resolver })
	stale := digest.FromString("unrelated same-named registry image")
	for _, registrySource := range []bool{true, false} {
		t.Run(map[bool]string{true: "classic store", false: "manifest-keeping store"}[registrySource], func(t *testing.T) {
			lookups := 0
			resolveImageSource = func(_ context.Context, got string) (*buildkit.ImageSource, error) {
				lookups++
				require.Equal(t, "registry.example.com/app:1.0-patched-amd64", got)
				return &buildkit.ImageSource{Name: got, Descriptor: specs.Descriptor{MediaType: specs.MediaTypeImageManifest, Digest: stale, Size: 10}, Registry: registrySource}, nil
			}
			original, err := reference.ParseNormalizedNamed("registry.example.com/app:1.0")
			require.NoError(t, err)
			result, err := createPatchResultWithStates(t.Context(), original, "registry.example.com/app:1.0-patched-amd64",
				&types.PatchPlatform{Platform: specs.Platform{OS: "linux", Architecture: "amd64"}}, nil, imageloader.Docker, nil)
			require.NoError(t, err)
			require.Equal(t, 1, lookups)
			if registrySource {
				require.Nil(t, result.PatchedDesc)
				return
			}
			require.NotNil(t, result.PatchedDesc)
			require.Equal(t, stale, result.PatchedDesc.Digest)
		})
	}
}
