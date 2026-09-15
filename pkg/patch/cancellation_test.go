package patch

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/distribution/reference"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	buildkitclient "github.com/moby/buildkit/client"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/utils"
	"github.com/stretchr/testify/require"
)

func TestPatchDiscoveryCancellation(t *testing.T) {
	for _, public := range []bool{false, true} {
		label := "dispatch"
		if public {
			label = "public"
		}
		t.Run(label, func(t *testing.T) {
			started, canceled, release := make(chan struct{}, 1), make(chan struct{}, 1), make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/_ping" {
					w.Header().Set("API-Version", "1.52")
					return
				}
				select {
				case started <- struct{}{}:
				default:
				}
				select {
				case <-r.Context().Done():
					select {
					case canceled <- struct{}{}:
					default:
					}
				case <-release:
				}
				w.WriteHeader(http.StatusServiceUnavailable)
			}))
			defer server.Close()
			t.Setenv("DOCKER_HOST", "tcp://"+strings.TrimPrefix(server.URL, "http://"))
			t.Setenv("DOCKER_API_VERSION", "1.52")
			t.Setenv("DOCKER_TLS_VERIFY", "")
			oldClient := bkNewClient
			t.Cleanup(func() { bkNewClient = oldClient })
			bkNewClient = func(context.Context, buildkit.Opts) (*buildkitclient.Client, error) {
				t.Error("canceled discovery must not create BuildKit client")
				return nil, errors.New("unexpected fallback")
			}
			ctx, cancel := context.WithCancel(t.Context())
			result, done := make(chan error, 1), make(chan struct{})
			opts := &types.Options{Image: "example.invalid/app:latest", PkgTypes: "os", Timeout: time.Minute, Progress: "plain"}
			go func() {
				defer close(done)
				if public {
					result <- Patch(ctx, opts)
				} else {
					result <- patchWithContext(ctx, opts)
				}
			}()
			defer func() {
				cancel()
				close(release)
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Error("patch did not exit")
				}
			}()
			select {
			case <-started:
			case err := <-result:
				t.Fatalf("patch returned before discovery: %v", err)
			case <-time.After(5 * time.Second):
				t.Fatal("discovery did not start")
			}
			cancel()
			select {
			case err := <-result:
				require.ErrorIs(t, err, context.Canceled)
			case <-time.After(2 * time.Second):
				t.Fatal("patch ignored cancellation")
			}
			select {
			case <-canceled:
			case <-time.After(2 * time.Second):
				t.Fatal("patch left discovery request running")
			}
		})
	}
}

func TestPlatformResultCancellation(t *testing.T) {
	for _, stage := range []string{
		"descriptor daemon", "descriptor legacy", "descriptor cached index", "descriptor registry",
		"original result", "patched result daemon", "patched result registry", "utility registry",
	} {
		t.Run(stage, func(t *testing.T) {
			started, release := make(chan struct{}, 1), make(chan struct{})
			remoteStage := strings.Contains(stage, "registry") || strings.Contains(stage, "cached index")
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/_ping" {
					w.Header().Set("API-Version", "1.52")
					return
				}
				if r.URL.Path == "/v2/" {
					return
				}
				if remoteStage && !strings.HasPrefix(r.URL.Path, "/v2/") {
					if stage == "utility registry" {
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					w.WriteHeader(http.StatusNotFound)
					return
				}
				select {
				case started <- struct{}{}:
				default:
				}
				select {
				case <-r.Context().Done():
				case <-release:
				}
				w.WriteHeader(http.StatusServiceUnavailable)
			}))
			defer server.Close()
			t.Setenv("DOCKER_HOST", "tcp://"+strings.TrimPrefix(server.URL, "http://"))
			t.Setenv("DOCKER_API_VERSION", "1.52")
			t.Setenv("DOCKER_TLS_VERIFY", "")
			input := strings.TrimPrefix(server.URL, "http://") + "/app:latest"
			oldLocal := localPlatformDescriptor
			t.Cleanup(func() { localPlatformDescriptor = oldLocal })
			switch stage {
			case "descriptor cached index":
				input = strings.TrimPrefix(server.URL, "http://") + "/app@sha256:" + strings.Repeat("c", 64)
				localPlatformDescriptor = func(context.Context, string, *ispec.Platform) (*ispec.Descriptor, bool, error) { return nil, true, nil }
			case "descriptor legacy", "descriptor registry":
				localPlatformDescriptor = func(context.Context, string, *ispec.Platform) (*ispec.Descriptor, bool, error) {
					return nil, false, nil
				}
			}
			ref, err := reference.ParseNormalizedNamed(input)
			require.NoError(t, err)
			platform := &types.PatchPlatform{Platform: ispec.Platform{OS: "linux", Architecture: "amd64"}}
			ctx, cancel := context.WithCancel(t.Context())
			result, done := make(chan error, 1), make(chan struct{})
			go func() {
				defer close(done)
				var err error
				switch {
				case stage == "utility registry":
					_, err = utils.GetImageDescriptor(ctx, input, "docker")
				case stage == "original result":
					_, err = createOriginalImageResult(ctx, ref, platform, input)
				case strings.HasPrefix(stage, "patched result"):
					_, err = createPatchResultWithStates(ctx, ref, input, platform, nil, "docker", nil)
				default:
					_, err = getPlatformDescriptorFromManifest(ctx, input, platform)
				}
				result <- err
			}()
			defer func() {
				cancel()
				close(release)
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Error("lookup did not exit")
				}
			}()
			select {
			case <-started:
			case err := <-result:
				t.Fatalf("lookup returned before request: %v", err)
			case <-time.After(5 * time.Second):
				t.Fatal("lookup did not start")
			}
			cancel()
			select {
			case err := <-result:
				require.ErrorIs(t, err, context.Canceled)
			case <-time.After(2 * time.Second):
				t.Fatal("lookup ignored cancellation")
			}
		})
	}
}

func TestPlatformResultExpiredContext(t *testing.T) {
	oldLocal := localPlatformDescriptor
	t.Cleanup(func() { localPlatformDescriptor = oldLocal })
	localPlatformDescriptor = func(context.Context, string, *ispec.Platform) (*ispec.Descriptor, bool, error) {
		t.Error("expired lookup must not inspect daemon")
		return nil, false, nil
	}
	for _, expired := range []bool{false, true} {
		t.Run(fmt.Sprintf("expired=%t", expired), func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			want := context.Canceled
			if expired {
				cancel()
				ctx, cancel = context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
				want = context.DeadlineExceeded
			} else {
				cancel()
			}
			defer cancel()
			input := "example.invalid/app:latest"
			ref, err := reference.ParseNormalizedNamed(input)
			require.NoError(t, err)
			platform := &types.PatchPlatform{Platform: ispec.Platform{OS: "linux", Architecture: "amd64"}}
			_, err = getPlatformDescriptorFromManifest(ctx, input, platform)
			require.ErrorIs(t, err, want)
			_, err = createOriginalImageResult(ctx, ref, platform, input)
			require.ErrorIs(t, err, want)
			_, err = createPatchResultWithStates(ctx, ref, input, platform, nil, "docker", nil)
			require.ErrorIs(t, err, want)
		})
	}
}
