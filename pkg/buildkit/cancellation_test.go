package buildkit

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/distribution/reference"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	remoteTypes "github.com/google/go-containerregistry/pkg/v1/types"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/stretchr/testify/require"
)

const (
	cancellationDaemonImage = "daemon image"
	cancellationCachedIndex = "cached index"
	cancellationAMD64       = "amd64"
)

func runCancelableImageOperation(ctx context.Context, operation, input, output string) error {
	switch operation {
	case "discovery":
		_, err := DiscoverPlatformsWithContext(ctx, input, "", "")
		return err
	case "platform reference":
		_, err := GetPlatformImageReferenceWithContext(ctx, input, &specs.Platform{OS: "linux", Architecture: cancellationAMD64})
		return err
	default:
		ref, err := reference.ParseNormalizedNamed(input)
		if err != nil {
			return err
		}
		return CreateOCILayoutFromResultsWithContext(ctx, output, []types.PatchResult{{OriginalRef: ref}},
			[]types.PatchPlatform{{Platform: specs.Platform{OS: "linux", Architecture: cancellationAMD64}, ShouldPreserve: true}},
			OCILayoutExportOptions{})
	}
}

// The server stays blocked until cancellation is observed by the production HTTP client.
func requireCanceledImageOperation(t *testing.T, started <-chan struct{}, release chan struct{}, run func(context.Context) error) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	done := make(chan struct{})
	go func() { defer close(done); result <- run(ctx) }()
	defer func() {
		cancel()
		close(release)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("image operation did not exit after releasing fixture")
		}
	}()
	select {
	case <-started:
	case err := <-result:
		t.Fatalf("image operation returned before request started: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("image request did not start")
	}
	cancel()
	select {
	case err := <-result:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("image operation ignored cancellation")
	}
}

func TestImageOperationsCancellation(t *testing.T) {
	for _, tc := range []struct{ operation, stage string }{
		{"discovery", "daemon inspect"},
		{"discovery", cancellationDaemonImage},
		{"discovery", cancellationCachedIndex},
		{"discovery", "remote image"},
		{"platform reference", "daemon inspect"},
		{"platform reference", cancellationDaemonImage},
		{"export", "daemon inspect"},
		{"export", cancellationDaemonImage},
		{"export", "incomplete index"},
		{"export", cancellationCachedIndex},
		{"export", "remote image"},
		{"export", "local materialization"},
	} {
		t.Run(tc.operation+"/"+tc.stage, func(t *testing.T) {
			started, release := make(chan struct{}, 1), make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/_ping" {
					w.Header().Set("API-Version", "1.52")
					return
				}
				if r.URL.Path == "/v2/" {
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
			oldPlatforms, oldIndex, oldLocal, oldRemote := localImagePlatforms, localImageIndex, tryGetManifestFromLocal, getRemoteImageDescriptor
			t.Cleanup(func() {
				localImagePlatforms, localImageIndex, tryGetManifestFromLocal, getRemoteImageDescriptor = oldPlatforms, oldIndex, oldLocal, oldRemote
			})
			input := "example.invalid/app:latest"
			if strings.HasPrefix(tc.stage, "daemon") || tc.stage == "local materialization" {
				t.Setenv("DOCKER_HOST", "tcp://"+strings.TrimPrefix(server.URL, "http://"))
				t.Setenv("DOCKER_API_VERSION", "1.52")
				t.Setenv("DOCKER_TLS_VERIFY", "")
				getRemoteImageDescriptor = func(name.Reference, ...remote.Option) (*remote.Descriptor, error) {
					t.Error("canceled daemon operation must not fall back to registry")
					return nil, errors.New("unexpected fallback")
				}
				if tc.stage == cancellationDaemonImage {
					localImagePlatforms = func(context.Context, string) ([]specs.Platform, bool, error) { return nil, false, nil }
					localImageIndex = func(context.Context, string) (*specs.Index, *specs.Descriptor, bool, bool, error) {
						return nil, nil, true, true, nil
					}
				}
				if tc.stage == "local materialization" {
					tryGetManifestFromLocal = func(context.Context, name.Reference) (*remote.Descriptor, v1.Hash, bool, error) {
						desc := testRemoteIndexDescriptor(strings.Repeat("a", 64))
						desc.MediaType = remoteTypes.OCIManifestSchema1
						return desc, desc.Digest, true, nil
					}
				}
			} else {
				top := v1.Hash{Algorithm: "sha256", Hex: strings.Repeat("c", 64)}
				input = strings.TrimPrefix(server.URL, "http://") + "/app@" + top.String()
				localImagePlatforms = func(context.Context, string) ([]specs.Platform, bool, error) {
					if tc.stage == cancellationCachedIndex {
						return []specs.Platform{{OS: "linux", Architecture: cancellationAMD64}}, true, nil
					}
					return nil, false, nil
				}
				tryGetManifestFromLocal = func(context.Context, name.Reference) (*remote.Descriptor, v1.Hash, bool, error) {
					if tc.stage == "remote image" {
						return nil, v1.Hash{}, false, errors.New("no local source")
					}
					desc := testRemoteIndexDescriptor(top.Hex)
					if tc.stage == cancellationCachedIndex {
						desc.MediaType = remoteTypes.OCIManifestSchema1
						desc.Digest.Hex = strings.Repeat("a", 64)
					}
					return desc, top, tc.stage == cancellationCachedIndex, nil
				}
			}
			output := filepath.Join(t.TempDir(), "layout")
			requireCanceledImageOperation(t, started, release, func(ctx context.Context) error { return runCancelableImageOperation(ctx, tc.operation, input, output) })
			if tc.operation == "export" {
				require.NoFileExists(t, filepath.Join(output, "index.json"))
			}
		})
	}
}

func TestImageOperationsExpiredContext(t *testing.T) {
	oldPlatforms, oldLocal, oldRemote := localImagePlatforms, tryGetManifestFromLocal, getRemoteImageDescriptor
	t.Cleanup(func() {
		localImagePlatforms, tryGetManifestFromLocal, getRemoteImageDescriptor = oldPlatforms, oldLocal, oldRemote
	})
	localImagePlatforms = func(context.Context, string) ([]specs.Platform, bool, error) {
		t.Error("expired discovery must not inspect daemon")
		return nil, false, nil
	}
	tryGetManifestFromLocal = func(context.Context, name.Reference) (*remote.Descriptor, v1.Hash, bool, error) {
		t.Error("expired operation must not inspect daemon")
		return nil, v1.Hash{}, false, errors.New("no local image")
	}
	getRemoteImageDescriptor = func(name.Reference, ...remote.Option) (*remote.Descriptor, error) {
		t.Error("expired operation must not contact registry")
		return nil, errors.New("no remote image")
	}
	for _, operation := range []string{"discovery", "platform reference", "export"} {
		for _, expired := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/expired=%t", operation, expired), func(t *testing.T) {
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
				output := filepath.Join(t.TempDir(), "layout")
				require.ErrorIs(t, runCancelableImageOperation(ctx, operation, "example.invalid/app:latest", output), want)
				require.NoDirExists(t, output)
			})
		}
	}
}

func TestImageContentCancellation(t *testing.T) {
	for _, stage := range []string{"discovery config", "export manifest", "export config", "export layer"} {
		t.Run(stage, func(t *testing.T) {
			img, err := random.Image(128, 1)
			require.NoError(t, err)
			cfg, err := img.ConfigFile()
			require.NoError(t, err)
			cfg.OS, cfg.Architecture = "linux", cancellationAMD64
			img, err = mutate.ConfigFile(img, cfg)
			require.NoError(t, err)
			manifest, err := img.Manifest()
			require.NoError(t, err)
			imageDigest, err := img.Digest()
			require.NoError(t, err)
			suffix := "/blobs/" + manifest.Config.Digest.String()
			if stage == "export manifest" {
				suffix = "/manifests/" + imageDigest.String()
			}
			if stage == "export layer" {
				suffix = "/blobs/" + manifest.Layers[0].Digest.String()
			}
			started, release := make(chan struct{}, 1), make(chan struct{})
			var armed atomic.Bool
			handler := registry.New()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if armed.Load() && strings.HasSuffix(r.URL.Path, suffix) {
					select {
					case started <- struct{}{}:
					default:
					}
					select {
					case <-r.Context().Done():
					case <-release:
					}
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				handler.ServeHTTP(w, r)
			}))
			defer server.Close()
			ref, err := name.NewTag(strings.TrimPrefix(server.URL, "http://") + "/app:latest")
			require.NoError(t, err)
			operation := "export"
			if stage == "discovery config" {
				operation = "discovery"
				require.NoError(t, remote.Write(ref, img, remote.WithContext(t.Context())))
			} else {
				index := mutate.AppendManifests(empty.Index, mutate.IndexAddendum{Add: img, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: cancellationAMD64}}})
				require.NoError(t, remote.WriteIndex(ref, index, remote.WithContext(t.Context())))
			}
			oldPlatforms, oldLocal := localImagePlatforms, tryGetManifestFromLocal
			t.Cleanup(func() { localImagePlatforms, tryGetManifestFromLocal = oldPlatforms, oldLocal })
			localImagePlatforms = func(context.Context, string) ([]specs.Platform, bool, error) { return nil, false, nil }
			tryGetManifestFromLocal = func(context.Context, name.Reference) (*remote.Descriptor, v1.Hash, bool, error) {
				return nil, v1.Hash{}, false, errors.New("no local image")
			}
			output := filepath.Join(t.TempDir(), "layout")
			armed.Store(true)
			requireCanceledImageOperation(t, started, release, func(ctx context.Context) error {
				return runCancelableImageOperation(ctx, operation, ref.String(), output)
			})
			require.NoFileExists(t, filepath.Join(output, "index.json"))
		})
	}
}
