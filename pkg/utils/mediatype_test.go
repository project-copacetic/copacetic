package utils

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	mobyimage "github.com/moby/moby/api/types/image"
	dockerClient "github.com/moby/moby/client"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/project-copacetic/copacetic/pkg/imageloader"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type mockDockerClient struct {
	mock.Mock
	dockerClient.APIClient
}

func (m *mockDockerClient) ImageInspect(ctx context.Context, ref string, opts ...dockerClient.ImageInspectOption) (dockerClient.ImageInspectResult, error) {
	args := m.Called(ctx, ref, opts)
	di, _ := args.Get(0).(dockerClient.ImageInspectResult)
	return di, args.Error(1)
}

func (m *mockDockerClient) Close() error {
	return nil
}

type mockRemote struct {
	mock.Mock
}

func (m *mockRemote) Get(ref name.Reference, opts ...remote.Option) (*remote.Descriptor, error) {
	args := m.Called(ref, opts)
	desc, _ := args.Get(0).(*remote.Descriptor)
	return desc, args.Error(1)
}

func TestLocalMediaType(t *testing.T) {
	md := new(mockDockerClient)
	fakeMediaType := "application/vnd.docker.distribution.manifest.v2+json"
	md.On("ImageInspect", mock.Anything, "alpine:latest", mock.Anything).Return(
		dockerClient.ImageInspectResult{InspectResponse: mobyimage.InspectResponse{
			Descriptor: &ocispec.Descriptor{
				MediaType: fakeMediaType,
			},
		}},
		nil,
	)

	origNewClient := newClient
	defer func() { newClient = origNewClient }()
	newClient = func() (dockerClient.APIClient, error) { return md, nil }

	mt, found, err := localMediaType(context.Background(), "alpine:latest")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, fakeMediaType, mt)
}

func TestLocalMediaTypeFailure(t *testing.T) {
	md := new(mockDockerClient)
	md.On("ImageInspect", mock.Anything, "bad:tag", mock.Anything).Return(
		dockerClient.ImageInspectResult{},
		errors.New("failed to inspect"),
	)

	origNewClient := newClient
	defer func() { newClient = origNewClient }()
	newClient = func() (dockerClient.APIClient, error) { return md, nil }

	mt, found, err := localMediaType(context.Background(), "bad:tag")
	require.Error(t, err)
	require.False(t, found)
	require.Empty(t, mt)
}

func TestRemoteMediaType_Success(t *testing.T) {
	mr := new(mockRemote)
	fakeRemoteType := types.MediaType("application/vnd.oci.image.config.v1+json")
	mr.On("Get", mock.Anything, mock.Anything).Return(
		&remote.Descriptor{Descriptor: v1.Descriptor{MediaType: fakeRemoteType}},
		nil,
	)

	origRemoteGet := remoteGet
	defer func() { remoteGet = origRemoteGet }()
	remoteGet = func(ref name.Reference, opts ...remote.Option) (*remote.Descriptor, error) {
		return mr.Get(ref, opts...)
	}

	mt, err := remoteMediaType(context.Background(), "alpine:latest")
	require.NoError(t, err)
	require.Equal(t, string(fakeRemoteType), mt)
}

func TestRemoteMediaType_Failure(t *testing.T) {
	mr := new(mockRemote)
	mr.On("Get", mock.Anything, mock.Anything).Return(nil, errors.New("network down"))

	origRemoteGet := remoteGet
	defer func() { remoteGet = origRemoteGet }()
	remoteGet = func(ref name.Reference, opts ...remote.Option) (*remote.Descriptor, error) {
		return mr.Get(ref, opts...)
	}

	_, err := remoteMediaType(context.Background(), "alpine:latest")
	require.Error(t, err)
}

// TestRemoteMediaType_ContextCanceled is a regression test for the context
// binding added in this change: a canceled context must abort the remote
// registry lookup promptly instead of issuing an unbounded network request, so
// media type detection cannot outlive the caller's patch timeout.
func TestRemoteMediaType_ContextCanceled(t *testing.T) {
	// Exercise the real context-aware remote.Get path (not the mock) so the
	// test verifies that remote.WithContext(ctx) is actually honored.
	origRemoteGet := remoteGet
	defer func() { remoteGet = origRemoteGet }()
	remoteGet = remote.Get

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	_, err := remoteMediaType(ctx, "alpine:latest")
	require.Error(t, err)
	require.ErrorIs(t, err, context.Canceled)
	require.Less(t, time.Since(start), 5*time.Second, "canceled context must abort promptly")
}

func TestGetMediaType_LocalSuccess(t *testing.T) {
	md := new(mockDockerClient)
	fakeLocalType := "application/vnd.docker.distribution.manifest.v2+json"
	md.On("ImageInspect", mock.Anything, "alpine:latest", mock.Anything).Return(
		dockerClient.ImageInspectResult{InspectResponse: mobyimage.InspectResponse{
			Descriptor: &ocispec.Descriptor{
				MediaType: fakeLocalType,
			},
		}},
		nil,
	)

	origNewClient := newClient
	defer func() { newClient = origNewClient }()
	newClient = func() (dockerClient.APIClient, error) { return md, nil }

	mt, err := GetMediaType("alpine:latest", imageloader.Docker)
	require.NoError(t, err)
	require.Equal(t, fakeLocalType, mt)
}

// TestGetMediaTypeWithContext_NilContext verifies the defensive guard: a nil
// context is treated as context.Background() instead of panicking downstream
// (e.g. exec.CommandContext / cli.ImageInspect).
func TestGetMediaTypeWithContext_NilContext(t *testing.T) {
	md := new(mockDockerClient)
	fakeLocalType := string(types.DockerManifestSchema2)
	md.On("ImageInspect", mock.Anything, "alpine:latest", mock.Anything).Return(
		dockerClient.ImageInspectResult{InspectResponse: mobyimage.InspectResponse{
			Descriptor: &ocispec.Descriptor{
				MediaType: fakeLocalType,
			},
		}},
		nil,
	)

	origNewClient := newClient
	defer func() { newClient = origNewClient }()
	newClient = func() (dockerClient.APIClient, error) { return md, nil }

	//nolint:staticcheck // SA1012: intentionally passing nil to exercise the guard.
	mt, err := GetMediaTypeWithContext(nil, "alpine:latest", imageloader.Docker)
	require.NoError(t, err)
	require.Equal(t, fakeLocalType, mt)
}

func TestGetMediaType_RemoteFallback(t *testing.T) {
	// Force local lookup to fail
	md := new(mockDockerClient)
	md.On("ImageInspect", mock.Anything, "alpine:latest", mock.Anything).Return(
		dockerClient.ImageInspectResult{},
		errors.New("local lookup failed"),
	)

	origNewClient := newClient
	defer func() { newClient = origNewClient }()
	newClient = func() (dockerClient.APIClient, error) { return md, nil }

	// Mock remote lookup
	mr := new(mockRemote)
	fakeRemoteType := types.MediaType("application/vnd.oci.image.config.v1+json")
	mr.On("Get", mock.Anything, mock.Anything).Return(
		&remote.Descriptor{Descriptor: v1.Descriptor{MediaType: fakeRemoteType}},
		nil,
	)

	origRemoteGet := remoteGet
	defer func() { remoteGet = origRemoteGet }()
	remoteGet = func(ref name.Reference, opts ...remote.Option) (*remote.Descriptor, error) {
		return mr.Get(ref, opts...)
	}

	mt, err := GetMediaType("alpine:latest", imageloader.Docker)
	require.NoError(t, err)
	require.Equal(t, string(fakeRemoteType), mt)
}

func TestPodmanMediaType_ImageNotFound(t *testing.T) {
	// This test covers the case where podman inspect fails because image doesn't exist
	// Since podman is available in the test environment, we test with non-existent image

	// Bound the call to a timeout so a stuck `podman inspect` cannot hang CI.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, found, err := podmanMediaType(ctx, "non-existent-image:test")
	require.Error(t, err)
	require.False(t, found)
	// Should get an error from podman command execution
}

func TestGetMediaType_PodmanRuntime(t *testing.T) {
	// Test that GetMediaType correctly calls podmanMediaType when runtime is Podman
	// Since we can't easily mock the podman command, we test the fallback to remote

	// Mock remote lookup to succeed
	mr := new(mockRemote)
	fakeRemoteType := types.MediaType("application/vnd.oci.image.manifest.v1+json")
	mr.On("Get", mock.Anything, mock.Anything).Return(
		&remote.Descriptor{Descriptor: v1.Descriptor{MediaType: fakeRemoteType}},
		nil,
	)

	origRemoteGet := remoteGet
	defer func() { remoteGet = origRemoteGet }()
	remoteGet = func(ref name.Reference, opts ...remote.Option) (*remote.Descriptor, error) {
		return mr.Get(ref, opts...)
	}

	// This should fail locally (podman not available) but succeed with remote fallback
	mt, err := GetMediaType("alpine:latest", imageloader.Podman)
	require.NoError(t, err)
	require.Equal(t, string(fakeRemoteType), mt)
}

func TestLocalMediaType_NilDescriptor(t *testing.T) {
	md := new(mockDockerClient)
	md.On("ImageInspect", mock.Anything, "alpine:latest", mock.Anything).Return(
		dockerClient.ImageInspectResult{InspectResponse: mobyimage.InspectResponse{
			Descriptor: nil,
		}},
		nil,
	)

	origNewClient := newClient
	defer func() { newClient = origNewClient }()
	newClient = func() (dockerClient.APIClient, error) { return md, nil }

	// A nil descriptor (and no per-platform manifest entries) means the image
	// is present in the local daemon but no manifest-level media type metadata
	// is available. The lookup must succeed (found=true) with an empty media
	// type so GetMediaType can short-circuit the remote probe.
	mt, found, err := localMediaType(context.Background(), "alpine:latest")
	require.NoError(t, err)
	require.True(t, found)
	require.Empty(t, mt)
}

// TestLocalMediaType_ManifestsFallback covers single-arch images loaded via
// `docker load` on multi-platform (containerd) image stores: the top-level
// descriptor's media type is empty, but the per-platform manifest descriptor
// carries the manifest's true media type. The fallback must surface that real
// type so callers can detect format-family preservation (OCI vs Docker) without
// falling through to the synthetic docker-v2 default.
func TestLocalMediaType_ManifestsFallback(t *testing.T) {
	md := new(mockDockerClient)
	ociManifest := string(types.OCIManifestSchema1)
	md.On("ImageInspect", mock.Anything, "loaded-oci:latest", mock.Anything).Return(
		dockerClient.ImageInspectResult{InspectResponse: mobyimage.InspectResponse{
			Descriptor: &ocispec.Descriptor{}, // top-level MediaType empty
			Manifests: []mobyimage.ManifestSummary{
				{
					Kind: mobyimage.ManifestKindImage,
					Descriptor: ocispec.Descriptor{
						MediaType: ociManifest,
					},
				},
			},
		}},
		nil,
	)

	origNewClient := newClient
	defer func() { newClient = origNewClient }()
	newClient = func() (dockerClient.APIClient, error) { return md, nil }

	mt, found, err := localMediaType(context.Background(), "loaded-oci:latest")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, ociManifest, mt)
}

func TestRemoteMediaType_InvalidReference(t *testing.T) {
	// Test with invalid image reference
	_, err := remoteMediaType(context.Background(), "invalid::reference")
	require.Error(t, err)
}

// TestGetMediaType_LocalNilDescriptorSkipsRemote guards against a regression
// where a daemon-only image tagged against an unreachable registry hostname
// (e.g. "127.0.0.1:1/copa-daemon-only:original") would be inspected locally,
// return a nil descriptor, and then fall through to a remote registry probe —
// triggering a "connection refused" log. After the fix, a successful local
// inspect must be treated as authoritative even when descriptor metadata is
// absent, so no remote call is made.
func TestGetMediaType_LocalNilDescriptorSkipsRemote(t *testing.T) {
	md := new(mockDockerClient)
	md.On("ImageInspect", mock.Anything, "127.0.0.1:1/copa-daemon-only:original", mock.Anything).Return(
		dockerClient.ImageInspectResult{InspectResponse: mobyimage.InspectResponse{
			Descriptor: nil,
		}},
		nil,
	)

	origNewClient := newClient
	defer func() { newClient = origNewClient }()
	newClient = func() (dockerClient.APIClient, error) { return md, nil }

	origRemoteGet := remoteGet
	defer func() { remoteGet = origRemoteGet }()
	remoteGet = func(_ name.Reference, _ ...remote.Option) (*remote.Descriptor, error) {
		t.Fatalf("remoteGet must not be called when the image is present in the local daemon")
		return nil, nil
	}

	mt, err := GetMediaType("127.0.0.1:1/copa-daemon-only:original", imageloader.Docker)
	require.NoError(t, err)
	require.Equal(t, string(types.DockerManifestSchema2), mt)
}
