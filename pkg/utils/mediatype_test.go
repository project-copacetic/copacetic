package utils

import (
	"context"
	"errors"
	"testing"

	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/registry"
	dockerClient "github.com/docker/docker/client"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/project-copacetic/copacetic/pkg/imageloader"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type mockDockerClient struct {
	mock.Mock
	dockerClient.APIClient
}

func (m *mockDockerClient) ImageInspect(ctx context.Context, ref string, _ ...dockerClient.ImageInspectOption) (image.InspectResponse, error) {
	args := m.Called(ctx, ref)
	di, _ := args.Get(0).(image.InspectResponse)
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
	md.On("ImageInspect", mock.Anything, "alpine:latest", mock.Anything).Return().Return(
		image.InspectResponse{
			Descriptor: &ocispec.Descriptor{
				MediaType: fakeMediaType,
			},
		},
		nil,
	)

	origNewClient := newClient
	defer func() { newClient = origNewClient }()
	newClient = func() (dockerClient.APIClient, error) { return md, nil }

	mt, err := localMediaType("alpine:latest")
	require.NoError(t, err)
	require.Equal(t, fakeMediaType, mt)
}

func TestLocalMediaTypeFailure(t *testing.T) {
	md := new(mockDockerClient)
	md.On("ImageInspect", mock.Anything, "bad:tag", mock.Anything).Return(
		image.InspectResponse{},
		errors.New("failed to inspect"),
	)

	origNewClient := newClient
	defer func() { newClient = origNewClient }()
	newClient = func() (dockerClient.APIClient, error) { return md, nil }

	mt, err := localMediaType("bad:tag")
	require.Error(t, err)
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

	mt, err := remoteMediaType("alpine:latest")
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

	_, err := remoteMediaType("alpine:latest")
	require.Error(t, err)
}

func TestGetMediaType_LocalSuccess(t *testing.T) {
	md := new(mockDockerClient)
	fakeLocalType := "application/vnd.docker.distribution.manifest.v2+json"
	md.On("ImageInspect", mock.Anything, "alpine:latest", mock.Anything).Return(
		image.InspectResponse{
			Descriptor: &ocispec.Descriptor{
				MediaType: fakeLocalType,
			},
		},
		nil,
	)

	origNewClient := newClient
	defer func() { newClient = origNewClient }()
	newClient = func() (dockerClient.APIClient, error) { return md, nil }

	mt, err := GetMediaType("alpine:latest", imageloader.Docker)
	require.NoError(t, err)
	require.Equal(t, fakeLocalType, mt)
}

func TestGetMediaType_RemoteFallback(t *testing.T) {
	// Force local lookup to fail
	md := new(mockDockerClient)
	md.On("ImageInspect", mock.Anything, "alpine:latest", mock.Anything).Return(
		registry.DistributionInspect{},
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

	_, err := podmanMediaType("non-existent-image:test")
	require.Error(t, err)
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
		image.InspectResponse{
			Descriptor: nil, // Nil descriptor should return error
		},
		nil,
	)

	origNewClient := newClient
	defer func() { newClient = origNewClient }()
	newClient = func() (dockerClient.APIClient, error) { return md, nil }

	mt, err := localMediaType("alpine:latest")
	require.Error(t, err)
	require.Contains(t, err.Error(), "descriptor is nil")
	require.Empty(t, mt)
}

func TestRemoteMediaType_InvalidReference(t *testing.T) {
	// Test with invalid image reference
	_, err := remoteMediaType("invalid::reference")
	require.Error(t, err)
}
