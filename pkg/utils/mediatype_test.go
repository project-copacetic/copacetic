package utils

import (
	"context"
	"errors"
	"testing"

	"github.com/docker/docker/api/types/registry"
	dockerClient "github.com/docker/docker/client"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/moby/buildkit/client"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type mockDockerClient struct {
	mock.Mock
	dockerClient.APIClient
}

func (m *mockDockerClient) DistributionInspect(ctx context.Context, ref, encodedAuth string) (registry.DistributionInspect, error) {
	args := m.Called(ctx, ref, encodedAuth)
	di, _ := args.Get(0).(registry.DistributionInspect)
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
	md.On("DistributionInspect", mock.Anything, "alpine:latest", "").Return(
		registry.DistributionInspect{
			Descriptor: ocispec.Descriptor{
				MediaType: fakeMediaType,
			},
		},
		nil,
	)

	oc := newClient
	defer func() { newClient = oc }()
	newClient = func() (dockerClient.APIClient, error) {
		return md, nil
	}

	mt, err := localMediaType("alpine:latest")
	require.NoError(t, err)
	require.Equal(t, fakeMediaType, mt)
}

func TestLocalMediaTypeFailure(t *testing.T) {
	md := new(mockDockerClient)
	md.On("DistributionInspect", mock.Anything, "bad:tag", "").Return(
		registry.DistributionInspect{},
		errors.New("failed to inspect"),
	)

	oc := newClient
	defer func() { newClient = oc }()
	newClient = func() (dockerClient.APIClient, error) {
		return md, nil
	}

	mt, err := localMediaType("bad:tag")
	require.Error(t, err)
	require.Empty(t, mt)
}

func TestGetMediaType_LocalSuccess(t *testing.T) {
	md := new(mockDockerClient)
	fakeLocalType := "application/vnd.docker.distribution.manifest.v2+json"
	md.On("DistributionInspect", mock.Anything, "alpine:latest", "").Return(
		registry.DistributionInspect{
			Descriptor: ocispec.Descriptor{
				MediaType: fakeLocalType,
			},
		},
		nil,
	)

	oc := newClient
	defer func() { newClient = oc }()
	newClient = func() (dockerClient.APIClient, error) {
		return md, nil
	}

	mt, err := GetMediaType("alpine:latest")
	require.NoError(t, err)
	require.Equal(t, fakeLocalType, mt)
}

func TestGetMediaType_RemoteCall(t *testing.T) {
	md := new(mockDockerClient)
	md.On("DistributionInspect", mock.Anything, "alpine:latest", "").Return(
		registry.DistributionInspect{},
		errors.New("local lookup failed"),
	)

	oc := newClient
	defer func() { newClient = oc }()
	newClient = func() (dockerClient.APIClient, error) {
		return md, nil
	}

	mr := new(mockRemote)
	fakeRemoteType := types.MediaType("application/vnd.oci.image.config.v1+json")
	mr.On("Get", mock.Anything, mock.Anything).Return(
		&remote.Descriptor{
			Descriptor: v1.Descriptor{MediaType: fakeRemoteType},
		},
		nil,
	)

	or := remoteGet
	defer func() { remoteGet = or }()
	remoteGet = func(ref name.Reference, opts ...remote.Option) (*remote.Descriptor, error) {
		return mr.Get(ref, opts...)
	}

	mt, err := GetMediaType("alpine:latest")
	require.NoError(t, err)
	require.Equal(t, string(fakeRemoteType), mt)
}

func TestParseMediaType(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"oci image", "application/vnd.oci.image", client.ExporterOCI},
		{"docker distribution", "application/vnd.docker.distribution.manifest.v2+json", client.ExporterDocker},
		{"docker container image", "application/vnd.docker.container.image.v1+json", client.ExporterDocker},
		{"unknown", "application/vnd.unknown", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseMediaType(tt.input)
			if got != tt.want {
				t.Errorf("ParseMediaType(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
