package utils

import (
	"context"
	"errors"
	"testing"

	"github.com/moby/moby/api/types/system"
	dockerClient "github.com/moby/moby/client"
	"github.com/stretchr/testify/require"
)

type infoDockerClient struct {
	dockerClient.APIClient
	info system.Info
	err  error
}

func (c *infoDockerClient) Info(context.Context, dockerClient.InfoOptions) (dockerClient.SystemInfoResult, error) {
	return dockerClient.SystemInfoResult{Info: c.info}, c.err
}

func (c *infoDockerClient) Close() error { return nil }

func TestLocalImageStoreKeepsManifests(t *testing.T) {
	original := newClient
	t.Cleanup(func() { newClient = original })
	for _, tc := range []struct {
		name   string
		status [][2]string
		err    error
		want   bool
	}{
		// Docker with the containerd image store (CI custom-unix, Docker 29 default).
		{name: "containerd image store", status: [][2]string{{"driver-type", "io.containerd.snapshotter.v1"}}, want: true},
		// Docker's classic graph-driver store (overlay2/vfs) reports no driver-type.
		{name: "classic overlay2 store", status: [][2]string{{"Backing Filesystem", "extfs"}, {"Supports d_type", "true"}}},
		{name: "classic vfs store"},
		{name: "other driver type", status: [][2]string{{"driver-type", "io.containerd.snapshotter.v2"}}},
		{name: "info failure", err: errors.New("daemon unavailable")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			newClient = func() (dockerClient.APIClient, error) {
				return &infoDockerClient{info: system.Info{DriverStatus: tc.status}, err: tc.err}, nil
			}
			got, err := LocalImageStoreKeepsManifests(t.Context())
			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
				require.False(t, got)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}
