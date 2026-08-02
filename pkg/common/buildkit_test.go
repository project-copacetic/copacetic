package common

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"testing"

	"github.com/containerd/platforms"
	"github.com/moby/buildkit/client/llb"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	fstypes "github.com/tonistiigi/fsutil/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/project-copacetic/copacetic/pkg/pkgmgr"
)

func TestGetDefaultLinuxPlatform(t *testing.T) {
	platform := GetDefaultLinuxPlatform()

	assert.Equal(t, LINUX, platform.OS)
	assert.NotEmpty(t, platform.Architecture)
}

func TestGetDefaultLinuxPlatform_NonLinux(t *testing.T) {
	// Save original platform
	originalPlatform := platforms.DefaultSpec()

	// Test that even with non-Linux default, we get Linux
	platform := GetDefaultLinuxPlatform()
	assert.Equal(t, LINUX, platform.OS)

	// Ensure we haven't modified the global default
	assert.Equal(t, originalPlatform, platforms.DefaultSpec())
}

// Test OSInfo struct initialization and validation.
func TestOSInfo_Initialization(t *testing.T) {
	osInfo := &OSInfo{
		Type:    "debian",
		Version: "11",
	}

	assert.Equal(t, "debian", osInfo.Type)
	assert.Equal(t, "11", osInfo.Version)
}

// Test OSInfo with different operating systems.
func TestOSInfo_DifferentOperatingSystems(t *testing.T) {
	testCases := []struct {
		name    string
		osType  string
		version string
	}{
		{"Debian", "debian", "11"},
		{"Ubuntu", "ubuntu", "20.04"},
		{"CentOS", "centos", "8"},
		{"Alpine", "alpine", "3.14"},
		{"RHEL", "rhel", "9"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			osInfo := &OSInfo{
				Type:    tc.osType,
				Version: tc.version,
			}
			assert.Equal(t, tc.osType, osInfo.Type)
			assert.Equal(t, tc.version, osInfo.Version)
		})
	}
}

// Test OSInfo with empty values.
func TestOSInfo_EmptyValues(t *testing.T) {
	osInfo := &OSInfo{}

	assert.Empty(t, osInfo.Type)
	assert.Empty(t, osInfo.Version)
}

// Test platform normalization for different architectures.
func TestGetDefaultLinuxPlatform_DifferentArchitectures(t *testing.T) {
	// This tests that the function consistently returns a Linux platform
	// regardless of the system's default
	platform := GetDefaultLinuxPlatform()

	assert.Equal(t, LINUX, platform.OS)
	// Verify that we get some valid architecture
	validArchs := []string{"amd64", "arm64", "arm", "386", "ppc64le", "s390x"}
	assert.Contains(t, validArchs, platform.Architecture)
}

// Test LINUX constant.
func TestLinuxConstant(t *testing.T) {
	assert.Equal(t, "linux", LINUX)
	assert.NotEmpty(t, LINUX)
}

func TestAddImageConfigLabels(t *testing.T) {
	input, err := json.Marshal(map[string]any{
		"architecture": "amd64",
		"config": map[string]any{
			"Labels": map[string]string{
				"existing":                     "preserved",
				pkgmgr.ChiselReleaseAnnotation: "old",
			},
		},
		"x-extra": map[string]any{"preserved": true},
	})
	require.NoError(t, err)

	updated, err := AddImageConfigLabels(input, map[string]string{
		pkgmgr.ChiselReleaseAnnotation: "ubuntu-24.04",
		pkgmgr.ChiselVersionAnnotation: "v1.4.2",
	})
	require.NoError(t, err)

	var image ocispecs.Image
	require.NoError(t, json.Unmarshal(updated, &image))
	assert.Equal(t, "preserved", image.Config.Labels["existing"])
	assert.Equal(t, "ubuntu-24.04", image.Config.Labels[pkgmgr.ChiselReleaseAnnotation])
	assert.Equal(t, "v1.4.2", image.Config.Labels[pkgmgr.ChiselVersionAnnotation])

	var raw map[string]any
	require.NoError(t, json.Unmarshal(updated, &raw))
	assert.Equal(t, map[string]any{"preserved": true}, raw["x-extra"])
}

type statePathTestClient struct {
	gwclient.Client
	result *gwclient.Result
	err    error
}

func (c *statePathTestClient) Solve(context.Context, gwclient.SolveRequest) (*gwclient.Result, error) {
	return c.result, c.err
}

type statePathTestReference struct {
	gwclient.Reference
	stat    *fstypes.Stat
	statErr error
}

func (r *statePathTestReference) StatFile(context.Context, gwclient.StatRequest) (*fstypes.Stat, error) {
	return r.stat, r.statErr
}

func TestStatePathExists(t *testing.T) {
	tests := []struct {
		name      string
		stat      *fstypes.Stat
		statErr   error
		exists    bool
		wantError bool
	}{
		{
			name:   "path exists",
			stat:   &fstypes.Stat{Path: pkgmgr.NativeChiselManifestPath},
			exists: true,
		},
		{
			name:    "gRPC path missing",
			statErr: status.Error(codes.NotFound, "missing"),
		},
		{
			name:    "filesystem path missing",
			statErr: &os.PathError{Op: "lstat", Path: pkgmgr.NativeChiselManifestPath, Err: fs.ErrNotExist},
		},
		{
			name:    "serialized BuildKit lstat missing",
			statErr: errors.New("failed to solve: lstat " + pkgmgr.NativeChiselManifestPath + ": no such file or directory"),
		},
		{
			name:      "stat failure",
			statErr:   status.Error(codes.PermissionDenied, "denied"),
			wantError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := gwclient.NewResult()
			result.SetRef(&statePathTestReference{stat: test.stat, statErr: test.statErr})
			client := &statePathTestClient{result: result}
			state := llb.Scratch()

			exists, err := StatePathExists(context.Background(), client, &state, nil, pkgmgr.NativeChiselManifestPath)
			assert.Equal(t, test.exists, exists)
			if test.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestStateFileExists(t *testing.T) {
	tests := []struct {
		name      string
		stat      *fstypes.Stat
		statErr   error
		exists    bool
		wantError string
	}{
		{
			name:   "regular file exists",
			stat:   &fstypes.Stat{Path: pkgmgr.NativeChiselManifestPath, Mode: 0o644},
			exists: true,
		},
		{
			name:      "directory is rejected",
			stat:      &fstypes.Stat{Path: pkgmgr.NativeChiselManifestPath, Mode: uint32(os.ModeDir | 0o755)},
			wantError: "not a regular file",
		},
		{
			name:    "missing file",
			statErr: &os.PathError{Op: "lstat", Path: pkgmgr.NativeChiselManifestPath, Err: fs.ErrNotExist},
		},
		{
			name:      "stat failure",
			statErr:   status.Error(codes.PermissionDenied, "denied"),
			wantError: "stat",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := gwclient.NewResult()
			result.SetRef(&statePathTestReference{stat: test.stat, statErr: test.statErr})
			client := &statePathTestClient{result: result}
			state := llb.Scratch()

			exists, err := StateFileExists(context.Background(), client, &state, nil, pkgmgr.NativeChiselManifestPath)
			assert.Equal(t, test.exists, exists)
			if test.wantError != "" {
				assert.ErrorContains(t, err, test.wantError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
