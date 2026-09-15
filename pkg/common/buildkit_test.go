package common

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/containerd/platforms"
	"github.com/moby/buildkit/client/llb"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/opencontainers/go-digest"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	fstypes "github.com/tonistiigi/fsutil/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/project-copacetic/copacetic/mocks"
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

func TestExtractOSReleaseFromStateEnforcesOneMiBLimit(t *testing.T) {
	ref := new(mocks.MockReference)
	ref.On("StatFile", mock.Anything, gwclient.StatRequest{Path: osReleasePath}).
		Return(&fstypes.Stat{Size: maxOSReleaseBytes + 1}, nil).
		Once()
	result := gwclient.NewResult()
	result.SetRef(ref)
	client := new(mocks.MockGWClient)
	client.On("Solve", mock.Anything, mock.Anything).Return(result, nil).Once()
	state := llb.Scratch()

	_, err := ExtractOSReleaseFromState(t.Context(), client, &state)
	require.ErrorContains(t, err, "maximum allowed size of 1048576 bytes")
	ref.AssertNotCalled(t, "ReadFile", mock.Anything, mock.Anything)
	client.AssertExpectations(t)
	ref.AssertExpectations(t)
}

func TestSetupBuildkitConfigAndManagerWithOptionsPreservesOSReleaseErrors(t *testing.T) {
	missingErr := &os.PathError{Op: "stat", Path: osReleasePath, Err: fs.ErrNotExist}
	tests := []struct {
		name      string
		stat      *fstypes.Stat
		statErr   error
		wantError string
		wantCause error
	}{
		{
			name:      "oversized",
			stat:      &fstypes.Stat{Size: maxOSReleaseBytes + 1},
			wantError: "maximum allowed size of 1048576 bytes",
		},
		{
			name:      "missing",
			statErr:   missingErr,
			wantError: "unable to extract /etc/os-release file from state",
			wantCause: fs.ErrNotExist,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			const image = "docker.io/example/os-release-test:latest"

			ref := new(mocks.MockReference)
			ref.On("StatFile", mock.Anything, gwclient.StatRequest{Path: osReleasePath}).
				Return(test.stat, test.statErr).
				Once()
			result := gwclient.NewResult()
			result.SetRef(ref)
			client := new(mocks.MockGWClient)
			client.On("ResolveImageConfig", mock.Anything, image, mock.Anything).
				Return(image, digest.FromString(image), []byte(`{"config":{}}`), nil).
				Twice()
			client.On("Solve", mock.Anything, mock.Anything).Return(result, nil).Once()

			_, _, err := SetupBuildkitConfigAndManagerWithOptions(
				t.Context(),
				client,
				image,
				nil,
				t.TempDir(),
				nil,
				pkgmgr.PackageManagerOptions{},
			)
			require.ErrorContains(t, err, test.wantError)
			if test.wantCause != nil {
				require.ErrorIs(t, err, test.wantCause)
			}
			ref.AssertNotCalled(t, "ReadFile", mock.Anything, mock.Anything)
			client.AssertExpectations(t)
			ref.AssertExpectations(t)
		})
	}
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

func TestAddImageConfigLabelsNormalizesLabelFieldCasing(t *testing.T) {
	const (
		updatedRelease = "ubuntu-24.04"
		updatedVersion = "v1.4.2"
	)

	tests := []struct {
		name       string
		input      string
		wantKey    string
		wantLabels map[string]string
	}{
		{
			name:    "uppercase only",
			input:   `{"config":{"Labels":{"existing":"uppercase","sh.copa.chisel.release":"stale"}}}`,
			wantKey: "Labels",
			wantLabels: map[string]string{
				"existing":                     "uppercase",
				pkgmgr.ChiselReleaseAnnotation: updatedRelease,
				pkgmgr.ChiselVersionAnnotation: updatedVersion,
			},
		},
		{
			name:    "lowercase only",
			input:   `{"config":{"labels":{"existing":"lowercase","sh.copa.chisel.release":"stale"}}}`,
			wantKey: "labels",
			wantLabels: map[string]string{
				"existing":                     "lowercase",
				pkgmgr.ChiselReleaseAnnotation: updatedRelease,
				pkgmgr.ChiselVersionAnnotation: updatedVersion,
			},
		},
		{
			name:    "uppercase before lowercase",
			input:   `{"config":{"Labels":{"existing":"uppercase"},"labels":{"existing":"lowercase","stale-only":"discard","sh.copa.chisel.release":"attacker"}}}`,
			wantKey: "Labels",
			wantLabels: map[string]string{
				"existing":                     "uppercase",
				pkgmgr.ChiselReleaseAnnotation: updatedRelease,
				pkgmgr.ChiselVersionAnnotation: updatedVersion,
			},
		},
		{
			name:    "lowercase before uppercase",
			input:   `{"config":{"labels":{"existing":"lowercase","stale-only":"discard","sh.copa.chisel.release":"attacker"},"Labels":{"existing":"uppercase"}}}`,
			wantKey: "Labels",
			wantLabels: map[string]string{
				"existing":                     "uppercase",
				pkgmgr.ChiselReleaseAnnotation: updatedRelease,
				pkgmgr.ChiselVersionAnnotation: updatedVersion,
			},
		},
		{
			name:    "canonical field discards other case variant",
			input:   `{"config":{"Labels":{"existing":"canonical"},"LABELS":{"stale-only":"discard","sh.copa.chisel.release":"attacker"}}}`,
			wantKey: "Labels",
			wantLabels: map[string]string{
				"existing":                     "canonical",
				pkgmgr.ChiselReleaseAnnotation: updatedRelease,
				pkgmgr.ChiselVersionAnnotation: updatedVersion,
			},
		},
		{
			name:    "single mixed-case field is preserved",
			input:   `{"config":{"lAbElS":{"existing":"mixed"}}}`,
			wantKey: "lAbElS",
			wantLabels: map[string]string{
				"existing":                     "mixed",
				pkgmgr.ChiselReleaseAnnotation: updatedRelease,
				pkgmgr.ChiselVersionAnnotation: updatedVersion,
			},
		},
		{
			name:    "uppercase null with lowercase duplicate",
			input:   `{"config":{"Labels":null,"labels":{"stale-only":"discard","sh.copa.chisel.release":"attacker"}}}`,
			wantKey: "Labels",
			wantLabels: map[string]string{
				pkgmgr.ChiselReleaseAnnotation: updatedRelease,
				pkgmgr.ChiselVersionAnnotation: updatedVersion,
			},
		},
		{
			name:    "lowercase null only",
			input:   `{"config":{"labels":null}}`,
			wantKey: "labels",
			wantLabels: map[string]string{
				pkgmgr.ChiselReleaseAnnotation: updatedRelease,
				pkgmgr.ChiselVersionAnnotation: updatedVersion,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			updated, err := AddImageConfigLabels([]byte(test.input), map[string]string{
				pkgmgr.ChiselReleaseAnnotation: updatedRelease,
				pkgmgr.ChiselVersionAnnotation: updatedVersion,
			})
			require.NoError(t, err)

			var rawImage map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(updated, &rawImage))
			var rawConfig map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(rawImage["config"], &rawConfig))

			require.Contains(t, rawConfig, test.wantKey)
			for key := range rawConfig {
				if strings.EqualFold(key, "labels") {
					assert.Equal(t, test.wantKey, key)
				}
			}

			var gotLabels map[string]string
			require.NoError(t, json.Unmarshal(rawConfig[test.wantKey], &gotLabels))
			assert.Equal(t, test.wantLabels, gotLabels)

			var image ocispecs.Image
			require.NoError(t, json.Unmarshal(updated, &image))
			assert.Equal(t, test.wantLabels, image.Config.Labels)
		})
	}
}

func TestAddImageConfigLabelsRejectsNullConfig(t *testing.T) {
	_, err := AddImageConfigLabels(
		[]byte(`{"config":null}`),
		map[string]string{pkgmgr.ChiselReleaseAnnotation: "ubuntu-24.04"},
	)
	require.EqualError(t, err, "image config does not contain an object-valued config field")
}

func TestAddImageConfigLabelsRejectsAmbiguousCaseVariants(t *testing.T) {
	_, err := AddImageConfigLabels(
		[]byte(`{"config":{"LABELS":{"first":"value"},"lAbElS":{"second":"value"}}}`),
		map[string]string{pkgmgr.ChiselReleaseAnnotation: "ubuntu-24.04"},
	)
	require.ErrorContains(t, err, "multiple case-insensitive labels fields")
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
	data    []byte
	readErr error
}

func (r *statePathTestReference) StatFile(context.Context, gwclient.StatRequest) (*fstypes.Stat, error) {
	return r.stat, r.statErr
}

func (r *statePathTestReference) ReadFile(context.Context, gwclient.ReadRequest) ([]byte, error) {
	return r.data, r.readErr
}

func TestTryExtractOSReleaseFromState(t *testing.T) {
	osRelease := []byte("ID=ubuntu\nVERSION_ID=20.04\n")
	tests := []struct {
		name      string
		ref       *statePathTestReference
		wantData  []byte
		wantExist bool
		wantError string
	}{
		{
			name:      "present",
			ref:       &statePathTestReference{stat: &fstypes.Stat{Size: int64(len(osRelease))}, data: osRelease},
			wantData:  osRelease,
			wantExist: true,
		},
		{
			name: "serialized BuildKit missing error",
			ref: &statePathTestReference{
				statErr: errors.New("failed to solve: lstat " + osReleasePath + ": no such file or directory"),
			},
		},
		{
			name:      "stat failure",
			ref:       &statePathTestReference{statErr: status.Error(codes.PermissionDenied, "denied")},
			wantError: "unable to stat",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := gwclient.NewResult()
			result.SetRef(test.ref)
			client := &statePathTestClient{result: result}
			state := llb.Scratch()

			data, exists, err := TryExtractOSReleaseFromState(t.Context(), client, &state)
			assert.Equal(t, test.wantData, data)
			assert.Equal(t, test.wantExist, exists)
			if test.wantError != "" {
				require.ErrorContains(t, err, test.wantError)
			} else {
				require.NoError(t, err)
			}
		})
	}
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
