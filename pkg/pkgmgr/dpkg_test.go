package pkgmgr

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/moby/buildkit/client/llb"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/solver/pb"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/project-copacetic/copacetic/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	fstypes "github.com/tonistiigi/fsutil/types"

	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/utils"
)

func TestStateFileExistsUsesStatOnly(t *testing.T) {
	const path = "/var/lib/chisel/manifest.wall"
	tests := []struct {
		name      string
		stat      *fstypes.Stat
		statErr   error
		solveErr  error
		want      bool
		wantError string
	}{
		{name: "exists regardless of size", stat: &fstypes.Stat{Size: 1 << 40}, want: true},
		{name: "missing", stat: &fstypes.Stat{}, statErr: fs.ErrNotExist},
		{name: "stat failure", stat: &fstypes.Stat{}, statErr: errors.New("permission denied"), wantError: "stating"},
		{name: "solve failure is not absence", solveErr: errors.New("solve failed while mentioning manifest.wall"), wantError: "solving state"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := &mocks.MockGWClient{}
			if test.solveErr != nil {
				client.On("Solve", mock.Anything, mock.Anything).Return((*gwclient.Result)(nil), test.solveErr).Once()
			} else {
				ref := &mocks.MockReference{}
				ref.On("StatFile", mock.Anything, gwclient.StatRequest{Path: path}).Return(test.stat, test.statErr).Once()
				result := gwclient.NewResult()
				result.SetRef(ref)
				client.On("Solve", mock.Anything, mock.Anything).Return(result, nil).Once()
				defer ref.AssertNotCalled(t, "ReadFile", mock.Anything, mock.Anything)
			}

			state := llb.Scratch()
			got, err := stateFileExists(t.Context(), client, &state, path)
			if test.wantError != "" {
				require.ErrorContains(t, err, test.wantError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, test.want, got)
			}
			client.AssertExpectations(t)
		})
	}
}

func TestExternalDPKGPatchedStateAvoidsNestedMergeGraph(t *testing.T) {
	current := llb.Scratch().
		File(llb.Mkdir(dpkgLibPath, 0o755, llb.WithParents(true))).
		File(llb.Mkfile(dpkgStatusPath, 0o644, []byte("Package: base-files\nVersion: 1\n")))
	updated := current.File(llb.Mkfile(dpkgStatusPath, 0o644, []byte("Package: base-files\nVersion: 2\n")))

	state := externalDPKGPatchedState(&updated)
	def, err := state.Marshal(t.Context())
	require.NoError(t, err)

	mergeOps := 0
	diffOps := 0
	for _, raw := range def.Def {
		var op pb.Op
		require.NoError(t, op.Unmarshal(raw))
		if op.GetMerge() != nil {
			mergeOps++
		}
		if op.GetDiff() != nil {
			diffOps++
		}
	}

	assert.Zero(t, mergeOps, "external dpkg output must remain a linear state so an exported image can be used as the next BuildKit source")
	assert.Zero(t, diffOps, "the updated mount already contains the complete current filesystem")
}

func TestDPKGInstallationModeString(t *testing.T) {
	tests := []struct {
		name string
		mode dpkgInstallationMode
		want string
	}{
		{name: "unknown", mode: dpkgInstallationModeUnknown, want: "unknown"},
		{name: "target tools", mode: dpkgInstallationModeTargetTools, want: "target-dpkg-tools"},
		{name: "external full status", mode: dpkgInstallationModeExternalFullStatus, want: "external-full-status"},
		{name: "external status directory", mode: dpkgInstallationModeExternalStatusDirectory, want: "external-status-directory"},
		{name: "native Chisel", mode: dpkgInstallationModeNativeChisel, want: "native-chisel"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.mode.String())
		})
	}
}

func TestClassifyDPKGInstallationMode(t *testing.T) {
	tests := []struct {
		name        string
		probe       dpkgProbeResult
		want        dpkgInstallationMode
		wantErr     bool
		errContains []string
	}{
		{
			name: "native manifest wins over full status and tools",
			probe: dpkgProbeResult{
				hasManifest: true,
				hasStatus:   true,
			},
			want: dpkgInstallationModeNativeChisel,
		},
		{
			name: "native manifest wins over every other format",
			probe: dpkgProbeResult{
				hasManifest:        true,
				hasStatus:          true,
				hasStatusDirectory: true,
				missingTools:       []string{"apt-get", "sh"},
			},
			want: dpkgInstallationModeNativeChisel,
		},
		{
			name: "full status with all tools uses target",
			probe: dpkgProbeResult{
				hasStatus: true,
			},
			want: dpkgInstallationModeTargetTools,
		},
		{
			name: "full status with tools wins over status directory",
			probe: dpkgProbeResult{
				hasStatus:          true,
				hasStatusDirectory: true,
			},
			want: dpkgInstallationModeTargetTools,
		},
		{
			name: "full status missing any tool uses external tooling",
			probe: dpkgProbeResult{
				hasStatus:    true,
				missingTools: []string{"tee"},
			},
			want: dpkgInstallationModeExternalFullStatus,
		},
		{
			name: "full status missing tools wins over status directory",
			probe: dpkgProbeResult{
				hasStatus:          true,
				hasStatusDirectory: true,
				missingTools:       []string{"apt-get", "dpkg"},
			},
			want: dpkgInstallationModeExternalFullStatus,
		},
		{
			name: "status directory uses external tooling",
			probe: dpkgProbeResult{
				hasStatusDirectory: true,
			},
			want: dpkgInstallationModeExternalStatusDirectory,
		},
		{
			name:        "unsupported metadata names every checked path",
			want:        dpkgInstallationModeUnknown,
			wantErr:     true,
			errContains: []string{chiselManifestPath, dpkgStatusPath, dpkgStatusFolder},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := classifyDPKGInstallationMode(tt.probe)
			assert.Equal(t, tt.want, got)
			if tt.wantErr {
				assert.Error(t, err)
				for _, expected := range tt.errContains {
					assert.ErrorContains(t, err, expected)
				}
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestIsValidDebianVersion(t *testing.T) {
	type args struct {
		v string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"valid version", args{"1.0"}, true},
		{"invalid version", args{"a.b"}, false},
		{"valid version with suffix", args{"1.0-r0"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidDebianVersion(tt.args.v); got != tt.want {
				t.Errorf("isValidDebianVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDebianVersionOrdering(t *testing.T) {
	tests := []struct {
		name  string
		older string
		newer string
	}{
		{name: "revision", older: "1.0-1", newer: "1.0-2"},
		{name: "tilde sorts before release", older: "1.0~rc1-1", newer: "1.0-1"},
		{name: "epoch", older: "1:99.0-1", newer: "2:1.0-1"},
		{name: "Ubuntu revision", older: "2.39-0ubuntu8.4", newer: "2.39-0ubuntu8.5"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.True(t, isLessThanDebianVersion(tt.older, tt.newer))
			assert.False(t, isLessThanDebianVersion(tt.newer, tt.older))
			assert.False(t, isLessThanDebianVersion(tt.older, tt.older))
		})
	}
}

func TestMarshalDPKGPackageVersions(t *testing.T) {
	data, err := marshalDPKGPackageVersions(map[string]string{
		"zlib1g:amd64":     "1:1.3.dfsg+really1.3.1-1ubuntu1",
		"base-files:amd64": "13ubuntu10.2",
	}, map[string]struct{}{"zlib1g:amd64": {}})
	assert.NoError(t, err)
	assert.Equal(t, "base-files:amd64|13ubuntu10.2|install\nzlib1g:amd64|1:1.3.dfsg+really1.3.1-1ubuntu1|hold\n", string(data))

	_, err = marshalDPKGPackageVersions(map[string]string{"bad;touch": "1.0"}, nil)
	assert.ErrorContains(t, err, "invalid package name")

	_, err = marshalDPKGPackageVersions(map[string]string{"base-files": "$(touch /tmp/pwned)"}, nil)
	assert.ErrorContains(t, err, "invalid installed version")
}

func TestMarshalDPKGVersionFloorsProtectsDependencyClosure(t *testing.T) {
	const (
		appFixedVersion          = "2.0"
		dependencyCurrentVersion = "3.0"
	)

	data, err := marshalDPKGVersionFloors(
		unversioned.UpdatePackages{{Name: "app", FixedVersion: appFixedVersion}},
		map[string]string{
			"app:amd64":                 "1.0",
			"app:i386":                  "0.9",
			"existing-dependency:amd64": dependencyCurrentVersion,
		},
	)
	require.NoError(t, err)
	assert.Equal(t, "app:amd64|1.0|"+appFixedVersion+"\napp:i386|0.9|"+appFixedVersion+"\nexisting-dependency:amd64|"+dependencyCurrentVersion+"|\n", string(data))

	packages, err := marshalDPKGUpdatePackageNames(
		unversioned.UpdatePackages{{Name: "app"}},
		map[string]string{"app:amd64": "1.0", "app:i386": "0.9"},
	)
	require.NoError(t, err)
	assert.Equal(t, "app:amd64\napp:i386\n", string(packages))

	_, err = marshalDPKGUpdatePackageNames(
		unversioned.UpdatePackages{{Name: "missing"}},
		map[string]string{"app:amd64": "1.0"},
	)
	require.ErrorContains(t, err, "is not installed in the target dpkg inventory")
}

func TestGetAPTImageName(t *testing.T) {
	tests := []struct {
		name           string
		osType         string
		osVersion      string
		useCachePrefix bool
		want           string
	}{
		{
			name:           "no-report Ubuntu uses detected Ubuntu release",
			osType:         utils.OSTypeUbuntu,
			osVersion:      "24.04",
			useCachePrefix: true,
			want:           "ghcr.io/project-copacetic/copacetic/ubuntu:24.04",
		},
		{
			name:           "Debian point release uses major slim tag",
			osType:         utils.OSTypeDebian,
			osVersion:      "11.1",
			useCachePrefix: true,
			want:           "ghcr.io/project-copacetic/copacetic/debian:11-slim",
		},
		{
			name:      "newer Debian uses stable slim",
			osType:    utils.OSTypeDebian,
			osVersion: "13",
			want:      "debian:stable-slim",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, getAPTImageName(tt.osType, tt.osVersion, tt.useCachePrefix))
		})
	}
}

func TestParseDPKGProbeResult(t *testing.T) {
	got, err := parseDPKGProbeResult([]byte("manifest=0\nstatus=1\nstatus_directory=1\nmissing_tools=apt-get tee\n"))
	assert.NoError(t, err)
	assert.Equal(t, dpkgProbeResult{
		hasStatus:          true,
		hasStatusDirectory: true,
		missingTools:       []string{"apt-get", "tee"},
	}, got)

	_, err = parseDPKGProbeResult([]byte("manifest=maybe\nstatus=1\nstatus_directory=0\nmissing_tools=\n"))
	assert.ErrorContains(t, err, "invalid value")
}

func TestLoadFullStatusRejectsOversizedMetadata(t *testing.T) {
	ref := &mocks.MockReference{}
	ref.On("StatFile", mock.Anything, gwclient.StatRequest{Path: dpkgStatusOutputFilename}).
		Return(&fstypes.Stat{Size: maxDPKGStatusBytes + 1}, nil).
		Once()

	result := gwclient.NewResult()
	result.SetRef(ref)
	client := &mocks.MockGWClient{}
	client.On("Solve", mock.Anything, mock.Anything).Return(result, nil).Once()

	dm := &dpkgManager{config: &buildkit.Config{Client: client}}
	state := llb.Scratch()
	_, err := dm.loadFullStatus(t.Context(), &state)
	require.Error(t, err)
	assert.ErrorContains(t, err, dpkgStatusPath)
	assert.ErrorContains(t, err, fmt.Sprintf("maximum size of %d bytes", maxDPKGStatusBytes))
	assert.ErrorContains(t, err, fmt.Sprintf("exceeding the maximum allowed size of %d bytes", maxDPKGStatusBytes))

	client.AssertExpectations(t)
	ref.AssertExpectations(t)
	ref.AssertNotCalled(t, "ReadFile", mock.Anything, mock.Anything)
}

func TestLoadStatusDirectoryRejectsOversizedPackageList(t *testing.T) {
	const maxBytes int64 = 8

	ref := &mocks.MockReference{}
	ref.On("StatFile", mock.Anything, gwclient.StatRequest{Path: dpkgStatusdListFilename}).
		Return(&fstypes.Stat{Size: maxBytes + 1}, nil).
		Once()

	result := gwclient.NewResult()
	result.SetRef(ref)
	client := &mocks.MockGWClient{}
	client.On("Solve", mock.Anything, mock.Anything).Return(result, nil).Once()

	dm := &dpkgManager{config: &buildkit.Config{Client: client}}
	state := llb.Scratch()
	err := dm.loadStatusDirectoryWithLimit(t.Context(), &state, maxBytes)
	require.Error(t, err)
	assert.ErrorContains(t, err, dpkgStatusFolder)
	assert.ErrorContains(t, err, fmt.Sprintf("aggregate maximum of %d bytes", maxBytes))
	assert.ErrorContains(t, err, fmt.Sprintf("exceeding the maximum allowed size of %d bytes", maxBytes))

	client.AssertExpectations(t)
	ref.AssertExpectations(t)
	ref.AssertNotCalled(t, "ReadFile", mock.Anything, mock.Anything)
}

func TestLoadStatusDirectoryEnforcesAggregateSizeLimit(t *testing.T) {
	const maxBytes int64 = 64

	statusdNames := []byte("first\nsecond\n")
	firstStatus := []byte("Package: first\nVersion: 1\n")
	remainingBytes := maxBytes - int64(len(statusdNames)) - int64(len(firstStatus))
	require.Positive(t, remainingBytes)

	firstPath := filepath.Join(dpkgStatusdFilesFolder, "first")
	secondPath := filepath.Join(dpkgStatusdFilesFolder, "second")
	ref := &mocks.MockReference{}
	ref.On("StatFile", mock.Anything, gwclient.StatRequest{Path: dpkgStatusdListFilename}).
		Return(&fstypes.Stat{Size: int64(len(statusdNames))}, nil).
		Once()
	ref.On("ReadFile", mock.Anything, gwclient.ReadRequest{
		Filename: dpkgStatusdListFilename,
		Range:    &gwclient.FileRange{Offset: 0, Length: len(statusdNames)},
	}).Return(statusdNames, nil).Once()
	ref.On("StatFile", mock.Anything, gwclient.StatRequest{Path: firstPath}).
		Return(&fstypes.Stat{Size: int64(len(firstStatus))}, nil).
		Once()
	ref.On("ReadFile", mock.Anything, gwclient.ReadRequest{
		Filename: firstPath,
		Range:    &gwclient.FileRange{Offset: 0, Length: len(firstStatus)},
	}).Return(firstStatus, nil).Once()
	ref.On("StatFile", mock.Anything, gwclient.StatRequest{Path: secondPath}).
		Return(&fstypes.Stat{Size: remainingBytes + 1}, nil).
		Once()

	result := gwclient.NewResult()
	result.SetRef(ref)
	client := &mocks.MockGWClient{}
	client.On("Solve", mock.Anything, mock.Anything).Return(result, nil).Times(3)

	dm := &dpkgManager{config: &buildkit.Config{Client: client}}
	state := llb.Scratch()
	err := dm.loadStatusDirectoryWithLimit(t.Context(), &state, maxBytes)
	require.Error(t, err)
	assert.ErrorContains(t, err, filepath.Join(dpkgStatusFolder, "second"))
	assert.ErrorContains(t, err, fmt.Sprintf("with %d of %d aggregate bytes remaining", remainingBytes, maxBytes))
	assert.ErrorContains(t, err, fmt.Sprintf("exceeding the maximum allowed size of %d bytes", remainingBytes))

	client.AssertExpectations(t)
	ref.AssertExpectations(t)
	ref.AssertNotCalled(t, "ReadFile", mock.Anything, mock.MatchedBy(func(req gwclient.ReadRequest) bool {
		return req.Filename == secondPath
	}))
}

var (
	//go:embed testdata/dpkg_valid.txt
	validDPKGManifest []byte

	// initialized to `nil`; tests error handling.
	nonExistingManifest []byte

	//go:embed testdata/empty.txt
	emptyManifest []byte

	//go:embed testdata/invalid.txt
	invalidDPKGManifest []byte

	//go:embed testdata/dpkg_full_status.txt
	fullDPKGStatus []byte
)

func TestParseDPKGStatus(t *testing.T) {
	input := bytes.Clone(fullDPKGStatus)
	parsed, err := parseDPKGStatus(input)
	assert.NoError(t, err)
	assert.Equal(t, map[string]string{
		"base-files:amd64": "13ubuntu10.2",
		"libc6:amd64":      "2.39-0ubuntu8.5",
		"tzdata:all":       "2025b-0ubuntu0.24.04.1",
	}, parsed.packages)
	assert.Equal(t, map[string]struct{}{"tzdata:all": {}}, parsed.heldPackages)
	assert.Equal(t, fullDPKGStatus, parsed.contents)
	assert.Contains(t, string(parsed.databaseContents), "Status: install ok installed")

	// The retained status must not alias the extraction buffer because it is
	// used later to reconstruct the temporary dpkg database verbatim.
	input[0] = 'X'
	assert.Equal(t, fullDPKGStatus, parsed.contents)
}

func TestParseDPKGStatusExcludesRemovedPackages(t *testing.T) {
	status := []byte("Package: installed\nStatus: install ok installed\nVersion: 1.0\n\nPackage: removed\nStatus: deinstall ok config-files\nVersion: 2.0\n")
	parsed, err := parseDPKGStatus(status)
	assert.NoError(t, err)
	assert.Equal(t, map[string]string{"installed": "1.0"}, parsed.packages)
	assert.Equal(t, status, parsed.contents)
}

func TestParseDPKGStatusAllowsNotInstalledPackageWithoutVersion(t *testing.T) {
	status := []byte("Package: installed\nStatus: install ok installed\nVersion: 1.0\n\nPackage: gnupg\nStatus: purge ok not-installed\n")
	parsed, err := parseDPKGStatus(status)
	assert.NoError(t, err)
	assert.Equal(t, map[string]string{"installed": "1.0"}, parsed.packages)
	assert.Empty(t, parsed.heldPackages)
	assert.Equal(t, status, parsed.contents)
}

func TestParseDPKGStatusAcceptsInventoryWithoutStatusFields(t *testing.T) {
	status := []byte("Package: base-files\nVersion: 13ubuntu10.2\nArchitecture: amd64\n\nPackage: libc6\nVersion: 2.39-0ubuntu8.4\nArchitecture: amd64\n")
	parsed, err := parseDPKGStatus(status)
	assert.NoError(t, err)
	assert.Equal(t, map[string]string{
		"base-files:amd64": "13ubuntu10.2",
		"libc6:amd64":      "2.39-0ubuntu8.4",
	}, parsed.packages)
	assert.Equal(t, status, parsed.contents)
	expectedDatabase := strings.Join([]string{
		"Package: base-files",
		"Status: install ok installed",
		"Version: 13ubuntu10.2",
		"Architecture: amd64",
		"",
		"Package: libc6",
		"Status: install ok installed",
		"Version: 2.39-0ubuntu8.4",
		"Architecture: amd64",
		"",
		"",
	}, "\n")
	assert.Equal(t, expectedDatabase, string(parsed.databaseContents))
}

func TestFilterDPKGStatusDependenciesPreservesInstalledRelationships(t *testing.T) {
	status := []byte(strings.Join([]string{
		"Package: app",
		"Version: 1.0",
		"Architecture: amd64",
		"Depends: libfoo (= 1.0),",
		" missing-a | missing-b",
		"",
		"Package: libfoo",
		"Version: 1.0",
		"Architecture: amd64",
		"",
		"Package: provider",
		"Version: 1.0",
		"Architecture: amd64",
		"Provides: virtual-feature (= 1.0)",
		"",
		"Package: consumer",
		"Version: 1.0",
		"Architecture: amd64",
		"Pre-Depends: virtual-feature, missing-c",
		"",
	}, "\n"))
	installed := map[string]string{
		"app:amd64":      "1.0",
		"libfoo:amd64":   "1.0",
		"provider:amd64": "1.0",
		"consumer:amd64": "1.0",
	}

	filtered, err := filterDPKGStatusDependencies(status, installed, "amd64")
	require.NoError(t, err)
	text := string(filtered)
	assert.Contains(t, text, "Depends: libfoo (= 1.0)\n")
	assert.NotContains(t, text, "missing-a")
	assert.NotContains(t, text, "missing-b")
	assert.Contains(t, text, "Pre-Depends: virtual-feature\n")
	assert.NotContains(t, text, "missing-c")
}

func TestFilterDPKGStatusDependenciesDropsUnsatisfiedVersion(t *testing.T) {
	status := []byte(strings.Join([]string{
		"Package: app", "Version: 1.0", "Architecture: amd64", "Depends: libfoo (>= 2.0)", "",
		"Package: libfoo", "Version: 1.0", "Architecture: amd64", "",
	}, "\n"))
	filtered, err := filterDPKGStatusDependencies(
		status, map[string]string{"app:amd64": "1.0", "libfoo:amd64": "1.0"}, "amd64",
	)
	require.NoError(t, err)
	assert.NotContains(t, string(filtered), "Depends: libfoo")
}

func TestFilterDPKGStatusDependenciesRejectsMalformedRelationship(t *testing.T) {
	status := []byte("Package: app\nVersion: 1.0\nArchitecture: amd64\nDepends: libfoo (>= 1.0\n")
	_, err := filterDPKGStatusDependencies(status, map[string]string{"app:amd64": "1.0", "libfoo:amd64": "1.0"}, "amd64")
	require.ErrorContains(t, err, "unbalanced relationship delimiters")
}

func TestParseDPKGStatusRetainsSameNameMultiarchInstances(t *testing.T) {
	status := []byte("Package: libc6\nStatus: install ok installed\nVersion: 2.35-1\nArchitecture: amd64\n\nPackage: libc6\nStatus: hold ok installed\nVersion: 2.35-2\nArchitecture: i386\n")
	parsed, err := parseDPKGStatus(status)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{
		"libc6:amd64": "2.35-1",
		"libc6:i386":  "2.35-2",
	}, parsed.packages)
	assert.Equal(t, map[string]struct{}{"libc6:i386": {}}, parsed.heldPackages)
}

func TestForeignDPKGArchitectures(t *testing.T) {
	tests := []struct {
		name      string
		platform  *ocispecs.Platform
		packages  map[string]string
		want      []string
		wantError string
	}{
		{
			name:     "native and architecture independent packages",
			platform: &ocispecs.Platform{OS: "linux", Architecture: "amd64"},
			packages: map[string]string{"libc6:amd64": "1", "tzdata:all": "1"},
			want:     []string{},
		},
		{
			name:     "sorted foreign architectures",
			platform: &ocispecs.Platform{OS: "linux", Architecture: "amd64"},
			packages: map[string]string{"libc6:i386": "1", "libc6:arm64": "1", "base-files:amd64": "1"},
			want:     []string{"arm64", "i386"},
		},
		{
			name:      "unsupported target architecture",
			platform:  &ocispecs.Platform{OS: "linux", Architecture: "mips64"},
			packages:  map[string]string{"base-files:mips64": "1"},
			wantError: "unsupported target architecture",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := foreignDPKGArchitectures(tt.packages, tt.platform)
			if tt.wantError != "" {
				require.ErrorContains(t, err, tt.wantError)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestNormalizeParsedDPKGArchitectures(t *testing.T) {
	parsed, err := parseDPKGStatus([]byte("Package: libc6\nVersion: 2.35-1\n"))
	require.NoError(t, err)
	normalized, err := normalizeParsedDPKGArchitectures(parsed, "amd64")
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"libc6:amd64": "2.35-1"}, normalized.packages)
}

func TestParseDPKGStatusErrors(t *testing.T) {
	tests := []struct {
		name    string
		status  string
		wantErr string
	}{
		{name: "empty", status: "", wantErr: "no package paragraphs"},
		{name: "missing package", status: "Status: install ok installed\nVersion: 1.0\n", wantErr: "no Package field"},
		{name: "missing version", status: "Package: base-files\nStatus: install ok installed\n", wantErr: "no Version field"},
		{name: "invalid package", status: "Package: -option\nStatus: install ok installed\nVersion: 1.0\n", wantErr: "invalid package name"},
		{name: "invalid version", status: "Package: base-files\nStatus: install ok installed\nVersion: invalid version\n", wantErr: "invalid version"},
		{name: "invalid status", status: "Package: base-files\nStatus: installed\nVersion: 1.0\n", wantErr: "invalid status"},
		{name: "invalid architecture any", status: "Package: base-files\nVersion: 1.0\nArchitecture: any\n", wantErr: "invalid architecture"},
		{name: "invalid architecture native", status: "Package: base-files\nVersion: 1.0\nArchitecture: native\n", wantErr: "invalid architecture"},
		{name: "malformed field", status: "Package: base-files\nStatus: install ok installed\nnot-a-field\nVersion: 1.0\n", wantErr: "malformed field"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseDPKGStatus([]byte(tt.status))
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestParseDPKGStatusAcceptsCRLFAndNoFinalNewline(t *testing.T) {
	status := []byte("Package: base-files\r\nStatus: install ok installed\r\nVersion: 1.0")
	parsed, err := parseDPKGStatus(status)
	assert.NoError(t, err)
	assert.Equal(t, map[string]string{"base-files": "1.0"}, parsed.packages)
	assert.Equal(t, status, parsed.contents)
}

func executeEmbeddedShellScript(t *testing.T, script []byte, env map[string]string) ([]byte, error) {
	t.Helper()

	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh is required for script tests")
	}
	scriptPath := filepath.Join(t.TempDir(), "script.sh")
	require.NoError(t, os.WriteFile(scriptPath, script, 0o600))
	require.NoError(t, os.Chmod(scriptPath, 0o700))

	cmd := exec.Command(sh, scriptPath)
	cmd.Env = os.Environ()
	for key, value := range env {
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	return cmd.CombinedOutput()
}

func runEmbeddedShellScript(t *testing.T, script []byte, env map[string]string) []byte {
	t.Helper()

	output, err := executeEmbeddedShellScript(t, script, env)
	if !assert.NoError(t, err, "script output: %s", output) {
		t.FailNow()
	}
	return output
}

func writeTestExecutable(t *testing.T, dir, name, contents string) string {
	t.Helper()

	path := filepath.Join(dir, name)
	assert.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
	assert.NoError(t, os.Chmod(path, 0o700))
	return path
}

func assertFileContent(t *testing.T, path, expected string) {
	t.Helper()
	contents, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, expected, string(contents))
}

func TestSelectDPKGUpdatesScriptOnlySelectsStrictlyNewerCandidates(t *testing.T) {
	binDir := t.TempDir()
	workDir := t.TempDir()
	installedPath := filepath.Join(workDir, "installed-packages")
	packagesPath := filepath.Join(workDir, "packages.txt")
	markerPath := filepath.Join(workDir, "updates.txt")
	compareLog := filepath.Join(workDir, "compare.log")

	installedData, err := marshalDPKGPackageVersions(map[string]string{
		"epoch":   "1:99.0-1",
		"equal":   "1.0-1",
		"held":    "1.0-1",
		"missing": "1.0-1",
		"newer":   "1.0~rc1-1",
		"older":   "2.0-1",
	}, map[string]struct{}{"held": {}})
	assert.NoError(t, err)
	assert.NoError(t, os.WriteFile(installedPath, installedData, 0o600))

	writeTestExecutable(t, binDir, "apt-cache", `#!/bin/sh
case "$2" in
    epoch) candidate='2:1.0-1' ;;
    equal) candidate='1.0-1' ;;
    missing) candidate='(none)' ;;
    newer) candidate='1.0-1' ;;
    older) candidate='1.9-1' ;;
    *) exit 2 ;;
esac
printf '  Candidate: %s\n' "$candidate"
`)
	writeTestExecutable(t, binDir, "dpkg", `#!/bin/sh
printf '%s|%s|%s\n' "$2" "$3" "$4" >> "$COMPARE_LOG"
case "$2|$3|$4" in
    '2:1.0-1|gt|1:99.0-1'|'1.0-1|gt|1.0~rc1-1') exit 0 ;;
    '1.0-1|gt|1.0-1'|'1.9-1|gt|2.0-1') exit 1 ;;
    *) exit 2 ;;
esac
`)

	runEmbeddedShellScript(t, selectDPKGUpdatesScript, map[string]string{
		"PATH":                    binDir + string(os.PathListSeparator) + os.Getenv("PATH"),
		"COMPARE_LOG":             compareLog,
		"INSTALLED_PACKAGES_FILE": installedPath,
		"UPDATE_PACKAGES_FILE":    packagesPath,
		"UPDATES_MARKER_FILE":     markerPath,
	})

	selected, err := os.ReadFile(packagesPath)
	assert.NoError(t, err)
	assert.Equal(t, "epoch\nnewer\n", string(selected))
	assert.FileExists(t, markerPath)

	comparisons, err := os.ReadFile(compareLog)
	assert.NoError(t, err)
	assert.Equal(t, strings.Join([]string{
		"2:1.0-1|gt|1:99.0-1",
		"1.0-1|gt|1.0-1",
		"1.0-1|gt|1.0~rc1-1",
		"1.9-1|gt|2.0-1",
	}, "\n")+"\n", string(comparisons))
}

func TestAptGetDownloadScriptResolvesClosureAndSkipsUnsafeVersions(t *testing.T) {
	binDir := t.TempDir()
	workDir := t.TempDir()
	downloadDir := filepath.Join(workDir, "downloads")
	dpkgRoot := filepath.Join(workDir, "rootfs")
	packagesPath := filepath.Join(workDir, "packages.txt")
	floorsPath := filepath.Join(workDir, "version-floors")
	finalizePath := filepath.Join(workDir, "finalize_dpkg_status.sh")
	resolverPath := filepath.Join(downloadDir, "resolver-status")
	aptLog := filepath.Join(workDir, "apt.log")
	installLog := filepath.Join(workDir, "install.log")

	require.NoError(t, os.MkdirAll(filepath.Join(dpkgRoot, "var", "lib", "dpkg", "info"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(dpkgRoot, "bin"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(dpkgRoot, "usr", "bin"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(dpkgRoot, "app"), 0o755))
	statusWithDependencies := append(bytes.Clone(fullDPKGStatus), []byte(strings.Join([]string{
		"",
		"Package: tightened-dependency",
		"Status: install ok installed",
		"Version: 1.0",
		"Architecture: amd64",
	}, "\n"))...)
	require.NoError(t, os.WriteFile(filepath.Join(dpkgRoot, "var", "lib", "dpkg", "status"), statusWithDependencies, 0o600))
	writeDPKGResolverStatusTestFile(t, resolverPath, statusWithDependencies)
	writeTestExecutable(t, filepath.Join(dpkgRoot, "bin"), "sh", "application-owned-shell")
	writeTestExecutable(t, filepath.Join(dpkgRoot, "usr", "bin"), "apt-get", "application-owned-apt")
	writeTestExecutable(t, filepath.Join(dpkgRoot, "usr", "bin"), "dpkg", "application-owned-dpkg")
	require.NoError(t, os.WriteFile(filepath.Join(dpkgRoot, "app", "sentinel"), []byte("preserve"), 0o600))
	require.NoError(t, os.WriteFile(packagesPath, []byte("safe\ndowngrade\nbelow-fixed\n"), 0o600))
	require.NoError(t, os.WriteFile(floorsPath, []byte(strings.Join([]string{
		"base-files:amd64|13ubuntu10.2|",
		"libc6:amd64|2.39-0ubuntu8.5|",
		"tzdata:all|2025b-0ubuntu0.24.04.1|",
		"below-fixed|1.0|3.0",
		"downgrade|3.0|2.0",
		"safe|1.0|2.0",
		"tightened-dependency:amd64|1.0|",
		"",
	}, "\n")), 0o600))
	require.NoError(t, os.WriteFile(finalizePath, finalizeDPKGStatusScript, 0o600))
	require.NoError(t, os.Chmod(finalizePath, 0o700))

	writeTestExecutable(t, binDir, "apt-get", `#!/bin/sh
printf '%s\n' "$*" >> "$APT_LOG"
command=''
after_separator=false
for arg in "$@"; do
    case "$arg" in
        update|download|install) command=$arg ;;
        --) after_separator=true ;;
        *)
            if [ "$command" = install ] && [ "$after_separator" = true ]; then
                : > "$DOWNLOAD_DIR/$arg.deb"
            fi
            ;;
    esac
done
case "$command" in
    update) exit 0 ;;
    download)
        echo 'external full-status updates must use apt-get install --download-only' >&2
        exit 90
        ;;
    install)
        case " $* " in
            *" -o Dir::State::status=$DOWNLOAD_DIR/resolver-status "*) ;;
            *) echo 'missing resolver status option' >&2; exit 91 ;;
        esac
        case " $* " in
            *" -o Dir::Cache::archives=$DOWNLOAD_DIR "*) ;;
            *) echo 'missing archive directory option' >&2; exit 92 ;;
        esac
        case " $* " in *" --download-only "*) ;; *) echo 'missing --download-only' >&2; exit 93 ;; esac
        case " $* " in *" --fix-broken "*) echo 'must not repair unrelated installed dependencies' >&2; exit 94 ;; esac
        case " $* " in *" --no-install-recommends "*) ;; *) echo 'missing --no-install-recommends' >&2; exit 95 ;; esac
        case " $* " in *" install -- safe downgrade below-fixed "*) ;; *) echo "unexpected selected packages: $*" >&2; exit 96 ;; esac
        grep -q '^Status: hold ok installed$' "$DPKG_ROOT/var/lib/dpkg/status"
        ! grep -q '^Depends:' "$DOWNLOAD_DIR/resolver-status"
        : > "$DOWNLOAD_DIR/new-dependency.deb"
        : > "$DOWNLOAD_DIR/tightened-dependency.deb"
        ;;
    *) echo "unexpected apt-get command: $*" >&2; exit 94 ;;
esac
`)
	writeTestExecutable(t, binDir, "dpkg-deb", `#!/bin/sh
case "$1" in
    -R)
        mkdir -p "$3/DEBIAN"
        exit 0
        ;;
    -b)
        : > "$3"
        exit 0
        ;;
    -f)
        package=${2##*/}
        package=${package%.deb}
        case "$3" in
            Package) printf '%s\n' "$package" ;;
            Architecture) printf 'amd64\n' ;;
            Version)
                case "$package" in
                    safe) printf '2.1\n' ;;
                    downgrade) printf '2.5\n' ;;
                    below-fixed) printf '2.0\n' ;;
                    new-dependency) printf '1.0\n' ;;
                    tightened-dependency) printf '2.0\n' ;;
                    *) exit 2 ;;
                esac
                ;;
            *) exit 2 ;;
        esac
        ;;
    *) exit 2 ;;
esac
`)
	writeTestExecutable(t, binDir, "dpkg", `#!/bin/sh
if [ "$1" = '--compare-versions' ]; then
    case "$2|$3|$4" in
        '2.1|ge|1.0'|'2.1|ge|2.0'|'2.5|ge|2.0'|'2.0|ge|1.0') exit 0 ;;
        '2.5|ge|3.0'|'2.0|ge|3.0') exit 1 ;;
        *) exit 2 ;;
    esac
fi
printf '%s\n' "$*" >> "$INSTALL_LOG"
`)
	writeTestExecutable(t, binDir, "busybox", "#!/bin/sh\n[ \"$1\" = --list ] && printf 'sh\\nsed\\ngrep\\nawk\\n'\n")

	runEmbeddedShellScript(t, aptGetDownloadScript, map[string]string{
		"PATH":                          binDir + string(os.PathListSeparator) + os.Getenv("PATH"),
		"IGNORE_ERRORS":                 "true",
		"UPDATE_ALL":                    "false",
		"DPKG_ROOT":                     dpkgRoot,
		"DOWNLOAD_DIR":                  downloadDir,
		"PACKAGES_FILE":                 packagesPath,
		"RESOLVER_STATUS_FILE":          resolverPath,
		"VERSION_FLOORS_FILE":           floorsPath,
		"FINALIZE_DPKG_STATUS_SCRIPT":   finalizePath,
		"DPKG_INSTALLATION_MODE":        dpkgInstallationModeExternalFullStatus.String(),
		"LIFECYCLE_PACKAGES":            "",
		"ALLOW_BUSYBOX_LIFECYCLE_SHELL": "true",
		"ALLOW_REGULAR_DEV_NULL":        "true",
		"TARGET_DPKG_ARCH":              "amd64",
		"STATUSD_FILE_MAP":              "{}",
		"APT_LOG":                       aptLog,
		"INSTALL_LOG":                   installLog,
		"BUSYBOX":                       filepath.Join(binDir, "busybox"),
	})

	aptCalls, err := os.ReadFile(aptLog)
	require.NoError(t, err)
	assert.Contains(t, string(aptCalls), "install -- safe downgrade below-fixed")
	assert.NotContains(t, string(aptCalls), " download ")

	installArgs, err := os.ReadFile(installLog)
	require.NoError(t, err)
	assert.Contains(t, string(installArgs), "safe.deb")
	assert.Contains(t, string(installArgs), "new-dependency.deb")
	assert.Contains(t, string(installArgs), "tightened-dependency.deb")
	assert.NotContains(t, string(installArgs), "downgrade.deb")
	assert.NotContains(t, string(installArgs), "below-fixed.deb")
	assert.FileExists(t, filepath.Join(downloadDir, "safe.deb"))
	assert.FileExists(t, filepath.Join(downloadDir, "new-dependency.deb"))
	assert.FileExists(t, filepath.Join(downloadDir, "tightened-dependency.deb"))
	assert.NoFileExists(t, filepath.Join(downloadDir, "downgrade.deb"))
	assert.NoFileExists(t, filepath.Join(downloadDir, "below-fixed.deb"))

	manifest, err := os.ReadFile(filepath.Join(dpkgRoot, "manifest"))
	require.NoError(t, err)
	manifestPackages, err := dpkgParseResultsManifest(manifest)
	require.NoError(t, err)
	assert.Equal(t, "1.0", manifestPackages["new-dependency:amd64"])
	assert.Equal(t, "2.0", manifestPackages["tightened-dependency:amd64"])
	errorPkgs, err := validateDebianPackageVersions(
		unversioned.UpdatePackages{
			{Name: "safe", FixedVersion: "2.0"},
			{Name: "downgrade", FixedVersion: "2.0"},
			{Name: "below-fixed", FixedVersion: "3.0"},
		},
		map[string]string{"safe:amd64": "1.0", "downgrade:amd64": "3.0", "below-fixed:amd64": "1.0"},
		VersionComparer{isValidDebianVersion, isLessThanDebianVersion},
		manifest,
		true,
		"amd64",
	)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"downgrade", "below-fixed"}, errorPkgs)

	status, err := os.ReadFile(filepath.Join(dpkgRoot, "var", "lib", "dpkg", "status"))
	require.NoError(t, err)
	assert.Equal(t, bytes.TrimSpace(statusWithDependencies), bytes.TrimSpace(status))
	assert.Contains(t, string(status), "Status: hold ok installed")
	assert.NoDirExists(t, filepath.Join(dpkgRoot, "var", "lib", "dpkg", "status.d"))
	assert.FileExists(t, filepath.Join(dpkgRoot, "bin", "sh"))
	assert.FileExists(t, filepath.Join(dpkgRoot, "usr", "bin", "apt-get"))
	assert.FileExists(t, filepath.Join(dpkgRoot, "usr", "bin", "dpkg"))
	assertFileContent(t, filepath.Join(dpkgRoot, "bin", "sh"), "application-owned-shell")
	assertFileContent(t, filepath.Join(dpkgRoot, "usr", "bin", "apt-get"), "application-owned-apt")
	assertFileContent(t, filepath.Join(dpkgRoot, "usr", "bin", "dpkg"), "application-owned-dpkg")
	assert.FileExists(t, filepath.Join(dpkgRoot, "app", "sentinel"))
}

func TestAptGetDownloadScriptRejectsUnsafeDependencyClosure(t *testing.T) {
	binDir := t.TempDir()
	workDir := t.TempDir()
	downloadDir := filepath.Join(workDir, "downloads")
	dpkgRoot := filepath.Join(workDir, "rootfs")
	packagesPath := filepath.Join(workDir, "packages.txt")
	floorsPath := filepath.Join(workDir, "version-floors")
	finalizePath := filepath.Join(workDir, "finalize.sh")
	resolverPath := filepath.Join(downloadDir, "resolver-status")
	finalizeMarker := filepath.Join(workDir, "finalize-called")
	dpkgMarker := filepath.Join(workDir, "dpkg-called")
	status := []byte(strings.Join([]string{
		"Package: app",
		"Status: install ok installed",
		"Version: 1.0",
		"Architecture: amd64",
		"",
		"Package: dependency",
		"Status: install ok installed",
		"Version: 3.0",
		"Architecture: amd64",
		"",
	}, "\n"))

	require.NoError(t, os.MkdirAll(filepath.Join(dpkgRoot, "var", "lib", "dpkg"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dpkgRoot, "var", "lib", "dpkg", "status"), status, 0o600))
	writeDPKGResolverStatusTestFile(t, resolverPath, status)
	require.NoError(t, os.WriteFile(packagesPath, []byte("app\n"), 0o600))
	require.NoError(t, os.WriteFile(floorsPath, []byte("app|1.0|2.0\ndependency|3.0|\n"), 0o600))
	writeTestExecutable(t, workDir, "finalize.sh", "#!/bin/sh\n: > \"$FINALIZE_MARKER\"\n")

	writeTestExecutable(t, binDir, "apt-get", `#!/bin/sh
command=''
for arg in "$@"; do
    case "$arg" in update|download|install) command=$arg ;; esac
done
case "$command" in
    update) exit 0 ;;
    install)
        : > "$DOWNLOAD_DIR/app.deb"
        : > "$DOWNLOAD_DIR/dependency.deb"
        ;;
    download) echo 'unexpected direct download' >&2; exit 90 ;;
    *) exit 91 ;;
esac
`)
	writeTestExecutable(t, binDir, "dpkg-deb", `#!/bin/sh
case "$1" in
    -f)
        package=${2##*/}
        package=${package%.deb}
        case "$3" in
            Package) printf '%s\n' "$package" ;;
            Architecture) printf 'amd64\n' ;;
            Version)
                case "$package" in
                    app|dependency) printf '2.0\n' ;;
                    *) exit 2 ;;
                esac
                ;;
            *) exit 2 ;;
        esac
        ;;
    *) exit 2 ;;
esac
`)
	writeTestExecutable(t, binDir, "dpkg", `#!/bin/sh
if [ "$1" = '--compare-versions' ]; then
    case "$2|$3|$4" in
        '2.0|ge|1.0'|'2.0|ge|2.0') exit 0 ;;
        '2.0|ge|3.0') exit 1 ;;
        *) exit 2 ;;
    esac
fi
: > "$DPKG_MARKER"
`)

	output, err := executeEmbeddedShellScript(t, aptGetDownloadScript, map[string]string{
		"PATH":                          binDir + string(os.PathListSeparator) + os.Getenv("PATH"),
		"IGNORE_ERRORS":                 "true",
		"UPDATE_ALL":                    "false",
		"DPKG_ROOT":                     dpkgRoot,
		"DOWNLOAD_DIR":                  downloadDir,
		"PACKAGES_FILE":                 packagesPath,
		"RESOLVER_STATUS_FILE":          resolverPath,
		"VERSION_FLOORS_FILE":           floorsPath,
		"FINALIZE_DPKG_STATUS_SCRIPT":   finalizePath,
		"DPKG_INSTALLATION_MODE":        dpkgInstallationModeExternalFullStatus.String(),
		"LIFECYCLE_PACKAGES":            "",
		"ALLOW_BUSYBOX_LIFECYCLE_SHELL": "true",
		"ALLOW_REGULAR_DEV_NULL":        "true",
		"TARGET_DPKG_ARCH":              "amd64",
		"STATUSD_FILE_MAP":              "{}",
		"FINALIZE_MARKER":               finalizeMarker,
		"DPKG_MARKER":                   dpkgMarker,
	})
	require.Error(t, err)
	assert.Contains(t, string(output), "downloaded package dependency:amd64 version 2.0 is lower than installed version 3.0")
	assert.Contains(t, string(output), "unsafe package dependency:amd64 is part of the resolved dependency closure")
	assert.NoFileExists(t, filepath.Join(downloadDir, "dependency.deb"))
	assert.NoFileExists(t, finalizeMarker)
	assert.NoFileExists(t, dpkgMarker)
	assert.NoDirExists(t, filepath.Join(dpkgRoot, "var", "lib", "dpkg", "status.d"))
	actualStatus, readErr := os.ReadFile(filepath.Join(dpkgRoot, "var", "lib", "dpkg", "status"))
	require.NoError(t, readErr)
	assert.Equal(t, status, actualStatus)
}

func TestAptGetDownloadScriptFailsWhenDependencyClosureCannotBeResolved(t *testing.T) {
	binDir := t.TempDir()
	workDir := t.TempDir()
	downloadDir := filepath.Join(workDir, "downloads")
	dpkgRoot := filepath.Join(workDir, "rootfs")
	packagesPath := filepath.Join(workDir, "packages.txt")
	floorsPath := filepath.Join(workDir, "version-floors")
	finalizePath := filepath.Join(workDir, "finalize.sh")
	resolverPath := filepath.Join(downloadDir, "resolver-status")
	finalizeMarker := filepath.Join(workDir, "finalize-called")
	dpkgMarker := filepath.Join(workDir, "dpkg-called")

	require.NoError(t, os.MkdirAll(filepath.Join(dpkgRoot, "var", "lib", "dpkg"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dpkgRoot, "var", "lib", "dpkg", "status"), fullDPKGStatus, 0o600))
	writeDPKGResolverStatusTestFile(t, resolverPath, fullDPKGStatus)
	require.NoError(t, os.WriteFile(packagesPath, []byte("base-files\n"), 0o600))
	require.NoError(t, os.WriteFile(floorsPath, []byte("base-files|13ubuntu10.2|13ubuntu10.3\n"), 0o600))
	writeTestExecutable(t, workDir, "finalize.sh", "#!/bin/sh\n: > \"$FINALIZE_MARKER\"\n")

	writeTestExecutable(t, binDir, "apt-get", `#!/bin/sh
command=''
for arg in "$@"; do
    case "$arg" in update|download|install) command=$arg ;; esac
done
case "$command" in
    update) exit 0 ;;
    install)
        echo 'unmet dependency: base-files depends on missing-runtime' >&2
        exit 42
        ;;
    download) echo 'unexpected direct download' >&2; exit 90 ;;
    *) exit 91 ;;
esac
`)
	writeTestExecutable(t, binDir, "dpkg", "#!/bin/sh\n: > \"$DPKG_MARKER\"\n")
	writeTestExecutable(t, binDir, "dpkg-deb", "#!/bin/sh\n: > \"$DPKG_MARKER\"\n")

	output, err := executeEmbeddedShellScript(t, aptGetDownloadScript, map[string]string{
		"PATH":                          binDir + string(os.PathListSeparator) + os.Getenv("PATH"),
		"IGNORE_ERRORS":                 "true",
		"UPDATE_ALL":                    "false",
		"DPKG_ROOT":                     dpkgRoot,
		"DOWNLOAD_DIR":                  downloadDir,
		"PACKAGES_FILE":                 packagesPath,
		"RESOLVER_STATUS_FILE":          resolverPath,
		"VERSION_FLOORS_FILE":           floorsPath,
		"FINALIZE_DPKG_STATUS_SCRIPT":   finalizePath,
		"DPKG_INSTALLATION_MODE":        dpkgInstallationModeExternalFullStatus.String(),
		"LIFECYCLE_PACKAGES":            "",
		"ALLOW_BUSYBOX_LIFECYCLE_SHELL": "true",
		"ALLOW_REGULAR_DEV_NULL":        "true",
		"TARGET_DPKG_ARCH":              "amd64",
		"STATUSD_FILE_MAP":              "{}",
		"FINALIZE_MARKER":               finalizeMarker,
		"DPKG_MARKER":                   dpkgMarker,
	})
	require.Error(t, err)
	assert.Contains(t, string(output), "unmet dependency: base-files depends on missing-runtime")
	assert.Contains(t, string(output), "failed to resolve and download the selected package dependency closure")
	assert.NoFileExists(t, finalizeMarker)
	assert.NoFileExists(t, dpkgMarker)
	assert.NoDirExists(t, filepath.Join(dpkgRoot, "var", "lib", "dpkg", "status.d"))
	status, readErr := os.ReadFile(filepath.Join(dpkgRoot, "var", "lib", "dpkg", "status"))
	require.NoError(t, readErr)
	assert.Equal(t, fullDPKGStatus, status)
}

func TestAptGetDownloadScriptPreservesStatusDirectoryFlow(t *testing.T) {
	binDir := t.TempDir()
	workDir := t.TempDir()
	downloadDir := filepath.Join(workDir, "downloads")
	dpkgRoot := filepath.Join(workDir, "rootfs")
	packagesPath := filepath.Join(workDir, "packages.txt")
	floorsPath := filepath.Join(workDir, "version-floors")
	finalizePath := filepath.Join(workDir, "finalize_dpkg_status.sh")
	aptLog := filepath.Join(workDir, "apt.log")
	installLog := filepath.Join(workDir, "install.log")
	status := []byte("Package: safe\nStatus: install ok installed\nVersion: 1.0\nArchitecture: amd64\n")

	require.NoError(t, os.MkdirAll(filepath.Join(dpkgRoot, "var", "lib", "dpkg", "info"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(dpkgRoot, "bin"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dpkgRoot, "var", "lib", "dpkg", "status"), status, 0o600))
	writeTestExecutable(t, filepath.Join(dpkgRoot, "bin"), "sh", "application-owned")
	require.NoError(t, os.WriteFile(packagesPath, []byte("safe\n"), 0o600))
	require.NoError(t, os.WriteFile(floorsPath, []byte("safe|1.0|2.0\n"), 0o600))
	require.NoError(t, os.WriteFile(finalizePath, finalizeDPKGStatusScript, 0o600))
	require.NoError(t, os.Chmod(finalizePath, 0o700))

	writeTestExecutable(t, binDir, "apt-get", `#!/bin/sh
printf '%s\n' "$*" >> "$APT_LOG"
command=''
after_separator=false
for arg in "$@"; do
    case "$arg" in
        update|download|install) command=$arg ;;
        --) after_separator=true ;;
        *)
            if [ "$command" = download ] && [ "$after_separator" = true ]; then
                : > "$DOWNLOAD_DIR/$arg.deb"
            fi
            ;;
    esac
done
case "$command" in
    update|download) exit 0 ;;
    install) echo 'status.d flow must not resolve against the mounted target status' >&2; exit 90 ;;
    *) exit 91 ;;
esac
`)
	writeTestExecutable(t, binDir, "dpkg-deb", `#!/bin/sh
case "$1" in
    -f)
        case "$3" in
            Package) printf 'safe\n' ;;
            Version) printf '2.0\n' ;;
            *) exit 2 ;;
        esac
        ;;
    *) exit 2 ;;
esac
`)
	writeTestExecutable(t, binDir, "dpkg", `#!/bin/sh
if [ "$1" = '--compare-versions' ]; then
    case "$2|$3|$4" in
        '2.0|ge|1.0'|'2.0|ge|2.0') exit 0 ;;
        *) exit 2 ;;
    esac
fi
printf '%s\n' "$*" >> "$INSTALL_LOG"
case " $* " in
    *" --install "*)
        cat >> "$DPKG_ROOT/var/lib/dpkg/status" <<'EOF'

Package: safe
Status: install ok installed
Version: 2.0
Architecture: amd64
EOF
        ;;
esac
`)

	runEmbeddedShellScript(t, aptGetDownloadScript, map[string]string{
		"PATH":                        binDir + string(os.PathListSeparator) + os.Getenv("PATH"),
		"IGNORE_ERRORS":               "false",
		"UPDATE_ALL":                  "false",
		"DPKG_ROOT":                   dpkgRoot,
		"DOWNLOAD_DIR":                downloadDir,
		"PACKAGES_FILE":               packagesPath,
		"VERSION_FLOORS_FILE":         floorsPath,
		"FINALIZE_DPKG_STATUS_SCRIPT": finalizePath,
		"DPKG_INSTALLATION_MODE":      dpkgInstallationModeExternalStatusDirectory.String(),
		"STATUSD_FILE_MAP":            `{"safe":"encoded-safe"}`,
		"APT_LOG":                     aptLog,
		"INSTALL_LOG":                 installLog,
	})

	aptCalls, err := os.ReadFile(aptLog)
	require.NoError(t, err)
	assert.Contains(t, string(aptCalls), "download --no-install-recommends -- safe")
	assert.NotContains(t, string(aptCalls), " install ")
	assert.NoFileExists(t, filepath.Join(dpkgRoot, "var", "lib", "dpkg", "status"))
	updatedStatus, err := os.ReadFile(filepath.Join(dpkgRoot, "var", "lib", "dpkg", "status.d", "encoded-safe"))
	require.NoError(t, err)
	assert.Contains(t, string(updatedStatus), "Version: 2.0")
	assert.FileExists(t, filepath.Join(dpkgRoot, "bin", "sh"), "status.d behavior must not apply full-status tooling cleanup")
}

func TestDPKGProbeScriptDoesNotExecuteTargetTools(t *testing.T) {
	targetRoot := t.TempDir()
	resultsDir := t.TempDir()
	toolDir := filepath.Join(targetRoot, "usr", "bin")
	assert.NoError(t, os.MkdirAll(toolDir, 0o755))

	markerPath := filepath.Join(t.TempDir(), "target-tool-executed")
	fakeTool := []byte("#!/bin/sh\nprintf executed > \"$MARKER_PATH\"\n")
	for _, tool := range requiredDPKGTools {
		toolPath := filepath.Join(toolDir, tool)
		assert.NoError(t, os.WriteFile(toolPath, fakeTool, 0o600))
		assert.NoError(t, os.Chmod(toolPath, 0o700))
	}

	statusPath := filepath.Join(targetRoot, strings.TrimPrefix(dpkgStatusPath, "/"))
	assert.NoError(t, os.MkdirAll(filepath.Dir(statusPath), 0o755))
	assert.NoError(t, os.WriteFile(statusPath, fullDPKGStatus, 0o600))

	probeOutputPath := filepath.Join(resultsDir, dpkgProbeOutputFilename)
	copiedStatusPath := filepath.Join(resultsDir, dpkgStatusOutputFilename)
	runEmbeddedShellScript(t, probeDPKGScript, map[string]string{
		"TARGET_ROOT":               targetRoot,
		"MARKER_PATH":               markerPath,
		"CHISEL_MANIFEST_PATH":      chiselManifestPath,
		"DPKG_STATUS_PATH":          dpkgStatusPath,
		"DPKG_STATUS_FOLDER":        dpkgStatusFolder,
		"REQUIRED_DPKG_TOOLS":       strings.Join(requiredDPKGTools, " "),
		"RESULTS_PATH":              resultsDir,
		"RESULT_STATUS_PATH":        copiedStatusPath,
		"RESULT_STATUSD_LIST_PATH":  filepath.Join(resultsDir, dpkgStatusdListFilename),
		"RESULT_STATUSD_FILES_PATH": filepath.Join(resultsDir, dpkgStatusdFilesFolder),
		"PROBE_OUTPUT_PATH":         probeOutputPath,
	})

	probeBytes, err := os.ReadFile(probeOutputPath)
	assert.NoError(t, err)
	probe, err := parseDPKGProbeResult(probeBytes)
	assert.NoError(t, err)
	assert.True(t, probe.hasStatus)
	assert.Empty(t, probe.missingTools)
	mode, err := classifyDPKGInstallationMode(probe)
	assert.NoError(t, err)
	assert.Equal(t, dpkgInstallationModeTargetTools, mode)

	copiedStatus, err := os.ReadFile(copiedStatusPath)
	assert.NoError(t, err)
	assert.Equal(t, fullDPKGStatus, copiedStatus)
	assert.NoFileExists(t, markerPath, "the probe must not execute target apt/dpkg/shell utilities")
}

func TestFinalizeDPKGStatusScript(t *testing.T) {
	t.Run("full status remains a full status file", func(t *testing.T) {
		root := t.TempDir()
		dpkgDir := filepath.Join(root, "var", "lib", "dpkg")
		assert.NoError(t, os.MkdirAll(filepath.Join(dpkgDir, "info"), 0o755))
		assert.NoError(t, os.MkdirAll(filepath.Join(dpkgDir, "status.d"), 0o755))
		writeDPKGTestFile(t, filepath.Join(dpkgDir, "status"), fullDPKGStatus, 0o644)
		writeDPKGTestFile(t, filepath.Join(dpkgDir, "info", "temporary.list"), []byte("temporary"), 0o644)
		writeDPKGTestFile(t, filepath.Join(dpkgDir, "status.d", "old"), []byte("old"), 0o644)

		runEmbeddedShellScript(t, finalizeDPKGStatusScript, map[string]string{
			"DPKG_ROOT":              root,
			"DPKG_INSTALLATION_MODE": dpkgInstallationModeExternalFullStatus.String(),
			"STATUSD_FILE_MAP":       "{}",
		})

		status, err := os.ReadFile(filepath.Join(dpkgDir, "status"))
		assert.NoError(t, err)
		assert.Equal(t, fullDPKGStatus, status)
		entries, err := os.ReadDir(dpkgDir)
		assert.NoError(t, err)
		assert.Equal(t, []string{"status"}, directoryEntryNames(entries))
		assert.NoDirExists(t, filepath.Join(dpkgDir, "status.d"))
	})

	t.Run("status directory behavior is preserved", func(t *testing.T) {
		root := t.TempDir()
		dpkgDir := filepath.Join(root, "var", "lib", "dpkg")
		assert.NoError(t, os.MkdirAll(filepath.Join(dpkgDir, "info"), 0o755))
		status := "Package: base-files\nStatus: install ok installed\nVersion: 1.0\n\nPackage: tzdata\nStatus: install ok installed\nVersion: 2.0\n"
		writeDPKGTestFile(t, filepath.Join(dpkgDir, "status"), []byte(status), 0o644)
		writeDPKGTestFile(t, filepath.Join(dpkgDir, "info", "temporary.list"), []byte("temporary"), 0o644)

		runEmbeddedShellScript(t, finalizeDPKGStatusScript, map[string]string{
			"DPKG_ROOT":              root,
			"DPKG_INSTALLATION_MODE": dpkgInstallationModeExternalStatusDirectory.String(),
			"STATUSD_FILE_MAP":       `{"base-files":"encoded-base-files"}`,
		})

		entries, err := os.ReadDir(dpkgDir)
		assert.NoError(t, err)
		assert.Equal(t, []string{"status.d"}, directoryEntryNames(entries))
		assert.NoFileExists(t, filepath.Join(dpkgDir, "status"))

		statusdEntries, err := os.ReadDir(filepath.Join(dpkgDir, "status.d"))
		assert.NoError(t, err)
		assert.Equal(t, []string{"encoded-base-files", "tzdata"}, directoryEntryNames(statusdEntries))
		baseFiles, err := os.ReadFile(filepath.Join(dpkgDir, "status.d", "encoded-base-files"))
		assert.NoError(t, err)
		assert.Contains(t, string(baseFiles), "Package: base-files")
		tzdata, err := os.ReadFile(filepath.Join(dpkgDir, "status.d", "tzdata"))
		assert.NoError(t, err)
		assert.Contains(t, string(tzdata), "Package: tzdata")
	})
}

func directoryEntryNames(entries []os.DirEntry) []string {
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names
}

func TestDpkgParseResultsManifest(t *testing.T) {
	t.Run("valid manifest", func(t *testing.T) {
		expectedMap := map[string]string{
			"apt-get":    "1.8.2.3",
			"base-files": "10.3+deb10u13",
		}
		actualMap, err := dpkgParseResultsManifest(validDPKGManifest)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if !reflect.DeepEqual(expectedMap, actualMap) {
			t.Fatalf("Expected map: %v, Actual map: %v", expectedMap, actualMap)
		}
	})

	t.Run("accepts architecture after version", func(t *testing.T) {
		manifest := []byte("Package: libc6\nVersion: 2.35-0ubuntu3.14\nArchitecture: amd64\n")
		actualMap, err := dpkgParseResultsManifest(manifest)
		require.NoError(t, err)
		assert.Equal(t, map[string]string{"libc6:amd64": "2.35-0ubuntu3.14"}, actualMap)
	})

	t.Run("last duplicate record wins", func(t *testing.T) {
		manifest := []byte(strings.Join([]string{
			"Package: libc6",
			"Architecture: amd64",
			"Version: 1.0",
			"Package: libc6",
			"Architecture: amd64",
			"Version: 2.0",
			"",
		}, "\n"))
		actualMap, err := dpkgParseResultsManifest(manifest)
		require.NoError(t, err)
		assert.Equal(t, map[string]string{"libc6:amd64": "2.0"}, actualMap)
	})

	t.Run("non-existing manifest file", func(t *testing.T) {
		expectedErr := fmt.Errorf("%s could not be opened", nonExistingManifest)
		_, actualErr := dpkgParseResultsManifest(nonExistingManifest)
		if errors.Is(actualErr, expectedErr) {
			t.Fatalf("Expected error: %v, Actual error: %v", expectedErr, actualErr)
		}
	})

	t.Run("empty manifest file", func(t *testing.T) {
		expectedMap := map[string]string{}
		actualMap, err := dpkgParseResultsManifest(emptyManifest)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if !reflect.DeepEqual(expectedMap, actualMap) {
			t.Fatalf("Expected map: %v, Actual map: %v", expectedMap, actualMap)
		}
	})

	t.Run("invalid manifest file", func(t *testing.T) {
		expectedErr := fmt.Errorf("unexpected results.manifest file entry: invalid")
		_, actualErr := dpkgParseResultsManifest(invalidDPKGManifest)
		if errors.Is(actualErr, expectedErr) {
			t.Fatalf("Expected error: %v, Actual error: %v", expectedErr, actualErr)
		}
	})
}

func TestValidateDebianPackageVersions(t *testing.T) {
	dpkgComparer := VersionComparer{isValidDebianVersion, isLessThanDebianVersion}

	testCases := []struct {
		name              string
		updates           unversioned.UpdatePackages
		installedVersions map[string]string
		cmp               VersionComparer
		resultsBytes      []byte
		ignoreErrors      bool
		expectedError     string
		expectedErrPkgs   []string
	}{
		{
			name:         "no updates",
			updates:      unversioned.UpdatePackages{},
			cmp:          dpkgComparer,
			resultsBytes: validDPKGManifest,
			ignoreErrors: false,
		},
		{
			name: "package not installed",
			updates: unversioned.UpdatePackages{
				{Name: "not-installed", FixedVersion: "1.0.0"},
			},
			cmp:          dpkgComparer,
			resultsBytes: validDPKGManifest,
			ignoreErrors: false,
		},
		{
			name: "invalid version",
			updates: unversioned.UpdatePackages{
				{Name: "base-files", FixedVersion: "1.0.0"},
			},
			cmp:           dpkgComparer,
			resultsBytes:  invalidDPKGManifest,
			ignoreErrors:  false,
			expectedError: `unexpected results.manifest file entry`,
		},
		{
			name: "invalid version with ignore errors",
			updates: unversioned.UpdatePackages{
				{Name: "base-files", FixedVersion: "1.0.0"},
			},
			cmp:          dpkgComparer,
			resultsBytes: validDPKGManifest,
			ignoreErrors: true,
		},
		{
			name: "version lower than requested",
			updates: unversioned.UpdatePackages{
				{Name: "apt-get", FixedVersion: "2.0"},
			},
			installedVersions: map[string]string{"apt-get": "1.0"},
			cmp:               dpkgComparer,
			resultsBytes:      validDPKGManifest,
			ignoreErrors:      false,
			expectedError: `1 error occurred:
	* downloaded package apt-get version 1.8.2.3 lower than required 2.0 for update`,
			expectedErrPkgs: []string{"apt-get"},
		},
		{
			name: "version lower than requested with ignore errors",
			updates: unversioned.UpdatePackages{
				{Name: "apt-get", FixedVersion: "2.0"},
			},
			installedVersions: map[string]string{"apt-get": "1.0"},
			cmp:               dpkgComparer,
			resultsBytes:      validDPKGManifest,
			ignoreErrors:      true,
			expectedErrPkgs:   []string{"apt-get"},
		},
		{
			name: "version lower than currently installed",
			updates: unversioned.UpdatePackages{
				{Name: "apt-get", FixedVersion: "1.0"},
			},
			installedVersions: map[string]string{"apt-get": "2.0"},
			cmp:               dpkgComparer,
			resultsBytes:      validDPKGManifest,
			ignoreErrors:      false,
			expectedError: `1 error occurred:
	* downloaded package apt-get version 1.8.2.3 lower than currently installed version 2.0`,
			expectedErrPkgs: []string{"apt-get"},
		},
		{
			name: "version lower than currently installed with ignore errors",
			updates: unversioned.UpdatePackages{
				{Name: "apt-get", FixedVersion: "1.0"},
			},
			installedVersions: map[string]string{"apt-get": "2.0"},
			cmp:               dpkgComparer,
			resultsBytes:      validDPKGManifest,
			ignoreErrors:      true,
			expectedErrPkgs:   []string{"apt-get"},
		},
		{
			name: "version equal to requested",
			updates: unversioned.UpdatePackages{
				{Name: "apt-get", FixedVersion: "1.8.2.3"},
			},
			installedVersions: map[string]string{"apt-get": "1.8.2.3"},
			cmp:               dpkgComparer,
			resultsBytes:      validDPKGManifest,
			ignoreErrors:      false,
		},
		{
			name: "qualified installed identity accepts unqualified result",
			updates: unversioned.UpdatePackages{
				{Name: "apt-get", FixedVersion: "1.8.2.3"},
			},
			installedVersions: map[string]string{"apt-get:amd64": "1.0"},
			cmp:               dpkgComparer,
			resultsBytes:      validDPKGManifest,
		},
		{
			name: "different qualified result does not validate installed architecture",
			updates: unversioned.UpdatePackages{
				{Name: "libc6", FixedVersion: "2.0"},
			},
			installedVersions: map[string]string{"libc6:i386": "1.0"},
			cmp:               dpkgComparer,
			resultsBytes:      []byte("Package: libc6\nArchitecture: amd64\nVersion: 2.0\n"),
			expectedError:     "installed package libc6:i386 was not present in the patch result",
			expectedErrPkgs:   []string{"libc6"},
		},
		{
			name: "unchanged current multiarch identity needs no archive",
			updates: unversioned.UpdatePackages{
				{Name: "libc6", FixedVersion: "2.0"},
			},
			installedVersions: map[string]string{"libc6:amd64": "1.0", "libc6:i386": "2.0"},
			cmp:               dpkgComparer,
			resultsBytes:      []byte("Package: libc6\nArchitecture: amd64\nVersion: 2.0\n"),
		},
		{
			name: "version greater than requested",
			updates: unversioned.UpdatePackages{
				{Name: "apt-get", FixedVersion: "0.9"},
			},
			installedVersions: map[string]string{"apt-get": "1.8.2.3"},
			cmp:               dpkgComparer,
			resultsBytes:      validDPKGManifest,
			ignoreErrors:      false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			errorPkgs, err := validateDebianPackageVersions(
				tc.updates, tc.installedVersions, tc.cmp, tc.resultsBytes, tc.ignoreErrors, "amd64",
			)
			if tc.expectedError != "" {
				if !strings.Contains(err.Error(), tc.expectedError) {
					t.Errorf("expected error %v, got %v", tc.expectedError, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}

			if tc.expectedErrPkgs != nil {
				if !reflect.DeepEqual(tc.expectedErrPkgs, errorPkgs) {
					t.Errorf("expected error packages %v, got %v", tc.expectedErrPkgs, errorPkgs)
				}
			}
		})
	}
}

func TestGetPackageType(t *testing.T) {
	type fields struct {
		config           *buildkit.Config
		workingFolder    string
		installationMode dpkgInstallationMode
		statusdNames     string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: utils.OSTypeDebian,
			fields: fields{
				config:           &buildkit.Config{},
				workingFolder:    utils.DefaultTempWorkingFolder,
				installationMode: dpkgInstallationModeTargetTools,
				statusdNames:     "",
			},
			want: "deb",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dm := &dpkgManager{
				config:           tt.fields.config,
				workingFolder:    tt.fields.workingFolder,
				installationMode: tt.fields.installationMode,
				statusdNames:     tt.fields.statusdNames,
			}
			if got := dm.GetPackageType(); got != tt.want {
				t.Errorf("dpkgManager.GetPackageType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_GetPackageInfo(t *testing.T) {
	type fields struct {
		name    string
		version string
		errMsg  string
	}
	tests := []struct {
		name string
		file string
		want fields
	}{
		{
			name: "valid package file format",
			file: `Package: tzdata
			Version: 2021a-1+deb11u8
			Architecture: all
			Maintainer: GNU Libc Maintainers <debian-glibc@lists.debian.org>
			Installed-Size: 3393
			Depends: debconf (>= 0.5) | debconf-2.0
			Provides: tzdata-bullseye
			Section: localization
			Priority: required
			Multi-Arch: foreign
			Homepage: https://www.iana.org/time-zones
			Description: time zone and daylight-saving time data
			 This package contains data required for the implementation of
			 standard local time for many representative locations around the
			 globe. It is updated periodically to reflect changes made by
			 political bodies to time zone boundaries, UTC offsets, and
			 daylight-saving rules.`,
			want: fields{
				name:    "tzdata",
				version: "2021a-1+deb11u8",
				errMsg:  "",
			},
		},
		{
			name: "invalid package file format",
			file: "PackageVersion",
			want: fields{
				name:    "",
				version: "",
				errMsg:  "no package name found for package",
			},
		},
		{
			name: "rejects leading dash (apt option injection)",
			file: "Package: -malicious\nVersion: 1.0",
			want: fields{
				name:    "",
				version: "",
				errMsg:  `invalid package name "-malicious"`,
			},
		},
		{
			name: "rejects double dash",
			file: "Package: --force-all\nVersion: 1.0",
			want: fields{
				name:    "",
				version: "",
				errMsg:  `invalid package name "--force-all"`,
			},
		},
		{
			name: "rejects whitespace in name",
			file: "Package: foo bar\nVersion: 1.0",
			want: fields{
				name:    "",
				version: "",
				errMsg:  `invalid package name "foo bar"`,
			},
		},
		{
			name: "accepts name with plus signs",
			file: "Package: g++\nVersion: 4:10.2.1",
			want: fields{
				name:    "g++",
				version: "4:10.2.1",
				errMsg:  "",
			},
		},
		{
			name: "accepts name with digits and dots",
			file: "Package: libssl1.1\nVersion: 1.1.1n-0+deb11u5",
			want: fields{
				name:    "libssl1.1",
				version: "1.1.1n-0+deb11u5",
				errMsg:  "",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, version, err := GetPackageInfo(tt.file)
			var errMsg string
			if err == nil {
				errMsg = ""
			} else {
				errMsg = err.Error()
			}

			if name != tt.want.name || version != tt.want.version || errMsg != tt.want.errMsg {
				t.Errorf("GetPackageInfo() = Name: %v, Version: %v Error: %v, want Name: %v, Version: %v, Error: %v", name, version, err, tt.want.name, tt.want.version, tt.want.errMsg)
			}
		})
	}
}

func Test_installUpdates_DPKG(t *testing.T) {
	tests := []struct {
		name                  string
		updates               unversioned.UpdatePackages
		ignoreErrors          bool
		mockSetup             func(reference *mocks.MockReference)
		expectedResult        []byte
		expectNoUpdates       bool
		expectedErrorContains string
	}{
		{
			name: "Update all packages",
			mockSetup: func(mr *mocks.MockReference) {
				mr.On("ReadFile", mock.Anything, mock.Anything).Return([]byte(nil), nil)
			},
			ignoreErrors:   false,
			expectedResult: nil,
		},
		{
			name: "Update all packages missing updates marker",
			mockSetup: func(mr *mocks.MockReference) {
				mr.On("ReadFile", mock.Anything, mock.MatchedBy(func(req gwclient.ReadRequest) bool {
					return req.Filename == "/updates.txt"
				})).Return([]byte(nil), fmt.Errorf("failed to stat /updates.txt: no such file or directory"))
			},
			expectNoUpdates: true,
		},
		{
			name: "Update all packages unrelated marker read failure",
			mockSetup: func(mr *mocks.MockReference) {
				mr.On("ReadFile", mock.Anything, mock.MatchedBy(func(req gwclient.ReadRequest) bool {
					return req.Filename == "/updates.txt"
				})).Return([]byte(nil), fmt.Errorf("repository not found"))
			},
			expectedErrorContains: "failed while checking for available apt updates: repository not found",
		},
		{
			name: "Update specific packages",
			mockSetup: func(mr *mocks.MockReference) {
				mr.On("ReadFile", mock.Anything, mock.Anything).Return([]byte("package1-1.0.1\npackage2-2.0.2\n"), nil)
			},
			updates: unversioned.UpdatePackages{
				{Name: "package1", FixedVersion: "1.0.1"},
				{Name: "package2", FixedVersion: "2.0.1"},
			},
			ignoreErrors:   false,
			expectedResult: []byte("package1-1.0.1\npackage2-2.0.2\n"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := new(mocks.MockGWClient)
			mockRef := new(mocks.MockReference)

			mockResult := &gwclient.Result{}
			mockResult.SetRef(mockRef)

			mockClient.On("Solve", mock.Anything, mock.Anything).Return(mockResult, nil)

			if tt.mockSetup != nil {
				tt.mockSetup(mockRef)
			}

			dm := &dpkgManager{
				config: &buildkit.Config{
					Client:     mockClient,
					ImageState: llb.Scratch(),
				},
			}

			updatedState, resultBytes, err := dm.installUpdates(context.TODO(), tt.updates, tt.ignoreErrors)

			switch {
			case tt.expectNoUpdates:
				assert.ErrorIs(t, err, types.ErrNoUpdatesFound)
				assert.Nil(t, updatedState)
				assert.Nil(t, resultBytes)
			case tt.expectedErrorContains != "":
				assert.Error(t, err)
				if err != nil {
					assert.Contains(t, err.Error(), tt.expectedErrorContains)
				}
				assert.False(t, errors.Is(err, types.ErrNoUpdatesFound))
				assert.Nil(t, updatedState)
				assert.Nil(t, resultBytes)
			default:
				assert.NoError(t, err)
				assert.NotNil(t, updatedState)
				assert.Equal(t, tt.expectedResult, resultBytes)
			}

			mockClient.AssertExpectations(t)
			mockRef.AssertExpectations(t)
		})
	}
}

func writeDPKGResolverStatusTestFile(t *testing.T, path string, status []byte) {
	t.Helper()
	parsed, err := parseDPKGStatus(status)
	require.NoError(t, err)
	resolver, err := filterDPKGStatusDependencies(parsed.databaseContents, parsed.packages, "amd64")
	require.NoError(t, err)
	directory := filepath.Dir(path)
	require.NoError(t, os.MkdirAll(directory, 0o755))
	require.NoError(t, os.WriteFile(path, resolver, 0o600))
}

func writeDPKGTestFile(t *testing.T, path string, contents []byte, mode os.FileMode) {
	t.Helper()
	assert.NoError(t, os.WriteFile(path, contents, 0o600))
	assert.NoError(t, os.Chmod(path, mode))
}
