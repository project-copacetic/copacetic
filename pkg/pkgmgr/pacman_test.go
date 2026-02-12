package pkgmgr

import (
	"context"
	_ "embed"
	"reflect"
	"strings"
	"testing"

	"github.com/moby/buildkit/client/llb"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/project-copacetic/copacetic/mocks"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

var (
	//go:embed testdata/pacman_valid.txt
	pacmanValid []byte

	//go:embed testdata/pacman_invalid.txt
	pacmanInvalid []byte

	//go:embed testdata/empty.txt
	pacmanEmpty []byte

	pacmanNoSuchFile []byte
)

func TestPacmanReadResultsManifest(t *testing.T) {
	type args struct {
		path []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr bool
	}{
		{"valid file", args{pacmanValid}, []string{"neovim 0.9.5-2", "go 2:1.21.6-1"}, false},
		{"file doesn't exist", args{pacmanNoSuchFile}, nil, true},
		{"empty file", args{pacmanEmpty}, nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := apkReadResultsManifest(tt.args.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("apkReadResultsManifest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("apkReadResultsManifest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidatePacmanPackageVersions(t *testing.T) {
	pacmanComparer := VersionComparer{isValidPacmanVersion, isLessThanPacmanVersion}

	testCases := []struct {
		name                    string
		updates                 unversioned.UpdatePackages
		cmp                     VersionComparer
		resultBytes             []byte
		ignoreErrors            bool
		expectedErrorSubstrings []string
		expectedErrPkgs         []string
	}{
		{
			name: "valid updates",
			updates: []unversioned.UpdatePackage{
				{Name: "neovim", FixedVersion: "0.9.5-2"},
				{Name: "go", FixedVersion: "2:1.21.6-1"},
			},
			cmp:          pacmanComparer,
			resultBytes:  pacmanValid,
			ignoreErrors: false,
		},
		{
			name: "invalid version",
			updates: []unversioned.UpdatePackage{
				{Name: "neovim", FixedVersion: "1.0"},
				{Name: "go", FixedVersion: "2.0"},
			},
			cmp:          pacmanComparer,
			resultBytes:  pacmanInvalid,
			ignoreErrors: false,
			expectedErrorSubstrings: []string{
				"invalid version 2:1/3-4 found for package go",
				"invalid version 0:9.2- found for package neovim",
			},
		},
		{
			name: "invalid version with ignore errors",
			updates: []unversioned.UpdatePackage{
				{Name: "neovim", FixedVersion: "1.0"},
				{Name: "go", FixedVersion: "2.0"},
			},
			cmp:          pacmanComparer,
			resultBytes:  pacmanInvalid,
			ignoreErrors: true,
		},
		{
			name: "expected 1 updates, installed 2",
			updates: []unversioned.UpdatePackage{
				{Name: "neovim", FixedVersion: "0.9.5-2"},
			},
			cmp:                     pacmanComparer,
			resultBytes:             pacmanValid,
			ignoreErrors:            false,
			expectedErrorSubstrings: []string{"expected 1 updates, installed 2"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			errorPkgs, err := validatePacmanPackageVersions(tc.updates, tc.cmp, tc.resultBytes, tc.ignoreErrors)

			if len(tc.expectedErrorSubstrings) > 0 {
				if err == nil {
					t.Errorf("expected error containing %v, got nil", tc.expectedErrorSubstrings)
				} else {
					for _, want := range tc.expectedErrorSubstrings {
						if !strings.Contains(err.Error(), want) {
							t.Errorf("error message missing expected content.\nWant substring: %q\nGot full error: %q", want, err.Error())
						}
					}
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

func Test_pacmanManager_GetPackageType(t *testing.T) {
	type fields struct {
		config        *buildkit.Config
		workingFolder string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "arch linux",
			fields: fields{
				config:        &buildkit.Config{},
				workingFolder: utils.DefaultTempWorkingFolder,
			},
			want: "pacman",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pm := &pacmanManager{
				config:        tt.fields.config,
				workingFolder: tt.fields.workingFolder,
			}
			if got := pm.GetPackageType(); got != tt.want {
				t.Errorf("apkManager.GetPackageType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_InstallUpdates_Pacman(t *testing.T) {
	tests := []struct {
		name          string
		manifest      *unversioned.UpdateManifest
		ignoreErrors  bool
		mockSetup     func(reference *mocks.MockReference)
		expectedState bool
		expectedPkgs  []string
		expectedError string
	}{
		{
			name: "Update specific packages",
			mockSetup: func(mr *mocks.MockReference) {
				// FIX: Added "-1" suffix to make these valid Pacman versions
				mr.On("ReadFile", mock.Anything, mock.Anything).Return([]byte("package1 1.0.1-1\npackage2 2.0.1-1\n"), nil)
			},
			manifest: &unversioned.UpdateManifest{
				OSUpdates: unversioned.UpdatePackages{
					// FIX: Added "-1" suffix
					{Name: "package1", FixedVersion: "1.0.1-1"},
					{Name: "package2", FixedVersion: "2.0.1-1"},
				},
			},
			ignoreErrors:  false,
			expectedState: true,
			expectedPkgs:  nil,
			expectedError: "",
		},
		{
			name: "Nil manifest",
			mockSetup: func(mr *mocks.MockReference) {
				mr.On("ReadFile", mock.Anything, mock.Anything).Return([]byte("package1 1.0.1-1\npackage2 2.0.1-1\n"), nil)
			},
			manifest:      nil,
			expectedState: true,
			expectedPkgs:  nil,
			expectedError: "",
		},
		{
			name: "Ignore errors",
			manifest: &unversioned.UpdateManifest{
				OSUpdates: unversioned.UpdatePackages{
					// FIX: Requesting 2.0.0-1
					{Name: "package1", FixedVersion: "2.0.0-1"},
				},
			},
			ignoreErrors: true,
			mockSetup: func(mr *mocks.MockReference) {
				// FIX: Mocking installed version as 1.0.1-1 (which is < 2.0.0-1, simulating a failed update)
				mr.On("ReadFile", mock.Anything, mock.Anything).Return([]byte("package1 1.0.1-1\n"), nil)
			},
			expectedState: true,
			expectedPkgs:  []string{"package1"}, // Now this should correctly capture the package due to version mismatch, not syntax error
			expectedError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockGWClient := new(mocks.MockGWClient)
			mockRef := new(mocks.MockReference)

			mockResult := &gwclient.Result{}
			mockResult.SetRef(mockRef)

			mockGWClient.On("Solve", mock.Anything, mock.Anything).Return(mockResult, nil)

			if tt.mockSetup != nil {
				tt.mockSetup(mockRef)
			}

			pm := &pacmanManager{
				config: &buildkit.Config{
					Client:     mockGWClient,
					ImageState: llb.Scratch(),
				},
				workingFolder: utils.DefaultTempWorkingFolder,
			}

			state, pkgs, err := pm.InstallUpdates(context.TODO(), tt.manifest, tt.ignoreErrors)

			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				assert.NoError(t, err)
			}

			if tt.expectedState {
				assert.NotNil(t, state)
			} else {
				assert.Nil(t, state)
			}

			assert.Equal(t, tt.expectedPkgs, pkgs)
		})
	}
}
