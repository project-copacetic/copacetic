package pkgmgr

import (
	"context"
	_ "embed"
	"reflect"
	"strings"
	"testing"

	"github.com/project-copacetic/copacetic/mocks"

	"github.com/moby/buildkit/client/llb"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/utils"
)

// TestApkReadResultsManifest tests the apkReadResultsManifest function.
func TestIsValidAPKVersion(t *testing.T) {
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
		{"invalid version with suffix", args{"1.0-rx"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidAPKVersion(tt.args.v); got != tt.want {
				t.Errorf("isValidAPKVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestApkReadResultsManifest tests the apkReadResultsManifest function.
func TestIsLessThanAPKVersion(t *testing.T) {
	type args struct {
		v1 string
		v2 string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"less than with suffix", args{"1.0-r0", "1.0-r1"}, true},
		{"equal with suffix", args{"1.0-r0", "1.0-r0"}, false},
		{"greater than with suffix", args{"1.0-r2", "1.0-r1"}, false},
		{"less than without suffix", args{"1.0", "2.0"}, true},
		{"equal without suffix", args{"2.0", "2.0"}, false},
		{"greater than without suffix", args{"3.0", "2.0"}, false},
		{"less than mixed suffixes", args{"1a_rc4_p5_b7-6-x86_64", "3a_rc4_p5_b7-6-x86_64"}, true},
		{"equal mixed suffixes", args{"3a_rc4_p5_b7-6-x86_64", "3a_rc4_p5_b7-6-x86_64"}, false},
		{"greater than mixed suffixes", args{"5a_rc4_p5_b7-6-x86_64", "3a_rc4_p5_b7-6-x86_64"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isLessThanAPKVersion(tt.args.v1, tt.args.v2); got != tt.want {
				t.Errorf("isLessThanAPKVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}

var (
	//go:embed testdata/apk_valid.txt
	apkValid []byte

	//go:embed testdata/apk_invalid.txt
	apkInvalid []byte

	//go:embed testdata/empty.txt
	apkEmpty []byte

	// initialized to `nil`; tests the error handling of the function.
	apkNoSuchFile []byte
)

// TestApkReadResultsManifest tests the apkReadResultsManifest function.
func TestApkReadResultsManifest(t *testing.T) {
	type args struct {
		path []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr bool
	}{
		{"valid file", args{apkValid}, []string{"apk-tools-2.12.7-r0", "busybox-1.33.1-r8"}, false},
		{"file does not exist", args{apkNoSuchFile}, nil, true},
		{"empty file", args{apkEmpty}, nil, false},
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

// TestValidateAPKPackageVersions tests the validateAPKPackageVersions function.
func TestValidateAPKPackageVersions(t *testing.T) {
	apkComparer := VersionComparer{isValidAPKVersion, isLessThanAPKVersion}

	// Define some test cases with inputs and expected outputs
	testCases := []struct {
		name            string
		updates         unversioned.UpdatePackages
		cmp             VersionComparer
		resultsBytes    []byte
		ignoreErrors    bool
		expectedError   string
		expectedErrPkgs []string
	}{
		{
			name:         "valid updates",
			updates:      []unversioned.UpdatePackage{{Name: "apk-tools", FixedVersion: "2.12.7-r0"}, {Name: "busybox", FixedVersion: "1.33.1-r8"}},
			cmp:          apkComparer,
			resultsBytes: apkValid,
			ignoreErrors: false,
		},
		{
			name:         "invalid version",
			updates:      []unversioned.UpdatePackage{{Name: "apk-tools", FixedVersion: "1.0"}, {Name: "busybox", FixedVersion: "2.0"}},
			cmp:          apkComparer,
			resultsBytes: apkInvalid,
			ignoreErrors: false,
			expectedError: `2 errors occurred:
	* invalid version x.y found for package apk-tools
	* invalid version a.b.c found for package busybox`,
		},
		{
			name:         "invalid version with ignore errors",
			updates:      []unversioned.UpdatePackage{{Name: "apk-tools", FixedVersion: "1.0"}, {Name: "busybox", FixedVersion: "2.0"}},
			cmp:          apkComparer,
			resultsBytes: apkValid,
			ignoreErrors: true,
		},
		{
			name:          "expected 1 updates, installed 2",
			updates:       []unversioned.UpdatePackage{{Name: "apk-tools", FixedVersion: "2.12.7-r0"}},
			cmp:           apkComparer,
			resultsBytes:  apkValid,
			ignoreErrors:  false,
			expectedError: `expected 1 updates, installed 2`,
		},
	}

	for _, tc := range testCases {
		// Use t.Run to run each test case as a subtest
		t.Run(tc.name, func(t *testing.T) {
			// Run the function to be tested
			errorPkgs, err := validateAPKPackageVersions(tc.updates, tc.cmp, tc.resultsBytes, tc.ignoreErrors)
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

func Test_apkManager_GetPackageType(t *testing.T) {
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
			name: "alpine",
			fields: fields{
				config:        &buildkit.Config{},
				workingFolder: utils.DefaultTempWorkingFolder,
			},
			want: "apk",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			am := &apkManager{
				config:        tt.fields.config,
				workingFolder: tt.fields.workingFolder,
			}
			if got := am.GetPackageType(); got != tt.want {
				t.Errorf("apkManager.GetPackageType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_InstallUpdates_APK(t *testing.T) {
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
				mr.On("ReadFile", mock.Anything, mock.Anything).Return([]byte("package1-1.0.1\npackage2-2.0.2\n"), nil)
			},
			manifest: &unversioned.UpdateManifest{
				OSUpdates: unversioned.UpdatePackages{
					{Name: "package1", FixedVersion: "1.0.1"},
					{Name: "package2", FixedVersion: "2.0.1"},
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
				mr.On("ReadFile", mock.Anything, mock.Anything).Return([]byte("package1-1.0.1\npackage2-2.0.1\n"), nil)
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
					{Name: "package1", FixedVersion: "2.0.0"},
				},
			},
			ignoreErrors: true,
			mockSetup: func(mr *mocks.MockReference) {
				mr.On("ReadFile", mock.Anything, mock.Anything).Return([]byte("package1-1.0.1\n"), nil)
			},
			expectedState: true,
			expectedPkgs:  []string{"package1"},
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

			am := &apkManager{
				config: &buildkit.Config{
					Client:     mockGWClient,
					ImageState: llb.Scratch(),
				},
				workingFolder: utils.DefaultTempWorkingFolder,
			}

			state, pkgs, err := am.InstallUpdates(context.TODO(), tt.manifest, tt.ignoreErrors)

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
