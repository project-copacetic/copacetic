package pkgmgr

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/moby/buildkit/client/llb"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/project-copacetic/copacetic/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/utils"
)

// TestGetPackageManager tests the GetPackageManager function.
func TestDPKGStatusTypeString(t *testing.T) {
	tests := []struct {
		name string
		st   dpkgStatusType
		want string
	}{
		{
			name: "none",
			st:   DPKGStatusNone,
			want: "DPKGStatusNone",
		},
		{
			name: "file",
			st:   DPKGStatusFile,
			want: "DPKGStatusFile",
		},
		{
			name: "directory",
			st:   DPKGStatusDirectory,
			want: "DPKGStatusDirectory",
		},
		{
			name: "mixed",
			st:   DPKGStatusMixed,
			want: "DPKGStatusMixed",
		},
		{
			name: "undefined",
			st:   99,
			want: "Undefined dpkgStatusType",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.st.String(); got != tt.want {
				t.Errorf("dpkgStatusType.String() = %v, want %v", got, tt.want)
			}
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

// TestGetAPTImageName tests the getAPTImageName function with different inputs and outputs.
func TestGetAPTImageName(t *testing.T) {
	// Define test cases with input and expected output
	testCases := []struct {
		name     string
		manifest *unversioned.UpdateManifest
		want     string
	}{
		{
			name: "ubuntu 20.04",
			manifest: &unversioned.UpdateManifest{
				Metadata: unversioned.Metadata{
					OS: unversioned.OS{
						Type:    utils.OSTypeUbuntu,
						Version: "20.04",
					},
				},
			},
			want: "ghcr.io/project-copacetic/copacetic/ubuntu:20.04",
		},
		{
			name: "debian 11.0",
			manifest: &unversioned.UpdateManifest{
				Metadata: unversioned.Metadata{
					OS: unversioned.OS{
						Type:    utils.OSTypeDebian,
						Version: "11.0",
					},
				},
			},
			want: "ghcr.io/project-copacetic/copacetic/debian:11-slim",
		},
		{
			name: "debian 11.1",
			manifest: &unversioned.UpdateManifest{
				Metadata: unversioned.Metadata{
					OS: unversioned.OS{
						Type:    utils.OSTypeDebian,
						Version: "11.1",
					},
				},
			},
			want: "ghcr.io/project-copacetic/copacetic/debian:11-slim",
		},
	}

	// Run test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := getAPTImageName(tc.manifest, tc.manifest.Metadata.OS.Version, true)
			if got != tc.want {
				t.Errorf("getAPTImageName() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestGetDPKGStatusType(t *testing.T) {
	// Create some temporary directories with different files
	tests := []struct {
		name        string
		input       []byte
		expectedOut dpkgStatusType
	}{
		{
			name:        "Empty directory",
			input:       []byte(fmt.Sprintf("%d", DPKGStatusNone)),
			expectedOut: DPKGStatusNone,
		},
		{
			name:        "Directory with status file",
			input:       []byte(fmt.Sprintf("%d", DPKGStatusFile)),
			expectedOut: DPKGStatusFile,
		},
		{
			name:        "Directory with status directory",
			input:       []byte(fmt.Sprintf("%d", DPKGStatusDirectory)),
			expectedOut: DPKGStatusDirectory,
		},
		{
			name:        "Directory with both status file and directory",
			input:       []byte(fmt.Sprintf("%d", DPKGStatusMixed)),
			expectedOut: DPKGStatusMixed,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			out := getDPKGStatusType(test.input)
			if out != test.expectedOut {
				t.Errorf("Expected %v but got %v", test.expectedOut, out)
			}
		})
	}
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
)

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
		name            string
		updates         unversioned.UpdatePackages
		cmp             VersionComparer
		resultsBytes    []byte
		ignoreErrors    bool
		expectedError   string
		expectedErrPkgs []string
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
			cmp:          dpkgComparer,
			resultsBytes: validDPKGManifest,
			ignoreErrors: false,
			expectedError: `1 error occurred:
	* downloaded package apt-get version 1.8.2.3 lower than required 2.0 for update`,
			expectedErrPkgs: []string{"apt-get"},
		},
		{
			name: "version lower than requested with ignore errors",
			updates: unversioned.UpdatePackages{
				{Name: "apt-get", FixedVersion: "2.0"},
			},
			cmp:          dpkgComparer,
			resultsBytes: validDPKGManifest,
			ignoreErrors: true,
		},
		{
			name: "version equal to requested",
			updates: unversioned.UpdatePackages{
				{Name: "apt-get", FixedVersion: "1.8.2.3"},
			},
			cmp:          dpkgComparer,
			resultsBytes: validDPKGManifest,
			ignoreErrors: false,
		},
		{
			name: "version greater than requested",
			updates: unversioned.UpdatePackages{
				{Name: "apt-get", FixedVersion: "0.9"},
			},
			cmp:          dpkgComparer,
			resultsBytes: validDPKGManifest,
			ignoreErrors: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			errorPkgs, err := validateDebianPackageVersions(tc.updates, tc.cmp, tc.resultsBytes, tc.ignoreErrors)
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
		config        *buildkit.Config
		workingFolder string
		isDistroless  bool
		statusdNames  string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: utils.OSTypeDebian,
			fields: fields{
				config:        &buildkit.Config{},
				workingFolder: utils.DefaultTempWorkingFolder,
				isDistroless:  false,
				statusdNames:  "",
			},
			want: "deb",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dm := &dpkgManager{
				config:        tt.fields.config,
				workingFolder: tt.fields.workingFolder,
				isDistroless:  tt.fields.isDistroless,
				statusdNames:  tt.fields.statusdNames,
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
		name           string
		updates        unversioned.UpdatePackages
		ignoreErrors   bool
		mockSetup      func(reference *mocks.MockReference)
		expectedResult []byte
		expectedError  string
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

			if tt.expectedError != "" {
				assert.EqualError(t, err, tt.expectedError)
				assert.Nil(t, updatedState)
				assert.Nil(t, resultBytes)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, updatedState)
				assert.Equal(t, tt.expectedResult, resultBytes)
			}

			mockClient.AssertExpectations(t)
			mockRef.AssertExpectations(t)
		})
	}
}
