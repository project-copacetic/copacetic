// ------------------------------------------------------------
// Copyright (c) Project Copacetic authors.
// Licensed under the MIT License.
// ------------------------------------------------------------

package pkgmgr

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/project-copacetic/copacetic/pkg/buildkit"
	testutils "github.com/project-copacetic/copacetic/pkg/test_utils"
	"github.com/project-copacetic/copacetic/pkg/types"
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
		manifest *types.UpdateManifest
		want     string
	}{
		{
			name: "ubuntu 20.04",
			manifest: &types.UpdateManifest{
				OSType:    "ubuntu",
				OSVersion: "20.04",
			},
			want: "ubuntu:20.04",
		},
		{
			name: "debian 11.0",
			manifest: &types.UpdateManifest{
				OSType:    "debian",
				OSVersion: "11.0",
			},
			want: "debian:11-slim",
		},
		{
			name: "debian 11.1",
			manifest: &types.UpdateManifest{
				OSType:    "debian",
				OSVersion: "11.1",
			},
			want: "debian:11-slim",
		},
	}

	// Run test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := getAPTImageName(tc.manifest)
			if got != tc.want {
				t.Errorf("getAPTImageName() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestGetDPKGStatusType(t *testing.T) {
	// Create some temporary directories with different files
	dir1 := t.TempDir() // empty directory

	dir2 := t.TempDir() // directory with status files
	testutils.CreateTempFileWithContent(dir2, "status")
	defer os.Remove(dir2)

	dir3 := t.TempDir() // directory with status.d directory
	testutils.CreateTempFileWithContent(dir3, "status.d")
	defer os.Remove(dir2)

	dir4 := t.TempDir() // directory with status file and status.d directory
	testutils.CreateTempFileWithContent(dir4, "status")
	testutils.CreateTempFileWithContent(dir4, "status.d")
	defer os.Remove(dir4)

	tests := []struct {
		name        string
		dir         string
		expectedOut dpkgStatusType
	}{
		{
			name:        "Empty directory",
			dir:         dir1,
			expectedOut: DPKGStatusNone,
		},
		{
			name:        "Directory with status file",
			dir:         dir2,
			expectedOut: DPKGStatusFile,
		},
		{
			name:        "Directory with status directory",
			dir:         dir3,
			expectedOut: DPKGStatusDirectory,
		},
		{
			name:        "Directory with both status file and directory",
			dir:         dir4,
			expectedOut: DPKGStatusMixed,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			out := getDPKGStatusType(test.dir)
			if out != test.expectedOut {
				t.Errorf("Expected %v but got %v", test.expectedOut, out)
			}
		})
	}
}

func TestDpkgParseResultsManifest(t *testing.T) {
	manifestPath := "testdata/dpkg_valid.txt"
	nonExistingManifestPath := "testdata/non_existing_manifest"
	emptyManifestPath := "testdata/empty.txt"
	invalidManifestPath := "testdata/invalid.txt"

	t.Run("valid manifest", func(t *testing.T) {
		expectedMap := map[string]string{
			"apt":        "1.8.2.3",
			"base-files": "10.3+deb10u13",
		}
		actualMap, err := dpkgParseResultsManifest(manifestPath)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if !reflect.DeepEqual(expectedMap, actualMap) {
			t.Fatalf("Expected map: %v, Actual map: %v", expectedMap, actualMap)
		}
	})

	t.Run("non-existing manifest file", func(t *testing.T) {
		expectedErr := fmt.Errorf("%s could not be opened", nonExistingManifestPath)
		_, actualErr := dpkgParseResultsManifest(nonExistingManifestPath)
		if errors.Is(actualErr, expectedErr) {
			t.Fatalf("Expected error: %v, Actual error: %v", expectedErr, actualErr)
		}
	})

	t.Run("empty manifest file", func(t *testing.T) {
		expectedMap := map[string]string{}
		actualMap, err := dpkgParseResultsManifest(emptyManifestPath)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if !reflect.DeepEqual(expectedMap, actualMap) {
			t.Fatalf("Expected map: %v, Actual map: %v", expectedMap, actualMap)
		}
	})

	t.Run("invalid manifest file", func(t *testing.T) {
		expectedErr := fmt.Errorf("unexpected results.manifest file entry: invalid")
		_, actualErr := dpkgParseResultsManifest(invalidManifestPath)
		if errors.Is(actualErr, expectedErr) {
			t.Fatalf("Expected error: %v, Actual error: %v", expectedErr, actualErr)
		}
	})
}

func TestValidateDebianPackageVersions(t *testing.T) {
	dpkgComparer := VersionComparer{isValidDebianVersion, isLessThanDebianVersion}

	testCases := []struct {
		name            string
		updates         types.UpdatePackages
		cmp             VersionComparer
		resultsPath     string
		ignoreErrors    bool
		expectedError   string
		expectedErrPkgs []string
	}{
		{
			name:         "no updates",
			updates:      types.UpdatePackages{},
			cmp:          dpkgComparer,
			resultsPath:  "testdata/dpkg_valid.txt",
			ignoreErrors: false,
		},
		{
			name: "package not installed",
			updates: types.UpdatePackages{
				{Name: "not-installed", FixedVersion: "1.0.0"},
			},
			cmp:          dpkgComparer,
			resultsPath:  "testdata/dpkg_valid.txt",
			ignoreErrors: false,
		},
		{
			name: "invalid version",
			updates: types.UpdatePackages{
				{Name: "base-files", FixedVersion: "1.0.0"},
			},
			cmp:           dpkgComparer,
			resultsPath:   "testdata/dpkg_invalid.txt",
			ignoreErrors:  false,
			expectedError: `invalid version`,
		},
		{
			name: "invalid version with ignore errors",
			updates: types.UpdatePackages{
				{Name: "base-files", FixedVersion: "1.0.0"},
			},
			cmp:          dpkgComparer,
			resultsPath:  "testdata/dpkg_valid.txt",
			ignoreErrors: true,
		},
		{
			name: "version lower than requested",
			updates: types.UpdatePackages{
				{Name: "apt", FixedVersion: "2.0"},
			},
			cmp:          dpkgComparer,
			resultsPath:  "testdata/dpkg_valid.txt",
			ignoreErrors: false,
			expectedError: `1 error occurred:
	* downloaded package apt version 1.8.2.3 lower than required 2.0 for update`,
			expectedErrPkgs: []string{"apt"},
		},
		{
			name: "version lower than requested with ignore errors",
			updates: types.UpdatePackages{
				{Name: "apt", FixedVersion: "2.0"},
			},
			cmp:          dpkgComparer,
			resultsPath:  "testdata/dpkg_valid.txt",
			ignoreErrors: true,
		},
		{
			name: "version equal to requested",
			updates: types.UpdatePackages{
				{Name: "apt", FixedVersion: "1.8.2.3"},
			},
			cmp:          dpkgComparer,
			resultsPath:  "testdata/dpkg_valid.txt",
			ignoreErrors: false,
		},
		{
			name: "version greater than requested",
			updates: types.UpdatePackages{
				{Name: "apt", FixedVersion: "0.9"},
			},
			cmp:          dpkgComparer,
			resultsPath:  "testdata/dpkg_valid.txt",
			ignoreErrors: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			errorPkgs, err := validateDebianPackageVersions(tc.updates, tc.cmp, tc.resultsPath, tc.ignoreErrors)
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

func Test_dpkgManager_GetPackageType(t *testing.T) {
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
			name: "debian",
			fields: fields{
				config:        &buildkit.Config{},
				workingFolder: "/tmp",
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
