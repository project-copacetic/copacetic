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
	"testing"

	testutils "github.com/project-copacetic/copacetic/pkg/test_utils"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/stretchr/testify/assert"
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

	t.Run("no updates", func(t *testing.T) {
		err := validateDebianPackageVersions(nil, dpkgComparer, "testdata/dpkg_valid.txt", false)
		assert.NoError(t, err)
	})

	t.Run("package not installed", func(t *testing.T) {
		updates := []types.UpdatePackage{
			{Name: "not_installed", Version: "1.0"},
		}
		err := validateDebianPackageVersions(updates, dpkgComparer, "testdata/dpkg_valid.txt", false)
		assert.NoError(t, err)
	})

	t.Run("invalid version", func(t *testing.T) {
		updates := []types.UpdatePackage{
			{Name: "base-files", Version: "1.0.0"},
		}
		err := validateDebianPackageVersions(updates, dpkgComparer, "testdata/dpkg_invalid.txt", false)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid version")
	})

	t.Run("invalid version: ignore errors", func(t *testing.T) {
		updates := []types.UpdatePackage{
			{Name: "base-files", Version: "1.0.0"},
		}
		err := validateDebianPackageVersions(updates, dpkgComparer, "testdata/dpkg_invalid.txt", true)
		assert.NoError(t, err)
	})

	t.Run("version lower than requested", func(t *testing.T) {
		updates := []types.UpdatePackage{
			{Name: "apt", Version: "2.0"},
		}
		err := validateDebianPackageVersions(updates, dpkgComparer, "testdata/dpkg_valid.txt", false)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "downloaded package")
	})

	t.Run("version lower than requested: ignore errors", func(t *testing.T) {
		updates := []types.UpdatePackage{
			{Name: "apt", Version: "2.0"},
		}
		err := validateDebianPackageVersions(updates, dpkgComparer, "testdata/dpkg_valid.txt", true)
		assert.NoError(t, err)
	})

	t.Run("version equal to requested", func(t *testing.T) {
		updates := []types.UpdatePackage{
			{Name: "apt", Version: "1.8.2.3"},
		}
		err := validateDebianPackageVersions(updates, dpkgComparer, "testdata/dpkg_valid.txt", false)
		assert.NoError(t, err)
	})

	t.Run("version greater than requested", func(t *testing.T) {
		updates := []types.UpdatePackage{
			{Name: "apt", Version: "0.9"},
		}
		err := validateDebianPackageVersions(updates, dpkgComparer, "testdata/dpkg_valid.txt", false)
		assert.NoError(t, err)
	})
}
