// ------------------------------------------------------------
// Copyright (c) Project Copacetic authors.
// Licensed under the MIT License.
// ------------------------------------------------------------

package pkgmgr

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/project-copacetic/copacetic/pkg/types"
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

// TestApkReadResultsManifest tests the apkReadResultsManifest function.
func TestApkReadResultsManifest(t *testing.T) {
	type args struct {
		path string
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr bool
	}{
		{"valid file", args{"testdata/apk_valid.txt"}, []string{"apk-tools-2.12.7-r0", "busybox-1.33.1-r8"}, false},
		{"file does not exist", args{"testdata/no_such_file.txt"}, nil, true},
		{"empty file", args{"testdata/empty.txt"}, nil, false},
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
		name        string
		updates     types.UpdatePackages
		cmp         VersionComparer
		resultsPath string
		expectedErr error
	}{
		{
			name:        "valid updates",
			updates:     []types.UpdatePackage{{Name: "apk-tools", Version: "2.12.7-r0"}, {Name: "busybox", Version: "1.33.1-r8"}},
			cmp:         apkComparer,
			resultsPath: "testdata/apk_valid.txt",
			expectedErr: nil,
		},
		{
			name:        "invalid version",
			updates:     []types.UpdatePackage{{Name: "apk-tools", Version: "1.0"}, {Name: "busybox", Version: "2.0"}},
			cmp:         apkComparer,
			resultsPath: "testdata/apk_invalid.txt",
			expectedErr: fmt.Errorf("2 errors occurred:\n\t* invalid version x.y found for package apk-tools\n\t* invalid version a.b.c found for package busybox"),
		},
		{
			name:        "expected 2 updates, installed 1",
			updates:     []types.UpdatePackage{{Name: "apk-tools", Version: "2.12.7-r0"}},
			cmp:         apkComparer,
			resultsPath: "testdata/apk_valid.txt",
			expectedErr: fmt.Errorf("expected 2 updates, installed 1"),
		},
	}

	for _, tc := range testCases {
		// Use t.Run to run each test case as a subtest
		t.Run(tc.name, func(t *testing.T) {
			// Run the function to be tested
			err := validateAPKPackageVersions(tc.updates, tc.cmp, tc.resultsPath)
			if tc.expectedErr != nil {
				if err == nil || errors.Is(err, tc.expectedErr) {
					t.Errorf("expected error %v, got %v", tc.expectedErr, err)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}
