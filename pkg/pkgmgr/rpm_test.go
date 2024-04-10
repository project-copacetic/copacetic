package pkgmgr

import (
	"bytes"
	_ "embed"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/stretchr/testify/assert"
)

// TestRpmDBTypeString tests the String method of rpmDBType.
func TestRpmDBTypeString(t *testing.T) {
	// Define test cases with input rpmDBType and expected output string
	testCases := []struct {
		rpmDBType rpmDBType
		str       string
	}{
		{
			rpmDBType: RPMDBNone,
			str:       "RPMDBNone",
		},
		{
			rpmDBType: RPMDBBerkley,
			str:       "RPMDBBerkley",
		},
		{
			rpmDBType: RPMDBNative,
			str:       "RPMDBNative",
		},
		{
			rpmDBType: RPMDBSqlLite,
			str:       "RPMDBSqlLite",
		},
		{
			rpmDBType: RPMDBManifests,
			str:       "RPMDBManifests",
		},
		{
			rpmDBType: RPMDBMixed,
			str:       "RPMDBMixed",
		},
		{
			rpmDBType: 99,
			str:       "Undefined rpmDBType",
		},
	}

	// Loop over test cases and run String method with each input rpmDbtype
	for _, tc := range testCases {
		t.Run(tc.str, func(t *testing.T) {
			str := tc.rpmDBType.String()
			// Use testify package to assert that the output string matches the expected one
			assert.Equal(t, tc.str, str)
		})
	}
}

func TestIsLessThanRPMVersion(t *testing.T) {
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
		{"equal without suffix", args{"2.0", "2.0"}, false},
		{"greater than without suffix", args{"3.0", "2.0"}, false},
		{"less than mixed suffixes", args{"1a_rc4_p5_b7-6-x86_64", "3a_rc4_p5_b7-6-x86_64"}, true},
		{"equal mixed suffixes", args{"3a_rc4_p5_b7-6-x86_64", "3a_rc4_p5_b7-6-x86_64"}, false},
		{"greater than mixed suffixes", args{"5a_rc4_p5_b7-6-x86_64", "3a_rc4_p5_b7-6-x86_64"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isLessThanRPMVersion(tt.args.v1, tt.args.v2); got != tt.want {
				t.Errorf("isLessThanRPMVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestGetRPMImageName tests the getRPMImageName function with different manifest inputs.
func TestGetRPMImageName(t *testing.T) {
	// Define test cases with input manifest and expected output image name
	testCases := []struct {
		manifest *unversioned.UpdateManifest
		image    string
	}{
		{
			manifest: &unversioned.UpdateManifest{
				Metadata: unversioned.Metadata{
					OS: unversioned.OS{
						Type:    "cbl-mariner",
						Version: "2.0.0",
					},
				},
			},
			image: "mcr.microsoft.com/cbl-mariner/base/core:2.0",
		},
		{
			manifest: &unversioned.UpdateManifest{
				Metadata: unversioned.Metadata{
					OS: unversioned.OS{
						Type:    "cbl-mariner",
						Version: "1.5",
					},
				},
			},
			image: "mcr.microsoft.com/cbl-mariner/base/core:1.5",
		},
		{
			manifest: &unversioned.UpdateManifest{
				Metadata: unversioned.Metadata{
					OS: unversioned.OS{
						Type:    "cbl-mariner",
						Version: "3",
					},
				},
			},
			image: "mcr.microsoft.com/cbl-mariner/base/core:3.0", // default minor version to 0
		},
		{
			manifest: &unversioned.UpdateManifest{
				Metadata: unversioned.Metadata{
					OS: unversioned.OS{
						Type:    "redhat",
						Version: "8.4",
					},
				},
			},
			image: "mcr.microsoft.com/cbl-mariner/base/core:2.0", // use default version of cbl-mariner image
		},
	}

	// Loop over test cases and run getRPMImageName function with each input manifest
	for _, tc := range testCases {
		t.Run(tc.image, func(t *testing.T) {
			image := getRPMImageName(tc.manifest)

			// Use testify package to assert that the output image name matches the expected one
			assert.Equal(t, tc.image, image)
		})
	}
}

// TestParseRPMTools tests the parseRPMTools function with a sample file.
func TestParseRPMTools(t *testing.T) {
	// Create a temporary file with some sample data
	var tmpfile bytes.Buffer

	tmpfile.WriteString("tool1:/path/to/tool1\n")
	tmpfile.WriteString("tool2:notfound\n")
	tmpfile.WriteString("tool3:/path/to/tool3\n")

	// Call the parseRPMTools function with the temporary file name
	rpmTools, err := parseRPMTools(tmpfile.Bytes())
	if err != nil {
		t.Errorf("parseRPMTools failed: %v", err)
	}

	// Check if the returned map matches the expected values
	expected := rpmToolPaths{
		"tool1": "/path/to/tool1",
		"tool3": "/path/to/tool3",
	}
	for k, v := range expected {
		if rpmTools[k] != v {
			t.Errorf("expected %s to be %s but got %s", k, v, rpmTools[k])
		}
	}
}

// TestGetRPMDBType tests the getRPMDBType function with different input directories.
func TestGetRPMDBType(t *testing.T) {
	// Define some test cases with expected output
	testCases := []struct {
		name     string
		input    []byte
		expected rpmDBType
	}{
		{"empty dir", []byte{}, RPMDBNone},
		{"dir with berkeley db", []byte(fmt.Sprintf("%s\n", rpmBDB)), RPMDBBerkley},
		{"dir with mixed db", []byte(fmt.Sprintf("%s\n%s\n", rpmBDB, rpmNDB)), RPMDBMixed},
		{"dir with manifests", []byte(fmt.Sprintf("%s\n%s\n", rpmManifest1, rpmManifest2)), RPMDBManifests},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			output := getRPMDBType(tc.input)
			if output != tc.expected {
				t.Errorf("expected %v but got %v", tc.expected, output)
			}
		})
	}
}

//go:embed testdata/rpm_valid.txt
var rpmValidManifest []byte

func TestRpmReadResultsManifest(t *testing.T) {
	// Test cases
	tests := []struct {
		name    string
		input   []byte
		want    []string
		wantErr bool
	}{
		{
			name:    "valid path",
			input:   rpmValidManifest,
			want:    []string{"openssl	2.1.1k-21.cm2	x86_64", "openssl-libs	2.1.1k-21.cm2	x86_64"},
			wantErr: false,
		},
		{
			name:    "invalid path",
			input:   nonExistingManifest,
			want:    nil,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := rpmReadResultsManifest(tc.input)
			if (err != nil) != tc.wantErr {
				t.Errorf("rpmReadResultsManifest(%v) error = %v, wantErr %v", tc.input, err, tc.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("rpmReadResultsManifest(%v) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

func TestValidateRPMPackageVersions(t *testing.T) {
	rpmComparer := VersionComparer{isValidRPMVersion, isLessThanRPMVersion}

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
			name: "successful validation",
			updates: unversioned.UpdatePackages{
				{Name: "openssl", FixedVersion: "1.1.1k-21.cm2"},
				{Name: "openssl-libs", FixedVersion: "1.1.1k-21.cm2"},
			},
			cmp:          rpmComparer,
			resultsBytes: rpmValidManifest,
			ignoreErrors: false,
		},
		{
			name: "downloaded package version lower than required",
			updates: unversioned.UpdatePackages{
				{Name: "openssl", FixedVersion: "3.1.1k-21.cm2"},
				{Name: "openssl-libs", FixedVersion: "3.1.1k-21.cm2"},
			},
			cmp:          rpmComparer,
			resultsBytes: rpmValidManifest,
			ignoreErrors: false,
			expectedError: `2 errors occurred:
	* downloaded package openssl version 2.1.1k-21.cm2 lower than required 3.1.1k-21.cm2 for update
	* downloaded package openssl-libs version 2.1.1k-21.cm2 lower than required 3.1.1k-21.cm2 for update`,
			expectedErrPkgs: []string{"openssl", "openssl-libs"},
		},
		{
			name: "downloaded package version lower than required with ignore errors",
			updates: unversioned.UpdatePackages{
				{Name: "openssl", FixedVersion: "3.1.1k-21.cm2"},
				{Name: "openssl-libs", FixedVersion: "3.1.1k-21.cm2"},
			},
			cmp:          rpmComparer,
			resultsBytes: rpmValidManifest,
			ignoreErrors: true,
		},
		{
			name: "unexpected number of installed packages",
			updates: unversioned.UpdatePackages{
				{Name: "openssl", FixedVersion: "1.1.1k-21.cm2"},
			},
			cmp:           rpmComparer,
			resultsBytes:  rpmValidManifest,
			expectedError: `expected 1 updates, installed 2`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			errorPkgs, err := validateRPMPackageVersions(tc.updates, tc.cmp, tc.resultsBytes, tc.ignoreErrors)
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

func Test_rpmManager_GetPackageType(t *testing.T) {
	type fields struct {
		config        *buildkit.Config
		workingFolder string
		rpmTools      rpmToolPaths
		isDistroless  bool
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "rpm manager",
			fields: fields{
				config:        &buildkit.Config{},
				workingFolder: "/tmp",
				rpmTools:      rpmToolPaths{},
				isDistroless:  false,
			},
			want: "rpm",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rm := &rpmManager{
				config:        tt.fields.config,
				workingFolder: tt.fields.workingFolder,
				rpmTools:      tt.fields.rpmTools,
				isDistroless:  tt.fields.isDistroless,
			}
			if got := rm.GetPackageType(); got != tt.want {
				t.Errorf("rpmManager.GetPackageType() = %v, want %v", got, tt.want)
			}
		})
	}
}
