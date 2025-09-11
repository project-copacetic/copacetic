package pkgmgr

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/moby/buildkit/client/llb"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/project-copacetic/copacetic/mocks"
	"github.com/stretchr/testify/mock"

	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/utils"
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
	testCases := []struct {
		name      string // Adding name for better test identification
		manifest  *unversioned.UpdateManifest
		osType    string
		osVersion string
		image     string
	}{
		{
			name: "CBL-Mariner 2.0",
			manifest: &unversioned.UpdateManifest{
				Metadata: unversioned.Metadata{
					OS: unversioned.OS{
						Type:    "cbl-mariner",
						Version: "2.0.0",
					},
				},
			},
			osType:    "cbl-mariner",
			osVersion: "2.0.0",
			image:     "ghcr.io/project-copacetic/copacetic/cbl-mariner/base/core:2.0",
		},
		{
			name: "CBL-Mariner 1.5",
			manifest: &unversioned.UpdateManifest{
				Metadata: unversioned.Metadata{
					OS: unversioned.OS{
						Type:    "cbl-mariner",
						Version: "1.5",
					},
				},
			},
			osType:    "cbl-mariner",
			osVersion: "1.5",
			image:     "ghcr.io/project-copacetic/copacetic/cbl-mariner/base/core:1.5",
		},
		{
			name: "CBL-Mariner 3 (default minor version)",
			manifest: &unversioned.UpdateManifest{
				Metadata: unversioned.Metadata{
					OS: unversioned.OS{
						Type:    "cbl-mariner",
						Version: "3",
					},
				},
			},
			osType:    "cbl-mariner",
			osVersion: "3",
			image:     "ghcr.io/project-copacetic/copacetic/cbl-mariner/base/core:3.0",
		},
		{
			name: "Azure Linux 3.0",
			manifest: &unversioned.UpdateManifest{
				Metadata: unversioned.Metadata{
					OS: unversioned.OS{
						Type:    "azurelinux",
						Version: "3.0",
					},
				},
			},
			osType:    "azurelinux",
			osVersion: "3.0",
			image:     "ghcr.io/project-copacetic/copacetic/azurelinux/base/core:3.0",
		},
		{
			name:      "Azure Linux 3.0 without update manifest",
			manifest:  &unversioned.UpdateManifest{},
			osType:    "azurelinux",
			osVersion: "3.0",
			image:     "ghcr.io/project-copacetic/copacetic/azurelinux/base/core:3.0",
		},
		{
			name:      "Azure Linux future version",
			manifest:  &unversioned.UpdateManifest{},
			osType:    "azurelinux",
			osVersion: "999.0",
			image:     "ghcr.io/project-copacetic/copacetic/azurelinux/base/core:999.0",
		},
		{
			name:      "RedHat (defaults to Azure Linux)",
			manifest:  &unversioned.UpdateManifest{},
			osType:    "redhat",
			osVersion: "8.4",
			image:     "ghcr.io/project-copacetic/copacetic/cbl-mariner/base/core:2.0", // uses default CBL-Mariner image
		},
		{
			name:      "Nil manifest",
			manifest:  nil,
			osType:    "",
			osVersion: "",
			image:     "ghcr.io/project-copacetic/copacetic/cbl-mariner/base/core:2.0", // uses default CBL-Mariner image
		},
	}

	// Loop over test cases and run getRPMImageName function with each input
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			image := getRPMImageName(tc.manifest, tc.osType, tc.osVersion, true)
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
				workingFolder: utils.DefaultTempWorkingFolder,
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

func TestIsValidVersion(t *testing.T) {
	tests := []struct {
		testName    string
		pkgVersion  string
		expectedErr string
	}{
		{
			testName:    "Valid version, numbers and dot",
			pkgVersion:  "1.2.3.4",
			expectedErr: "",
		},
		{
			testName:    "Valid version, with hyphen",
			pkgVersion:  "1.2.3-beta",
			expectedErr: "",
		},
		{
			testName:    "Valid version, with underscore",
			pkgVersion:  "2_0_0",
			expectedErr: "",
		},
		{
			testName:    "Valid version, with tilde",
			pkgVersion:  "3.0.1~rc1",
			expectedErr: "",
		},
		{
			testName:    "Valid version, with colon",
			pkgVersion:  "2:9.0.1314-1.amzn2.0.1",
			expectedErr: "",
		},
		{
			testName:    "Invalid version, starts with letter",
			pkgVersion:  "a1.2.3",
			expectedErr: "upstream_version must start with digit",
		},
		{
			testName:    "Invalid version, has spaces",
			pkgVersion:  "1.2.3 with fix",
			expectedErr: "upstream_version 1.2.3 with fix includes invalid character ' '",
		},
		{
			testName:    "Invalid version, has special character",
			pkgVersion:  "1.2.3@",
			expectedErr: "upstream_version 1.2.3@ includes invalid character '@'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.testName, func(t *testing.T) {
			err := isValidVersion(tt.pkgVersion)
			if (err != nil && err.Error() != tt.expectedErr) || (err == nil && tt.expectedErr != "") {
				t.Errorf("isValidPackage(%q) error = %v, want %v", tt.pkgVersion, err, tt.expectedErr)
			}
		})
	}
}

func TestParseManifestFile(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected map[string]string
		wantErr  bool
	}{
		{
			name:  "Valid input",
			input: "package1\t1.0.0.cm2\npackage2\t2.3.4.cm2\n",
			expected: map[string]string{
				"package1": "1.0.0.cm2",
				"package2": "2.3.4.cm2",
			},
			wantErr: false,
		},
		{
			name:     "Empty input",
			input:    "",
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "Input with extra newline",
			input:    "package1\t1.0.0.cm2\npackage2\t2.3.4.cm2\n\n",
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "Invalid format - missing version",
			input:    "package1\t1.0.0.cm2\npackage2\n",
			expected: nil,
			wantErr:  true,
		},
		{
			name:  "Input with extra tabs",
			input: "package1\t1.0.0.cm2\textra\npackage2\t2.3.4.cm2\n",
			expected: map[string]string{
				"package1": "1.0.0.cm2",
				"package2": "2.3.4.cm2",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseManifestFile(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseManifestFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("parseManifestFile() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func Test_installUpdates_RPM(t *testing.T) {
	tests := []struct {
		name           string
		updates        unversioned.UpdatePackages
		ignoreErrors   bool
		mockSetup      func(reference *mocks.MockReference)
		rpmTools       rpmToolPaths
		expectedResult []byte
		expectedError  string
	}{
		{
			name: "DNF update all packages",
			mockSetup: func(mr *mocks.MockReference) {
				mr.On("ReadFile", mock.Anything, mock.Anything).Return([]byte(""), nil)
			},
			rpmTools: rpmToolPaths{
				"dnf": "/usr/bin/dnf",
			},
			expectedResult: nil,
		},
		{
			name: "YUM update all packages",
			mockSetup: func(mr *mocks.MockReference) {
				mr.On("ReadFile", mock.Anything, mock.Anything).Return([]byte(""), nil)
			},
			rpmTools: rpmToolPaths{
				"yum": "/usr/bin/yum",
				"rpm": "/usr/bin/rpm",
			},
			expectedResult: nil,
		},
		{
			name: "MicroDNF update all packages",
			mockSetup: func(mr *mocks.MockReference) {
				mr.On("ReadFile", mock.Anything, mock.Anything).Return([]byte(""), nil)
			},
			rpmTools: rpmToolPaths{
				"microdnf": "/usr/bin/microdnf",
				"rpm":      "/usr/bin/rpm",
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
			rpmTools: rpmToolPaths{
				"dnf": "/usr/bin/dnf",
			},
			ignoreErrors:   false,
			expectedResult: []byte("package1-1.0.1\npackage2-2.0.2\n"),
		},
		{
			name:          "No package manager available",
			rpmTools:      rpmToolPaths{},
			expectedError: "unexpected: no package manager tools were found for patching",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := new(mocks.MockGWClient)
			mockRef := new(mocks.MockReference)

			mockResult := &gwclient.Result{}
			mockResult.SetRef(mockRef)

			if tt.mockSetup != nil {
				mockClient.On("Solve", mock.Anything, mock.Anything).Return(mockResult, nil)
			}

			if tt.mockSetup != nil {
				tt.mockSetup(mockRef)
			}

			rm := &rpmManager{
				config: &buildkit.Config{
					Client:     mockClient,
					ImageState: llb.Scratch(),
				},
				rpmTools: tt.rpmTools,
			}

			updatedState, resultBytes, err := rm.installUpdates(context.TODO(), tt.updates, tt.ignoreErrors)

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

func Test_unpackAndMergeUpdates_RPM(t *testing.T) {
	// Due to the generateToolInstallCmd function, we need to pass in a package manager as well
	// Without a package manager passed in, these tests all fail
	tests := []struct {
		name           string
		updates        unversioned.UpdatePackages
		mockSetup      func(reference *mocks.MockReference)
		toolImage      string
		ignoreErrors   bool
		expectedError  bool
		expectedResult []byte
	}{
		{
			name: "Successful update with specific packages",
			mockSetup: func(mr *mocks.MockReference) {
				mr.On("ReadFile", mock.Anything, mock.Anything).Return([]byte("package1\t1.2.3\tx86_64\npackage2\t2.3.4\tx86_64\ntdnf"), nil)
			},
			updates: unversioned.UpdatePackages{
				{Name: "package1", FixedVersion: "1.2.3"},
				{Name: "package2", FixedVersion: "2.3.4"},
			},
			toolImage:      "test-tool-image:latest",
			ignoreErrors:   false,
			expectedError:  false,
			expectedResult: []byte("package1\t1.2.3\tx86_64\npackage2\t2.3.4\tx86_64\ntdnf"),
		},
		{
			name: "Successful update all packages",
			mockSetup: func(mr *mocks.MockReference) {
				mr.On("ReadFile", mock.Anything, mock.Anything).Return([]byte("tdnf"), nil)
			},
			updates:        nil,
			toolImage:      "test-tool-image:latest",
			ignoreErrors:   false,
			expectedResult: []byte("tdnf"),
			expectedError:  false,
		},
		{
			name: "Ignore errors during update",
			mockSetup: func(mr *mocks.MockReference) {
				mr.On("ReadFile", mock.Anything, mock.Anything).Return([]byte("package1\t1.0.1\ntdnf"), nil)
			},
			updates: unversioned.UpdatePackages{
				{Name: "package1", FixedVersion: "2.0.0"},
			},
			toolImage:      "test-tool-image:latest",
			ignoreErrors:   true,
			expectedError:  false,
			expectedResult: []byte("package1\t1.0.1\ntdnf"),
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

			rm := &rpmManager{
				config: &buildkit.Config{
					Client:     mockClient,
					ImageState: llb.Scratch(),
				},
			}

			result, resultBytes, err := rm.unpackAndMergeUpdates(context.TODO(), tt.updates, tt.toolImage, tt.ignoreErrors)

			// Assert
			if tt.expectedError {
				assert.Error(t, err)
				assert.Nil(t, result)
				assert.Nil(t, resultBytes)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.Equal(t, tt.expectedResult, resultBytes)
			}

			mockClient.AssertExpectations(t)
			mockRef.AssertExpectations(t)
		})
	}
}

func Test_getJSONPackageData_RPM(t *testing.T) {
	tests := []struct {
		name           string
		packageInfo    map[string]string
		wantErr        bool
		expectedResult []byte
	}{
		{
			name:           "Successful parsing of rm.PackageInfo",
			wantErr:        false,
			expectedResult: []byte("{\"filesystem\":\"1.1-19.cm2\",\"mariner-release\":\"2.0-56.cm2\"}"),
			packageInfo: map[string]string{
				"filesystem":      "1.1-19.cm2",
				"mariner-release": "2.0-56.cm2",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := getJSONPackageData(tt.packageInfo)

			if (err != nil) != tt.wantErr {
				t.Errorf("getJSONPackageData(%v) error = %v, wantErr %v", err, err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(result, tt.expectedResult) {
				t.Errorf("getJSONPackageData() = %v, want %v", result, tt.expectedResult)
			}
		})
	}
}
