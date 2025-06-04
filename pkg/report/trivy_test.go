package report

import (
	"reflect"
	"testing"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	trivyTypes "github.com/aquasecurity/trivy/pkg/types"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// TestParseTrivyReport tests the parseTrivyReport function.
func TestParseTrivyReport(t *testing.T) {
	// Define a table of test cases with inputs and expected outputs
	tests := []struct {
		name    string
		file    string
		msr     *trivyTypes.Report
		wantErr bool
	}{
		{
			name: "valid file",
			file: "testdata/trivy_valid.json",
			msr: &trivyTypes.Report{
				SchemaVersion: 2,
				ArtifactName:  "alpine:3.14.0",
				ArtifactType:  "container_image",
				Metadata: trivyTypes.Metadata{
					OS: &ftypes.OS{
						Family: "alpine",
						Name:   "3.14.0",
					},
					ImageConfig: v1.ConfigFile{
						Architecture: "amd64",
					},
				},
				Results: []trivyTypes.Result{
					{
						Target: "alpine:3.14.0 (alpine 3.14.0)",
						Class:  trivyTypes.ClassOSPkg,
						Type:   "alpine",
						Vulnerabilities: []trivyTypes.DetectedVulnerability{
							{
								VulnerabilityID:  "CVE-2021-36159",
								PkgID:            "apk-tools@2.12.5-r1",
								PkgName:          "apk-tools",
								InstalledVersion: "2.12.5-r1",
								FixedVersion:     "2.12.6-r0",
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name:    "invalid file",
			file:    "testdata/invalid.json",
			msr:     nil,
			wantErr: true,
		},
	}

	// Iterate over the test cases and run each subtest with t.Run
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Call the function under test with the input from the test case
			msr, err := parseTrivyReport(tc.file)

			// Check if the output matches the expected output from the test case
			if !reflect.DeepEqual(msr, tc.msr) {
				t.Errorf("got %v, want %v", msr, tc.msr)
			}

			if err != nil && !tc.wantErr {
				t.Errorf("got error %v, want no error", err)
			}
		})
	}
}

// TestOptimalVersionSelection tests the optimal version selection logic.
func TestOptimalVersionSelection(t *testing.T) {
	// Test the optimal version selection logic
	testCases := []struct {
		name             string
		installedVersion string
		fixedVersions    []string
		expected         string
		description      string
	}{
		{
			name:             "patch_version_preference",
			installedVersion: "1.26.16",
			fixedVersions:    []string{"1.26.19", "2.0.6", "1.26.17"},
			expected:         "1.26.19", // Should pick highest patch version that fixes all CVEs
			description:      "Should prefer patch version over major version bump",
		},
		{
			name:             "minor_version_preference",
			installedVersion: "1.25.5",
			fixedVersions:    []string{"1.26.19", "2.0.6", "1.27.1"},
			expected:         "1.27.1", // Should pick highest minor version that fixes all CVEs
			description:      "Should prefer minor version over major version bump",
		},
		{
			name:             "major_version_when_needed",
			installedVersion: "1.25.5",
			fixedVersions:    []string{"2.0.6", "2.2.2"},
			expected:         "2.2.2", // Should pick highest major version when no other option
			description:      "Should pick highest major version when no other choice",
		},
		{
			name:             "comma_separated_versions",
			installedVersion: "1.26.16",
			fixedVersions:    []string{"2.0.7, 1.26.18"},
			expected:         "1.26.18", // Should handle comma-separated and pick most compatible patch version
			description:      "Should handle comma-separated versions correctly and prefer compatibility",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := findOptimalFixedVersion(tc.installedVersion, tc.fixedVersions)
			if result != tc.expected {
			    t.Errorf("got %s, want %s", result, tc.expected)
			}
		})
	}
}
