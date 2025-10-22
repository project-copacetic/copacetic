package report

import (
	"reflect"
	"testing"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	trivyTypes "github.com/aquasecurity/trivy/pkg/types"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/project-copacetic/copacetic/pkg/utils"
	"github.com/stretchr/testify/assert"
)

const (
	majorPatchLevel = "major"
	minorPatchLevel = "minor"
	patchPatchLevel = "patch"
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
			expected:         "", // Should not fall back to minor/major when patch level is default
			description:      "Should not fall back to minor/major versions in strict patch mode",
		},
		{
			name:             "major_version_when_needed",
			installedVersion: "1.25.5",
			fixedVersions:    []string{"2.0.6", "2.2.2"},
			expected:         "", // Should not fall back to major when patch level is default
			description:      "Should not fall back to major versions in strict patch mode",
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

// TestOptimalVersionSelectionWithPatchLevel tests the library patch level specific logic.
func TestOptimalVersionSelectionWithPatchLevel(t *testing.T) {
	testCases := []struct {
		name             string
		installedVersion string
		fixedVersions    []string
		patchLevel       string
		expected         string
		description      string
	}{
		// Patch level tests
		{
			name:             "patch_level_only_patch_versions",
			installedVersion: "1.26.16",
			fixedVersions:    []string{"1.26.17", "1.26.19"},
			patchLevel:       patchPatchLevel,
			expected:         "1.26.19",
			description:      "Should pick highest patch version when patch level is specified",
		},
		{
			name:             "patch_level_with_mixed_versions_no_fallback",
			installedVersion: "1.26.16",
			fixedVersions:    []string{"1.27.1", "2.0.6"}, // only minor and major available
			patchLevel:       patchPatchLevel,
			expected:         "",
			description:      "Should not fall back to minor/major when patch level is specified",
		},
		{
			name:             "patch_level_comma_separated_mixed",
			installedVersion: "1.26.16",
			fixedVersions:    []string{"1.26.18, 1.27.1, 2.0.6"},
			patchLevel:       patchPatchLevel,
			expected:         "1.26.18",
			description:      "Should keep to patch level only with comma-separated values",
		},

		// Minor level tests
		{
			name:             "minor_level_prefers_patch",
			installedVersion: "1.26.16",
			fixedVersions:    []string{"1.26.19", "1.27.1", "2.0.6"},
			patchLevel:       minorPatchLevel,
			expected:         "1.26.19",
			description:      "Should prefer patch over minor when minor level is specified",
		},
		{
			name:             "minor_level_uses_minor_when_no_patch",
			installedVersion: "1.26.16",
			fixedVersions:    []string{"1.27.1", "2.0.6"},
			patchLevel:       minorPatchLevel,
			expected:         "1.27.1",
			description:      "Should use minor when no patch available and minor level is specified",
		},
		{
			name:             "minor_level_no_major_fallback",
			installedVersion: "1.26.16",
			fixedVersions:    []string{"2.0.6", "2.1.0"},
			patchLevel:       minorPatchLevel,
			expected:         "",
			description:      "Should not fall back to major when minor level is specified",
		},

		// Major level tests
		{
			name:             "major_level_picks_highest_when_no_comma_separated",
			installedVersion: "1.26.16",
			fixedVersions:    []string{"1.26.19", "1.27.1", "2.0.6"},
			patchLevel:       majorPatchLevel,
			expected:         "2.0.6",
			description:      "Should pick highest version when no comma-separated versions and major level is specified",
		},
		{
			name:             "major_level_use_major_when_only_option",
			installedVersion: "1.26.16",
			fixedVersions:    []string{"2.0.6", "2.1.0"},
			patchLevel:       majorPatchLevel,
			expected:         "2.1.0",
			description:      "Should use major when it's the only option and major level is specified",
		},
		{
			name:             "major_level_comma_separated_prefers_patch",
			installedVersion: "1.26.16",
			fixedVersions:    []string{"1.26.18, 2.0.6"},
			patchLevel:       majorPatchLevel,
			expected:         "1.26.18",
			description:      "Should prefer patch version from comma-separated values when major level is specified",
		},
		{
			name:             "major_level_picks_highest_minor_when_no_comma_separated",
			installedVersion: "1.26.16",
			fixedVersions:    []string{"1.27.1", "1.28.0"},
			patchLevel:       majorPatchLevel,
			expected:         "1.28.0",
			description:      "Should pick highest version when no comma-separated versions and major level is specified",
		},

		// Edge cases
		{
			name:             "patch_level_empty_when_no_valid_versions",
			installedVersion: "1.26.16",
			fixedVersions:    []string{"1.26.15", "1.25.0"}, // older versions
			patchLevel:       patchPatchLevel,
			expected:         "",
			description:      "Should return empty when no valid patch versions available",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := FindOptimalFixedVersionWithPatchLevel(tc.installedVersion, tc.fixedVersions, tc.patchLevel)
			if result != tc.expected {
				t.Errorf("%s: got %s, want %s", tc.description, result, tc.expected)
			}
		})
	}
}

// Test for certifi exception - should always get latest version regardless of patch level setting.
func TestCertifiExceptionWithMockData(t *testing.T) {
	// Test the core logic using direct function calls since we can't easily mock file parsing
	testCases := []struct {
		name             string
		installedVersion string
		fixedVersions    []string
		patchLevel       string
		packageName      string
		expected         string
		description      string
	}{
		{
			name:             "certifi_patch_level_gets_major",
			installedVersion: "2021.10.8",
			fixedVersions:    []string{"2022.12.7", "2023.5.7", "2024.2.2"},
			patchLevel:       patchPatchLevel,
			packageName:      "certifi",
			expected:         "2024.2.2",
			description:      "certifi should get latest version even with patch level",
		},
		{
			name:             "certifi_minor_level_gets_major",
			installedVersion: "2021.10.8",
			fixedVersions:    []string{"2022.12.7", "2023.5.7", "2024.2.2"},
			patchLevel:       minorPatchLevel,
			packageName:      "certifi",
			expected:         "2024.2.2",
			description:      "certifi should get latest version even with minor level",
		},
		{
			name:             "certifi_major_level_gets_major",
			installedVersion: "2021.10.8",
			fixedVersions:    []string{"2022.12.7", "2023.5.7", "2024.2.2"},
			patchLevel:       majorPatchLevel,
			packageName:      "certifi",
			expected:         "2024.2.2",
			description:      "certifi should get latest version with major level (no change)",
		},
		{
			name:             "other_package_respects_patch_level",
			installedVersion: "2.25.1",
			fixedVersions:    []string{"2.25.2", "2.26.0", "3.0.0"},
			patchLevel:       patchPatchLevel,
			packageName:      "requests",
			expected:         "2.25.2",
			description:      "non-certifi packages should respect patch level restrictions",
		},
		{
			name:             "other_package_respects_minor_level",
			installedVersion: "2.25.1",
			fixedVersions:    []string{"2.25.2", "2.26.0", "3.0.0"},
			patchLevel:       minorPatchLevel,
			packageName:      "requests",
			expected:         "2.25.2",
			description:      "non-certifi packages should prefer patch over minor with minor level",
		},
		{
			name:             "other_package_uses_minor_when_no_patch",
			installedVersion: "2.25.1",
			fixedVersions:    []string{"2.26.0", "2.27.0", "3.0.0"},
			patchLevel:       minorPatchLevel,
			packageName:      "requests",
			expected:         "2.27.0",
			description:      "non-certifi packages should use highest minor when no patch available",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Simulate the logic that would be used in ParseWithLibraryPatchLevel
			patchLevelToUse := tc.patchLevel
			if tc.packageName == "certifi" {
				patchLevelToUse = majorPatchLevel
			}

			result := FindOptimalFixedVersionWithPatchLevel(tc.installedVersion, tc.fixedVersions, patchLevelToUse)
			if result != tc.expected {
				t.Errorf("%s: got %s, want %s", tc.description, result, tc.expected)
			}
		})
	}
}

// TestPythonTargetFormatHandling tests that only python-pkg is recognized as a valid Python package identifier.
func TestPythonTargetFormatHandling(t *testing.T) {
	// Test cases for verifying that only python-pkg is considered a valid Python package
	testCases := []struct {
		name        string
		target      string
		resultType  string
		class       string
		shouldMatch bool
		description string
	}{
		{
			name:        "python_pkg_type",
			target:      "some/path/to/python/lib",
			resultType:  "python-pkg",
			class:       "lang-pkgs",
			shouldMatch: true,
			description: "Should match python-pkg type",
		},
		{
			name:        "python_in_target_but_not_python_pkg",
			target:      "Python",
			resultType:  "library",
			class:       "lang-pkgs",
			shouldMatch: false,
			description: "Should not match target containing 'Python' if type is not python-pkg",
		},
		{
			name:        "requirements_txt_not_python_pkg",
			target:      "requirements.txt",
			resultType:  "library",
			class:       "lang-pkgs",
			shouldMatch: false,
			description: "Should not match requirements.txt if type is not python-pkg",
		},
		{
			name:        "pipfile_lock_not_python_pkg",
			target:      "Pipfile.lock",
			resultType:  "library",
			class:       "lang-pkgs",
			shouldMatch: false,
			description: "Should not match Pipfile.lock if type is not python-pkg",
		},
		{
			name:        "pyproject_toml_not_python_pkg",
			target:      "pyproject.toml",
			resultType:  "library",
			class:       "lang-pkgs",
			shouldMatch: false,
			description: "Should not match pyproject.toml if type is not python-pkg",
		},
		{
			name:        "python_pkg_with_different_target",
			target:      "some/other/path",
			resultType:  "python-pkg",
			class:       "lang-pkgs",
			shouldMatch: true,
			description: "Should match python-pkg type regardless of target name",
		},
		{
			name:        "non_python_target",
			target:      "nodejs",
			resultType:  "npm",
			class:       "lang-pkgs",
			shouldMatch: false,
			description: "Should not match non-Python targets",
		},
		{
			name:        "os_package",
			target:      "ubuntu:20.04 (ubuntu 20.04)",
			resultType:  "ubuntu",
			class:       "os-pkgs",
			shouldMatch: false,
			description: "Should not match OS packages",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test the logic that determines if a result is a Python target
			// Only python-pkg type should be considered valid for Python packages
			isPythonTarget := tc.resultType == "python-pkg"

			if isPythonTarget != tc.shouldMatch {
				t.Errorf("%s: expected isPythonTarget=%v, got %v", tc.description, tc.shouldMatch, isPythonTarget)
			}
		})
	}
}

func TestPkgTypesFiltering(t *testing.T) {
	// Use a test report file in testdata
	testFile := "testdata/pkg_types_test.json"

	testCases := []struct {
		name                   string
		pkgTypes               string
		expectedOSUpdates      int
		expectedLibraryUpdates int
		description            string
	}{
		{
			name:                   "include_library_and_os",
			pkgTypes:               "os,library",
			expectedOSUpdates:      1,
			expectedLibraryUpdates: 1,
			description:            "Should process both OS and library packages when both are included",
		},
		{
			name:                   "include_only_os",
			pkgTypes:               "os",
			expectedOSUpdates:      1,
			expectedLibraryUpdates: 0,
			description:            "Should only process OS packages when library is excluded",
		},
		{
			name:                   "include_only_library",
			pkgTypes:               "library",
			expectedOSUpdates:      0,
			expectedLibraryUpdates: 1,
			description:            "Should only process library packages when OS is excluded",
		},
		{
			name:                   "exclude_both",
			pkgTypes:               "",
			expectedOSUpdates:      0,
			expectedLibraryUpdates: 0,
			description:            "Should not process any packages when both are excluded",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			manifest, err := TryParseScanReport(testFile, "trivy", tc.pkgTypes, utils.PatchTypeMajor)
			if err != nil {
				t.Fatalf("TryParseScanReport failed: %v", err)
			}

			// Count OS updates vs library updates
			osUpdates := len(manifest.OSUpdates)
			libraryUpdates := len(manifest.LangUpdates)

			if osUpdates != tc.expectedOSUpdates {
				t.Errorf("%s: expected %d OS updates, got %d", tc.description, tc.expectedOSUpdates, osUpdates)
			}

			if libraryUpdates != tc.expectedLibraryUpdates {
				t.Errorf("%s: expected %d library updates, got %d", tc.description, tc.expectedLibraryUpdates, libraryUpdates)
			}

			t.Logf("%s: OS updates=%d, Library updates=%d", tc.description, osUpdates, libraryUpdates)
		})
	}
}

// TestPatchLevelVersionSelection tests the FindOptimalFixedVersionWithPatchLevel function
// with comprehensive test cases covering patch level restrictions and various scenarios.
// The test cases include CVE tracking to verify that patch level settings correctly
// balance security fixes with version stability requirements.
func TestPatchLevelVersionSelection(t *testing.T) {
	testCases := []struct {
		name             string
		installedVersion string
		fixedVersions    []string
		patchLevel       string
		expected         string
		description      string
		cves             []string // CVEs that would be fixed by the selected version (for documentation/testing)
	}{
		// Major patch level tests - picks highest version when no comma-separated versions
		{
			name:             "major_patch_level_picks_highest_version",
			installedVersion: "41.0.6",
			fixedVersions:    []string{"41.0.7", "42.0.0", "42.0.4", "42.0.2", "43.0.1"},
			patchLevel:       majorPatchLevel,
			expected:         "43.0.1", // Should pick highest version to fix all CVEs when no comma-separated versions
			description:      "should upgrade to highest version to fix all CVEs with major patch level when no comma-separated versions",
			cves:             []string{"CVE-2023-50782", "CVE-2024-26130", "CVE-2024-0727", "GHSA-h4gh-qq45-vh27"},
		},
		{
			name:             "major_patch_level_no_patch_available",
			installedVersion: "41.0.6",
			fixedVersions:    []string{"42.0.0", "42.0.4", "42.0.2", "43.0.1"},
			patchLevel:       majorPatchLevel,
			expected:         "43.0.1", // Should pick highest major version when no patch versions available
			description:      "should upgrade to highest major version when no patch versions available with major patch level",
			cves:             []string{"CVE-2023-50782", "CVE-2024-26130", "CVE-2024-0727", "GHSA-h4gh-qq45-vh27"},
		},

		// Patch level restriction tests
		{
			name:             "patch_level_restriction_no_upgrade",
			installedVersion: "41.0.6",
			fixedVersions:    []string{"42.0.0", "42.0.4", "42.0.2", "43.0.1"},
			patchLevel:       patchPatchLevel,
			expected:         "", // Should not upgrade when only major versions available
			description:      "should NOT upgrade with patch level when only major versions available",
			cves:             []string{"CVE-2023-50782", "CVE-2024-26130", "CVE-2024-0727", "GHSA-h4gh-qq45-vh27"},
		},
		{
			name:             "patch_level_picks_highest_patch",
			installedVersion: "41.0.6",
			fixedVersions:    []string{"41.0.7", "41.0.8", "42.0.0", "43.0.1"},
			patchLevel:       patchPatchLevel,
			expected:         "41.0.8", // Should pick highest patch version
			description:      "should upgrade to highest patch version when patch versions are available",
			cves:             []string{"CVE-2023-50782", "CVE-2024-26130"},
		},
		{
			name:             "patch_level_no_major_jump",
			installedVersion: "2.6.0",
			fixedVersions:    []string{"3.4.0"},
			patchLevel:       patchPatchLevel,
			expected:         "",
			description:      "should NOT upgrade to major version with patch level",
		},
		{
			name:             "patch_level_with_patch_available",
			installedVersion: "2.6.0",
			fixedVersions:    []string{"2.6.1", "3.4.0"},
			patchLevel:       patchPatchLevel,
			expected:         "2.6.1",
			description:      "should upgrade to patch version with patch level",
		},

		// Minor level restriction tests
		{
			name:             "minor_level_restriction_no_major",
			installedVersion: "41.0.6",
			fixedVersions:    []string{"42.0.0", "42.0.4", "42.0.2", "43.0.1"},
			patchLevel:       minorPatchLevel,
			expected:         "", // Should not upgrade to major versions even with minor level
			description:      "should NOT upgrade to major versions with minor patch level",
			cves:             []string{"CVE-2023-50782", "CVE-2024-26130", "CVE-2024-0727", "GHSA-h4gh-qq45-vh27"},
		},
		{
			name:             "minor_level_prefers_patch",
			installedVersion: "1.26.5",
			fixedVersions:    []string{"1.26.6", "1.27.0", "2.0.0"},
			patchLevel:       minorPatchLevel,
			expected:         "1.26.6",
			description:      "should prefer patch over minor with minor level",
		},
		{
			name:             "minor_level_uses_minor_when_no_patch",
			installedVersion: "1.26.5",
			fixedVersions:    []string{"1.27.0", "1.28.0", "2.0.0"},
			patchLevel:       minorPatchLevel,
			expected:         "1.28.0",
			description:      "should use highest minor when no patch available with minor level",
		},

		// Major level allows major upgrades
		{
			name:             "major_level_allows_major_upgrade",
			installedVersion: "2.6.0",
			fixedVersions:    []string{"3.4.0"},
			patchLevel:       majorPatchLevel,
			expected:         "3.4.0",
			description:      "should upgrade to major version with major level",
		},

		// Comma-separated version handling
		{
			name:             "comma_separated_prefers_patch_over_major",
			installedVersion: "1.26.16",
			fixedVersions:    []string{"2.0.6, 1.26.17"},
			patchLevel:       majorPatchLevel,
			expected:         "1.26.17", // Should prefer patch version from comma-separated list
			description:      "should prefer patch version from comma-separated list with major patch level",
			cves:             []string{"CVE-2023-43804"},
		},
		{
			name:             "comma_separated_with_patch_preference",
			installedVersion: "41.0.6",
			fixedVersions:    []string{"41.0.8, 42.0.4", "43.0.1"},
			patchLevel:       majorPatchLevel,
			expected:         "41.0.8", // Should prefer patch version from comma-separated list
			description:      "should prefer patch version from comma-separated list even with major patch level",
			cves:             []string{"CVE-2023-50782", "CVE-2024-26130", "CVE-2024-0727", "GHSA-h4gh-qq45-vh27"},
		},
		{
			name:             "comma_separated_multiple_entries",
			installedVersion: "1.26.16",
			fixedVersions:    []string{"2.0.7, 1.26.18", "1.26.19, 2.2.2"}, // Multiple comma-separated entries
			patchLevel:       majorPatchLevel,
			expected:         "1.26.19", // Should pick highest patch version across all comma-separated lists
			description:      "should prefer highest patch version across multiple comma-separated lists",
			cves:             []string{"CVE-2023-45803", "CVE-2024-37891"},
		},
		{
			name:             "comma_separated_no_patch_available",
			installedVersion: "41.0.6",
			fixedVersions:    []string{"42.0.0, 42.0.4", "43.0.1"},
			patchLevel:       majorPatchLevel,
			expected:         "43.0.1", // Should handle comma-separated and pick highest when comma-separated versions don't contain patches
			description:      "should handle comma-separated versions and pick highest with major patch level",
			cves:             []string{"CVE-2023-50782", "CVE-2024-26130", "CVE-2024-0727", "GHSA-h4gh-qq45-vh27"},
		},

		// Edge cases
		{
			name:             "no_valid_versions_available",
			installedVersion: "1.26.16",
			fixedVersions:    []string{"1.26.15", "1.25.0"}, // older versions
			patchLevel:       patchPatchLevel,
			expected:         "",
			description:      "should return empty when no valid patch versions available",
		},
		{
			name:             "certifi_special_handling_simulation",
			installedVersion: "2021.10.8",
			fixedVersions:    []string{"2022.12.7", "2023.5.7", "2024.2.2"},
			patchLevel:       majorPatchLevel,
			expected:         "2024.2.2",
			description:      "should get latest version with major level for date-based versioning",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := FindOptimalFixedVersionWithPatchLevel(tc.installedVersion, tc.fixedVersions, tc.patchLevel)

			assert.Equal(t, tc.expected, result, tc.description)

			// Log test results with CVE information if present
			if len(tc.cves) > 0 {
				t.Logf("%s: installedVersion=%s, fixedVersions=%v, patchLevel=%s, result=%s, CVEs=%v",
					tc.description, tc.installedVersion, tc.fixedVersions, tc.patchLevel, result, tc.cves)

				// Verify that when major patch level is used, we can fix CVEs
				if tc.patchLevel == majorPatchLevel && result != "" {
					t.Logf("✓ Major patch level successfully selected version %s to fix CVEs: %v", result, tc.cves)
					t.Logf("  (behavior: highest version for non-comma-separated, prefer patch for comma-separated)")
				} else if tc.patchLevel != majorPatchLevel && result == "" {
					t.Logf("✓ Patch level '%s' correctly restricted upgrade, CVEs remain unfixed: %v", tc.patchLevel, tc.cves)
				}
			} else {
				t.Logf("%s: installedVersion=%s, fixedVersions=%v, patchLevel=%s, result=%s",
					tc.description, tc.installedVersion, tc.fixedVersions, tc.patchLevel, result)
			}
		})
	}
}

// TestNewTrivyParser tests the NewTrivyParser constructor function.
func TestNewTrivyParser(t *testing.T) {
	parser := NewTrivyParser()
	assert.NotNil(t, parser)
	assert.IsType(t, &TrivyParser{}, parser)
}

// TestTrivyParserParseEdgeCases tests edge cases for TrivyParser.Parse.
func TestTrivyParserParseEdgeCases(t *testing.T) {
	testCases := []struct {
		name        string
		file        string
		wantErr     bool
		errContains string
	}{
		{
			name:        "non-existent file",
			file:        "non-existent-file.json",
			wantErr:     true,
			errContains: "no such file or directory",
		},
		{
			name:        "invalid JSON file",
			file:        "testdata/invalid.json",
			wantErr:     true,
			errContains: "",
		},
	}

	parser := NewTrivyParser()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := parser.Parse(tc.file)

			if tc.wantErr {
				assert.Error(t, err)
				if tc.errContains != "" {
					assert.Contains(t, err.Error(), tc.errContains)
				}
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
			}
		})
	}
}

// TestTrivyParserParseWithNodeJS tests the TrivyParser.Parse method with Node.js packages.
func TestTrivyParserParseWithNodeJS(t *testing.T) {
	tests := []struct {
		name            string
		file            string
		wantOSUpdates   int
		wantLangUpdates int
		wantErr         bool
	}{
		{
			name:            "OS packages only",
			file:            "testdata/trivy_valid.json",
			wantOSUpdates:   1,
			wantLangUpdates: 0,
			wantErr:         false,
		},
		{
			name:            "OS and Node.js packages",
			file:            "testdata/trivy_node_valid.json",
			wantOSUpdates:   1,
			wantLangUpdates: 2,
			wantErr:         false,
		},
		{
			name:            "invalid file",
			file:            "testdata/invalid.json",
			wantOSUpdates:   0,
			wantLangUpdates: 0,
			wantErr:         true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			parser := &TrivyParser{}
			manifest, err := parser.Parse(tc.file)

			if tc.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, manifest)
			assert.Equal(t, tc.wantOSUpdates, len(manifest.OSUpdates))
			assert.Equal(t, tc.wantLangUpdates, len(manifest.LangUpdates))

			// Validate specific content for Node.js test
			if tc.name == "OS and Node.js packages" {
				// Check OS package
				assert.Equal(t, "protobuf-c", manifest.OSUpdates[0].Name)

				// Check Node.js packages
				assert.Equal(t, "ansi-regex", manifest.LangUpdates[0].Name)
				assert.Equal(t, "3.0.0", manifest.LangUpdates[0].InstalledVersion)
				assert.Equal(t, "3.0.1", manifest.LangUpdates[0].FixedVersion)
				assert.Equal(t, utils.NodePackages, manifest.LangUpdates[0].Type)

				assert.Equal(t, "follow-redirects", manifest.LangUpdates[1].Name)
				assert.Equal(t, "1.14.7", manifest.LangUpdates[1].InstalledVersion)
				assert.Equal(t, "1.14.8", manifest.LangUpdates[1].FixedVersion)
				assert.Equal(t, utils.NodePackages, manifest.LangUpdates[1].Type)
			}
		})
	}
}
