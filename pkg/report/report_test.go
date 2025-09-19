package report

import (
	"fmt"
	"os"
	"testing"

	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/utils"
	"github.com/stretchr/testify/assert"
)

// TestTryParseScanReport tests the TryParseScanReport function with different scan report files.
func TestTryParseScanReport(t *testing.T) {
	// Define test cases with input file and expected output manifest and error
	testCases := []struct {
		file     string
		manifest *unversioned.UpdateManifest
		err      error
	}{
		{
			file: "testdata/trivy_valid.json",
			manifest: &unversioned.UpdateManifest{
				Metadata: unversioned.Metadata{
					OS: unversioned.OS{
						Type:    "alpine",
						Version: "3.14.0",
					},
					Config: unversioned.Config{
						Arch: "amd64",
					},
				},
				OSUpdates: []unversioned.UpdatePackage{
					{
						Name:             "apk-tools",
						VulnerabilityID:  "CVE-2021-36159",
						FixedVersion:     "2.12.6-r0",
						InstalledVersion: "2.12.5-r1",
						Type:             "alpine",
						Class:            "os-pkgs",
					},
				},
				LangUpdates: []unversioned.UpdatePackage{},
			},
			err: nil,
		},
		{
			file:     "testdata/invalid.json",
			manifest: nil,
			err:      fmt.Errorf("testdata/invalid.json is not a supported scan report format"),
		},
	}

	// Loop over test cases and run TryParseScanReport function with each input file
	for _, tc := range testCases {
		t.Run(tc.file, func(t *testing.T) {
			manifest, err := TryParseScanReport(tc.file, "trivy", utils.PkgTypeOS, utils.PatchTypePatch)

			// Use testify package to assert that the output manifest and error match the expected ones
			assert.Equal(t, tc.manifest, manifest)
			assert.Equal(t, tc.err, err)
		})
	}
}

// TestErrorUnsupported tests the ErrorUnsupported error type.
func TestErrorUnsupported(t *testing.T) {
	originalErr := fmt.Errorf("original error message")
	errUnsupported := &ErrorUnsupported{err: originalErr}

	assert.Equal(t, "original error message", errUnsupported.Error())
	assert.Contains(t, errUnsupported.Error(), "original error message")
}

// TestConvertToUnversionedAPI tests the convertToUnversionedAPI function.
func TestConvertToUnversionedAPI(t *testing.T) {
	testCases := []struct {
		name          string
		scannerOutput []byte
		jsonMap       map[string]interface{}
		wantErr       bool
		errContains   string
	}{
		{
			name:          "valid v1alpha1 format",
			scannerOutput: []byte(`{"apiVersion":"v1alpha1","metadata":{"os":{"type":"alpine","version":"3.14.0"}},"updates":[]}`),
			jsonMap: map[string]interface{}{
				"apiVersion": "v1alpha1",
			},
			wantErr: false,
		},
		{
			name:          "unsupported apiVersion string",
			scannerOutput: []byte(`{"apiVersion":"v2"}`),
			jsonMap: map[string]interface{}{
				"apiVersion": "v2",
			},
			wantErr:     true,
			errContains: "unsupported apiVersion: v2",
		},
		{
			name:          "unsupported apiVersion type",
			scannerOutput: []byte(`{"apiVersion":123}`),
			jsonMap: map[string]interface{}{
				"apiVersion": 123,
			},
			wantErr:     true,
			errContains: "unsupported apiVersion type",
		},
		{
			name:          "missing apiVersion",
			scannerOutput: []byte(`{}`),
			jsonMap:       map[string]interface{}{},
			wantErr:       true,
			errContains:   "unsupported apiVersion type",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := convertToUnversionedAPI(tc.scannerOutput, tc.jsonMap)

			if tc.wantErr {
				assert.Error(t, err)
				if tc.errContains != "" {
					assert.Contains(t, err.Error(), tc.errContains)
				}
				// Check that error is of type ErrorUnsupported
				var errUnsupported *ErrorUnsupported
				assert.ErrorAs(t, err, &errUnsupported)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
			}
		})
	}
}

// TestCustomParseScanReport tests customParseScanReport function.
func TestCustomParseScanReport(t *testing.T) {
	testCases := []struct {
		name        string
		file        string
		scanner     string
		wantErr     bool
		errContains string
	}{
		{
			name:        "native scanner with non-existent file",
			file:        "non-existent-file.json",
			scanner:     "native",
			wantErr:     true,
			errContains: "error reading file",
		},
		{
			name:        "custom scanner not found",
			file:        "testdata/trivy_valid.json",
			scanner:     "nonexistent",
			wantErr:     true,
			errContains: "error running scanner nonexistent",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := customParseScanReport(tc.file, tc.scanner)

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

// TestTryParseScanReportWithNativeScanner tests TryParseScanReport with native scanner.
func TestTryParseScanReportWithNativeScanner(t *testing.T) {
	// Create a valid v1alpha1 format test file content
	validV1Alpha1Content := `{
		"apiVersion": "v1alpha1",
		"metadata": {
			"os": {
				"type": "alpine",
				"version": "3.14.0"
			},
			"config": {
				"arch": "amd64"
			}
		},
		"updates": [
			{
				"name": "test-pkg",
				"installedVersion": "1.0.0",
				"fixedVersion": "1.0.1",
				"vulnerabilityID": "CVE-2023-0001"
			}
		]
	}`

	// Write test file
	tmpFile := "testdata/native_test.json"
	err := os.WriteFile(tmpFile, []byte(validV1Alpha1Content), 0o600)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	defer os.Remove(tmpFile)

	result, err := TryParseScanReport(tmpFile, "native", utils.PkgTypeOS, utils.PatchTypePatch)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, utils.OSTypeAlpine, result.Metadata.OS.Type)
	assert.Equal(t, "3.14.0", result.Metadata.OS.Version)
	assert.Len(t, result.OSUpdates, 1)
	assert.Equal(t, "test-pkg", result.OSUpdates[0].Name)
}
