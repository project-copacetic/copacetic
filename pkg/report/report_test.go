// ------------------------------------------------------------
// Copyright (c) Project Copacetic authors.
// Licensed under the MIT License.
// ------------------------------------------------------------

package report

import (
	"fmt"
	"testing"

	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/stretchr/testify/assert"
)

// TestTryParseScanReport tests the TryParseScanReport function with different scan report files.
func TestTryParseScanReport(t *testing.T) {
	// Define test cases with input file and expected output manifest and error
	testCases := []struct {
		file     string
		manifest *types.UpdateManifest
		err      error
	}{
		{
			file: "testdata/trivy_valid.json",
			manifest: &types.UpdateManifest{
				OSType:    "alpine",
				OSVersion: "3.14.0",
				Arch:      "amd64",
				Updates: []types.UpdatePackage{
					{
						Name:    "apk-tools",
						Version: "2.12.6-r0",
					},
				},
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
			manifest, err := TryParseScanReport(tc.file)

			// Use testify package to assert that the output manifest and error match the expected ones
			assert.Equal(t, tc.manifest, manifest)
			assert.Equal(t, tc.err, err)
		})
	}
}
