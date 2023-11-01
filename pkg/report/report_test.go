package report

import (
	"fmt"
	"testing"

	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
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
				Updates: []unversioned.UpdatePackage{
					{
						Name:             "apk-tools",
						VulnerabilityID:  "CVE-2021-36159",
						FixedVersion:     "2.12.6-r0",
						InstalledVersion: "2.12.5-r1",
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
			manifest, err := TryParseScanReport(tc.file, "trivy")

			// Use testify package to assert that the output manifest and error match the expected ones
			assert.Equal(t, tc.manifest, manifest)
			assert.Equal(t, tc.err, err)
		})
	}
}
