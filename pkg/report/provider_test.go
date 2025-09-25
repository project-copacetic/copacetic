package report

import (
	"fmt"
	"testing"

	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/utils"
	"github.com/stretchr/testify/assert"
)

// TestDummyProvider tests the TryParseScanReport function with dummy provider & different scan report files.
func TestDummyProvider(t *testing.T) {
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
						Type:    utils.OSTypeAlpine,
						Version: "3.14.0",
					},
					Config: unversioned.Config{
						Arch: "amd64",
					},
				},
				OSUpdates: []unversioned.UpdatePackage{
					{
						Name:             "apk-tools",
						InstalledVersion: "2.12.6-r0",
					},
				},
			},
			err: fmt.Errorf("error running scanner dummy: exec: \"copa-dummy\": executable file not found in $PATH"),
		},
		{
			file:     "testdata/invalid.json",
			manifest: nil,
			err:      fmt.Errorf("error running scanner dummy: exec: \"copa-dummy\": executable file not found in $PATH"),
		},
	}

	// Loop over test cases and run TryParseScanReport function with each input file
	for _, tc := range testCases {
		t.Run(tc.file, func(t *testing.T) {
			_, err := TryParseScanReport(tc.file, "dummy", utils.PkgTypeOS, utils.PatchTypePatch)

			// We will get error from dummy provider because the binary "copa-dummy" does not exist
			assert.EqualError(t, err, tc.err.Error())
		})
	}
}
