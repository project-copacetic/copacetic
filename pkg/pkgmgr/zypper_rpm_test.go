package pkgmgr

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test_getZypperToolingImageName tests the getZypperToolingImageName function.
func Test_getZypperToolingImageName(t *testing.T) {
	testCases := []struct {
		name      string // Adding name for better test identification
		osType    string
		osVersion string
		image     string
	}{
		{
			name:      "SLES 15.7",
			osType:    "sles",
			osVersion: "15.7",
			image:     "registry.suse.com/bci/bci-base:15.7",
		},
		{
			name:      "OpenSUSE Leap 15.6",
			osType:    "opensuse-leap",
			osVersion: "15.6",
			image:     "registry.opensuse.org/opensuse/leap:15.6",
		},
		{
			name:      "OpenSUSE Tumbleweed latest",
			osType:    "opensuse-tumbleweed",
			osVersion: "latest",
			image:     "registry.opensuse.org/opensuse/tumbleweed:latest",
		},
	}

	// Loop over test cases and run getZypperToolingImageName function with each input
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			image := getZypperToolingImageName(tc.osType, tc.osVersion)
			assert.Equal(t, tc.image, image)
		})
	}
}
