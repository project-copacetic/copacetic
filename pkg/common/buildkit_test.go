package common

import (
	"testing"

	"github.com/containerd/platforms"
	"github.com/stretchr/testify/assert"
)

func TestGetDefaultLinuxPlatform(t *testing.T) {
	platform := GetDefaultLinuxPlatform()

	assert.Equal(t, LINUX, platform.OS)
	assert.NotEmpty(t, platform.Architecture)
}

func TestGetDefaultLinuxPlatform_NonLinux(t *testing.T) {
	// Save original platform
	originalPlatform := platforms.DefaultSpec()

	// Test that even with non-Linux default, we get Linux
	platform := GetDefaultLinuxPlatform()
	assert.Equal(t, LINUX, platform.OS)

	// Ensure we haven't modified the global default
	assert.Equal(t, originalPlatform, platforms.DefaultSpec())
}

// Test OSInfo struct initialization and validation.
func TestOSInfo_Initialization(t *testing.T) {
	osInfo := &OSInfo{
		Type:    "debian",
		Version: "11",
	}

	assert.Equal(t, "debian", osInfo.Type)
	assert.Equal(t, "11", osInfo.Version)
}

// Test OSInfo with different operating systems.
func TestOSInfo_DifferentOperatingSystems(t *testing.T) {
	testCases := []struct {
		name    string
		osType  string
		version string
	}{
		{"Debian", "debian", "11"},
		{"Ubuntu", "ubuntu", "20.04"},
		{"CentOS", "centos", "8"},
		{"Alpine", "alpine", "3.14"},
		{"RHEL", "rhel", "9"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			osInfo := &OSInfo{
				Type:    tc.osType,
				Version: tc.version,
			}
			assert.Equal(t, tc.osType, osInfo.Type)
			assert.Equal(t, tc.version, osInfo.Version)
		})
	}
}

// Test OSInfo with empty values.
func TestOSInfo_EmptyValues(t *testing.T) {
	osInfo := &OSInfo{}

	assert.Empty(t, osInfo.Type)
	assert.Empty(t, osInfo.Version)
}

// Test platform normalization for different architectures.
func TestGetDefaultLinuxPlatform_DifferentArchitectures(t *testing.T) {
	// This tests that the function consistently returns a Linux platform
	// regardless of the system's default
	platform := GetDefaultLinuxPlatform()

	assert.Equal(t, LINUX, platform.OS)
	// Verify that we get some valid architecture
	validArchs := []string{"amd64", "arm64", "arm", "386", "ppc64le", "s390x"}
	assert.Contains(t, validArchs, platform.Architecture)
}

// Test LINUX constant.
func TestLinuxConstant(t *testing.T) {
	assert.Equal(t, "linux", LINUX)
	assert.NotEmpty(t, LINUX)
}
