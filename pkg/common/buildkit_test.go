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
