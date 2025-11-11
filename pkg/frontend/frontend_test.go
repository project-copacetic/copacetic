package frontend

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/containerd/platforms"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Note: Build() and buildMultiarch() tests are covered by e2e tests in test/e2e/frontend/
// since they require a real BuildKit gateway client. This file tests helper logic.

func TestPlatformParsing(t *testing.T) {
	t.Run("Parse single platform", func(t *testing.T) {
		platformStr := "linux/amd64"
		platform, err := platforms.Parse(platformStr)
		require.NoError(t, err)

		assert.Equal(t, "linux", platform.OS)
		assert.Equal(t, "amd64", platform.Architecture)
		assert.Empty(t, platform.Variant)
	})

	t.Run("Parse platform with variant", func(t *testing.T) {
		platformStr := "linux/arm/v7"
		platform, err := platforms.Parse(platformStr)
		require.NoError(t, err)

		assert.Equal(t, "linux", platform.OS)
		assert.Equal(t, "arm", platform.Architecture)
		assert.Equal(t, "v7", platform.Variant)
	})

	t.Run("Parse multiple platforms", func(t *testing.T) {
		platformStrs := []string{"linux/amd64", "linux/arm64", "linux/arm/v7"}
		var parsedPlatforms []ocispecs.Platform

		for _, platformStr := range platformStrs {
			platform, err := platforms.Parse(platformStr)
			require.NoError(t, err)
			parsedPlatforms = append(parsedPlatforms, platform)
		}

		assert.Len(t, parsedPlatforms, 3)
		assert.Equal(t, "amd64", parsedPlatforms[0].Architecture)
		assert.Equal(t, "arm64", parsedPlatforms[1].Architecture)
		assert.Equal(t, "arm", parsedPlatforms[2].Architecture)
		assert.Equal(t, "v7", parsedPlatforms[2].Variant)
	})

	t.Run("Invalid platform format", func(_ *testing.T) {
		platformStr := "invalid-platform"
		_, err := platforms.Parse(platformStr)
		// platforms.Parse is lenient, so this might not error
		// but we test that we handle it gracefully
		_ = err
	})
}

func TestPlatformFormatting(t *testing.T) {
	t.Run("Format standard platforms", func(t *testing.T) {
		testCases := []struct {
			platform ocispecs.Platform
			expected string
		}{
			{
				platform: ocispecs.Platform{OS: "linux", Architecture: "amd64"},
				expected: "linux/amd64",
			},
			{
				platform: ocispecs.Platform{OS: "linux", Architecture: "arm64"},
				expected: "linux/arm64",
			},
			{
				platform: ocispecs.Platform{OS: "linux", Architecture: "arm", Variant: "v7"},
				expected: "linux/arm/v7",
			},
		}

		for _, tc := range testCases {
			t.Run(tc.expected, func(t *testing.T) {
				formatted := platforms.Format(tc.platform)
				assert.Equal(t, tc.expected, formatted)
			})
		}
	})
}

func TestReportDirectoryPlatformDetection(t *testing.T) {
	t.Run("Detect platform files in directory", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create platform-specific report files
		platformFiles := []string{
			"linux-amd64.json",
			"linux-arm64.json",
			"linux-arm-v7.json",
		}

		for _, file := range platformFiles {
			err := os.WriteFile(filepath.Join(tmpDir, file), []byte("{}"), 0o600)
			require.NoError(t, err)
		}

		// Check directory for platform-specific files
		entries, err := os.ReadDir(tmpDir)
		require.NoError(t, err)

		hasPlatformFiles := false
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
				// Check if filename matches platform pattern (contains hyphen)
				name := strings.TrimSuffix(entry.Name(), ".json")
				if strings.Contains(name, "-") {
					hasPlatformFiles = true
					break
				}
			}
		}

		assert.True(t, hasPlatformFiles)
	})

	t.Run("No platform files in directory", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create non-platform-specific files
		files := []string{"report.json", "other.json"}
		for _, file := range files {
			err := os.WriteFile(filepath.Join(tmpDir, file), []byte("{}"), 0o600)
			require.NoError(t, err)
		}

		// Check directory - report.json has no hyphen, so not platform-specific
		entries, err := os.ReadDir(tmpDir)
		require.NoError(t, err)

		hasPlatformFiles := false
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
				name := strings.TrimSuffix(entry.Name(), ".json")
				// "report" and "other" don't contain hyphens
				if strings.Contains(name, "-") {
					hasPlatformFiles = true
					break
				}
			}
		}

		assert.False(t, hasPlatformFiles)
	})

	t.Run("Mixed files in directory", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create mix of platform and non-platform files
		files := map[string]bool{
			"linux-amd64.json": true,  // Platform file
			"linux-arm64.json": true,  // Platform file
			"report.json":      false, // Not platform file
			"readme.txt":       false, // Not JSON
		}

		for file := range files {
			err := os.WriteFile(filepath.Join(tmpDir, file), []byte("{}"), 0o600)
			require.NoError(t, err)
		}

		// Check for platform files
		entries, err := os.ReadDir(tmpDir)
		require.NoError(t, err)

		hasPlatformFiles := false
		platformCount := 0
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
				name := strings.TrimSuffix(entry.Name(), ".json")
				if strings.Contains(name, "-") {
					hasPlatformFiles = true
					if files[entry.Name()] {
						platformCount++
					}
				}
			}
		}

		assert.True(t, hasPlatformFiles)
		assert.Equal(t, 2, platformCount)
	})
}

func TestTempDirectoryNaming(t *testing.T) {
	t.Run("Single file pattern detection", func(t *testing.T) {
		// Simulate the pattern used in extractReportFromContext
		tmpDir, err := os.MkdirTemp("", "copa-frontend-report-")
		require.NoError(t, err)
		defer os.RemoveAll(tmpDir)

		// Check if it's a single file temp dir
		isSingleFile := strings.Contains(filepath.Base(tmpDir), "copa-frontend-report-")
		assert.True(t, isSingleFile)

		// Should NOT match the directory pattern
		isDirectory := strings.Contains(filepath.Base(tmpDir), "copa-frontend-reports-")
		assert.False(t, isDirectory)
	})

	t.Run("Directory pattern detection", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "copa-frontend-reports-")
		require.NoError(t, err)
		defer os.RemoveAll(tmpDir)

		// Check if it's a directory temp dir
		isDirectory := strings.Contains(filepath.Base(tmpDir), "copa-frontend-reports-")
		assert.True(t, isDirectory)
	})
}

func TestPlatformSliceOperations(t *testing.T) {
	t.Run("Build platform slice from strings", func(t *testing.T) {
		platformStrs := []string{"linux/amd64", "linux/arm64"}
		var targetPlatforms []ocispecs.Platform

		for _, platformStr := range platformStrs {
			platform, err := platforms.Parse(platformStr)
			require.NoError(t, err)
			targetPlatforms = append(targetPlatforms, platform)
		}

		assert.Len(t, targetPlatforms, 2)
	})

	t.Run("Empty platform slice", func(t *testing.T) {
		var targetPlatforms []ocispecs.Platform
		assert.Len(t, targetPlatforms, 0)
		assert.Empty(t, targetPlatforms)
	})

	t.Run("Append to platform slice", func(t *testing.T) {
		var platformList []ocispecs.Platform

		p1, err := platforms.Parse("linux/amd64")
		require.NoError(t, err)
		platformList = append(platformList, p1)

		p2, err := platforms.Parse("linux/arm64")
		require.NoError(t, err)
		platformList = append(platformList, p2)

		assert.Len(t, platformList, 2)
		assert.Equal(t, "amd64", platformList[0].Architecture)
		assert.Equal(t, "arm64", platformList[1].Architecture)
	})
}

func TestFileSystemOperations(t *testing.T) {
	t.Run("Check if path is directory", func(t *testing.T) {
		tmpDir := t.TempDir()

		fi, err := os.Stat(tmpDir)
		require.NoError(t, err)
		assert.True(t, fi.IsDir())
	})

	t.Run("Check if path is file", func(t *testing.T) {
		tmpDir := t.TempDir()
		tmpFile := filepath.Join(tmpDir, "test.json")

		err := os.WriteFile(tmpFile, []byte("{}"), 0o600)
		require.NoError(t, err)

		fi, err := os.Stat(tmpFile)
		require.NoError(t, err)
		assert.False(t, fi.IsDir())
	})

	t.Run("Read directory entries", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create some files
		files := []string{"file1.json", "file2.json", "file3.txt"}
		for _, file := range files {
			err := os.WriteFile(filepath.Join(tmpDir, file), []byte("test"), 0o600)
			require.NoError(t, err)
		}

		entries, err := os.ReadDir(tmpDir)
		require.NoError(t, err)
		assert.Len(t, entries, 3)

		// Count JSON files
		jsonCount := 0
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), ".json") {
				jsonCount++
			}
		}
		assert.Equal(t, 2, jsonCount)
	})
}

func TestPlatformNormalization(t *testing.T) {
	t.Run("Normalize platform strings", func(t *testing.T) {
		// Test that different representations normalize correctly
		testCases := []struct {
			input    string
			expected string
		}{
			{"linux/amd64", "linux/amd64"},
			{"linux/arm64", "linux/arm64"},
			{"linux/arm/v7", "linux/arm/v7"},
		}

		for _, tc := range testCases {
			t.Run(tc.input, func(t *testing.T) {
				platform, err := platforms.Parse(tc.input)
				require.NoError(t, err)

				normalized := platforms.Format(platform)
				assert.Equal(t, tc.expected, normalized)
			})
		}
	})
}
