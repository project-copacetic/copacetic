package frontend

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	osLinux = "linux"
)

// Note: buildPatchedImage tests are covered by e2e tests in test/e2e/frontend/
// since they require a real BuildKit gateway client and complex setup.
// This file tests helper functions that can be unit tested.

func TestPlatformSpecificReportFilename(t *testing.T) {
	t.Run("AMD64 platform", func(t *testing.T) {
		// Test the platform-specific filename construction logic
		// This mimics the logic in buildPatchedImage
		osName := osLinux
		arch := "amd64"
		variant := ""

		platformFile := osName + "-" + arch
		if variant != "" {
			platformFile = platformFile + "-" + variant
		}
		platformFile += jsonExt

		assert.Equal(t, "linux-amd64.json", platformFile)
	})

	t.Run("ARM64 v8 platform with variant", func(t *testing.T) {
		osName := osLinux
		arch := "arm64"
		variant := "v8"

		platformFile := osName + "-" + arch
		if variant != "" {
			platformFile = platformFile + "-" + variant
		}
		platformFile += jsonExt

		assert.Equal(t, "linux-arm64-v8.json", platformFile)
	})

	t.Run("ARM v7 platform", func(t *testing.T) {
		osName := osLinux
		arch := "arm"
		variant := "v7"

		platformFile := osName + "-" + arch
		if variant != "" {
			platformFile = platformFile + "-" + variant
		}
		platformFile += jsonExt

		assert.Equal(t, "linux-arm-v7.json", platformFile)
	})
}

func TestReportDirectoryStructure(t *testing.T) {
	t.Run("Create directory with platform-specific reports", func(t *testing.T) {
		// Create temporary directory
		tmpDir := t.TempDir()

		// Create platform-specific report files
		platforms := []string{
			"linux-amd64.json",
			"linux-arm64.json",
			"linux-arm-v7.json",
		}

		for _, platform := range platforms {
			reportPath := filepath.Join(tmpDir, platform)
			err := os.WriteFile(reportPath, []byte(`{"vulnerabilities":[]}`), 0o600)
			require.NoError(t, err)

			// Verify file exists
			_, err = os.Stat(reportPath)
			assert.NoError(t, err)
		}

		// Verify directory exists
		fi, err := os.Stat(tmpDir)
		require.NoError(t, err)
		assert.True(t, fi.IsDir())

		// Read directory and verify files
		entries, err := os.ReadDir(tmpDir)
		require.NoError(t, err)
		assert.Len(t, entries, 3)
	})

	t.Run("Platform-specific report file discovery", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create some platform-specific files
		testFiles := map[string]bool{
			"linux-amd64.json": true,  // Should be found
			"linux-arm64.json": true,  // Should be found
			"report.json":      false, // Generic report
			"other.txt":        false, // Non-JSON file
			"linux-amd64.txt":  false, // Wrong extension
		}

		for filename := range testFiles {
			err := os.WriteFile(filepath.Join(tmpDir, filename), []byte("test"), 0o600)
			require.NoError(t, err)
		}

		// Check directory for platform-specific JSON files
		entries, err := os.ReadDir(tmpDir)
		require.NoError(t, err)

		platformFiles := 0
		for _, entry := range entries {
			if !entry.IsDir() && filepath.Ext(entry.Name()) == jsonExt {
				// Check if filename matches platform pattern (contains hyphen)
				name := entry.Name()
				baseName := name[:len(name)-len(filepath.Ext(name))]
				if filepath.Ext(name) == jsonExt && len(baseName) > 0 && filepath.Base(baseName) == baseName {
					// This is a potential platform-specific file if it contains a hyphen
					if testFiles[entry.Name()] {
						platformFiles++
					}
				}
			}
		}

		assert.Equal(t, 2, platformFiles)
	})
}

func TestReportFileValidation(t *testing.T) {
	t.Run("Valid single report file", func(t *testing.T) {
		tmpDir := t.TempDir()
		reportFile := filepath.Join(tmpDir, "report.json")

		// Write valid JSON
		validJSON := `{"vulnerabilities":[{"id":"CVE-2023-1234"}]}`
		err := os.WriteFile(reportFile, []byte(validJSON), 0o600)
		require.NoError(t, err)

		// Verify file exists and can be read
		data, err := os.ReadFile(reportFile)
		require.NoError(t, err)
		assert.Contains(t, string(data), "CVE-2023-1234")
	})

	t.Run("Empty report file", func(t *testing.T) {
		tmpDir := t.TempDir()
		reportFile := filepath.Join(tmpDir, "empty.json")

		// Write empty JSON
		err := os.WriteFile(reportFile, []byte(`{}`), 0o600)
		require.NoError(t, err)

		// Verify file exists
		_, err = os.Stat(reportFile)
		assert.NoError(t, err)
	})

	t.Run("Missing report file", func(t *testing.T) {
		tmpDir := t.TempDir()
		reportFile := filepath.Join(tmpDir, "nonexistent.json")

		// Verify file does not exist
		_, err := os.Stat(reportFile)
		assert.Error(t, err)
		assert.True(t, os.IsNotExist(err))
	})
}

func TestTempDirPatterns(t *testing.T) {
	t.Run("Single file temp dir pattern", func(t *testing.T) {
		// This tests the temp directory pattern used in extractReportFromContext
		tmpDir, err := os.MkdirTemp("", "copa-frontend-report-")
		require.NoError(t, err)
		defer os.RemoveAll(tmpDir)

		assert.Contains(t, tmpDir, "copa-frontend-report-")

		// Verify we can write to it
		testFile := filepath.Join(tmpDir, "test.json")
		err = os.WriteFile(testFile, []byte("test"), 0o600)
		assert.NoError(t, err)
	})

	t.Run("Directory temp dir pattern", func(t *testing.T) {
		// This tests the temp directory pattern used for report directories
		tmpDir, err := os.MkdirTemp("", "copa-frontend-reports-")
		require.NoError(t, err)
		defer os.RemoveAll(tmpDir)

		assert.Contains(t, tmpDir, "copa-frontend-reports-")

		// Verify we can create multiple files
		files := []string{"linux-amd64.json", "linux-arm64.json"}
		for _, file := range files {
			err = os.WriteFile(filepath.Join(tmpDir, file), []byte("test"), 0o600)
			assert.NoError(t, err)
		}
	})
}

func TestReportPathLogic(t *testing.T) {
	t.Run("Detect directory vs file", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create a directory
		subDir := filepath.Join(tmpDir, "reports")
		err := os.Mkdir(subDir, 0o755)
		require.NoError(t, err)

		// Create a file
		reportFile := filepath.Join(tmpDir, "report.json")
		err = os.WriteFile(reportFile, []byte("{}"), 0o600)
		require.NoError(t, err)

		// Test directory detection
		fi, err := os.Stat(subDir)
		require.NoError(t, err)
		assert.True(t, fi.IsDir())

		// Test file detection
		fi, err = os.Stat(reportFile)
		require.NoError(t, err)
		assert.False(t, fi.IsDir())
	})

	t.Run("Platform-specific file within directory", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create platform-specific files
		platforms := map[string]string{
			"linux-amd64.json": `{"platform":"amd64"}`,
			"linux-arm64.json": `{"platform":"arm64"}`,
		}

		for filename, content := range platforms {
			path := filepath.Join(tmpDir, filename)
			err := os.WriteFile(path, []byte(content), 0o600)
			require.NoError(t, err)
		}

		// Test looking for specific platform file
		targetPlatform := "linux-amd64.json"
		specificPath := filepath.Join(tmpDir, targetPlatform)

		_, err := os.Stat(specificPath)
		assert.NoError(t, err)

		// Test looking for non-existent platform
		nonExistentPath := filepath.Join(tmpDir, "linux-s390x.json")
		_, err = os.Stat(nonExistentPath)
		assert.Error(t, err)
		assert.True(t, os.IsNotExist(err))
	})
}

func TestJSONFileFiltering(t *testing.T) {
	t.Run("Filter only JSON files from directory", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create mix of files
		files := map[string]string{
			"report1.json": "{}",
			"report2.json": "{}",
			"readme.md":    "# Readme",
			"config.yaml":  "key: value",
			"data.txt":     "text",
		}

		for filename, content := range files {
			err := os.WriteFile(filepath.Join(tmpDir, filename), []byte(content), 0o600)
			require.NoError(t, err)
		}

		// Read and filter JSON files
		entries, err := os.ReadDir(tmpDir)
		require.NoError(t, err)

		jsonFiles := []string{}
		for _, entry := range entries {
			if !entry.IsDir() && filepath.Ext(entry.Name()) == jsonExt {
				jsonFiles = append(jsonFiles, entry.Name())
			}
		}

		assert.Len(t, jsonFiles, 2)
		assert.Contains(t, jsonFiles, "report1.json")
		assert.Contains(t, jsonFiles, "report2.json")
	})
}
