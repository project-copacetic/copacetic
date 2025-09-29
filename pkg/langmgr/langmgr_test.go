package langmgr

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testWorkingFolder = "/tmp/test"

func TestGetLanguageManagers(t *testing.T) {
	config := &buildkit.Config{}
	workingFolder := testWorkingFolder

	// Test with empty manifest
	emptyManifest := &unversioned.UpdateManifest{}
	managers := GetLanguageManagers(config, workingFolder, emptyManifest)
	assert.Empty(t, managers, "Should return no managers for empty manifest")

	// Test with invalid package type
	invalidManifest := &unversioned.UpdateManifest{
		LangUpdates: unversioned.LangUpdatePackages{
			{
				Name: "foo",
				Type: "bar",
			},
		},
	}
	managers = GetLanguageManagers(config, workingFolder, invalidManifest)
	assert.Empty(t, managers, "Should return no managers for invalid manifest")

	// Test with Python packages
	manifestWithPython := &unversioned.UpdateManifest{
		LangUpdates: unversioned.LangUpdatePackages{
			{
				Name: "urllib3",
				Type: "python-pkg",
			},
		},
	}
	managers = GetLanguageManagers(config, workingFolder, manifestWithPython)

	assert.NotEmpty(t, managers, "Should return at least one language manager")
	assert.Len(t, managers, 1, "Should return only Python manager when only python packages present")

	// Check that we have Python manager and no .NET manager
	pythonFound := false
	dotnetFound := false
	for _, manager := range managers {
		if _, ok := manager.(*pythonManager); ok {
			pythonFound = true
		}
		if _, ok := manager.(*dotnetManager); ok {
			dotnetFound = true
		}
	}
	assert.True(t, pythonFound, "Should include Python manager")
	assert.False(t, dotnetFound, "Should not include .NET manager without dotnet packages")
}

func TestGetUniqueLatestUpdates(t *testing.T) {
	tests := []struct {
		name         string
		updates      unversioned.LangUpdatePackages
		comparer     VersionComparer
		ignoreErrors bool
		expected     unversioned.LangUpdatePackages
		expectError  bool
	}{
		{
			name:     "empty updates",
			updates:  unversioned.LangUpdatePackages{},
			comparer: mockVersionComparer(),
			expected: unversioned.LangUpdatePackages{},
		},
		{
			name: "single update",
			updates: unversioned.LangUpdatePackages{
				{Name: "package1", FixedVersion: "1.0.0"},
			},
			comparer: mockVersionComparer(),
			expected: unversioned.LangUpdatePackages{
				{Name: "package1", FixedVersion: "1.0.0"},
			},
		},
		{
			name: "multiple updates same package - should pick latest",
			updates: unversioned.LangUpdatePackages{
				{Name: "package1", FixedVersion: "1.0.0"},
				{Name: "package1", FixedVersion: "1.2.0"},
				{Name: "package1", FixedVersion: "1.1.0"},
			},
			comparer: mockVersionComparer(),
			expected: unversioned.LangUpdatePackages{
				{Name: "package1", FixedVersion: "1.2.0"},
			},
		},
		{
			name: "multiple packages",
			updates: unversioned.LangUpdatePackages{
				{Name: "package1", FixedVersion: "1.0.0"},
				{Name: "package2", FixedVersion: "2.0.0"},
				{Name: "package1", FixedVersion: "1.1.0"},
			},
			comparer: mockVersionComparer(),
			expected: unversioned.LangUpdatePackages{
				{Name: "package1", FixedVersion: "1.1.0"},
				{Name: "package2", FixedVersion: "2.0.0"},
			},
		},
		{
			name: "invalid version with ignore errors",
			updates: unversioned.LangUpdatePackages{
				{Name: "package1", FixedVersion: "invalid"},
				{Name: "package2", FixedVersion: "1.0.0"},
			},
			comparer:     mockVersionComparer(),
			ignoreErrors: true,
			expected: unversioned.LangUpdatePackages{
				{Name: "package2", FixedVersion: "1.0.0"},
			},
		},
		{
			name: "empty fixed version - should be skipped due to patch level restrictions",
			updates: unversioned.LangUpdatePackages{
				{Name: "package1", FixedVersion: ""},
				{Name: "package2", FixedVersion: "1.0.0"},
			},
			comparer:     mockVersionComparer(),
			ignoreErrors: false,
			expected: unversioned.LangUpdatePackages{
				{Name: "package2", FixedVersion: "1.0.0"},
			},
		},
		{
			name: "invalid version without ignore errors",
			updates: unversioned.LangUpdatePackages{
				{Name: "package1", FixedVersion: "invalid"},
			},
			comparer:     mockVersionComparer(),
			ignoreErrors: false,
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := GetUniqueLatestUpdates(tt.updates, tt.comparer, tt.ignoreErrors)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.ElementsMatch(t, tt.expected, result)
		})
	}
}

func TestGetValidatedUpdatesMap(t *testing.T) {
	tempDir := t.TempDir()

	// Create test files
	testFiles := []string{"package1-1.0.0.whl", "package2-2.0.0.whl"}
	for _, file := range testFiles {
		f, err := os.Create(filepath.Join(tempDir, file))
		require.NoError(t, err)
		f.Close()
	}

	tests := []struct {
		name        string
		updates     unversioned.LangUpdatePackages
		stagingPath string
		reader      PackageInfoReader
		expected    UpdateMap
		expectError bool
		expectNil   bool
	}{
		{
			name: "successful validation",
			updates: unversioned.LangUpdatePackages{
				{Name: "package1", FixedVersion: "1.0.0"},
				{Name: "package2", FixedVersion: "2.0.0"},
			},
			stagingPath: tempDir,
			reader:      newMockPackageInfoReader(),
			expected: UpdateMap{
				"package1": &UpdatePackageInfo{Version: "1.0.0", Filename: "package1-1.0.0.whl"},
				"package2": &UpdatePackageInfo{Version: "2.0.0", Filename: "package2-2.0.0.whl"},
			},
		},
		{
			name:        "empty staging directory",
			updates:     unversioned.LangUpdatePackages{},
			stagingPath: t.TempDir(), // empty directory
			reader:      newMockPackageInfoReader(),
			expectNil:   true,
		},
		{
			name:        "non-existent staging directory",
			updates:     unversioned.LangUpdatePackages{},
			stagingPath: "/non/existent/path",
			reader:      newMockPackageInfoReader(),
			expectError: true,
		},
		{
			name: "version mismatch - downloaded version lower than required",
			updates: unversioned.LangUpdatePackages{
				{Name: "package1", FixedVersion: "2.0.0"}, // Required version higher than downloaded
			},
			stagingPath: tempDir,
			reader:      newMockPackageInfoReader(),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			comparer := mockVersionComparer()
			result, err := GetValidatedUpdatesMap(tt.updates, comparer, tt.reader, tt.stagingPath)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			if tt.expectNil {
				assert.NoError(t, err)
				assert.Nil(t, result)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Mock implementations for testing

func mockVersionComparer() VersionComparer {
	return VersionComparer{
		IsValid: func(version string) bool {
			return version != "invalid"
		},
		LessThan: func(v1, v2 string) bool {
			// Simple string comparison for testing
			return v1 < v2
		},
	}
}

type mockPackageInfoReader struct{}

func newMockPackageInfoReader() PackageInfoReader {
	return &mockPackageInfoReader{}
}

func (m *mockPackageInfoReader) GetName(filename string) (string, error) {
	// Extract package name from filename (assumes format: package-version.ext)
	parts := strings.Split(filename, "-")
	if len(parts) < 2 {
		return "", errors.New("invalid filename format")
	}
	return parts[0], nil
}

func (m *mockPackageInfoReader) GetVersion(filename string) (string, error) {
	// Extract version from filename (assumes format: package-version.ext)
	parts := strings.Split(filename, "-")
	if len(parts) < 2 {
		return "", errors.New("invalid filename format")
	}
	versionPart := parts[1]
	// Remove file extension
	if dotIndex := strings.LastIndex(versionPart, "."); dotIndex != -1 {
		versionPart = versionPart[:dotIndex]
	}
	return versionPart, nil
}

// Test constants.
func TestConstants(t *testing.T) {
	assert.Equal(t, "copa-", copaPrefix)
	assert.Equal(t, "/copa-out", resultsPath)
	assert.Equal(t, "/copa-downloads", downloadPath)
	assert.Equal(t, "/copa-unpacked", unpackPath)
	assert.Equal(t, "langresults.manifest", resultManifest)
}
