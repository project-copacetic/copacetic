package langmgr

import (
	"context"
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
	managers := GetLanguageManagers(config, workingFolder, emptyManifest, "", "", "")
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
	managers = GetLanguageManagers(config, workingFolder, invalidManifest, "", "", "")
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
	managers = GetLanguageManagers(config, workingFolder, manifestWithPython, "", "", "")

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

func TestGetLanguageManagers_Java(t *testing.T) {
	config := &buildkit.Config{}
	workingFolder := testWorkingFolder

	javaTypes := []string{"jar", "pom", "gradle", "sbt"}
	for _, jt := range javaTypes {
		t.Run("registers javaManager for type="+jt, func(t *testing.T) {
			manifest := &unversioned.UpdateManifest{
				LangUpdates: unversioned.LangUpdatePackages{
					{Name: "org.apache.logging.log4j:log4j-core", Type: jt, FixedVersion: "2.17.0"},
				},
			}
			managers := GetLanguageManagers(config, workingFolder, manifest, "", "", "")
			require.Len(t, managers, 1, "should register exactly one manager for a single Java type")
			_, ok := managers[0].(*javaManager)
			assert.True(t, ok, "manager should be javaManager")
		})
	}

	t.Run("registers javaManager only once across all four Java types", func(t *testing.T) {
		manifest := &unversioned.UpdateManifest{
			LangUpdates: unversioned.LangUpdatePackages{
				{Name: "g1:a1", Type: "jar"},
				{Name: "g2:a2", Type: "pom"},
				{Name: "g3:a3", Type: "gradle"},
				{Name: "g4:a4", Type: "sbt"},
			},
		}
		managers := GetLanguageManagers(config, workingFolder, manifest, "", "", "")
		require.Len(t, managers, 1, "should de-duplicate javaManager across all four Java types")
		_, ok := managers[0].(*javaManager)
		assert.True(t, ok, "manager should be javaManager")
	})
}

func TestJavaManager_InstallUpdates_Stub(t *testing.T) {
	jm := &javaManager{config: &buildkit.Config{}, workingFolder: testWorkingFolder}

	t.Run("nil manifest returns nil failures", func(t *testing.T) {
		state, failed, err := jm.InstallUpdates(context.TODO(), nil, nil, false)
		assert.NoError(t, err)
		assert.Nil(t, state)
		assert.Nil(t, failed)
	})

	t.Run("non-Java updates are ignored", func(t *testing.T) {
		manifest := &unversioned.UpdateManifest{
			LangUpdates: unversioned.LangUpdatePackages{
				{Name: "urllib3", Type: "python-pkg", FixedVersion: "2.0.0"},
			},
		}
		_, failed, err := jm.InstallUpdates(context.TODO(), nil, manifest, false)
		assert.NoError(t, err)
		assert.Empty(t, failed, "javaManager should not report non-Java updates as failures")
	})

	t.Run("Java updates are reported as failed packages", func(t *testing.T) {
		manifest := &unversioned.UpdateManifest{
			LangUpdates: unversioned.LangUpdatePackages{
				{Name: "org.apache.logging.log4j:log4j-core", Type: "jar", InstalledVersion: "2.11.1", FixedVersion: "2.17.0"},
				{Name: "com.fasterxml.jackson.core:jackson-databind", Type: "pom", InstalledVersion: "2.10.4", FixedVersion: "2.13.4"},
				{Name: "io.netty:netty-codec", Type: "gradle", InstalledVersion: "4.1.77", FixedVersion: "4.1.86"},
			},
		}
		_, failed, err := jm.InstallUpdates(context.TODO(), nil, manifest, false)
		assert.NoError(t, err)
		assert.Len(t, failed, 3, "every Java update should be reported as failed in the scaffold")
		assert.Contains(t, failed, "org.apache.logging.log4j:log4j-core")
		assert.Contains(t, failed, "com.fasterxml.jackson.core:jackson-databind")
		assert.Contains(t, failed, "io.netty:netty-codec")
	})

	t.Run("filterJavaUpdates picks only Java types", func(t *testing.T) {
		updates := unversioned.LangUpdatePackages{
			{Name: "g:a", Type: "jar"},
			{Name: "urllib3", Type: "python-pkg"},
			{Name: "g:b", Type: "pom"},
			{Name: "lodash", Type: "node-pkg"},
			{Name: "g:c", Type: "gradle"},
			{Name: "stdlib", Type: "gobinary"},
			{Name: "g:d", Type: "sbt"},
		}
		got := filterJavaUpdates(updates)
		assert.Len(t, got, 4)
		for _, u := range got {
			assert.True(t, isJavaUpdate(u.Type), "filtered entry should be Java type, got %s", u.Type)
		}
	})
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
		{
			name: "same package at different PkgPaths - kept as separate entries",
			updates: unversioned.LangUpdatePackages{
				{Name: "pip", FixedVersion: "24.0", PkgPath: "usr/lib/python3.12/site-packages"},
				{Name: "pip", FixedVersion: "24.0", PkgPath: "opt/venv/lib/python3.12/site-packages"},
			},
			comparer: mockVersionComparer(),
			expected: unversioned.LangUpdatePackages{
				{Name: "pip", FixedVersion: "24.0", PkgPath: "usr/lib/python3.12/site-packages"},
				{Name: "pip", FixedVersion: "24.0", PkgPath: "opt/venv/lib/python3.12/site-packages"},
			},
		},
		{
			name: "same package at same PkgPath with different CVEs - merged to one entry with latest version",
			updates: unversioned.LangUpdatePackages{
				{Name: "pip", FixedVersion: "23.0", PkgPath: "opt/venv/lib/python3.12/site-packages"},
				{Name: "pip", FixedVersion: "24.0", PkgPath: "opt/venv/lib/python3.12/site-packages"},
			},
			comparer: mockVersionComparer(),
			expected: unversioned.LangUpdatePackages{
				{Name: "pip", FixedVersion: "24.0", PkgPath: "opt/venv/lib/python3.12/site-packages"},
			},
		},
		{
			name: "packages without PkgPath still deduplicate by name (backward compat)",
			updates: unversioned.LangUpdatePackages{
				{Name: "urllib3", FixedVersion: "1.26.0"},
				{Name: "urllib3", FixedVersion: "1.27.0"},
			},
			comparer: mockVersionComparer(),
			expected: unversioned.LangUpdatePackages{
				{Name: "urllib3", FixedVersion: "1.27.0"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := GetUniqueLatestUpdates(tt.updates, tt.comparer, tt.ignoreErrors)

			if tt.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
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
				require.Error(t, err)
				return
			}

			if tt.expectNil {
				require.NoError(t, err)
				assert.Nil(t, result)
				return
			}

			require.NoError(t, err)
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
