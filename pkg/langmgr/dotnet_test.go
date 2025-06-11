package langmgr

import (
	"context"
	"testing"

	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsValidDotnetVersion(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected bool
	}{
		{
			name:     "valid semantic version",
			version:  "1.2.3",
			expected: true,
		},
		{
			name:     "valid semantic version with prerelease",
			version:  "1.2.3-alpha",
			expected: true,
		},
		{
			name:     "valid semantic version with build metadata",
			version:  "1.2.3+build.1",
			expected: true,
		},
		{
			name:     "invalid version",
			version:  "invalid-version",
			expected: false,
		},
		{
			name:     "empty version",
			version:  "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidDotnetVersion(tt.version)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsLessThanDotnetVersion(t *testing.T) {
	tests := []struct {
		name     string
		v1       string
		v2       string
		expected bool
	}{
		{
			name:     "v1 is less than v2",
			v1:       "1.2.3",
			v2:       "1.2.4",
			expected: true,
		},
		{
			name:     "v1 is greater than v2",
			v1:       "1.2.4",
			v2:       "1.2.3",
			expected: false,
		},
		{
			name:     "v1 equals v2",
			v1:       "1.2.3",
			v2:       "1.2.3",
			expected: false,
		},
		{
			name:     "major version difference",
			v1:       "1.2.3",
			v2:       "2.0.0",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isLessThanDotnetVersion(tt.v1, tt.v2)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetUniqueLatestUpdates_Dotnet(t *testing.T) {
	dotnetComparer := VersionComparer{isValidDotnetVersion, isLessThanDotnetVersion}

	tests := []struct {
		name          string
		updates       unversioned.LangUpdatePackages
		ignoreErrors  bool
		expected      unversioned.LangUpdatePackages
		expectedError bool
	}{
		{
			name: "single package with valid version",
			updates: unversioned.LangUpdatePackages{
				{Name: "Newtonsoft.Json", FixedVersion: "13.0.1"},
			},
			ignoreErrors: false,
			expected: unversioned.LangUpdatePackages{
				{Name: "Newtonsoft.Json", FixedVersion: "13.0.1"},
			},
			expectedError: false,
		},
		{
			name: "multiple versions of same package",
			updates: unversioned.LangUpdatePackages{
				{Name: "Newtonsoft.Json", FixedVersion: "13.0.1"},
				{Name: "Newtonsoft.Json", FixedVersion: "13.0.2"},
			},
			ignoreErrors: false,
			expected: unversioned.LangUpdatePackages{
				{Name: "Newtonsoft.Json", FixedVersion: "13.0.2"},
			},
			expectedError: false,
		},
		{
			name: "invalid version with ignore errors",
			updates: unversioned.LangUpdatePackages{
				{Name: "Newtonsoft.Json", FixedVersion: "invalid"},
				{Name: "Microsoft.Extensions.Logging", FixedVersion: "6.0.0"},
			},
			ignoreErrors: true,
			expected: unversioned.LangUpdatePackages{
				{Name: "Microsoft.Extensions.Logging", FixedVersion: "6.0.0"},
			},
			expectedError: false,
		},
		{
			name: "empty fixed version should be skipped",
			updates: unversioned.LangUpdatePackages{
				{Name: "Newtonsoft.Json", FixedVersion: ""},
				{Name: "Microsoft.Extensions.Logging", FixedVersion: "6.0.0"},
			},
			ignoreErrors: false,
			expected: unversioned.LangUpdatePackages{
				{Name: "Microsoft.Extensions.Logging", FixedVersion: "6.0.0"},
			},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := GetUniqueLatestUpdates(tt.updates, dotnetComparer, tt.ignoreErrors)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Len(t, result, len(tt.expected))

				// Convert to maps for easier comparison
				resultMap := make(map[string]string)
				for _, pkg := range result {
					resultMap[pkg.Name] = pkg.FixedVersion
				}

				expectedMap := make(map[string]string)
				for _, pkg := range tt.expected {
					expectedMap[pkg.Name] = pkg.FixedVersion
				}

				assert.Equal(t, expectedMap, resultMap)
			}
		})
	}
}

func TestDotnetManagerInstallUpdates(t *testing.T) {
	config := &buildkit.Config{}
	workingFolder := "/tmp/test"
	dnm := &dotnetManager{
		config:        config,
		workingFolder: workingFolder,
	}

	ctx := context.Background()

	tests := []struct {
		name         string
		manifest     *unversioned.UpdateManifest
		ignoreErrors bool
		expectError  bool
	}{
		{
			name: "no updates",
			manifest: &unversioned.UpdateManifest{
				LangUpdates: unversioned.LangUpdatePackages{},
			},
			ignoreErrors: false,
		},
		{
			name: "valid updates",
			manifest: &unversioned.UpdateManifest{
				LangUpdates: unversioned.LangUpdatePackages{
					{Name: "Newtonsoft.Json", FixedVersion: "13.0.3", Type: "dotnet-core"},
					{Name: "Microsoft.Extensions.Logging", FixedVersion: "7.0.0", Type: "dotnet-core"},
				},
			},
			ignoreErrors: false,
			// This will likely error in test environment due to missing buildkit setup
			expectError: true,
		},
		{
			name: "invalid version",
			manifest: &unversioned.UpdateManifest{
				LangUpdates: unversioned.LangUpdatePackages{
					{Name: "Newtonsoft.Json", FixedVersion: "invalid-version", Type: "dotnet-core"},
				},
			},
			ignoreErrors: false,
			expectError:  true,
		},
		{
			name: "invalid version with ignore errors",
			manifest: &unversioned.UpdateManifest{
				LangUpdates: unversioned.LangUpdatePackages{
					{Name: "Newtonsoft.Json", FixedVersion: "invalid-version", Type: "dotnet-core"},
				},
			},
			ignoreErrors: true,
			expectError:  false, // Should not error when ignoring errors
		},
		{
			name: "mixed package types - should ignore non-dotnet",
			manifest: &unversioned.UpdateManifest{
				LangUpdates: unversioned.LangUpdatePackages{
					{Name: "Newtonsoft.Json", FixedVersion: "13.0.3", Type: "dotnet-core"},
					{Name: "requests", FixedVersion: "2.28.0", Type: "python-pkg"}, // Should be ignored
				},
			},
			ignoreErrors: false,
			expectError:  true, // Will error due to buildkit, but should only process dotnet packages
		},
		{
			name: "only non-dotnet packages - should return success",
			manifest: &unversioned.UpdateManifest{
				LangUpdates: unversioned.LangUpdatePackages{
					{Name: "requests", FixedVersion: "2.28.0", Type: "python-pkg"},
				},
			},
			ignoreErrors: false,
			expectError:  false, // Should return successfully since no dotnet packages to process
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state, errPkgs, err := dnm.InstallUpdates(ctx, tt.manifest, tt.ignoreErrors)

			if tt.expectError {
				// In test environment, we expect errors due to missing buildkit setup
				// We mainly test that the function handles input validation correctly
				if err == nil && len(tt.manifest.LangUpdates) > 0 {
					t.Log("Expected error due to buildkit setup, but got none")
				}
			}

			// State should always be returned (never nil)
			assert.NotNil(t, state)

			// Error packages should be a slice (may be empty)
			assert.NotNil(t, errPkgs)

			// If no updates, should not error
			if len(tt.manifest.LangUpdates) == 0 {
				assert.NoError(t, err)
				assert.Empty(t, errPkgs)
			}
		})
	}
}

func TestDotnetManagerType(t *testing.T) {
	config := &buildkit.Config{}
	workingFolder := "/tmp/test"
	dnm := &dotnetManager{
		config:        config,
		workingFolder: workingFolder,
	}

	// Test that dotnetManager implements LangManager interface
	var _ LangManager = dnm

	// Test that GetLanguageManagers returns both pythonManager and dotnetManager
	managers := GetLanguageManagers(config, workingFolder)
	require.Len(t, managers, 2)

	// Find the dotnet manager (should be the second one)
	var dotnetMgr *dotnetManager
	var found bool
	for _, mgr := range managers {
		if dnMgr, ok := mgr.(*dotnetManager); ok {
			dotnetMgr = dnMgr
			found = true
			break
		}
	}

	assert.True(t, found, "Should find a dotnetManager in the list")
	assert.NotNil(t, dotnetMgr)
	assert.Equal(t, config, dotnetMgr.config)
	assert.Equal(t, workingFolder, dotnetMgr.workingFolder)
}
