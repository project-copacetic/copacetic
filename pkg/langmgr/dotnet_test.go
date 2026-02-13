package langmgr

import (
	"testing"

	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/utils"
	"github.com/stretchr/testify/assert"
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
			name:     "valid 4-part NuGet version",
			version:  "1.2.3.4",
			expected: true,
		},
		{
			name:     "valid 4-part version with prerelease",
			version:  "1.0.0.0-preview",
			expected: true,
		},
		{
			name:     "valid 4-part version with build metadata",
			version:  "1.2.3.4+build",
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
		{
			name:     "invalid 5-part version",
			version:  "1.2.3.4.5",
			expected: false,
		},
		{
			name:     "invalid 2-part version",
			version:  "1.2",
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
		{
			name:     "4-part version comparison - less than",
			v1:       "1.0.0.0",
			v2:       "1.0.0.1",
			expected: true,
		},
		{
			name:     "4-part version comparison - greater than",
			v1:       "1.0.0.2",
			v2:       "1.0.0.1",
			expected: false,
		},
		{
			name:     "4-part version comparison - equal",
			v1:       "1.2.3.4",
			v2:       "1.2.3.4",
			expected: false,
		},
		{
			name:     "mixed 3-part and 4-part comparison",
			v1:       "1.0.0",
			v2:       "1.0.0.1",
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

func TestGetLanguageManagers_DotnetAndPython(t *testing.T) {
	config := &buildkit.Config{}

	manifest := &unversioned.UpdateManifest{
		LangUpdates: unversioned.LangUpdatePackages{
			{Name: "Newtonsoft.Json", FixedVersion: "13.0.3", Type: utils.DotNetPackages},
			{Name: "requests", FixedVersion: "2.31.0", Type: utils.PythonPackages},
		},
	}

	managers := GetLanguageManagers(config, testWorkingFolder, manifest, "")
	// Expect two managers (order not strictly guaranteed)
	assert.Len(t, managers, 2)

	var sawDotnet, sawPython bool
	for _, m := range managers {
		switch m.(type) {
		case *dotnetManager:
			sawDotnet = true
		case *pythonManager:
			sawPython = true
		}
	}
	assert.True(t, sawDotnet, "expected dotnetManager to be returned")
	assert.True(t, sawPython, "expected pythonManager to be returned")
}

func TestGetLanguageManagers_None(t *testing.T) {
	config := &buildkit.Config{}
	manifest := &unversioned.UpdateManifest{LangUpdates: unversioned.LangUpdatePackages{}}
	managers := GetLanguageManagers(config, testWorkingFolder, manifest, "")
	assert.Len(t, managers, 0)
}

func TestGetLanguageManagers_DotnetOnly(t *testing.T) {
	config := &buildkit.Config{}
	manifest := &unversioned.UpdateManifest{LangUpdates: unversioned.LangUpdatePackages{{Name: "Newtonsoft.Json", FixedVersion: "13.0.3", Type: utils.DotNetPackages}}}
	managers := GetLanguageManagers(config, testWorkingFolder, manifest, "")
	assert.Len(t, managers, 1)
	_, ok := managers[0].(*dotnetManager)
	assert.True(t, ok, "expected first manager to be dotnetManager")
}
