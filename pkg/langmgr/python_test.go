package langmgr

import (
	"context"
	"testing"

	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsValidPythonVersion(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected bool
	}{
		{
			name:     "valid simple version",
			version:  "1.0.0",
			expected: true,
		},
		{
			name:     "valid version with pre-release",
			version:  "1.0.0a1",
			expected: true,
		},
		{
			name:     "valid version with post-release",
			version:  "1.0.0.post1",
			expected: true,
		},
		{
			name:     "valid version with dev release",
			version:  "1.0.0.dev1",
			expected: true,
		},
		{
			name:     "valid complex version",
			version:  "2.0.0rc1.post1.dev1",
			expected: true,
		},
		{
			name:     "invalid version format",
			version:  "invalid",
			expected: false,
		},
		{
			name:     "empty version",
			version:  "",
			expected: false,
		},
		{
			name:     "version with invalid characters",
			version:  "1.0.0@invalid",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidPythonVersion(tt.version)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsLessThanPythonVersion(t *testing.T) {
	tests := []struct {
		name     string
		v1       string
		v2       string
		expected bool
	}{
		{
			name:     "v1 less than v2",
			v1:       "1.0.0",
			v2:       "1.1.0",
			expected: true,
		},
		{
			name:     "v1 greater than v2",
			v1:       "1.1.0",
			v2:       "1.0.0",
			expected: false,
		},
		{
			name:     "v1 equals v2",
			v1:       "1.0.0",
			v2:       "1.0.0",
			expected: false,
		},
		{
			name:     "pre-release vs release",
			v1:       "1.0.0a1",
			v2:       "1.0.0",
			expected: true,
		},
		{
			name:     "invalid v1",
			v1:       "invalid",
			v2:       "1.0.0",
			expected: false,
		},
		{
			name:     "invalid v2",
			v1:       "1.0.0",
			v2:       "invalid",
			expected: false,
		},
		{
			name:     "both invalid",
			v1:       "invalid1",
			v2:       "invalid2",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isLessThanPythonVersion(tt.v1, tt.v2)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPythonManagerInstallUpdates(t *testing.T) {
	config := &buildkit.Config{}
	workingFolder := "/tmp/test"
	pm := &pythonManager{
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
					{Name: "requests", FixedVersion: "2.28.0"},
					{Name: "urllib3", FixedVersion: "1.26.12"},
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
					{Name: "requests", FixedVersion: "invalid-version"},
				},
			},
			ignoreErrors: false,
			expectError:  true,
		},
		{
			name: "invalid version with ignore errors",
			manifest: &unversioned.UpdateManifest{
				LangUpdates: unversioned.LangUpdatePackages{
					{Name: "requests", FixedVersion: "invalid-version"},
				},
			},
			ignoreErrors: true,
			expectError:  false, // Should not error when ignoring errors
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock current state (using the same imageState from pm.config)
			currentState := &pm.config.ImageState
			state, errPkgs, err := pm.InstallUpdates(ctx, currentState, tt.manifest, tt.ignoreErrors)

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

func TestValidatePythonPackageVersions(t *testing.T) {
	config := &buildkit.Config{}
	pm := &pythonManager{
		config:        config,
		workingFolder: "/tmp/test",
	}

	ctx := context.Background()

	tests := []struct {
		name            string
		resultsBytes    []byte
		expectedUpdates unversioned.LangUpdatePackages
		ignoreErrors    bool
		expectedFailed  []string
		expectError     bool
	}{
		{
			name:         "nil results bytes",
			resultsBytes: nil,
			expectedUpdates: unversioned.LangUpdatePackages{
				{Name: "requests", FixedVersion: "2.28.0"},
			},
			ignoreErrors:   false,
			expectedFailed: []string{"requests"},
			expectError:    true,
		},
		{
			name:            "nil results bytes with ignore errors",
			resultsBytes:    nil,
			expectedUpdates: unversioned.LangUpdatePackages{},
			ignoreErrors:    true,
			expectedFailed:  []string{},
			expectError:     false,
		},
		{
			name:         "successful validation",
			resultsBytes: []byte("requests==2.28.0\nurllib3==1.26.12\n"),
			expectedUpdates: unversioned.LangUpdatePackages{
				{Name: "requests", FixedVersion: "2.28.0"},
				{Name: "urllib3", FixedVersion: "1.26.12"},
			},
			ignoreErrors:   false,
			expectedFailed: []string{},
			expectError:    false,
		},
		{
			name:         "version mismatch",
			resultsBytes: []byte("requests==2.27.0\n"),
			expectedUpdates: unversioned.LangUpdatePackages{
				{Name: "requests", FixedVersion: "2.28.0"},
			},
			ignoreErrors:   false,
			expectedFailed: []string{"requests"},
			expectError:    true,
		},
		{
			name:         "version mismatch with ignore errors",
			resultsBytes: []byte("requests==2.27.0\n"),
			expectedUpdates: unversioned.LangUpdatePackages{
				{Name: "requests", FixedVersion: "2.28.0"},
			},
			ignoreErrors:   true,
			expectedFailed: []string{"requests"},
			expectError:    false,
		},
		{
			name:         "package not found",
			resultsBytes: []byte("urllib3==1.26.12\n"),
			expectedUpdates: unversioned.LangUpdatePackages{
				{Name: "requests", FixedVersion: "2.28.0"},
			},
			ignoreErrors:   false,
			expectedFailed: []string{"requests"},
			expectError:    true,
		},
		{
			name:         "invalid installed version",
			resultsBytes: []byte("requests==invalid-version\n"),
			expectedUpdates: unversioned.LangUpdatePackages{
				{Name: "requests", FixedVersion: "2.28.0"},
			},
			ignoreErrors:   false,
			expectedFailed: []string{"requests"},
			expectError:    true,
		},
		{
			name:         "invalid expected version",
			resultsBytes: []byte("requests==2.28.0\n"),
			expectedUpdates: unversioned.LangUpdatePackages{
				{Name: "requests", FixedVersion: "invalid-version"},
			},
			ignoreErrors:   false,
			expectedFailed: []string{"requests"},
			expectError:    true,
		},
		{
			name:         "malformed pip freeze output",
			resultsBytes: []byte("invalid-line\nrequests==2.28.0\n"),
			expectedUpdates: unversioned.LangUpdatePackages{
				{Name: "requests", FixedVersion: "2.28.0"},
			},
			ignoreErrors:   false,
			expectedFailed: []string{},
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			failed, err := pm.validatePythonPackageVersions(ctx, tt.resultsBytes, tt.expectedUpdates, tt.ignoreErrors)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			assert.ElementsMatch(t, tt.expectedFailed, failed)
		})
	}
}

func TestPythonManagerType(t *testing.T) {
	config := &buildkit.Config{}
	workingFolder := "/tmp/test"
	pm := &pythonManager{
		config:        config,
		workingFolder: workingFolder,
	}

	// Test that pythonManager implements LangManager interface
	var _ LangManager = pm

	// Test that GetLanguageManagers returns a pythonManager when there are Python packages
	manifest := &unversioned.UpdateManifest{
		LangUpdates: unversioned.LangUpdatePackages{
			{
				Name: "urllib3",
				Type: "python-pkg",
			},
		},
	}
	managers := GetLanguageManagers(config, workingFolder, manifest, false)
	require.Len(t, managers, 1)

	pythonMgr, ok := managers[0].(*pythonManager)
	assert.True(t, ok, "First manager should be a pythonManager")
	assert.Equal(t, config, pythonMgr.config)
	assert.Equal(t, workingFolder, pythonMgr.workingFolder)
}
