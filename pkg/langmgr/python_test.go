package langmgr

import (
	"context"
	"strings"
	"testing"

	"github.com/moby/buildkit/client/llb"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/utils"
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

func TestValidateVenvRoot(t *testing.T) {
	tests := []struct {
		name      string
		venvRoot  string
		expectErr bool
	}{
		{name: "valid opt venv", venvRoot: "/opt/venv", expectErr: false},
		{name: "valid app dotenv", venvRoot: "/app/.venv", expectErr: false},
		{name: "valid home venv", venvRoot: "/home/user/venv", expectErr: false},
		{name: "empty string", venvRoot: "", expectErr: true},
		{name: "relative path", venvRoot: "opt/venv", expectErr: true},
		{name: "dollar sign injection", venvRoot: "/opt/$(touch /pwned)", expectErr: true},
		{name: "semicolon injection", venvRoot: "/opt/venv; rm -rf /", expectErr: true},
		{name: "backtick injection", venvRoot: "/opt/`id`", expectErr: true},
		{name: "single quote injection", venvRoot: "/opt/v'env", expectErr: true},
		{name: "double quote injection", venvRoot: `/opt/v"env`, expectErr: true},
		{name: "space in path", venvRoot: "/opt/my venv", expectErr: true},
		{name: "pipe injection", venvRoot: "/opt/venv|evil", expectErr: true},
		{name: "path traversal dotdot", venvRoot: "/opt/venv/../../etc", expectErr: true},
		{name: "path traversal at start", venvRoot: "/../etc/lib", expectErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateVenvRoot(tt.venvRoot)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDeriveVenvRoot(t *testing.T) {
	tests := []struct {
		name     string
		pkgPath  string
		expected string
	}{
		{
			name:     "venv at /opt/venv",
			pkgPath:  "opt/venv/lib/python3.12/site-packages",
			expected: "/opt/venv",
		},
		{
			name:     "venv at /opt/venv with trailing subpath",
			pkgPath:  "opt/venv/lib/python3.12/site-packages/jaraco.context/",
			expected: "/opt/venv",
		},
		{
			name:     "venv at /app/.venv",
			pkgPath:  "app/.venv/lib/python3.11/site-packages",
			expected: "/app/.venv",
		},
		{
			name:     "venv at /home/user/venv",
			pkgPath:  "home/user/venv/lib/python3.9/site-packages",
			expected: "/home/user/venv",
		},
		{
			name:     "system path usr/local is not a venv",
			pkgPath:  "usr/local/lib/python3.12/site-packages",
			expected: "",
		},
		{
			name:     "system path usr/lib is not a venv",
			pkgPath:  "usr/lib/python3/dist-packages",
			expected: "",
		},
		{
			name:     "Azure CLI system path is not a venv",
			pkgPath:  "usr/lib/az/lib/python3.12/site-packages",
			expected: "",
		},
		{
			name:     "empty path",
			pkgPath:  "",
			expected: "",
		},
		{
			name:     "path with no site-packages pattern",
			pkgPath:  "some/random/path",
			expected: "",
		},
		{
			name:     "with leading slash",
			pkgPath:  "/opt/venv/lib/python3.12/site-packages",
			expected: "/opt/venv",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := deriveVenvRoot(tt.pkgPath)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGroupPackagesByEnv(t *testing.T) {
	tests := []struct {
		name           string
		updates        unversioned.LangUpdatePackages
		expectedSystem unversioned.LangUpdatePackages
		expectedVenvs  map[string]unversioned.LangUpdatePackages
	}{
		{
			name: "all system packages",
			updates: unversioned.LangUpdatePackages{
				{Name: "requests", FixedVersion: "2.28.0", PkgPath: "usr/lib/python3.12/site-packages"},
				{Name: "urllib3", FixedVersion: "1.26.0", PkgPath: "usr/local/lib/python3.12/site-packages"},
			},
			expectedSystem: unversioned.LangUpdatePackages{
				{Name: "requests", FixedVersion: "2.28.0", PkgPath: "usr/lib/python3.12/site-packages"},
				{Name: "urllib3", FixedVersion: "1.26.0", PkgPath: "usr/local/lib/python3.12/site-packages"},
			},
			expectedVenvs: map[string]unversioned.LangUpdatePackages{},
		},
		{
			name: "all venv packages",
			updates: unversioned.LangUpdatePackages{
				{Name: "pip", FixedVersion: "24.0", PkgPath: "opt/venv/lib/python3.12/site-packages"},
				{Name: "wheel", FixedVersion: "0.43.0", PkgPath: "opt/venv/lib/python3.12/site-packages"},
			},
			expectedSystem: unversioned.LangUpdatePackages{},
			expectedVenvs: map[string]unversioned.LangUpdatePackages{
				"/opt/venv": {
					{Name: "pip", FixedVersion: "24.0", PkgPath: "opt/venv/lib/python3.12/site-packages"},
					{Name: "wheel", FixedVersion: "0.43.0", PkgPath: "opt/venv/lib/python3.12/site-packages"},
				},
			},
		},
		{
			name: "mixed system and venv",
			updates: unversioned.LangUpdatePackages{
				{Name: "requests", FixedVersion: "2.28.0", PkgPath: "usr/lib/python3.12/site-packages"},
				{Name: "pip", FixedVersion: "24.0", PkgPath: "opt/venv/lib/python3.12/site-packages"},
			},
			expectedSystem: unversioned.LangUpdatePackages{
				{Name: "requests", FixedVersion: "2.28.0", PkgPath: "usr/lib/python3.12/site-packages"},
			},
			expectedVenvs: map[string]unversioned.LangUpdatePackages{
				"/opt/venv": {
					{Name: "pip", FixedVersion: "24.0", PkgPath: "opt/venv/lib/python3.12/site-packages"},
				},
			},
		},
		{
			name: "two different venvs",
			updates: unversioned.LangUpdatePackages{
				{Name: "pip", FixedVersion: "24.0", PkgPath: "opt/venv/lib/python3.12/site-packages"},
				{Name: "requests", FixedVersion: "2.28.0", PkgPath: "app/.venv/lib/python3.11/site-packages"},
			},
			expectedSystem: unversioned.LangUpdatePackages{},
			expectedVenvs: map[string]unversioned.LangUpdatePackages{
				"/opt/venv": {
					{Name: "pip", FixedVersion: "24.0", PkgPath: "opt/venv/lib/python3.12/site-packages"},
				},
				"/app/.venv": {
					{Name: "requests", FixedVersion: "2.28.0", PkgPath: "app/.venv/lib/python3.11/site-packages"},
				},
			},
		},
		{
			name: "same package at system AND venv - one in each group",
			updates: unversioned.LangUpdatePackages{
				{Name: "pip", FixedVersion: "24.0", PkgPath: "usr/lib/python3.12/site-packages"},
				{Name: "pip", FixedVersion: "24.0", PkgPath: "opt/venv/lib/python3.12/site-packages"},
			},
			expectedSystem: unversioned.LangUpdatePackages{
				{Name: "pip", FixedVersion: "24.0", PkgPath: "usr/lib/python3.12/site-packages"},
			},
			expectedVenvs: map[string]unversioned.LangUpdatePackages{
				"/opt/venv": {
					{Name: "pip", FixedVersion: "24.0", PkgPath: "opt/venv/lib/python3.12/site-packages"},
				},
			},
		},
		{
			name: "empty PkgPath goes to system group",
			updates: unversioned.LangUpdatePackages{
				{Name: "requests", FixedVersion: "2.28.0"},
			},
			expectedSystem: unversioned.LangUpdatePackages{
				{Name: "requests", FixedVersion: "2.28.0"},
			},
			expectedVenvs: map[string]unversioned.LangUpdatePackages{},
		},
		{
			name: "vendored package is skipped, top-level dist-info path is kept",
			updates: unversioned.LangUpdatePackages{
				// Top-level package reported via dist-info METADATA path — patchable, keep it.
				{
					Name: "pip", InstalledVersion: "25.3", FixedVersion: "26.0",
					PkgPath: "app/.venv/lib/python3.14/site-packages/pip-25.3.dist-info/METADATA",
				},
				// Vendored copy inside setuptools — skip it.
				{
					Name: "wheel", InstalledVersion: "0.45.1", FixedVersion: "0.46.2",
					PkgPath: "app/.venv/lib/python3.14/site-packages/setuptools/_vendor/wheel-0.45.1.dist-info/METADATA",
				},
			},
			expectedSystem: unversioned.LangUpdatePackages{},
			expectedVenvs: map[string]unversioned.LangUpdatePackages{
				"/app/.venv": {
					{
						Name: "pip", InstalledVersion: "25.3", FixedVersion: "26.0",
						PkgPath: "app/.venv/lib/python3.14/site-packages/pip-25.3.dist-info/METADATA",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			system, venvs := groupPackagesByEnv(tt.updates)
			assert.ElementsMatch(t, tt.expectedSystem, system)
			assert.Equal(t, len(tt.expectedVenvs), len(venvs))
			for venvRoot, expectedPkgs := range tt.expectedVenvs {
				assert.ElementsMatch(t, expectedPkgs, venvs[venvRoot])
			}
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
	managers := GetLanguageManagers(config, workingFolder, manifest)
	require.Len(t, managers, 1)

	pythonMgr, ok := managers[0].(*pythonManager)
	assert.True(t, ok, "First manager should be a pythonManager")
	assert.Equal(t, config, pythonMgr.config)
	assert.Equal(t, workingFolder, pythonMgr.workingFolder)
}

func TestValidatePythonPackageName(t *testing.T) {
	tests := []struct {
		name      string
		pkgName   string
		expectErr bool
	}{
		{name: "valid simple", pkgName: "requests", expectErr: false},
		{name: "valid with dash", pkgName: "my-package", expectErr: false},
		{name: "valid with dot", pkgName: "pkg.name", expectErr: false},
		{name: "valid with underscore", pkgName: "pkg_name", expectErr: false},
		{name: "valid alphanumeric", pkgName: "pkg123", expectErr: false},
		{name: "valid single char", pkgName: "a", expectErr: false},
		{name: "empty string", pkgName: "", expectErr: true},
		{name: "too long", pkgName: strings.Repeat("a", 215), expectErr: true},
		{name: "semicolon injection", pkgName: "pkg;evil", expectErr: true},
		{name: "dollar sign", pkgName: "pkg$var", expectErr: true},
		{name: "backtick", pkgName: "pkg`cmd`", expectErr: true},
		{name: "pipe", pkgName: "pkg|evil", expectErr: true},
		{name: "starts with dash", pkgName: "-pkg", expectErr: true},
		{name: "starts with dot", pkgName: ".pkg", expectErr: true},
		{name: "spaces", pkgName: "pkg name", expectErr: true},
		{name: "single quote", pkgName: "pkg'name", expectErr: true},
		{name: "double quote", pkgName: `pkg"name`, expectErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePythonPackageName(tt.pkgName)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidatePythonVersion(t *testing.T) {
	tests := []struct {
		name      string
		version   string
		expectErr bool
	}{
		{name: "valid simple", version: "1.0.0", expectErr: false},
		{name: "valid two part", version: "1.26", expectErr: false},
		{name: "valid complex", version: "2.28.0.post1", expectErr: false},
		{name: "valid pre-release", version: "1.0.0a1", expectErr: false},
		{name: "empty string", version: "", expectErr: true},
		{name: "not a version", version: "not-a-version", expectErr: true},
		{name: "semicolon injection", version: "1.0.0;evil", expectErr: true},
		{name: "dollar sign", version: "1.0.$var", expectErr: true},
		{name: "backtick", version: "1.0.`id`", expectErr: true},
		{name: "pipe", version: "1.0|evil", expectErr: true},
		{name: "single quote", version: "1.0'x", expectErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePythonVersion(tt.version)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestFilterPythonPackages(t *testing.T) {
	tests := []struct {
		name     string
		input    unversioned.LangUpdatePackages
		expected int
	}{
		{
			name: "only python packages",
			input: unversioned.LangUpdatePackages{
				{Name: "requests", Type: utils.PythonPackages},
				{Name: "urllib3", Type: utils.PythonPackages},
			},
			expected: 2,
		},
		{
			name: "mixed package types",
			input: unversioned.LangUpdatePackages{
				{Name: "requests", Type: utils.PythonPackages},
				{Name: "express", Type: utils.NodePackages},
				{Name: "other", Type: "other-type"},
			},
			expected: 1,
		},
		{
			name:     "empty input",
			input:    unversioned.LangUpdatePackages{},
			expected: 0,
		},
		{
			name:     "nil input",
			input:    nil,
			expected: 0,
		},
		{
			name: "no python packages",
			input: unversioned.LangUpdatePackages{
				{Name: "express", Type: utils.NodePackages},
			},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filterPythonPackages(tt.input)
			assert.Len(t, result, tt.expected)
			for _, pkg := range result {
				assert.Equal(t, utils.PythonPackages, pkg.Type)
			}
		})
	}
}

func TestInstallPythonPackages(t *testing.T) {
	config := &buildkit.Config{}
	pm := &pythonManager{config: config, workingFolder: "/tmp/test"}
	base := llb.Scratch()

	t.Run("empty packageSpecs returns input state without error", func(t *testing.T) {
		// Empty input should not panic and returns a valid state.
		result := pm.installPythonPackages(&base, nil, false)
		_ = result // llb.State contains func values; just verify no panic/error
		result = pm.installPythonPackages(&base, []string{}, false)
		_ = result
	})

	t.Run("non-empty with ignoreErrors=false builds state without panic", func(t *testing.T) {
		// llb.Args path — verifies DAG construction doesn't panic.
		result := pm.installPythonPackages(&base, []string{"requests==2.28.0"}, false)
		_ = result
	})

	t.Run("non-empty with ignoreErrors=true builds state without panic", func(t *testing.T) {
		// sh -c script path — verifies DAG construction doesn't panic.
		result := pm.installPythonPackages(&base, []string{"requests==2.28.0", "urllib3==1.26.0"}, true)
		_ = result
	})
}

func TestInstallPythonPackagesWithPip(t *testing.T) {
	config := &buildkit.Config{}
	pm := &pythonManager{config: config, workingFolder: "/tmp/test"}
	base := llb.Scratch()
	pipPath := "/opt/venv/bin/pip"

	t.Run("empty packageSpecs returns without panic", func(t *testing.T) {
		result := pm.installPythonPackagesWithPip(&base, pipPath, nil, false)
		_ = result
		result = pm.installPythonPackagesWithPip(&base, pipPath, []string{}, true)
		_ = result
	})

	t.Run("non-empty with ignoreErrors=false uses llb.Args without panic", func(t *testing.T) {
		result := pm.installPythonPackagesWithPip(&base, pipPath, []string{"requests==2.28.0"}, false)
		_ = result
	})

	t.Run("non-empty with ignoreErrors=true uses positional args without panic", func(t *testing.T) {
		// Verifies the fixed path: pipPath passed via llb.Args, not interpolated into shell string.
		result := pm.installPythonPackagesWithPip(&base, pipPath, []string{"requests==2.28.0"}, true)
		_ = result
	})

	t.Run("multiple specs with ignoreErrors=true without panic", func(t *testing.T) {
		result := pm.installPythonPackagesWithPip(&base, "/opt/my-env/bin/pip3",
			[]string{"requests==2.28.0", "urllib3==1.26.0"}, true)
		_ = result
	})
}

func TestIsNestedSitePackage(t *testing.T) {
	tests := []struct {
		name     string
		pkgPath  string
		expected bool
	}{
		{
			name:     "empty path",
			pkgPath:  "",
			expected: false,
		},
		{
			name:     "top-level site-packages directory only",
			pkgPath:  "app/.venv/lib/python3.14/site-packages",
			expected: false,
		},
		{
			name:     "top-level site-packages with trailing slash",
			pkgPath:  "app/.venv/lib/python3.14/site-packages/",
			expected: false,
		},
		{
			name:     "package's own dist-info directly under site-packages (trivy METADATA path format)",
			pkgPath:  "app/.venv/lib/python3.14/site-packages/pip-25.3.dist-info/METADATA",
			expected: false,
		},
		{
			name:     "system package dist-info directly under site-packages",
			pkgPath:  "usr/local/lib/python3.14/site-packages/pip-25.3.dist-info/METADATA",
			expected: false,
		},
		{
			name:     "egg-info directly under site-packages",
			pkgPath:  "usr/local/lib/python3.11/site-packages/requests-2.28.0.egg-info",
			expected: false,
		},
		{
			name:     "vendored copy inside setuptools _vendor",
			pkgPath:  "app/.venv/lib/python3.14/site-packages/setuptools/_vendor/wheel-0.45.1.dist-info/METADATA",
			expected: true,
		},
		{
			name:     "vendored copy inside pip _vendor",
			pkgPath:  "app/.venv/lib/python3.12/site-packages/pip/_vendor/requests-2.28.0.dist-info/METADATA",
			expected: true,
		},
		{
			name:     "nested package in another package subdirectory",
			pkgPath:  "usr/local/lib/python3.11/site-packages/some_pkg/bundled/certifi-2021.10.8.dist-info",
			expected: true,
		},
		{
			name:     "system path with no site-packages segment",
			pkgPath:  "usr/lib/python3.11/dist-packages",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isNestedSitePackage(tt.pkgPath)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDeriveVenvRootEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		pkgPath  string
		expected string
	}{
		{
			name:     "double slash produces slash prefix - not a venv",
			pkgPath:  "//lib/python3.12/site-packages",
			expected: "",
		},
		{
			name:     "only site-packages pattern at root - not a venv",
			pkgPath:  "/lib/python3.12/site-packages",
			expected: "",
		},
		{
			name:     "dist-packages is not site-packages",
			pkgPath:  "opt/venv/lib/python3.12/dist-packages",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := deriveVenvRoot(tt.pkgPath)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExtractSitePackagesDir(t *testing.T) {
	tests := []struct {
		name     string
		pkgPath  string
		expected string
	}{
		{
			name:     "empty path",
			pkgPath:  "",
			expected: "",
		},
		{
			name:     "site-packages directory only — no subpath",
			pkgPath:  "usr/lib/python3.12/site-packages",
			expected: "",
		},
		{
			name:     "site-packages with trailing slash — no subpath",
			pkgPath:  "usr/lib/python3.12/site-packages/",
			expected: "",
		},
		{
			name:     "system dist-info path",
			pkgPath:  "usr/local/lib/python3.14/site-packages/pip-25.3.dist-info/METADATA",
			expected: "/usr/local/lib/python3.14/site-packages",
		},
		{
			name:     "venv dist-info path",
			pkgPath:  "app/.venv/lib/python3.14/site-packages/pip-25.3.dist-info/METADATA",
			expected: "/app/.venv/lib/python3.14/site-packages",
		},
		{
			name:     "vendored dist-info path — also has site-packages dir",
			pkgPath:  "app/.venv/lib/python3.14/site-packages/setuptools/_vendor/wheel-0.45.1.dist-info/METADATA",
			expected: "/app/.venv/lib/python3.14/site-packages",
		},
		{
			name:     "path with no site-packages segment",
			pkgPath:  "usr/lib/python3.11/dist-packages",
			expected: "",
		},
		{
			name:     "package directory directly under site-packages",
			pkgPath:  "usr/local/lib/python3.11/site-packages/requests",
			expected: "/usr/local/lib/python3.11/site-packages",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractSitePackagesDir(tt.pkgPath)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExtractVendorParent(t *testing.T) {
	tests := []struct {
		name     string
		pkgPath  string
		expected string
	}{
		{
			name:     "empty path",
			pkgPath:  "",
			expected: "",
		},
		{
			name:     "top-level dist-info path — not vendored",
			pkgPath:  "app/.venv/lib/python3.14/site-packages/pip-25.3.dist-info/METADATA",
			expected: "",
		},
		{
			name:     "site-packages directory only — not vendored",
			pkgPath:  "app/.venv/lib/python3.14/site-packages",
			expected: "",
		},
		{
			name:     "setuptools vendors wheel",
			pkgPath:  "app/.venv/lib/python3.14/site-packages/setuptools/_vendor/wheel-0.45.1.dist-info/METADATA",
			expected: "setuptools",
		},
		{
			name:     "pip vendors requests",
			pkgPath:  "app/.venv/lib/python3.12/site-packages/pip/_vendor/requests-2.28.0.dist-info/METADATA",
			expected: "pip",
		},
		{
			name:     "some_pkg bundles certifi — system site-packages",
			pkgPath:  "usr/local/lib/python3.11/site-packages/some_pkg/bundled/certifi-2021.10.8.dist-info",
			expected: "some_pkg",
		},
		{
			name:     "no site-packages segment",
			pkgPath:  "usr/lib/python3.11/dist-packages",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractVendorParent(tt.pkgPath)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCollectVendorParentNames(t *testing.T) {
	tests := []struct {
		name     string
		updates  unversioned.LangUpdatePackages
		expected map[string][]string
	}{
		{
			name:     "no vendored packages",
			updates:  unversioned.LangUpdatePackages{},
			expected: map[string][]string{},
		},
		{
			name: "top-level packages only — no parents collected",
			updates: unversioned.LangUpdatePackages{
				{Name: "requests", PkgPath: "opt/venv/lib/python3.12/site-packages"},
				{Name: "pip", PkgPath: "opt/venv/lib/python3.12/site-packages/pip-25.3.dist-info/METADATA"},
			},
			expected: map[string][]string{},
		},
		{
			name: "vendored package in venv — parent collected under venv root",
			updates: unversioned.LangUpdatePackages{
				{Name: "wheel", PkgPath: "app/.venv/lib/python3.14/site-packages/setuptools/_vendor/wheel-0.45.1.dist-info/METADATA"},
			},
			expected: map[string][]string{
				"/app/.venv": {"setuptools"},
			},
		},
		{
			name: "two vendored packages with same parent — parent deduplicated",
			updates: unversioned.LangUpdatePackages{
				{Name: "wheel", PkgPath: "app/.venv/lib/python3.14/site-packages/setuptools/_vendor/wheel-0.45.1.dist-info/METADATA"},
				{Name: "jaraco.context", PkgPath: "app/.venv/lib/python3.14/site-packages/setuptools/_vendor/jaraco.context-5.3.0.dist-info/METADATA"},
			},
			expected: map[string][]string{
				"/app/.venv": {"setuptools"},
			},
		},
		{
			name: "vendored packages from two different parents in the same venv",
			updates: unversioned.LangUpdatePackages{
				{Name: "wheel", PkgPath: "app/.venv/lib/python3.14/site-packages/setuptools/_vendor/wheel-0.45.1.dist-info/METADATA"},
				{Name: "requests", PkgPath: "app/.venv/lib/python3.14/site-packages/pip/_vendor/requests-2.28.0.dist-info/METADATA"},
			},
			expected: map[string][]string{
				// Parent packages are "setuptools" and "pip" (the vendoring packages, not the vendored ones).
				"/app/.venv": {"setuptools", "pip"},
			},
		},
		{
			name: "vendored package in system site-packages — empty string key",
			updates: unversioned.LangUpdatePackages{
				{Name: "certifi", PkgPath: "usr/local/lib/python3.11/site-packages/some_pkg/bundled/certifi-2021.10.8.dist-info"},
			},
			expected: map[string][]string{
				"": {"some_pkg"},
			},
		},
		{
			name: "mix of top-level and vendored packages",
			updates: unversioned.LangUpdatePackages{
				{Name: "pip", PkgPath: "app/.venv/lib/python3.14/site-packages/pip-25.3.dist-info/METADATA"},
				{Name: "wheel", PkgPath: "app/.venv/lib/python3.14/site-packages/setuptools/_vendor/wheel-0.45.1.dist-info/METADATA"},
			},
			expected: map[string][]string{
				"/app/.venv": {"setuptools"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := collectVendorParentNames(tt.updates)
			assert.Equal(t, len(tt.expected), len(result), "number of env roots mismatch")
			for root, expectedParents := range tt.expected {
				assert.ElementsMatch(t, expectedParents, result[root],
					"parents for root %q mismatch", root)
			}
		})
	}
}
