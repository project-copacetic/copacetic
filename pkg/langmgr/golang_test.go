package langmgr

import (
	"context"
	"fmt"
	"io/fs"
	"testing"

	"github.com/moby/buildkit/client/llb"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	fstypes "github.com/tonistiigi/fsutil/types"
)

func TestIsValidGoVersion(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected bool
	}{
		{
			name:     "valid simple version with v prefix",
			version:  "v1.2.3",
			expected: true,
		},
		{
			name:     "valid simple version without v prefix",
			version:  "1.2.3",
			expected: true,
		},
		{
			name:     "valid major.minor version",
			version:  "v1.2.0",
			expected: true,
		},
		{
			name:     "valid pseudo-version",
			version:  "v0.0.0-20230101120000-abcdef123456",
			expected: true,
		},
		{
			name:     "valid pre-release version",
			version:  "v1.2.3-beta.1",
			expected: true,
		},
		{
			name:     "valid version with build metadata",
			version:  "v1.2.3+build.1",
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
			name:     "version without v prefix (still valid after normalization)",
			version:  "0.0.0",
			expected: true,
		},
		{
			name:     "invalid characters",
			version:  "v1.2.3@invalid",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidGoVersion(tt.version)
			assert.Equal(t, tt.expected, result, "Version: %s", tt.version)
		})
	}
}

func TestIsLessThanGoVersion(t *testing.T) {
	tests := []struct {
		name     string
		v1       string
		v2       string
		expected bool
	}{
		{
			name:     "v1 less than v2",
			v1:       "v1.0.0",
			v2:       "v1.1.0",
			expected: true,
		},
		{
			name:     "v1 greater than v2",
			v1:       "v1.1.0",
			v2:       "v1.0.0",
			expected: false,
		},
		{
			name:     "v1 equals v2",
			v1:       "v1.0.0",
			v2:       "v1.0.0",
			expected: false,
		},
		{
			name:     "different major versions",
			v1:       "v1.0.0",
			v2:       "v2.0.0",
			expected: true,
		},
		{
			name:     "patch version difference",
			v1:       "v1.2.0",
			v2:       "v1.2.1",
			expected: true,
		},
		{
			name:     "pseudo-versions comparison",
			v1:       "v0.0.0-20230101120000-abcdef123456",
			v2:       "v0.0.0-20230102120000-ghijkl789012",
			expected: true,
		},
		{
			name:     "pre-release vs release",
			v1:       "v1.0.0-beta.1",
			v2:       "v1.0.0",
			expected: true,
		},
		{
			name:     "versions without v prefix",
			v1:       "1.0.0",
			v2:       "1.1.0",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isLessThanGoVersion(tt.v1, tt.v2)
			assert.Equal(t, tt.expected, result, "v1: %s, v2: %s", tt.v1, tt.v2)
		})
	}
}

func TestValidateGoPackageName(t *testing.T) {
	tests := []struct {
		name        string
		packageName string
		expectError bool
	}{
		{
			name:        "valid package name",
			packageName: "github.com/user/repo",
			expectError: false,
		},
		{
			name:        "valid package name with subdirectory",
			packageName: "github.com/user/repo/pkg/module",
			expectError: false,
		},
		{
			name:        "valid package name with version suffix",
			packageName: "github.com/user/repo/v2",
			expectError: false,
		},
		{
			name:        "valid golang.org package",
			packageName: "golang.org/x/mod",
			expectError: false,
		},
		{
			name:        "empty package name",
			packageName: "",
			expectError: true,
		},
		{
			name:        "package name without slash",
			packageName: "invalid",
			expectError: true,
		},
		{
			name:        "package name with shell injection characters (semicolon)",
			packageName: "github.com/user/repo; rm -rf /",
			expectError: true,
		},
		{
			name:        "package name with shell injection characters (pipe)",
			packageName: "github.com/user/repo | cat /etc/passwd",
			expectError: true,
		},
		{
			name:        "package name with backticks",
			packageName: "github.com/user/`echo hacked`",
			expectError: true,
		},
		{
			name:        "package name with dollar sign",
			packageName: "github.com/user/$HOME",
			expectError: true,
		},
		{
			name:        "package name with whitespace",
			packageName: "github.com/user/repo name",
			expectError: true,
		},
		{
			name:        "package name with newline",
			packageName: "github.com/user/repo\n",
			expectError: true,
		},
		{
			name:        "package name starting with dash",
			packageName: "-modfile=/tmp/pwn/mod",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateGoPackageName(tt.packageName)
			if tt.expectError {
				assert.Error(t, err, "Expected error for package name: %s", tt.packageName)
			} else {
				assert.NoError(t, err, "Expected no error for package name: %s", tt.packageName)
			}
		})
	}
}

func TestValidateGoVersion(t *testing.T) {
	tests := []struct {
		name        string
		version     string
		expectError bool
	}{
		{
			name:        "valid version with v prefix",
			version:     "v1.2.3",
			expectError: false,
		},
		{
			name:        "valid version without v prefix",
			version:     "1.2.3",
			expectError: false,
		},
		{
			name:        "valid pseudo-version",
			version:     "v0.0.0-20230101120000-abcdef123456",
			expectError: false,
		},
		{
			name:        "valid pre-release",
			version:     "v1.0.0-beta.1",
			expectError: false,
		},
		{
			name:        "empty version",
			version:     "",
			expectError: true,
		},
		{
			name:        "invalid version format",
			version:     "invalid",
			expectError: true,
		},
		{
			name:        "version with shell injection (semicolon)",
			version:     "v1.0.0; echo hacked",
			expectError: true,
		},
		{
			name:        "version with shell injection (pipe)",
			version:     "v1.0.0 | cat /etc/passwd",
			expectError: true,
		},
		{
			name:        "version with backticks",
			version:     "v1.0.0`echo hacked`",
			expectError: true,
		},
		{
			name:        "version with dollar sign",
			version:     "v1.0.0$HOME",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateGoVersion(tt.version)
			if tt.expectError {
				assert.Error(t, err, "Expected error for version: %s", tt.version)
			} else {
				assert.NoError(t, err, "Expected no error for version: %s", tt.version)
			}
		})
	}
}

func TestCleanGoVersion(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "single version with v prefix",
			input:    "v1.2.3",
			expected: "v1.2.3",
		},
		{
			name:     "single version without v prefix",
			input:    "1.2.3",
			expected: "v1.2.3",
		},
		{
			name:     "comma-separated versions",
			input:    "v1.2.3, v1.2.4, v1.2.5",
			expected: "v1.2.3",
		},
		{
			name:     "comma-separated with whitespace",
			input:    "  v1.2.3  ,  v1.2.4  ",
			expected: "v1.2.3",
		},
		{
			name:     "single pseudo-version",
			input:    "v0.0.0-20230101120000-abcdef123456",
			expected: "v0.0.0-20230101120000-abcdef123456",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "invalid version in list",
			input:    "invalid, v1.2.3",
			expected: "v1.2.3",
		},
		{
			name:     "all invalid versions",
			input:    "invalid1, invalid2",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cleanGoVersion(tt.input)
			assert.Equal(t, tt.expected, result, "Input: %s", tt.input)
		})
	}
}

func TestFilterGoPackages(t *testing.T) {
	tests := []struct {
		name           string
		input          unversioned.LangUpdatePackages
		expected       int
		expectedStdlib string
		expectedNames  []string
	}{
		{
			name: "all Go modules",
			input: unversioned.LangUpdatePackages{
				{Name: "pkg1", Type: utils.GoModules},
				{Name: "pkg2", Type: utils.GoModules},
			},
			expected:      2,
			expectedNames: []string{"pkg1", "pkg2"},
		},
		{
			name: "all Go binaries",
			input: unversioned.LangUpdatePackages{
				{Name: "pkg1", Type: utils.GoBinary},
				{Name: "pkg2", Type: utils.GoBinary},
			},
			expected:      2,
			expectedNames: []string{"pkg1", "pkg2"},
		},
		{
			name: "mixed Go modules and binaries",
			input: unversioned.LangUpdatePackages{
				{Name: "pkg1", Type: utils.GoModules},
				{Name: "pkg2", Type: utils.GoBinary},
			},
			expected:      2,
			expectedNames: []string{"pkg1", "pkg2"},
		},
		{
			name: "mixed with other package types",
			input: unversioned.LangUpdatePackages{
				{Name: "pkg1", Type: utils.GoModules},
				{Name: "pkg2", Type: utils.PythonPackages},
				{Name: "pkg3", Type: utils.NodePackages},
				{Name: "pkg4", Type: utils.GoBinary},
			},
			expected:      2,
			expectedNames: []string{"pkg1", "pkg4"},
		},
		{
			name: "no Go packages",
			input: unversioned.LangUpdatePackages{
				{Name: "pkg1", Type: utils.PythonPackages},
				{Name: "pkg2", Type: utils.NodePackages},
			},
			expected: 0,
		},
		{
			name:     "empty input",
			input:    unversioned.LangUpdatePackages{},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, stdlibFixedVersion := filterGoPackages(tt.input)
			require.Len(t, result, tt.expected, "Expected %d packages, got %d", tt.expected, len(result))
			assert.Equal(t, tt.expectedStdlib, stdlibFixedVersion, "stdlibFixedVersion mismatch")

			// Verify all returned packages are Go packages with expected names
			var names []string
			for _, pkg := range result {
				assert.True(t,
					pkg.Type == utils.GoModules || pkg.Type == utils.GoBinary,
					"Package %s has unexpected type %s", pkg.Name, pkg.Type)
				names = append(names, pkg.Name)
			}
			if tt.expectedNames != nil {
				assert.ElementsMatch(t, tt.expectedNames, names, "Returned package names mismatch")
			}
		})
	}

	// Test stdlib detection
	t.Run("stdlib detected", func(t *testing.T) {
		input := unversioned.LangUpdatePackages{
			{Name: "stdlib", Type: utils.GoBinary, InstalledVersion: "v1.23.7", FixedVersion: "1.24.6"},
			{Name: "golang.org/x/crypto", Type: utils.GoModules, FixedVersion: "v0.45.0"},
		}
		result, stdlibFixedVersion := filterGoPackages(input)
		assert.NotEmpty(t, stdlibFixedVersion, "Expected stdlibFixedVersion to be set")
		assert.Equal(t, "v1.24.6", stdlibFixedVersion)
		assert.Len(t, result, 1, "Expected 1 non-stdlib package")
		assert.Equal(t, "golang.org/x/crypto", result[0].Name)
	})

	t.Run("stdlib only", func(t *testing.T) {
		input := unversioned.LangUpdatePackages{
			{Name: "stdlib", Type: utils.GoBinary, InstalledVersion: "v1.23.7", FixedVersion: "1.24.6"},
		}
		result, stdlibFixedVersion := filterGoPackages(input)
		assert.NotEmpty(t, stdlibFixedVersion, "Expected stdlibFixedVersion to be set")
		assert.Equal(t, "v1.24.6", stdlibFixedVersion)
		assert.Len(t, result, 0, "Expected 0 non-stdlib packages")
	})

	t.Run("no stdlib", func(t *testing.T) {
		input := unversioned.LangUpdatePackages{
			{Name: "golang.org/x/crypto", Type: utils.GoModules, FixedVersion: "v0.45.0"},
		}
		result, stdlibFixedVersion := filterGoPackages(input)
		assert.Empty(t, stdlibFixedVersion, "Expected stdlibFixedVersion to be empty")
		assert.Len(t, result, 1)
	})

	t.Run("multiple stdlib vulns picks highest fix", func(t *testing.T) {
		input := unversioned.LangUpdatePackages{
			{Name: "stdlib", Type: utils.GoBinary, InstalledVersion: "v1.22.0", FixedVersion: "1.23.5"},
			{Name: "stdlib", Type: utils.GoBinary, InstalledVersion: "v1.22.0", FixedVersion: "1.24.1"},
			{Name: "stdlib", Type: utils.GoBinary, InstalledVersion: "v1.22.0", FixedVersion: "1.23.8"},
		}
		result, stdlibFixedVersion := filterGoPackages(input)
		assert.Equal(t, "v1.24.1", stdlibFixedVersion, "Expected highest stdlib fix version")
		assert.Len(t, result, 0)
	})
}

func TestGetLanguageManagers_Go(t *testing.T) {
	config := &buildkit.Config{}
	workingFolder := "/tmp"

	tests := []struct {
		name            string
		manifest        *unversioned.UpdateManifest
		expectedCount   int
		expectGoMgr     bool
		expectPythonMgr bool
		expectNodeMgr   bool
	}{
		{
			name: "only Go modules",
			manifest: &unversioned.UpdateManifest{
				LangUpdates: unversioned.LangUpdatePackages{
					{Name: "github.com/user/repo", Type: utils.GoModules, FixedVersion: "v1.2.3"},
				},
			},
			expectedCount:   1,
			expectGoMgr:     true,
			expectPythonMgr: false,
			expectNodeMgr:   false,
		},
		{
			name: "only Go binaries",
			manifest: &unversioned.UpdateManifest{
				LangUpdates: unversioned.LangUpdatePackages{
					{Name: "github.com/user/repo", Type: utils.GoBinary, FixedVersion: "v1.2.3"},
				},
			},
			expectedCount:   1,
			expectGoMgr:     true,
			expectPythonMgr: false,
			expectNodeMgr:   false,
		},
		{
			name: "Go modules and Python packages",
			manifest: &unversioned.UpdateManifest{
				LangUpdates: unversioned.LangUpdatePackages{
					{Name: "github.com/user/repo", Type: utils.GoModules, FixedVersion: "v1.2.3"},
					{Name: "requests", Type: utils.PythonPackages, FixedVersion: "2.28.0"},
				},
			},
			expectedCount:   2,
			expectGoMgr:     true,
			expectPythonMgr: true,
			expectNodeMgr:   false,
		},
		{
			name: "all language types",
			manifest: &unversioned.UpdateManifest{
				LangUpdates: unversioned.LangUpdatePackages{
					{Name: "github.com/user/repo", Type: utils.GoModules, FixedVersion: "v1.2.3"},
					{Name: "requests", Type: utils.PythonPackages, FixedVersion: "2.28.0"},
					{Name: "express", Type: utils.NodePackages, FixedVersion: "4.18.0"},
				},
			},
			expectedCount:   3,
			expectGoMgr:     true,
			expectPythonMgr: true,
			expectNodeMgr:   true,
		},
		{
			name: "no language updates",
			manifest: &unversioned.UpdateManifest{
				LangUpdates: unversioned.LangUpdatePackages{},
			},
			expectedCount:   0,
			expectGoMgr:     false,
			expectPythonMgr: false,
			expectNodeMgr:   false,
		},
		{
			name:            "nil manifest",
			manifest:        nil,
			expectedCount:   0,
			expectGoMgr:     false,
			expectPythonMgr: false,
			expectNodeMgr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			managers := GetLanguageManagers(config, workingFolder, tt.manifest, "", "", "")
			assert.Len(t, managers, tt.expectedCount, "Expected %d managers, got %d", tt.expectedCount, len(managers))

			var hasGoMgr, hasPythonMgr, hasNodeMgr bool
			for _, mgr := range managers {
				switch mgr.(type) {
				case *golangManager:
					hasGoMgr = true
				case *pythonManager:
					hasPythonMgr = true
				case *nodejsManager:
					hasNodeMgr = true
				}
			}

			assert.Equal(t, tt.expectGoMgr, hasGoMgr, "Go manager presence mismatch")
			assert.Equal(t, tt.expectPythonMgr, hasPythonMgr, "Python manager presence mismatch")
			assert.Equal(t, tt.expectNodeMgr, hasNodeMgr, "Node manager presence mismatch")
		})
	}

	// Verify toolchainPatchLevel is propagated to the Go manager
	t.Run("toolchainPatchLevel propagated", func(t *testing.T) {
		manifest := &unversioned.UpdateManifest{
			LangUpdates: unversioned.LangUpdatePackages{
				{Name: "github.com/user/repo", Type: utils.GoModules, FixedVersion: "v1.2.3"},
			},
		}
		managers := GetLanguageManagers(config, workingFolder, manifest, "minor", "", "")
		require.Len(t, managers, 1)
		goMgr, ok := managers[0].(*golangManager)
		require.True(t, ok, "Expected golangManager")
		assert.Equal(t, "minor", goMgr.toolchainPatchLevel, "toolchainPatchLevel should be propagated")
	})

	t.Run("toolchainPatchLevel empty when not set", func(t *testing.T) {
		manifest := &unversioned.UpdateManifest{
			LangUpdates: unversioned.LangUpdatePackages{
				{Name: "github.com/user/repo", Type: utils.GoModules, FixedVersion: "v1.2.3"},
			},
		}
		managers := GetLanguageManagers(config, workingFolder, manifest, "", "", "")
		require.Len(t, managers, 1)
		goMgr, ok := managers[0].(*golangManager)
		require.True(t, ok, "Expected golangManager")
		assert.Empty(t, goMgr.toolchainPatchLevel, "toolchainPatchLevel should be empty when not set")
	})
}

func TestGetUniqueLatestUpdates_Go(t *testing.T) {
	goComparer := VersionComparer{isValidGoVersion, isLessThanGoVersion}

	tests := []struct {
		name          string
		input         unversioned.LangUpdatePackages
		ignoreErrors  bool
		expectedCount int
		expectError   bool
		checkPackage  func(*testing.T, unversioned.LangUpdatePackages)
	}{
		{
			name: "single package single version",
			input: unversioned.LangUpdatePackages{
				{Name: "github.com/gin-gonic/gin", FixedVersion: "v1.7.7", Type: utils.GoModules},
			},
			ignoreErrors:  false,
			expectedCount: 1,
			expectError:   false,
			checkPackage: func(t *testing.T, packages unversioned.LangUpdatePackages) {
				require.Len(t, packages, 1)
				assert.Equal(t, "github.com/gin-gonic/gin", packages[0].Name)
				assert.Equal(t, "v1.7.7", packages[0].FixedVersion)
			},
		},
		{
			name: "single package multiple versions - selects highest",
			input: unversioned.LangUpdatePackages{
				{Name: "github.com/gin-gonic/gin", FixedVersion: "v1.7.0", Type: utils.GoModules},
				{Name: "github.com/gin-gonic/gin", FixedVersion: "v1.7.7", Type: utils.GoModules},
				{Name: "github.com/gin-gonic/gin", FixedVersion: "v1.7.4", Type: utils.GoModules},
			},
			ignoreErrors:  false,
			expectedCount: 1,
			expectError:   false,
			checkPackage: func(t *testing.T, packages unversioned.LangUpdatePackages) {
				require.Len(t, packages, 1)
				assert.Equal(t, "github.com/gin-gonic/gin", packages[0].Name)
				assert.Equal(t, "v1.7.7", packages[0].FixedVersion, "Should select highest version")
			},
		},
		{
			name: "multiple packages",
			input: unversioned.LangUpdatePackages{
				{Name: "github.com/gin-gonic/gin", FixedVersion: "v1.7.7", Type: utils.GoModules},
				{Name: "golang.org/x/net", FixedVersion: "v0.5.0", Type: utils.GoModules},
			},
			ignoreErrors:  false,
			expectedCount: 2,
			expectError:   false,
			checkPackage: func(t *testing.T, packages unversioned.LangUpdatePackages) {
				require.Len(t, packages, 2)
				nameToVersion := map[string]string{}
				for _, pkg := range packages {
					nameToVersion[pkg.Name] = pkg.FixedVersion
				}
				assert.Equal(t, "v1.7.7", nameToVersion["github.com/gin-gonic/gin"])
				assert.Equal(t, "v0.5.0", nameToVersion["golang.org/x/net"])
			},
		},
		{
			name: "package with empty FixedVersion - should be skipped",
			input: unversioned.LangUpdatePackages{
				{Name: "github.com/gin-gonic/gin", FixedVersion: "", Type: utils.GoModules},
				{Name: "golang.org/x/net", FixedVersion: "v0.5.0", Type: utils.GoModules},
			},
			ignoreErrors:  false,
			expectedCount: 1,
			expectError:   false,
			checkPackage: func(t *testing.T, packages unversioned.LangUpdatePackages) {
				require.Len(t, packages, 1)
				assert.Equal(t, "golang.org/x/net", packages[0].Name)
			},
		},
		{
			name: "invalid version with ignoreErrors=true",
			input: unversioned.LangUpdatePackages{
				{Name: "github.com/gin-gonic/gin", FixedVersion: "invalid", Type: utils.GoModules},
				{Name: "golang.org/x/net", FixedVersion: "v0.5.0", Type: utils.GoModules},
			},
			ignoreErrors:  true,
			expectedCount: 1,
			expectError:   false,
			checkPackage: func(t *testing.T, packages unversioned.LangUpdatePackages) {
				require.Len(t, packages, 1)
				assert.Equal(t, "golang.org/x/net", packages[0].Name)
			},
		},
		{
			name: "invalid version with ignoreErrors=false",
			input: unversioned.LangUpdatePackages{
				{Name: "github.com/gin-gonic/gin", FixedVersion: "invalid", Type: utils.GoModules},
			},
			ignoreErrors:  false,
			expectedCount: 0,
			expectError:   true,
		},
		{
			name: "pseudo-versions",
			input: unversioned.LangUpdatePackages{
				{Name: "github.com/user/repo", FixedVersion: "v0.0.0-20230101120000-abcdef123456", Type: utils.GoModules},
				{Name: "github.com/user/repo", FixedVersion: "v0.0.0-20230102120000-ghijkl789012", Type: utils.GoModules},
			},
			ignoreErrors:  false,
			expectedCount: 1,
			expectError:   false,
			checkPackage: func(t *testing.T, packages unversioned.LangUpdatePackages) {
				require.Len(t, packages, 1)
				assert.Equal(t, "v0.0.0-20230102120000-ghijkl789012", packages[0].FixedVersion, "Should select later pseudo-version")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := GetUniqueLatestUpdates(tt.input, goComparer, tt.ignoreErrors)

			if tt.expectError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			assert.Len(t, result, tt.expectedCount, "Expected %d packages, got %d", tt.expectedCount, len(result))

			if tt.checkPackage != nil {
				tt.checkPackage(t, result)
			}
		})
	}
}

func TestRebuildFailureString(t *testing.T) {
	tests := []struct {
		name     string
		failure  rebuildFailure
		expected string
	}{
		{
			name:     "no build info",
			failure:  rebuildFailure{binaryPath: "/usr/bin/foo", reason: "no build info"},
			expected: "/usr/bin/foo: no build info",
		},
		{
			name:     "error reason",
			failure:  rebuildFailure{binaryPath: "/usr/bin/bar", reason: "exit status 1"},
			expected: "/usr/bin/bar: exit status 1",
		},
		{
			name:     "empty reason",
			failure:  rebuildFailure{binaryPath: "/usr/bin/baz", reason: ""},
			expected: "/usr/bin/baz: ",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.failure.String())
		})
	}
}

func TestRebuildFailureSliceFormat(t *testing.T) {
	failures := []rebuildFailure{
		{binaryPath: "/usr/bin/foo", reason: "no build info"},
		{binaryPath: "/usr/bin/bar", reason: "exit status 1"},
	}
	oldStyle := []string{
		"/usr/bin/foo: no build info",
		"/usr/bin/bar: exit status 1",
	}
	assert.Equal(t, fmt.Sprintf("%v", oldStyle), fmt.Sprintf("%v", failures),
		"rebuildFailure slice must format identically to the old []string representation")
}

func TestCollectGoBinaryInfo(t *testing.T) {
	tests := []struct {
		name        string
		updates     unversioned.LangUpdatePackages
		wantPaths   []string
		wantVersion string
	}{
		{
			name: "extracts paths and Go version from stdlib",
			updates: unversioned.LangUpdatePackages{
				{Name: "stdlib", PkgPath: "manager", Type: utils.GoBinary, InstalledVersion: "v1.26.0"},
				{Name: "golang.org/x/crypto", PkgPath: "manager", Type: utils.GoBinary},
			},
			wantPaths:   []string{"manager"},
			wantVersion: "1.26.0",
		},
		{
			name: "multiple paths no stdlib",
			updates: unversioned.LangUpdatePackages{
				{Name: "golang.org/x/crypto", PkgPath: "bin/consul", Type: utils.GoBinary},
				{Name: "golang.org/x/net", PkgPath: "bin/consul-agent", Type: utils.GoBinary},
			},
			wantPaths:   []string{"bin/consul", "bin/consul-agent"},
			wantVersion: "",
		},
		{
			name:      "skips non-gobinary",
			updates:   unversioned.LangUpdatePackages{{Name: "flask", PkgPath: "app/requirements.txt", Type: "pip"}},
			wantPaths: nil,
		},
		{
			name: "skips gomod entries even if PkgPath set",
			updates: unversioned.LangUpdatePackages{
				{Name: "github.com/foo/bar", PkgPath: "src/go.mod", Type: utils.GoModules},
				{Name: "stdlib", PkgPath: "manager", Type: utils.GoBinary, InstalledVersion: "v1.26.0"},
			},
			wantPaths:   []string{"manager"},
			wantVersion: "1.26.0",
		},
		{
			name: "all gomod, no binary paths returned",
			updates: unversioned.LangUpdatePackages{
				{Name: "github.com/foo/bar", PkgPath: "src/go.mod", Type: utils.GoModules},
				{Name: "github.com/baz/qux", PkgPath: "src/go.sum", Type: utils.GoModules},
			},
			wantPaths:   nil,
			wantVersion: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paths, goVersion := collectGoBinaryInfo(tt.updates)
			assert.Equal(t, tt.wantPaths, paths)
			assert.Equal(t, tt.wantVersion, goVersion)
		})
	}
}

func TestBuildSyntheticBinaryInfo(t *testing.T) {
	tests := []struct {
		name      string
		paths     []string
		goVCSURL  string
		wantCount int
		wantPaths []string
		wantMod   string
	}{
		{
			name:      "single binary path",
			paths:     []string{"manager"},
			goVCSURL:  "https://github.com/grafana/grafana-operator@v5.22.0",
			wantCount: 1,
			wantPaths: []string{"/manager"},
			wantMod:   "github.com/grafana/grafana-operator",
		},
		{
			name:      "multiple paths",
			paths:     []string{"bin/consul", "bin/consul-agent"},
			goVCSURL:  "https://github.com/hashicorp/consul@v1.22.4",
			wantCount: 2,
			wantPaths: []string{"/bin/consul", "/bin/consul-agent"},
			wantMod:   "github.com/hashicorp/consul",
		},
		{
			name:      "path already has leading slash",
			paths:     []string{"/usr/local/bin/app"},
			goVCSURL:  "https://github.com/example/app@v1.0.0",
			wantCount: 1,
			wantPaths: []string{"/usr/local/bin/app"},
			wantMod:   "github.com/example/app",
		},
		{
			name:      "empty paths",
			paths:     []string{},
			goVCSURL:  "https://github.com/example/app@v1.0.0",
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildSyntheticBinaryInfo(tt.paths, tt.goVCSURL, "1.26.0")
			assert.Len(t, result, tt.wantCount)

			for i, wantPath := range tt.wantPaths {
				if i < len(result) {
					assert.Equal(t, wantPath, result[i].Path)
					assert.Equal(t, tt.wantMod, result[i].ModulePath)
					assert.Equal(t, "0", result[i].BuildSettings["CGO_ENABLED"])
					assert.Equal(t, "0755", result[i].FileMode)
					assert.Equal(t, "0:0", result[i].FileOwner)
				}
			}
		})
	}
}

// TestBuildGoUpdateCmd asserts that the shell command emitted for both Go
// module update sites uses `go mod tidy -e`. The -e flag tolerates broken
// upstream go.mod files so that unrelated upstream module hygiene issues do
// not block CVE patches; see the helper's docstring in golang.go.
func TestBuildGoUpdateCmd(t *testing.T) {
	tests := []struct {
		name      string
		modPath   string
		allGetCmd string
		want      string
	}{
		{
			// Site 1: primary in-image path with a discovered go.mod path.
			name:      "in-image module path",
			modPath:   "/app",
			allGetCmd: "go get golang.org/x/net@v0.23.0",
			want:      `sh -c 'cd /app && go get golang.org/x/net@v0.23.0 && go mod tidy -e'`,
		},
		{
			// Site 2: tooling container fallback path.
			name:      "tooling container workspace",
			modPath:   "/workspace",
			allGetCmd: "go get golang.org/x/net@v0.23.0 && go get golang.org/x/text@v0.14.0",
			want:      `sh -c 'cd /workspace && go get golang.org/x/net@v0.23.0 && go get golang.org/x/text@v0.14.0 && go mod tidy -e'`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildGoUpdateCmd(tt.modPath, tt.allGetCmd)
			assert.Equal(t, tt.want, got)
			// Explicit guards against regression to bare `go mod tidy`.
			assert.Contains(t, got, "go mod tidy -e",
				"updateCmd must use 'go mod tidy -e' to tolerate broken upstream go.mod")
			assert.NotContains(t, got, "go mod tidy'",
				"updateCmd must not end with bare 'go mod tidy' (missing -e flag)")
		})
	}
}

func TestFilterGoDowngrades(t *testing.T) {
	tests := []struct {
		name            string
		input           unversioned.LangUpdatePackages
		expectedNames   []string
		expectedSkipped []string
	}{
		{
			name: "fixed version older than installed - skipped",
			input: unversioned.LangUpdatePackages{
				{Name: "github.com/gin-gonic/gin", InstalledVersion: "v1.9.1", FixedVersion: "v1.7.7", Type: utils.GoModules},
			},
			expectedNames:   []string{},
			expectedSkipped: []string{"github.com/gin-gonic/gin"},
		},
		{
			name: "fixed version equal to installed - skipped",
			input: unversioned.LangUpdatePackages{
				{Name: "github.com/gin-gonic/gin", InstalledVersion: "v1.7.7", FixedVersion: "v1.7.7", Type: utils.GoModules},
			},
			expectedNames:   []string{},
			expectedSkipped: []string{"github.com/gin-gonic/gin"},
		},
		{
			name: "fixed version newer than installed - kept",
			input: unversioned.LangUpdatePackages{
				{Name: "github.com/gin-gonic/gin", InstalledVersion: "v1.7.0", FixedVersion: "v1.7.7", Type: utils.GoModules},
			},
			expectedNames: []string{"github.com/gin-gonic/gin"},
		},
		{
			name: "versions without v prefix are normalized",
			input: unversioned.LangUpdatePackages{
				{Name: "github.com/gin-gonic/gin", InstalledVersion: "1.9.1", FixedVersion: "1.7.7", Type: utils.GoModules},
				{Name: "golang.org/x/net", InstalledVersion: "0.4.0", FixedVersion: "0.5.0", Type: utils.GoModules},
			},
			expectedNames:   []string{"golang.org/x/net"},
			expectedSkipped: []string{"github.com/gin-gonic/gin"},
		},
		{
			name: "empty installed version - kept",
			input: unversioned.LangUpdatePackages{
				{Name: "github.com/gin-gonic/gin", InstalledVersion: "", FixedVersion: "v1.7.7", Type: utils.GoModules},
			},
			expectedNames: []string{"github.com/gin-gonic/gin"},
		},
		{
			name: "empty fixed version - kept",
			input: unversioned.LangUpdatePackages{
				{Name: "github.com/gin-gonic/gin", InstalledVersion: "v1.9.1", FixedVersion: "", Type: utils.GoModules},
			},
			expectedNames: []string{"github.com/gin-gonic/gin"},
		},
		{
			name: "unparsable installed version - kept",
			input: unversioned.LangUpdatePackages{
				{Name: "github.com/gin-gonic/gin", InstalledVersion: "not-a-version", FixedVersion: "v1.7.7", Type: utils.GoModules},
			},
			expectedNames: []string{"github.com/gin-gonic/gin"},
		},
		{
			name: "unparsable fixed version - kept",
			input: unversioned.LangUpdatePackages{
				{Name: "github.com/gin-gonic/gin", InstalledVersion: "v1.9.1", FixedVersion: "v1.7.7, v1.8.0", Type: utils.GoModules},
			},
			expectedNames: []string{"github.com/gin-gonic/gin"},
		},
		{
			name: "mixed packages - only downgrades removed",
			input: unversioned.LangUpdatePackages{
				{Name: "github.com/gin-gonic/gin", InstalledVersion: "v1.9.1", FixedVersion: "v1.7.7", Type: utils.GoModules},
				{Name: "golang.org/x/net", InstalledVersion: "v0.4.0", FixedVersion: "v0.5.0", Type: utils.GoModules},
				{Name: "golang.org/x/text", InstalledVersion: "v0.3.8", FixedVersion: "v0.3.8", Type: utils.GoModules},
			},
			expectedNames:   []string{"golang.org/x/net"},
			expectedSkipped: []string{"github.com/gin-gonic/gin", "golang.org/x/text"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, skipped := filterGoDowngrades(tt.input)
			names := make([]string, 0, len(result))
			for _, pkg := range result {
				names = append(names, pkg.Name)
			}
			assert.Equal(t, tt.expectedNames, names)
			assert.Equal(t, tt.expectedSkipped, skipped)
			for _, skippedName := range skipped {
				assert.NotContains(t, names, skippedName,
					"skipped downgrade must not appear in the updates that get applied")
			}
		})
	}
}

func TestGolangManagerInstallUpdatesSkipsNonNewerVersion(t *testing.T) {
	config := &buildkit.Config{}
	currentState := &config.ImageState
	manager := &golangManager{}
	manifest := &unversioned.UpdateManifest{
		LangUpdates: unversioned.LangUpdatePackages{
			{
				Name:             "github.com/gin-gonic/gin",
				InstalledVersion: "v1.9.1",
				FixedVersion:     "v1.7.7",
				Type:             utils.GoModules,
			},
		},
	}

	state, errPkgs, err := manager.InstallUpdates(t.Context(), currentState, manifest, false)

	require.NoError(t, err)
	assert.Equal(t, []string{"github.com/gin-gonic/gin"}, errPkgs,
		"downgrade-skipped packages must be reported as unpatched so they stay out of validated updates")
	assert.Same(t, currentState, state)
}

func TestAppendIncompatibleIfNeeded(t *testing.T) {
	tests := []struct {
		name       string
		modulePath string
		version    string
		expected   string
	}{
		{
			name:       "pre-module major v2+ without path suffix",
			modulePath: "github.com/docker/docker",
			version:    "v28.0.0",
			expected:   "v28.0.0+incompatible",
		},
		{
			name:       "module path with matching major suffix",
			modulePath: "github.com/foo/bar/v2",
			version:    "v2.1.0",
			expected:   "v2.1.0",
		},
		{
			name:       "major v0",
			modulePath: "github.com/foo/bar",
			version:    "v0.9.1",
			expected:   "v0.9.1",
		},
		{
			name:       "major v1",
			modulePath: "github.com/foo/bar",
			version:    "v1.2.3",
			expected:   "v1.2.3",
		},
		{
			name:       "already suffixed",
			modulePath: "github.com/docker/docker",
			version:    "v28.0.0+incompatible",
			expected:   "v28.0.0+incompatible",
		},
		{
			name:       "pseudo-version at v0",
			modulePath: "github.com/foo/bar",
			version:    "v0.0.0-20230101120000-abcdef123456",
			expected:   "v0.0.0-20230101120000-abcdef123456",
		},
		{
			name:       "pseudo-version at major v2 without path suffix",
			modulePath: "github.com/foo/bar",
			version:    "v2.0.1-0.20230101120000-abcdef123456",
			expected:   "v2.0.1-0.20230101120000-abcdef123456+incompatible",
		},
		{
			name:       "pseudo-version at major v2 with path suffix",
			modulePath: "github.com/foo/bar/v2",
			version:    "v2.0.1-0.20230101120000-abcdef123456",
			expected:   "v2.0.1-0.20230101120000-abcdef123456",
		},
		{
			name:       "invalid version left unchanged",
			modulePath: "github.com/foo/bar",
			version:    "not-a-version",
			expected:   "not-a-version",
		},
		{
			name:       "empty version left unchanged",
			modulePath: "github.com/foo/bar",
			version:    "",
			expected:   "",
		},
		{
			// A version that already carries build metadata must not gain a
			// second '+' component, which would be invalid semver.
			name:       "existing build metadata left unchanged",
			modulePath: "github.com/foo/bar",
			version:    "v2.0.0+build1",
			expected:   "v2.0.0+build1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := appendIncompatibleIfNeeded(tt.modulePath, tt.version)
			assert.Equal(t, tt.expected, result, "Module: %s, version: %s", tt.modulePath, tt.version)
		})
	}
}

// TestIncompatibleVersionsPassValidation ensures the +incompatible build tag
// survives the existing version validation and cleaning paths.
func TestIncompatibleVersionsPassValidation(t *testing.T) {
	assert.True(t, isValidGoVersion("v28.0.0+incompatible"))
	assert.NoError(t, validateGoVersion("v28.0.0+incompatible"))
	assert.Equal(t, "v28.0.0+incompatible", cleanGoVersion("v28.0.0+incompatible"))
}

// TestBuildBinaryUpdateMap asserts that the binary-rebuild path normalizes the
// versions it records as module requirements: a missing 'v' prefix is added and
// pre-module major>=2 dependencies gain the +incompatible build tag, matching
// the `go get` spec construction used by the in-image module path.
func TestBuildBinaryUpdateMap(t *testing.T) {
	updates := unversioned.LangUpdatePackages{
		{Name: "github.com/docker/docker", FixedVersion: "v28.0.0"},
		{Name: "github.com/moby/moby", FixedVersion: "28.0.0"},
		{Name: "github.com/foo/bar/v2", FixedVersion: "v2.1.0"},
		{Name: "golang.org/x/net", FixedVersion: "v0.23.0"},
		{Name: "github.com/already/tagged", FixedVersion: "v3.1.0+incompatible"},
		{Name: "github.com/no/fix", FixedVersion: ""},
		{Name: "k8s.io/kubernetes", FixedVersion: "v1.30.0"},
	}

	got := buildBinaryUpdateMap(updates)

	want := map[string]string{
		"github.com/docker/docker":  "v28.0.0+incompatible",
		"github.com/moby/moby":      "v28.0.0+incompatible",
		"github.com/foo/bar/v2":     "v2.1.0",
		"golang.org/x/net":          "v0.23.0",
		"github.com/already/tagged": "v3.1.0+incompatible",
	}
	assert.Equal(t, want, got)
}

// TestVerifyGoModUpdates asserts that the post-update go.mod check catches
// updates that did not land. `go mod tidy -e` drops requirements for modules
// no longer imported by reachable code, so a `go get` bump can be silently
// reverted and the package still reported as patched.
func TestVerifyGoModUpdates(t *testing.T) {
	tests := []struct {
		name      string
		goMod     string
		goSum     string
		updates   unversioned.LangUpdatePackages
		wantErr   bool
		errSubstr string
	}{
		{
			name: "module present at target version",
			goMod: `module example.com/app

go 1.22

require golang.org/x/net v0.23.0
`,
			updates: unversioned.LangUpdatePackages{
				{Name: "golang.org/x/net", FixedVersion: "v0.23.0"},
			},
			wantErr: false,
		},
		{
			name: "module dropped by tidy",
			goMod: `module example.com/app

go 1.22

require golang.org/x/text v0.14.0
`,
			updates: unversioned.LangUpdatePackages{
				{Name: "golang.org/x/net", FixedVersion: "v0.23.0"},
			},
			wantErr:   true,
			errSubstr: "golang.org/x/net",
		},
		{
			name: "landed version below target",
			goMod: `module example.com/app

go 1.22

require golang.org/x/net v0.17.0
`,
			updates: unversioned.LangUpdatePackages{
				{Name: "golang.org/x/net", FixedVersion: "v0.23.0"},
			},
			wantErr:   true,
			errSubstr: "v0.17.0",
		},
		{
			name: "landed version above target",
			goMod: `module example.com/app

go 1.22

require golang.org/x/net v0.25.0
`,
			updates: unversioned.LangUpdatePackages{
				{Name: "golang.org/x/net", FixedVersion: "v0.23.0"},
			},
			wantErr: false,
		},
		{
			name: "target version without v prefix",
			goMod: `module example.com/app

go 1.22

require golang.org/x/net v0.23.0
`,
			updates: unversioned.LangUpdatePackages{
				{Name: "golang.org/x/net", FixedVersion: "0.23.0"},
			},
			wantErr: false,
		},
		{
			// A replacement whose left-hand side is another module says nothing
			// about u.Name: the two module paths have unrelated version lines.
			name: "unrelated module replacement does not satisfy target",
			goMod: `module example.com/app

go 1.22

require github.com/pkg/legacy v1.0.0

replace github.com/pkg/legacy => golang.org/x/net v0.23.0
`,
			updates: unversioned.LangUpdatePackages{
				{Name: "golang.org/x/net", FixedVersion: "v0.23.0"},
			},
			wantErr:   true,
			errSubstr: "not found in go.mod",
		},
		{
			// A versioned replacement pointing at a different module path cannot
			// prove the replaced module reached the requested version: the two
			// paths have unrelated version lines.
			name: "cross-module replacement cannot prove requested version",
			goMod: `module example.com/app

go 1.22

require github.com/pkg/legacy v0.17.0

replace github.com/pkg/legacy => golang.org/x/net v0.23.0
`,
			updates: unversioned.LangUpdatePackages{
				{Name: "github.com/pkg/legacy", FixedVersion: "v0.23.0"},
			},
			wantErr:   true,
			errSubstr: "different module path",
		},
		{
			name: "replace directive pins version below target",
			goMod: `module example.com/app

go 1.22

require golang.org/x/net v0.23.0

replace golang.org/x/net => golang.org/x/net v0.17.0
`,
			updates: unversioned.LangUpdatePackages{
				{Name: "golang.org/x/net", FixedVersion: "v0.23.0"},
			},
			wantErr:   true,
			errSubstr: "v0.17.0",
		},
		{
			// The contents behind a filesystem replacement carry no version, so
			// the require entry cannot prove the local code is patched.
			name: "filesystem replacement cannot prove requested version",
			goMod: `module example.com/app

go 1.22

require golang.org/x/net v0.23.0

replace golang.org/x/net => ./vendored/net
`,
			updates: unversioned.LangUpdatePackages{
				{Name: "golang.org/x/net", FixedVersion: "v0.23.0"},
			},
			wantErr:   true,
			errSubstr: "unversioned",
		},
		{
			// go.mod resolution prefers a replacement that names a version over
			// a filesystem replacement of the same module path.
			name: "versioned replacement preferred over filesystem replacement",
			goMod: `module example.com/app

go 1.22

require golang.org/x/net v0.17.0

replace golang.org/x/net => ./vendored/net

replace golang.org/x/net v0.17.0 => golang.org/x/net v0.23.0
`,
			updates: unversioned.LangUpdatePackages{
				{Name: "golang.org/x/net", FixedVersion: "v0.23.0"},
			},
			wantErr: false,
		},
		{
			// A replacement pinned to the selected version wins over a
			// path-wide replacement, as it does in the go command.
			name: "version pinned replacement preferred over path wide replacement",
			goMod: `module example.com/app

go 1.22

require golang.org/x/net v0.17.0

replace golang.org/x/net => golang.org/x/net v0.23.0

replace golang.org/x/net v0.17.0 => golang.org/x/net v0.10.0
`,
			updates: unversioned.LangUpdatePackages{
				{Name: "golang.org/x/net", FixedVersion: "v0.23.0"},
			},
			wantErr:   true,
			errSubstr: "v0.10.0",
		},
		{
			name: "version-specific replace for unselected version is ignored",
			goMod: `module example.com/app

go 1.22

require golang.org/x/net v0.23.0

replace golang.org/x/net v0.17.0 => golang.org/x/net v0.10.0
`,
			updates: unversioned.LangUpdatePackages{
				{Name: "golang.org/x/net", FixedVersion: "v0.23.0"},
			},
			wantErr: false,
		},
		{
			name: "incompatible suffix compares by semver core",
			goMod: `module example.com/app

go 1.22

require github.com/docker/docker v25.0.6+incompatible
`,
			updates: unversioned.LangUpdatePackages{
				{Name: "github.com/docker/docker", FixedVersion: "v25.0.6+incompatible"},
			},
			wantErr: false,
		},
		{
			name: "incompatible suffix below target",
			goMod: `module example.com/app

go 1.22

require github.com/docker/docker v24.0.9+incompatible
`,
			updates: unversioned.LangUpdatePackages{
				{Name: "github.com/docker/docker", FixedVersion: "v25.0.6+incompatible"},
			},
			wantErr:   true,
			errSubstr: "github.com/docker/docker",
		},
		{
			name: "empty updates",
			goMod: `module example.com/app

go 1.22
`,
			updates: unversioned.LangUpdatePackages{},
			wantErr: false,
		},
		{
			name: "updates without fixed version are skipped",
			goMod: `module example.com/app

go 1.22
`,
			updates: unversioned.LangUpdatePackages{
				{Name: "golang.org/x/net", FixedVersion: ""},
			},
			wantErr: false,
		},
		{
			name:  "unparseable go.mod",
			goMod: "this is not a go.mod\n",
			updates: unversioned.LangUpdatePackages{
				{Name: "golang.org/x/net", FixedVersion: "v0.23.0"},
			},
			wantErr:   true,
			errSubstr: "go.mod",
		},
		{
			name: "multiple modules, one missing",
			goMod: `module example.com/app

go 1.22

require golang.org/x/net v0.23.0
`,
			updates: unversioned.LangUpdatePackages{
				{Name: "golang.org/x/net", FixedVersion: "v0.23.0"},
				{Name: "golang.org/x/text", FixedVersion: "v0.14.0"},
			},
			wantErr:   true,
			errSubstr: "golang.org/x/text",
		},
		{
			// Modules before go 1.17 record only direct requirements in go.mod,
			// so an indirect dependency Trivy reports is proven by the version
			// go.sum says the build downloads.
			name: "pre-1.17 go.sum only dependency at target version",
			goMod: `module example.com/app

go 1.16

require github.com/direct/dep v1.4.0
`,
			goSum: `github.com/direct/dep v1.4.0 h1:aaaa=
github.com/direct/dep v1.4.0/go.mod h1:bbbb=
golang.org/x/net v0.17.0/go.mod h1:cccc=
golang.org/x/net v0.23.0 h1:dddd=
golang.org/x/net v0.23.0/go.mod h1:eeee=
`,
			updates: unversioned.LangUpdatePackages{
				{Name: "golang.org/x/net", FixedVersion: "v0.23.0"},
			},
			wantErr: false,
		},
		{
			name: "pre-1.17 go.sum only dependency below target version",
			goMod: `module example.com/app

go 1.16

require github.com/direct/dep v1.4.0
`,
			goSum: `github.com/direct/dep v1.4.0 h1:aaaa=
github.com/direct/dep v1.4.0/go.mod h1:bbbb=
golang.org/x/net v0.17.0 h1:cccc=
golang.org/x/net v0.17.0/go.mod h1:dddd=
`,
			updates: unversioned.LangUpdatePackages{
				{Name: "golang.org/x/net", FixedVersion: "v0.23.0"},
			},
			wantErr:   true,
			errSubstr: "v0.17.0",
		},
		{
			// A go.mod-only entry names a version in the module graph whose code
			// is not downloaded, so it cannot prove the patch landed.
			name: "go.sum go.mod only entry does not prove the patch",
			goMod: `module example.com/app

go 1.16

require github.com/direct/dep v1.4.0
`,
			goSum: `golang.org/x/net v0.23.0/go.mod h1:aaaa=
`,
			updates: unversioned.LangUpdatePackages{
				{Name: "golang.org/x/net", FixedVersion: "v0.23.0"},
			},
			wantErr:   true,
			errSubstr: "not found in go.mod",
		},
		{
			name: "require entry wins over stale go.sum entry",
			goMod: `module example.com/app

go 1.16

require golang.org/x/net v0.23.0
`,
			goSum: `golang.org/x/net v0.17.0 h1:aaaa=
golang.org/x/net v0.17.0/go.mod h1:bbbb=
golang.org/x/net v0.23.0 h1:cccc=
golang.org/x/net v0.23.0/go.mod h1:dddd=
`,
			updates: unversioned.LangUpdatePackages{
				{Name: "golang.org/x/net", FixedVersion: "v0.23.0"},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifyGoModUpdates([]byte(tt.goMod), []byte(tt.goSum), tt.updates)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errSubstr)
				return
			}
			assert.NoError(t, err)
		})
	}
}

// TestFilterUpdatesInGoMod asserts that verification is scoped to the modules a
// given go.mod actually referenced before the update. Verifying every requested
// update against every module in the image fails modules that never depended on
// the vulnerable package.
func TestFilterUpdatesInGoMod(t *testing.T) {
	goMod := `module example.com/app

go 1.22

require (
	golang.org/x/net v0.17.0
	golang.org/x/text v0.14.0 // indirect
)

replace github.com/pkg/legacy => github.com/pkg/legacy v1.2.3
`

	goSum := `github.com/pkg/legacy v1.2.3 h1:aaaa=
github.com/pkg/legacy v1.2.3/go.mod h1:bbbb=
gopkg.in/yaml.v2 v2.4.0 h1:cccc=
gopkg.in/yaml.v2 v2.4.0/go.mod h1:dddd=
`

	tests := []struct {
		name      string
		goMod     string
		goSum     string
		updates   unversioned.LangUpdatePackages
		want      []string
		wantErr   bool
		errSubstr string
	}{
		{
			// Before go 1.17 an indirect dependency lives only in go.sum, and
			// excluding it would leave the update unverified while the VEX
			// document still claimed it as patched.
			name:  "keeps pre-1.17 go.sum only dependency",
			goMod: goMod,
			goSum: goSum,
			updates: unversioned.LangUpdatePackages{
				{Name: "gopkg.in/yaml.v2", FixedVersion: "v2.4.0"},
			},
			want: []string{"gopkg.in/yaml.v2"},
		},
		{
			name:  "drops modules absent from go.mod and go.sum",
			goMod: goMod,
			goSum: goSum,
			updates: unversioned.LangUpdatePackages{
				{Name: "github.com/absent/mod", FixedVersion: "v1.0.0"},
			},
			want: []string{},
		},
		{
			name:  "keeps required modules and drops absent ones",
			goMod: goMod,
			updates: unversioned.LangUpdatePackages{
				{Name: "golang.org/x/net", FixedVersion: "v0.23.0"},
				{Name: "github.com/absent/mod", FixedVersion: "v1.0.0"},
			},
			want: []string{"golang.org/x/net"},
		},
		{
			name:  "keeps indirect requirements",
			goMod: goMod,
			updates: unversioned.LangUpdatePackages{
				{Name: "golang.org/x/text", FixedVersion: "v0.21.0"},
			},
			want: []string{"golang.org/x/text"},
		},
		{
			name:  "keeps replaced module paths",
			goMod: goMod,
			updates: unversioned.LangUpdatePackages{
				{Name: "github.com/pkg/legacy", FixedVersion: "v1.2.3"},
			},
			want: []string{"github.com/pkg/legacy"},
		},
		{
			name:  "no applicable updates",
			goMod: goMod,
			updates: unversioned.LangUpdatePackages{
				{Name: "github.com/absent/mod", FixedVersion: "v1.0.0"},
			},
			want: []string{},
		},
		{
			name:      "unparseable go.mod",
			goMod:     "not a go.mod\n",
			updates:   unversioned.LangUpdatePackages{{Name: "golang.org/x/net", FixedVersion: "v0.23.0"}},
			wantErr:   true,
			errSubstr: "go.mod",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := filterUpdatesInGoMod([]byte(tt.goMod), []byte(tt.goSum), tt.updates)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errSubstr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, getPackageNames(got))
		})
	}
}

// TestGoWorkspaceMemberDirs asserts that workspace members are resolved from
// go.work so each member module can be verified. The workspace root has no
// authoritative go.mod: requirements land in the member modules.
func TestGoWorkspaceMemberDirs(t *testing.T) {
	tests := []struct {
		name      string
		goWork    string
		root      string
		want      []string
		wantErr   bool
		errSubstr string
	}{
		{
			name: "relative use entries",
			goWork: `go 1.22

use ./svc-a
use ./svc-b
`,
			root: "/app",
			want: []string{"/app/svc-a", "/app/svc-b"},
		},
		{
			name: "use block with root and parent entries",
			goWork: `go 1.22

use (
	.
	../lib
)
`,
			root: "/app",
			want: []string{"/app", "/lib"},
		},
		{
			name: "absolute use entry",
			goWork: `go 1.22

use /src/other
`,
			root: "/app",
			want: []string{"/src/other"},
		},
		{
			name:      "no use entries",
			goWork:    "go 1.22\n",
			root:      "/app",
			wantErr:   true,
			errSubstr: "no module directories",
		},
		{
			name:      "unparseable go.work",
			goWork:    "not a go.work\n",
			root:      "/app",
			wantErr:   true,
			errSubstr: "go.work",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := goWorkspaceMemberDirs([]byte(tt.goWork), tt.root)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errSubstr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestUpdateGoModuleReportsFailedPackages asserts that a failed module update
// names the affected packages so callers can report them as unpatched. Without
// the names, --ignore-errors drops the failure and the VEX document claims
// remediation that never landed.
func TestUpdateGoModuleReportsFailedPackages(t *testing.T) {
	updates := unversioned.LangUpdatePackages{
		{Name: "golang.org/x/net", FixedVersion: "v0.23.0"},
		{Name: "golang.org/x/text", FixedVersion: "v0.21.0"},
	}

	tests := []struct {
		name    string
		modPath string
		updates unversioned.LangUpdatePackages
		want    []string
	}{
		{
			name:    "unsafe module path",
			modPath: "/app; rm -rf /",
			updates: updates,
			want:    []string{"golang.org/x/net", "golang.org/x/text"},
		},
		{
			name:    "unsafe package name",
			modPath: "/app",
			updates: unversioned.LangUpdatePackages{{Name: "golang.org/x/net;id", FixedVersion: "v0.23.0"}},
			want:    []string{"golang.org/x/net;id"},
		},
	}

	gm := &golangManager{config: &buildkit.Config{}}
	state := llb.Scratch()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, failed, err := gm.updateGoModule(context.Background(), &state, tt.modPath, tt.updates, false, false)
			require.Error(t, err)
			assert.Equal(t, tt.want, failed)
		})
	}
}

// TestGoSumBuiltVersions asserts that only full module hashes count as versions
// the build downloads. A "/go.mod" line names a version in the module graph
// whose code never enters the image, so it cannot prove a patch landed.
func TestGoSumBuiltVersions(t *testing.T) {
	goSum := `golang.org/x/net v0.17.0/go.mod h1:aaaa=
golang.org/x/net v0.23.0 h1:bbbb=
golang.org/x/net v0.23.0/go.mod h1:cccc=
gopkg.in/yaml.v2 v2.4.0 h1:dddd=

malformed line
`

	got := goSumBuiltVersions([]byte(goSum))

	assert.Equal(t, map[string][]string{
		"golang.org/x/net": {"v0.23.0"},
		"gopkg.in/yaml.v2": {"v2.4.0"},
	}, got)
	assert.Empty(t, goSumBuiltVersions(nil))
}

// TestUnverifiedUpdateNames asserts that failure reporting names every update
// whose patch has not been confirmed, so partial verification cannot leave an
// unproven package inside the validated set.
func TestUnverifiedUpdateNames(t *testing.T) {
	updates := unversioned.LangUpdatePackages{
		{Name: "golang.org/x/net", FixedVersion: "v0.23.0"},
		{Name: "golang.org/x/text", FixedVersion: "v0.21.0"},
		{Name: "gopkg.in/yaml.v2", FixedVersion: "v2.4.0"},
	}

	assert.Equal(t,
		[]string{"golang.org/x/net", "golang.org/x/text", "gopkg.in/yaml.v2"},
		unverifiedUpdateNames(updates, nil))

	verified := map[string]struct{}{"golang.org/x/text": {}}
	assert.Equal(t,
		[]string{"golang.org/x/net", "gopkg.in/yaml.v2"},
		unverifiedUpdateNames(updates, verified))

	for _, u := range updates {
		verified[u.Name] = struct{}{}
	}
	assert.Empty(t, unverifiedUpdateNames(updates, verified))
}

// goSumTestReference serves file contents from a map and fails once the read
// budget is exhausted, standing in for a BuildKit solve that breaks partway
// through workspace verification.
type fakeGatewayReference struct {
	gwclient.Reference
	files      map[string][]byte
	reads      *int
	failAfter  int
	failedRead error
}

func (r *fakeGatewayReference) ReadFile(_ context.Context, req gwclient.ReadRequest) ([]byte, error) {
	*r.reads++
	if r.failAfter > 0 && *r.reads > r.failAfter {
		return nil, r.failedRead
	}
	content, ok := r.files[req.Filename]
	if !ok {
		return nil, fmt.Errorf("%s: no such file or directory", req.Filename)
	}
	return content, nil
}

func (r *fakeGatewayReference) StatFile(_ context.Context, req gwclient.StatRequest) (*fstypes.Stat, error) {
	content, ok := r.files[req.Path]
	if !ok {
		return nil, fmt.Errorf("lstat %s: %w", req.Path, fs.ErrNotExist)
	}
	return &fstypes.Stat{Mode: uint32(0o644), Size: int64(len(content))}, nil
}

type fakeGatewayClient struct {
	gwclient.Client
	ref *fakeGatewayReference
}

func (c *fakeGatewayClient) Solve(context.Context, gwclient.SolveRequest) (*gwclient.Result, error) {
	result := gwclient.NewResult()
	result.SetRef(c.ref)
	return result, nil
}

// TestUpdateGoModuleWorkspaceFailureReportsAllUnverified asserts that a read
// failure during workspace verification reports every update still lacking
// proof, not only the member being read. Reporting one member would let the
// other members' packages reach the validated set unverified.
func TestUpdateGoModuleWorkspaceFailureReportsAllUnverified(t *testing.T) {
	memberGoMod := `module example.com/svc-a

go 1.22

require golang.org/x/net v0.23.0
`
	otherGoMod := `module example.com/svc-b

go 1.22

require golang.org/x/text v0.21.0
`
	files := map[string][]byte{
		"/app/go.work":      []byte("go 1.22\n\nuse (\n\t./svc-a\n\t./svc-b\n)\n"),
		"/app/svc-a/go.mod": []byte(memberGoMod),
		"/app/svc-b/go.mod": []byte(otherGoMod),
	}

	reads := 0
	client := &fakeGatewayClient{ref: &fakeGatewayReference{
		files:      files,
		reads:      &reads,
		failAfter:  3, // go.work plus both pre-update go.mod reads succeed
		failedRead: fmt.Errorf("failed to solve: exit code 1"),
	}}
	gm := &golangManager{config: &buildkit.Config{Client: client}}
	state := llb.Scratch()
	updates := unversioned.LangUpdatePackages{
		{Name: "golang.org/x/net", FixedVersion: "v0.23.0"},
		{Name: "golang.org/x/text", FixedVersion: "v0.21.0"},
	}

	_, failed, err := gm.updateGoModule(t.Context(), &state, "/app", updates, true, false)

	require.ErrorContains(t, err, "after update",
		"the failure must come from post-update verification, not the pre-update capture")
	assert.Equal(t, []string{"golang.org/x/net", "golang.org/x/text"}, failed,
		"a workspace verification failure must report every update still lacking verification")
}
