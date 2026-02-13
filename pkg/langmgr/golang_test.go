package langmgr

import (
	"testing"

	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			managers := GetLanguageManagers(config, workingFolder, tt.manifest, "")
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
		managers := GetLanguageManagers(config, workingFolder, manifest, "minor")
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
		managers := GetLanguageManagers(config, workingFolder, manifest, "")
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
