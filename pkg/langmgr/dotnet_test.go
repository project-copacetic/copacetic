package langmgr

import (
	"strings"
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

func TestBuildUpdateDepsJsonScript_FiltersUnsafeUpdates(t *testing.T) {
	dnm := &dotnetManager{}
	updates := unversioned.LangUpdatePackages{
		{
			Name:             "Newtonsoft.Json",
			InstalledVersion: "12.0.3",
			FixedVersion:     "13.0.1",
		},
		{
			Name:             `bad"; touch /tmp/pwned; #`,
			InstalledVersion: "1.0.0",
			FixedVersion:     "1.0.1",
		},
		{
			Name:             "System.Text.Json",
			InstalledVersion: `1.0.0"; touch /tmp/pwned; #`,
			FixedVersion:     "1.0.1",
		},
	}

	script := dnm.buildUpdateDepsJsonScript(updates)
	assert.Contains(t, script, "Newtonsoft.Json")
	assert.NotContains(t, script, "touch /tmp/pwned")
	assert.NotContains(t, script, `bad";`)
	assert.NotContains(t, script, `1.0.0";`)
}

func TestBuildUpdateDepsJsonScript_NoValidUpdates(t *testing.T) {
	dnm := &dotnetManager{}
	updates := unversioned.LangUpdatePackages{
		{
			Name:             `bad"; touch /tmp/pwned; #`,
			InstalledVersion: "1.0.0",
			FixedVersion:     "1.0.1",
		},
	}

	script := dnm.buildUpdateDepsJsonScript(updates)
	assert.Equal(t, `echo "No valid updates to apply to deps.json"`, script)
}

func TestBuildPatchCsproj(t *testing.T) {
	refs := `    <PackageReference Include="Newtonsoft.Json" Version="13.0.1" />` + "\n" +
		`    <PackageReference Include="NuGet.Packaging" Version="7.3.1" />` + "\n"

	got := buildPatchCsproj("net8.0", refs)

	assert.Contains(t, got, `<TargetFramework>net8.0</TargetFramework>`,
		"target framework should be included")
	assert.Contains(t, got, `<OutputType>Library</OutputType>`,
		"output type should be Library")
	assert.Contains(t, got, `<NoWarn>NU1605</NoWarn>`,
		"NU1605 must be suppressed so transitive-dependency minimums do not fail restore")
	assert.Contains(t, got,
		`<PackageReference Include="Newtonsoft.Json" Version="13.0.1" />`,
		"Newtonsoft.Json reference should be present")
	assert.Contains(t, got,
		`<PackageReference Include="NuGet.Packaging" Version="7.3.1" />`,
		"NuGet.Packaging reference should be present")

	assert.True(t, strings.Contains(got, "</Project>"), "project should be closed")
	propStart := strings.Index(got, "<PropertyGroup>")
	propEnd := strings.Index(got, "</PropertyGroup>")
	noWarn := strings.Index(got, "<NoWarn>NU1605</NoWarn>")
	assert.True(t, propStart >= 0 && propEnd > propStart && noWarn > propStart && noWarn < propEnd,
		"<NoWarn> must live inside <PropertyGroup>")
}

func TestBuildPatchCsproj_EmptyPackageRefs(t *testing.T) {
	got := buildPatchCsproj("net9.0", "")
	assert.Contains(t, got, `<TargetFramework>net9.0</TargetFramework>`)
	assert.Contains(t, got, `<NoWarn>NU1605</NoWarn>`)
	assert.Contains(t, got, "<ItemGroup>\n  </ItemGroup>",
		"empty ItemGroup should still be well-formed")
}

func TestBuildUpdateDepsJsonScript_ResolvesActualVersion(t *testing.T) {
	dnm := &dotnetManager{}
	updates := unversioned.LangUpdatePackages{
		{
			Name:             "Newtonsoft.Json",
			InstalledVersion: "12.0.1",
			FixedVersion:     "13.0.1",
			Type:             "dotnet-core",
		},
	}

	got := dnm.buildUpdateDepsJsonScript(updates)

	assert.Contains(t, got, `RESOLVED_KEY=`,
		"script must resolve the actual package key from the generated deps.json")
	assert.Contains(t, got, `select(startswith($name + "/"))`,
		"script must look up by Name prefix, not Name/TrivyPin")
	assert.Contains(t, got, `RESOLVED_VERSION="${RESOLVED_KEY#Newtonsoft.Json/}"`,
		"script must strip the package name prefix to extract the resolved version")
	assert.Contains(t, got, `--arg newKey "$RESOLVED_KEY"`,
		"targets insertion must use the resolved key, not Name/TrivyPin")
	assert.Contains(t, got, `--arg newKey "$RESOLVED_LIB_KEY"`,
		"libraries insertion must use the resolved key, not Name/TrivyPin")
	assert.Contains(t, got, `--arg ver "$RESOLVED_VERSION"`,
		"dependency version updates must use the resolved version, not Trivy's pin")
	assert.Contains(t, got, `"Newtonsoft.Json/12.0.1"`,
		"old entry must still be deleted using the installed version from Trivy")
}

func TestBuildUpdateDepsJsonScript_HardcodedTrivyPinRemoved(t *testing.T) {
	dnm := &dotnetManager{}
	updates := unversioned.LangUpdatePackages{
		{
			Name:             "NuGet.Packaging",
			InstalledVersion: "6.11.1",
			FixedVersion:     "7.3.1",
			Type:             "dotnet-core",
		},
	}

	got := dnm.buildUpdateDepsJsonScript(updates)

	assert.NotContains(t, got, `"NuGet.Packaging/7.3.1": $newTarget`,
		"new target entry must not hardcode Trivy's requested version - transitive deps can force a higher one")
	assert.NotContains(t, got, `"NuGet.Packaging/7.3.1": $newLib`,
		"new library entry must not hardcode Trivy's requested version")
	assert.NotContains(t, got,
		`jq '(.targets[][].dependencies // {}) |= with_entries(if .key == "NuGet.Packaging" then .value = "7.3.1"`,
		"dependency version rewrite must not hardcode Trivy's requested version")
}

func TestBuildUpdateDepsJsonScript_EmptyUpdates(t *testing.T) {
	dnm := &dotnetManager{}
	got := dnm.buildUpdateDepsJsonScript(unversioned.LangUpdatePackages{})
	assert.Equal(t, `echo "No updates to apply to deps.json"`, got,
		"empty updates should produce a no-op script")
}
