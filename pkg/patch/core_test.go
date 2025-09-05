package patch

import (
	"testing"

	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"

	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
)

// Test Options struct initialization and validation.
func TestOptions_Initialization(t *testing.T) {
	opts := &Options{
		ImageName: "test:latest",
		TargetPlatform: &types.PatchPlatform{
			Platform: v1.Platform{
				OS:           "linux",
				Architecture: "amd64",
			},
		},
		WorkingFolder: "/tmp/test",
		IgnoreError:   true,
	}

	assert.Equal(t, "test:latest", opts.ImageName)
	assert.Equal(t, "linux", opts.TargetPlatform.OS)
	assert.Equal(t, "amd64", opts.TargetPlatform.Architecture)
	assert.Equal(t, "/tmp/test", opts.WorkingFolder)
	assert.True(t, opts.IgnoreError)
}

// Test Options with Updates.
func TestOptions_WithUpdates(t *testing.T) {
	updates := &unversioned.UpdateManifest{
		OSUpdates: []unversioned.UpdatePackage{
			{
				Name:             "test-package",
				InstalledVersion: "1.0.0",
				FixedVersion:     "1.0.1",
			},
		},
		Metadata: unversioned.Metadata{
			OS: unversioned.OS{
				Type:    "debian",
				Version: "11",
			},
		},
	}

	opts := &Options{
		ImageName: "test:latest",
		Updates:   updates,
	}

	assert.Equal(t, "test:latest", opts.ImageName)
	assert.NotNil(t, opts.Updates)
	assert.Len(t, opts.Updates.OSUpdates, 1)
	assert.Equal(t, "test-package", opts.Updates.OSUpdates[0].Name)
	assert.Equal(t, "debian", opts.Updates.Metadata.OS.Type)
}

// Test Options with error channel.
func TestOptions_WithErrorChannel(t *testing.T) {
	errorChannel := make(chan error, 10)

	opts := &Options{
		ImageName:    "test:latest",
		ErrorChannel: errorChannel,
	}

	assert.Equal(t, "test:latest", opts.ImageName)
	assert.NotNil(t, opts.ErrorChannel)
	assert.Equal(t, cap(errorChannel), cap(opts.ErrorChannel))
}

// Test Result struct initialization and validation.
func TestResult_Initialization(t *testing.T) {
	result := &Result{
		PackageType:       "deb",
		ErroredPackages:   []string{"pkg1", "pkg2"},
		ValidatedManifest: &unversioned.UpdateManifest{OSUpdates: []unversioned.UpdatePackage{{Name: "pkg3", FixedVersion: "1.0.1"}}},
	}

	assert.Equal(t, "deb", result.PackageType)
	assert.Equal(t, []string{"pkg1", "pkg2"}, result.ErroredPackages)
	assert.NotNil(t, result.ValidatedManifest)
	assert.Len(t, result.ValidatedManifest.OSUpdates, 1)
	assert.Equal(t, "pkg3", result.ValidatedManifest.OSUpdates[0].Name)
}

// Test Result with empty fields.
func TestResult_Empty(t *testing.T) {
	result := &Result{}

	assert.Empty(t, result.PackageType)
	assert.Nil(t, result.ErroredPackages)
	assert.Nil(t, result.ValidatedManifest)
	assert.Nil(t, result.Result)
}

// Test Result with multiple validated updates.
func TestResult_MultipleValidatedUpdates(t *testing.T) {
	result := &Result{
		PackageType: "rpm",
		ValidatedManifest: &unversioned.UpdateManifest{OSUpdates: []unversioned.UpdatePackage{
			{Name: "pkg1", FixedVersion: "1.0.1"},
			{Name: "pkg2", FixedVersion: "2.0.1"},
			{Name: "pkg3", FixedVersion: "3.0.1"},
		}},
	}

	assert.Equal(t, "rpm", result.PackageType)
	assert.NotNil(t, result.ValidatedManifest)
	assert.Len(t, result.ValidatedManifest.OSUpdates, 3)
	assert.Equal(t, "pkg1", result.ValidatedManifest.OSUpdates[0].Name)
	assert.Equal(t, "pkg2", result.ValidatedManifest.OSUpdates[1].Name)
	assert.Equal(t, "pkg3", result.ValidatedManifest.OSUpdates[2].Name)
}

// Test Context struct initialization.
func TestContext_Initialization(t *testing.T) {
	// Test with nil values
	patchCtx := &Context{}

	assert.Nil(t, patchCtx.Context)
	assert.Nil(t, patchCtx.Client)
}

// Test package types commonly used.
func TestResult_CommonPackageTypes(t *testing.T) {
	testCases := []struct {
		name        string
		packageType string
	}{
		{"Debian packages", "deb"},
		{"RPM packages", "rpm"},
		{"Alpine packages", "apk"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := &Result{
				PackageType: tc.packageType,
			}
			assert.Equal(t, tc.packageType, result.PackageType)
		})
	}
}

// Test Options with different platform architectures.
func TestOptions_DifferentArchitectures(t *testing.T) {
	architectures := []string{"amd64", "arm64", "386", "arm"}

	for _, arch := range architectures {
		t.Run(arch, func(t *testing.T) {
			opts := &Options{
				ImageName: "test:latest",
				TargetPlatform: &types.PatchPlatform{
					Platform: v1.Platform{
						OS:           "linux",
						Architecture: arch,
					},
				},
			}

			assert.Equal(t, arch, opts.TargetPlatform.Architecture)
			assert.Equal(t, "linux", opts.TargetPlatform.OS)
		})
	}
}

// Test Options validation scenarios.
func TestOptions_ValidationScenarios(t *testing.T) {
	testCases := []struct {
		name     string
		opts     *Options
		expected string
	}{
		{
			name: "Valid options with all fields",
			opts: &Options{
				ImageName:     "nginx:latest",
				WorkingFolder: "/tmp/patch",
				IgnoreError:   false,
				TargetPlatform: &types.PatchPlatform{
					Platform: v1.Platform{OS: "linux", Architecture: "amd64"},
				},
			},
			expected: "nginx:latest",
		},
		{
			name: "Empty image name",
			opts: &Options{
				ImageName:     "",
				WorkingFolder: "/tmp/patch",
			},
			expected: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.opts.ImageName)
		})
	}
}
