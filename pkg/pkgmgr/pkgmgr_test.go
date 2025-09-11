package pkgmgr

import (
	"reflect"
	"strings"
	"testing"

	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/utils"
	"github.com/stretchr/testify/assert"
)

// TestGetPackageManager tests the GetPackageManager function.
func TestGetPackageManager(t *testing.T) {
	// Create a mock config and workingFolder
	config := &buildkit.Config{}

	t.Run("should return an apkManager for alpine", func(t *testing.T) {
		manager, err := GetPackageManager(utils.OSTypeAlpine, "1.0", config, utils.DefaultTempWorkingFolder)

		// Assert that there is no error and the manager is not nil
		assert.NoError(t, err)
		assert.NotNil(t, manager)

		// Assert that the manager is an instance of apkManager
		assert.IsType(t, &apkManager{}, manager)
	})

	t.Run("should return a dpkgManager for debian", func(t *testing.T) {
		manager, err := GetPackageManager(utils.OSTypeDebian, "1.0", config, utils.DefaultTempWorkingFolder)

		// Assert that there is no error and the manager is not nil
		assert.NoError(t, err)
		assert.NotNil(t, manager)

		// Assert that the manager is an instance of dpkgManager
		assert.IsType(t, &dpkgManager{}, manager)
	})

	t.Run("should return a dpkgManager for ubuntu", func(t *testing.T) {
		manager, err := GetPackageManager(utils.OSTypeUbuntu, "1.0", config, utils.DefaultTempWorkingFolder)

		// Assert that there is no error and the manager is not nil
		assert.NoError(t, err)
		assert.NotNil(t, manager)

		// Assert that the manager is an instance of dpkgManager
		assert.IsType(t, &dpkgManager{}, manager)
	})

	t.Run("should return an rpmManager for cbl-mariner", func(t *testing.T) {
		manager, err := GetPackageManager(utils.OSTypeCBLMariner, "1.0", config, utils.DefaultTempWorkingFolder)

		// Assert that there is no error and the manager is not nil
		assert.NoError(t, err)
		assert.NotNil(t, manager)

		// Assert that the manager is an instance of rpmManager
		assert.IsType(t, &rpmManager{}, manager)
	})

	t.Run("should return an rpmManager for azurelinux", func(t *testing.T) {
		manager, err := GetPackageManager(utils.OSTypeAzureLinux, "1.0", config, utils.DefaultTempWorkingFolder)

		// Assert that there is no error and the manager is not nil
		assert.NoError(t, err)
		assert.NotNil(t, manager)

		// Assert that the manager is an instance of rpmManager
		assert.IsType(t, &rpmManager{}, manager)
	})

	t.Run("should return an rpmManager for redhat", func(t *testing.T) {
		manager, err := GetPackageManager(utils.OSTypeRedHat, "1.0", config, utils.DefaultTempWorkingFolder)

		// Assert that there is no error and the manager is not nil
		assert.NoError(t, err)
		assert.NotNil(t, manager)

		// Assert that the manager is an instance of rpmManager
		assert.IsType(t, &rpmManager{}, manager)
	})

	t.Run("should return an error for unsupported osType", func(t *testing.T) {
		// Call the GetPackageManager function with "unsupported" as osType
		manager, err := GetPackageManager("unsupported", "", config, utils.DefaultTempWorkingFolder)

		// Assert that there is an error and the manager is nil
		assert.Error(t, err)
		assert.Nil(t, manager)
	})
}

func IsValid(version string) bool {
	return version != "invalid"
}

func LessThan(v1, v2 string) bool {
	// Simplistic comparison for testing
	return v1 < v2
}

func TestGetUniqueLatestUpdates(t *testing.T) {
	cmp := VersionComparer{IsValid, LessThan}

	tests := []struct {
		name          string
		updates       unversioned.UpdatePackages
		ignoreErrors  bool
		want          unversioned.UpdatePackages
		expectedError string
	}{
		{
			name:          "empty updates",
			updates:       unversioned.UpdatePackages{},
			ignoreErrors:  false,
			want:          nil,
			expectedError: "no patchable vulnerabilities found",
		},
		{
			name: "valid updates",
			updates: unversioned.UpdatePackages{
				{Name: "pkg1", FixedVersion: "1.0"},
				{Name: "pkg1", FixedVersion: "2.0"},
			},
			ignoreErrors: false,
			want: unversioned.UpdatePackages{
				{Name: "pkg1", FixedVersion: "2.0"},
			},
			expectedError: "",
		},
		{
			name: "updates with invalid version",
			updates: unversioned.UpdatePackages{
				{Name: "pkg1", FixedVersion: "invalid"},
			},
			ignoreErrors:  false,
			want:          nil,
			expectedError: "invalid version invalid found for package pkg1",
		},
		{
			name: "ignore errors",
			updates: unversioned.UpdatePackages{
				{Name: "pkg1", FixedVersion: "invalid"},
			},
			ignoreErrors:  true,
			want:          unversioned.UpdatePackages{},
			expectedError: "",
		},
		{
			name: "Updates with the same highest version",
			updates: unversioned.UpdatePackages{
				{Name: "pkg2", FixedVersion: "2.0"},
				{Name: "pkg1", FixedVersion: "1.0"},
				{Name: "pkg2", FixedVersion: "2.0"},
				{Name: "pkg1", FixedVersion: "1.0"},
			},
			ignoreErrors: false,
			want: unversioned.UpdatePackages{
				{Name: "pkg1", FixedVersion: "1.0"},
				{Name: "pkg2", FixedVersion: "2.0"},
			},
			expectedError: "",
		},
		{
			name: "Invalid versions with ignoreErrors true",
			updates: unversioned.UpdatePackages{
				{Name: "pkg1", FixedVersion: "invalid"},
				{Name: "pkg2", FixedVersion: "3.0"},
				{Name: "pkg3", FixedVersion: "invalid"},
			},
			ignoreErrors: true,
			want: unversioned.UpdatePackages{
				{Name: "pkg2", FixedVersion: "3.0"},
			},
			expectedError: "",
		},
		{
			name: "Updates with decreasing versions",
			updates: unversioned.UpdatePackages{
				{Name: "pkg1", FixedVersion: "2.0"},
				{Name: "pkg1", FixedVersion: "1.5"},
				{Name: "pkg1", FixedVersion: "3.0"},
			},
			ignoreErrors: false,
			want: unversioned.UpdatePackages{
				{Name: "pkg1", FixedVersion: "3.0"},
			},
			expectedError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetUniqueLatestUpdates(tt.updates, cmp, tt.ignoreErrors)
			if err != nil {
				if tt.expectedError == "" {
					t.Errorf("GetUniqueLatestUpdates() unexpected error = %v", err)
				} else if !strings.Contains(err.Error(), tt.expectedError) {
					t.Errorf("GetUniqueLatestUpdates() error = %v, wantErrMsg %v", err, tt.expectedError)
				}
			} else if tt.expectedError != "" {
				t.Errorf("GetUniqueLatestUpdates() expected error %v, got none", tt.expectedError)
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("%s: got = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}
