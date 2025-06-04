package pkgmgr

import (
	"strings"
	"testing"

	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/stretchr/testify/assert"
)

// TestGetPackageManager tests the GetPackageManager function.
func TestGetPackageManager(t *testing.T) {
	// Create a mock config and workingFolder
	config := &buildkit.Config{}
	workingFolder := "/tmp"

	t.Run("should return an apkManager for alpine", func(t *testing.T) {
		// Call the GetPackageManager function with "alpine" as osType
		manager, err := GetPackageManager("alpine", "1.0", config, workingFolder)

		// Assert that there is no error and the manager is not nil
		assert.NoError(t, err)
		assert.NotNil(t, manager)

		// Assert that the manager is an instance of apkManager
		assert.IsType(t, &apkManager{}, manager)
	})

	t.Run("should return a dpkgManager for debian", func(t *testing.T) {
		// Call the GetPackageManager function with "debian" as osType
		manager, err := GetPackageManager("debian", "1.0", config, workingFolder)

		// Assert that there is no error and the manager is not nil
		assert.NoError(t, err)
		assert.NotNil(t, manager)

		// Assert that the manager is an instance of dpkgManager
		assert.IsType(t, &dpkgManager{}, manager)
	})

	t.Run("should return a dpkgManager for ubuntu", func(t *testing.T) {
		// Call the GetPackageManager function with "ubuntu" as osType
		manager, err := GetPackageManager("ubuntu", "1.0", config, workingFolder)

		// Assert that there is no error and the manager is not nil
		assert.NoError(t, err)
		assert.NotNil(t, manager)

		// Assert that the manager is an instance of dpkgManager
		assert.IsType(t, &dpkgManager{}, manager)
	})

	t.Run("should return an rpmManager for cbl-mariner", func(t *testing.T) {
		// Call the GetPackageManager function with "cbl-mariner" as osType
		manager, err := GetPackageManager("cbl-mariner", "1.0", config, workingFolder)

		// Assert that there is no error and the manager is not nil
		assert.NoError(t, err)
		assert.NotNil(t, manager)

		// Assert that the manager is an instance of rpmManager
		assert.IsType(t, &rpmManager{}, manager)
	})

	t.Run("should return an rpmManager for azurelinux", func(t *testing.T) {
		// Call the GetPackageManager function with "azurelinux" as osType
		manager, err := GetPackageManager("azurelinux", "1.0", config, workingFolder)

		// Assert that there is no error and the manager is not nil
		assert.NoError(t, err)
		assert.NotNil(t, manager)

		// Assert that the manager is an instance of rpmManager
		assert.IsType(t, &rpmManager{}, manager)
	})

	t.Run("should return an rpmManager for redhat", func(t *testing.T) {
		// Call the GetPackageManager function with "redhat" as osType
		manager, err := GetPackageManager("redhat", "1.0", config, workingFolder)

		// Assert that there is no error and the manager is not nil
		assert.NoError(t, err)
		assert.NotNil(t, manager)

		// Assert that the manager is an instance of rpmManager
		assert.IsType(t, &rpmManager{}, manager)
	})

	t.Run("should return an error for unsupported osType", func(t *testing.T) {
		// Call the GetPackageManager function with "unsupported" as osType
		manager, err := GetPackageManager("unsupported", "", config, workingFolder)

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

// isEqualIgnoreOrder compares two slices of UpdatePackage without considering order.
func isEqualIgnoreOrder(a, b unversioned.UpdatePackages) bool {
	if len(a) != len(b) {
		return false
	}

	// Use a map to count occurrences
	counts := make(map[unversioned.UpdatePackage]int)
	for _, v := range a {
		counts[v]++
	}

	for _, v := range b {
		counts[v]--
		if counts[v] < 0 {
			return false // Found more of v in b than in a
		}
	}

	return true
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
			want:          unversioned.UpdatePackages{},
			expectedError: "",
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
				{Name: "pkg2", FixedVersion: "2.0"},
				{Name: "pkg1", FixedVersion: "1.0"},
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

			if !isEqualIgnoreOrder(got, tt.want) {
				t.Errorf("%s: got = %v, want %v (order ignored)", tt.name, got, tt.want)
			}
		})
	}
}
