/*
Copyright (c) Project Copacetic authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package pkgmgr

import (
	"testing"

	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/stretchr/testify/assert"
)

// TestGetPackageManager tests the GetPackageManager function.
func TestGetPackageManager(t *testing.T) {
	// Create a mock config and workingFolder
	config := &buildkit.Config{}
	workingFolder := "/tmp"

	t.Run("should return an apkManager for alpine", func(t *testing.T) {
		// Call the GetPackageManager function with "alpine" as osType
		manager, err := GetPackageManager("alpine", config, workingFolder)

		// Assert that there is no error and the manager is not nil
		assert.NoError(t, err)
		assert.NotNil(t, manager)

		// Assert that the manager is an instance of apkManager
		assert.IsType(t, &apkManager{}, manager)
	})

	t.Run("should return a dpkgManager for debian", func(t *testing.T) {
		// Call the GetPackageManager function with "debian" as osType
		manager, err := GetPackageManager("debian", config, workingFolder)

		// Assert that there is no error and the manager is not nil
		assert.NoError(t, err)
		assert.NotNil(t, manager)

		// Assert that the manager is an instance of dpkgManager
		assert.IsType(t, &dpkgManager{}, manager)
	})

	t.Run("should return a dpkgManager for ubuntu", func(t *testing.T) {
		// Call the GetPackageManager function with "ubuntu" as osType
		manager, err := GetPackageManager("ubuntu", config, workingFolder)

		// Assert that there is no error and the manager is not nil
		assert.NoError(t, err)
		assert.NotNil(t, manager)

		// Assert that the manager is an instance of dpkgManager
		assert.IsType(t, &dpkgManager{}, manager)
	})

	t.Run("should return an rpmManager for cbl-mariner", func(t *testing.T) {
		// Call the GetPackageManager function with "cbl-mariner" as osType
		manager, err := GetPackageManager("cbl-mariner", config, workingFolder)

		// Assert that there is no error and the manager is not nil
		assert.NoError(t, err)
		assert.NotNil(t, manager)

		// Assert that the manager is an instance of rpmManager
		assert.IsType(t, &rpmManager{}, manager)
	})

	t.Run("should return an rpmManager for redhat", func(t *testing.T) {
		// Call the GetPackageManager function with "redhat" as osType
		manager, err := GetPackageManager("redhat", config, workingFolder)

		// Assert that there is no error and the manager is not nil
		assert.NoError(t, err)
		assert.NotNil(t, manager)

		// Assert that the manager is an instance of rpmManager
		assert.IsType(t, &rpmManager{}, manager)
	})

	t.Run("should return an error for unsupported osType", func(t *testing.T) {
		// Call the GetPackageManager function with "unsupported" as osType
		manager, err := GetPackageManager("unsupported", config, workingFolder)

		// Assert that there is an error and the manager is nil
		assert.Error(t, err)
		assert.Nil(t, manager)
	})
}
