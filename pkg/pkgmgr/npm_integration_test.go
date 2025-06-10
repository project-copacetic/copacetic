// +build integration

package pkgmgr

import (
	"context"
	"testing"

	"github.com/moby/buildkit/client/llb"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNpmManagerIntegrationRealImage tests npm patching with a real image
// Run with: go test -tags=integration
func TestNpmManagerIntegrationRealImage(t *testing.T) {
	ctx := context.Background()

	// Test with actual vulnerable packages from known CVEs
	manifest := &unversioned.UpdateManifest{
		Metadata: unversioned.Metadata{
			OS: unversioned.OS{
				Type:    "linux",
				Version: "alpine",
			},
		},
		Updates: []unversioned.UpdatePackage{
			{
				Name:             "lodash",
				InstalledVersion: "4.17.20",
				FixedVersion:     "4.17.21",
				VulnerabilityID:  "CVE-2021-23337",
			},
			{
				Name:             "minimist",
				InstalledVersion: "1.2.5",
				FixedVersion:     "1.2.8",
				VulnerabilityID:  "CVE-2021-44906",
			},
			{
				Name:             "ansi-regex",
				InstalledVersion: "3.0.0",
				FixedVersion:     "3.0.1",
				VulnerabilityID:  "CVE-2021-3807",
			},
		},
	}

	config := &buildkit.Config{
		ImageState: llb.Image("node:18-alpine"),
	}

	manager := NewNpmManager(config, "/tmp/copa-npm-test")

	// This will create actual buildkit operations
	state, errPkgs, err := manager.InstallUpdates(ctx, manifest, false)

	require.NoError(t, err)
	assert.NotNil(t, state)
	assert.Empty(t, errPkgs)
}

// TestNpmManagerIntegrationComplexScenario tests complex patching scenarios
func TestNpmManagerIntegrationComplexScenario(t *testing.T) {
	ctx := context.Background()

	// Complex scenario with multiple version formats and edge cases
	manifest := &unversioned.UpdateManifest{
		Updates: []unversioned.UpdatePackage{
			// Multiple versions scenario
			{
				Name:             "ansi-regex",
				InstalledVersion: "3.0.0",
				FixedVersion:     "3.0.1, 5.0.1, 6.0.0",
				VulnerabilityID:  "CVE-2021-3807",
			},
			// Pre-release version
			{
				Name:             "next",
				InstalledVersion: "12.0.0",
				FixedVersion:     "12.1.0-canary.1",
				VulnerabilityID:  "CVE-2022-XXXXX",
			},
			// Scoped package
			{
				Name:             "@babel/traverse",
				InstalledVersion: "7.0.0",
				FixedVersion:     "7.23.2",
				VulnerabilityID:  "CVE-2023-45133",
			},
			// Version range
			{
				Name:             "semver",
				InstalledVersion: "5.7.1",
				FixedVersion:     ">=5.7.2",
				VulnerabilityID:  "CVE-2022-25883",
			},
		},
	}

	config := &buildkit.Config{
		ImageState: llb.Image("node:18-alpine"),
	}

	manager := NewNpmManager(config, "/tmp/copa-npm-test")

	// Test with ignoreErrors to continue on pre-release version issues
	state, errPkgs, err := manager.InstallUpdates(ctx, manifest, true)

	require.NoError(t, err)
	assert.NotNil(t, state)
	assert.Empty(t, errPkgs)
}

// TestNpmManagerIntegrationWithBitnamiExpress tests with the documented example
func TestNpmManagerIntegrationWithBitnamiExpress(t *testing.T) {
	ctx := context.Background()

	// Test case based on the documentation example
	manifest := &unversioned.UpdateManifest{
		Metadata: unversioned.Metadata{
			OS: unversioned.OS{
				Type:    "linux",
				Version: "debian",
			},
		},
		Updates: []unversioned.UpdatePackage{
			{
				Name:             "express",
				InstalledVersion: "0.0.0",
				FixedVersion:     "4.19.2",
				VulnerabilityID:  "CVE-2024-10491",
			},
			{
				Name:             "express",
				InstalledVersion: "0.0.0",
				FixedVersion:     "4.5",
				VulnerabilityID:  "CVE-2014-6393",
			},
		},
	}

	config := &buildkit.Config{
		ImageState: llb.Image("bitnami/express:latest"),
	}

	manager := NewNpmManager(config, "/tmp/copa-npm-test")

	state, errPkgs, err := manager.InstallUpdates(ctx, manifest, false)

	require.NoError(t, err)
	assert.NotNil(t, state)
	assert.Empty(t, errPkgs)
}

// TestNpmManagerIntegrationStressTest tests with a large number of packages
func TestNpmManagerIntegrationStressTest(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	ctx := context.Background()

	// Generate a large manifest to stress test the implementation
	var updates []unversioned.UpdatePackage
	packages := []string{
		"lodash", "express", "react", "vue", "angular",
		"webpack", "babel-core", "typescript", "jest", "mocha",
		"chai", "sinon", "axios", "request", "got",
		"chalk", "commander", "yargs", "minimist", "optimist",
	}

	for i, pkg := range packages {
		updates = append(updates, unversioned.UpdatePackage{
			Name:             pkg,
			InstalledVersion: "1.0.0",
			FixedVersion:     "1.0.1",
			VulnerabilityID:  "CVE-2023-" + string(rune('A'+i)),
		})
	}

	manifest := &unversioned.UpdateManifest{
		Updates: updates,
	}

	config := &buildkit.Config{
		ImageState: llb.Image("node:18-alpine"),
	}

	manager := NewNpmManager(config, "/tmp/copa-npm-test")

	state, errPkgs, err := manager.InstallUpdates(ctx, manifest, true)

	require.NoError(t, err)
	assert.NotNil(t, state)
	assert.Empty(t, errPkgs)
}