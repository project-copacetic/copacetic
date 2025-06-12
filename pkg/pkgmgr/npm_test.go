package pkgmgr

import (
	"context"
	"testing"

	"github.com/moby/buildkit/client/llb"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/stretchr/testify/assert"
)

func TestNpmManagerGetPackageType(t *testing.T) {
	manager := &npmManager{}
	assert.Equal(t, "node", manager.GetPackageType())
}

func TestNewNpmManager(t *testing.T) {
	config := &buildkit.Config{
		ImageState: llb.Image("node:18-alpine"),
	}
	workingFolder := "/tmp/test"

	manager := NewNpmManager(config, workingFolder)

	assert.NotNil(t, manager)
	assert.IsType(t, &npmManager{}, manager)
	assert.Equal(t, "node", manager.GetPackageType())
}

func TestNpmManagerInstallUpdates(t *testing.T) {
	ctx := context.Background()
	config := &buildkit.Config{
		ImageState: llb.Image("node:18-alpine"),
	}

	tests := []struct {
		name         string
		manifest     *unversioned.UpdateManifest
		ignoreErrors bool
		wantErr      bool
		description  string
	}{
		{
			name:         "nil_manifest",
			manifest:     nil,
			ignoreErrors: false,
			wantErr:      false,
			description:  "Should handle nil manifest gracefully",
		},
		{
			name: "empty_updates",
			manifest: &unversioned.UpdateManifest{
				Updates: []unversioned.UpdatePackage{},
			},
			ignoreErrors: false,
			wantErr:      false,
			description:  "Should handle empty updates list",
		},
		{
			name: "single_package_update",
			manifest: &unversioned.UpdateManifest{
				Updates: []unversioned.UpdatePackage{
					{
						Name:             "lodash",
						InstalledVersion: "4.17.20",
						FixedVersion:     "4.17.21",
						VulnerabilityID:  "CVE-2021-23337",
					},
				},
			},
			ignoreErrors: false,
			wantErr:      false,
			description:  "Should process single package update",
		},
		{
			name: "multiple_comma_separated_versions",
			manifest: &unversioned.UpdateManifest{
				Updates: []unversioned.UpdatePackage{
					{
						Name:             "ansi-regex",
						InstalledVersion: "3.0.0",
						FixedVersion:     "3.0.1, 5.0.1, 6.0.0",
						VulnerabilityID:  "CVE-2021-3807",
					},
				},
			},
			ignoreErrors: false,
			wantErr:      false,
			description:  "Should handle multiple versions correctly",
		},
		{
			name: "scoped_package",
			manifest: &unversioned.UpdateManifest{
				Updates: []unversioned.UpdatePackage{
					{
						Name:             "@babel/core",
						InstalledVersion: "7.0.0",
						FixedVersion:     "7.23.2",
						VulnerabilityID:  "CVE-2023-45133",
					},
				},
			},
			ignoreErrors: false,
			wantErr:      false,
			description:  "Should handle scoped packages correctly",
		},
		{
			name: "ignore_errors_mode",
			manifest: &unversioned.UpdateManifest{
				Updates: []unversioned.UpdatePackage{
					{
						Name:             "some-package",
						InstalledVersion: "1.0.0",
						FixedVersion:     "1.0.1",
						VulnerabilityID:  "CVE-2023-12345",
					},
				},
			},
			ignoreErrors: true,
			wantErr:      false,
			description:  "Should continue when ignoreErrors is true",
		},
		{
			name: "multiple_packages",
			manifest: &unversioned.UpdateManifest{
				Updates: []unversioned.UpdatePackage{
					{
						Name:             "express",
						InstalledVersion: "4.17.1",
						FixedVersion:     "4.18.2",
						VulnerabilityID:  "CVE-2022-24999",
					},
					{
						Name:             "minimist",
						InstalledVersion: "1.2.5",
						FixedVersion:     "1.2.8",
						VulnerabilityID:  "CVE-2021-44906",
					},
				},
			},
			ignoreErrors: false,
			wantErr:      false,
			description:  "Should handle multiple package updates",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			manager := NewNpmManager(config, "/tmp/test")
			state, errPkgs, err := manager.InstallUpdates(ctx, tc.manifest, tc.ignoreErrors)

			if tc.wantErr {
				assert.Error(t, err, tc.description)
			} else {
				assert.NoError(t, err, tc.description)
				assert.NotNil(t, state, tc.description)
				assert.Equal(t, 0, len(errPkgs), tc.description)
			}
		})
	}
}

// TestNpmManagerScriptEmbedding tests that the embedded scripts are not empty
func TestNpmManagerScriptEmbedding(t *testing.T) {
	tests := []struct {
		name   string
		script string
	}{
		{"detect-nodejs-apps.sh", detectNodejsAppsScript},
		{"update-nodejs-package.sh", updateNodejsPackageScript},
		{"cleanup-nodejs-apps.sh", cleanupNodejsAppsScript},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.NotEmpty(t, tc.script, "Script should not be empty")
			assert.Contains(t, tc.script, "node_modules", "Script should check for node_modules")
		})
	}
}

// TestNpmManagerEdgeCases tests edge cases that need special handling
func TestNpmManagerEdgeCases(t *testing.T) {
	ctx := context.Background()
	config := &buildkit.Config{
		ImageState: llb.Image("node:18-alpine"),
	}

	tests := []struct {
		name        string
		manifest    *unversioned.UpdateManifest
		description string
	}{
		{
			name: "version_with_spaces_and_commas",
			manifest: &unversioned.UpdateManifest{
				Updates: []unversioned.UpdatePackage{
					{
						Name:             "test-package",
						InstalledVersion: "1.0.0",
						FixedVersion:     " 1.0.1 , 2.0.0 , 3.0.0 ",
						VulnerabilityID:  "CVE-2023-TEST",
					},
				},
			},
			description: "Should handle versions with extra spaces",
		},
		{
			name: "pre_release_versions",
			manifest: &unversioned.UpdateManifest{
				Updates: []unversioned.UpdatePackage{
					{
						Name:             "next",
						InstalledVersion: "12.0.0",
						FixedVersion:     "12.1.0-canary.1",
						VulnerabilityID:  "CVE-2022-XXXXX",
					},
				},
			},
			description: "Should handle pre-release versions",
		},
		{
			name: "package_with_quotes",
			manifest: &unversioned.UpdateManifest{
				Updates: []unversioned.UpdatePackage{
					{
						Name:             "some'package",
						InstalledVersion: "1.0.0",
						FixedVersion:     "1.0.1",
						VulnerabilityID:  "CVE-2023-QUOTE",
					},
				},
			},
			description: "Should handle package names with quotes",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			manager := NewNpmManager(config, "/tmp/test")
			state, errPkgs, err := manager.InstallUpdates(ctx, tc.manifest, true)

			// All edge cases should be handled without error when ignoreErrors is true
			assert.NoError(t, err, tc.description)
			assert.NotNil(t, state, tc.description)
			assert.Equal(t, 0, len(errPkgs), tc.description)
		})
	}
}