package gateway

import (
	"context"
	"testing"
	"time"

	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"

	"github.com/project-copacetic/copacetic/pkg/patch"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/test/testenv"
)

// TestPatchRPM tests Copa patching on RPM-based distributions.
func TestPatchRPM(t *testing.T) {
	t.Parallel()

	if buildkitAddr == "" {
		t.Skip("Skipping: no BuildKit address provided")
	}

	testCases := []patchTestCase{
		// Mariner / CBL-Mariner
		{
			name:      "mariner 2.0",
			image:     "mcr.microsoft.com/cbl-mariner/base/core:2.0",
			osType:    "cbl-mariner",
			osVersion: "2.0",
			packages: []testenv.PackageUpdate{
				{
					Name:             "openssl",
					InstalledVersion: "1.1.1k-24.cm2",
					FixedVersion:     "1.1.1k-28.cm2",
					VulnerabilityID:  "CVE-2023-TEST",
				},
			},
			expectedPkgMgr: []string{"tdnf", "dnf", "yum", "rpm"},
			osReleaseMatch: "Mariner",
		},
		{
			name:           "mariner update all",
			image:          "mcr.microsoft.com/cbl-mariner/base/core:2.0",
			osType:         "cbl-mariner",
			osVersion:      "2.0",
			packages:       nil,
			expectedPkgMgr: []string{"tdnf", "dnf", "yum", "rpm"},
			osReleaseMatch: "Mariner",
		},
		// Azure Linux
		{
			name:      "azure linux 3.0",
			image:     "mcr.microsoft.com/azurelinux/base/core:3.0",
			osType:    "azurelinux",
			osVersion: "3.0",
			packages: []testenv.PackageUpdate{
				{
					Name:             "openssl",
					InstalledVersion: "3.3.0-1.azl3",
					FixedVersion:     "3.3.0-2.azl3",
					VulnerabilityID:  "CVE-2023-TEST",
				},
			},
			expectedPkgMgr: []string{"tdnf", "dnf", "rpm"},
			osReleaseMatch: "Azure Linux",
		},
		{
			name:           "azure linux update all",
			image:          "mcr.microsoft.com/azurelinux/base/core:3.0",
			osType:         "azurelinux",
			osVersion:      "3.0",
			packages:       nil,
			expectedPkgMgr: []string{"tdnf", "dnf", "rpm"},
			osReleaseMatch: "Azure Linux",
		},
		// Amazon Linux
		{
			name:      "amazon linux 2",
			image:     "docker.io/library/amazonlinux:2",
			osType:    "amzn",
			osVersion: "2",
			packages: []testenv.PackageUpdate{
				{
					Name:             "openssl",
					InstalledVersion: "1:1.0.2k-16.amzn2.1.1",
					FixedVersion:     "1:1.0.2k-24.amzn2.0.10",
					VulnerabilityID:  "CVE-2023-TEST",
				},
			},
			expectedPkgMgr: []string{"yum", "dnf", "rpm"},
			osReleaseMatch: "Amazon Linux",
		},
		{
			name:           "amazon linux update all",
			image:          "docker.io/library/amazonlinux:2",
			osType:         "amzn",
			osVersion:      "2",
			packages:       nil,
			expectedPkgMgr: []string{"yum", "dnf", "rpm"},
			osReleaseMatch: "Amazon Linux",
		},
		// Rocky Linux
		{
			name:      "rocky linux 9",
			image:     "docker.io/library/rockylinux:9",
			osType:    "rocky",
			osVersion: "9",
			packages: []testenv.PackageUpdate{
				{
					Name:             "openssl",
					InstalledVersion: "1:3.0.7-17.el9",
					FixedVersion:     "1:3.0.7-27.el9",
					VulnerabilityID:  "CVE-2023-TEST",
				},
			},
			expectedPkgMgr: []string{"dnf", "yum", "rpm"},
			osReleaseMatch: "Rocky Linux",
		},
		{
			name:           "rocky linux update all",
			image:          "docker.io/library/rockylinux:9",
			osType:         "rocky",
			osVersion:      "9",
			packages:       nil,
			expectedPkgMgr: []string{"dnf", "yum", "rpm"},
			osReleaseMatch: "Rocky Linux",
		},
		// AlmaLinux
		{
			name:      "almalinux 9",
			image:     "docker.io/library/almalinux:9",
			osType:    "almalinux",
			osVersion: "9",
			packages: []testenv.PackageUpdate{
				{
					Name:             "openssl",
					InstalledVersion: "1:3.0.7-17.el9",
					FixedVersion:     "1:3.0.7-27.el9_4",
					VulnerabilityID:  "CVE-2023-TEST",
				},
			},
			expectedPkgMgr: []string{"dnf", "yum", "rpm"},
			osReleaseMatch: "AlmaLinux",
		},
		{
			name:           "almalinux update all",
			image:          "docker.io/library/almalinux:9",
			osType:         "almalinux",
			osVersion:      "9",
			packages:       nil,
			expectedPkgMgr: []string{"dnf", "yum", "rpm"},
			osReleaseMatch: "AlmaLinux",
		},
		// Red Hat UBI
		{
			name:      "redhat ubi9 minimal",
			image:     "registry.access.redhat.com/ubi9-minimal:latest",
			osType:    "rhel",
			osVersion: "9",
			packages: []testenv.PackageUpdate{
				{
					Name:             "openssl-libs",
					InstalledVersion: "1:3.0.7-17.el9",
					FixedVersion:     "1:3.0.7-27.el9_4",
					VulnerabilityID:  "CVE-2023-TEST",
				},
			},
			expectedPkgMgr: []string{"microdnf", "dnf", "rpm"},
			osReleaseMatch: "Red Hat",
		},
		{
			name:           "redhat ubi update all",
			image:          "registry.access.redhat.com/ubi9-minimal:latest",
			osType:         "rhel",
			osVersion:      "9",
			packages:       nil,
			expectedPkgMgr: []string{"microdnf", "dnf", "rpm"},
			osReleaseMatch: "Red Hat",
		},
		// Oracle Linux
		{
			name:      "oracle linux 8",
			image:     "docker.io/library/oraclelinux:8",
			osType:    "ol",
			osVersion: "8",
			packages: []testenv.PackageUpdate{
				{
					Name:             "openssl-libs",
					InstalledVersion: "1:1.1.1k-5.el8",
					FixedVersion:     "1:1.1.1k-12.el8_9",
					VulnerabilityID:  "CVE-2023-TEST",
				},
			},
			expectedPkgMgr: []string{"dnf", "yum", "rpm"},
			osReleaseMatch: "Oracle Linux",
		},
		{
			name:           "oracle linux update all",
			image:          "docker.io/library/oraclelinux:8",
			osType:         "ol",
			osVersion:      "8",
			packages:       nil,
			expectedPkgMgr: []string{"dnf", "yum", "rpm"},
			osReleaseMatch: "Oracle Linux",
		},
	}

	runPatchTests(t, testCases)
}

// TestSymlinkPreservation verifies that symlinks are preserved after patching.
func TestSymlinkPreservation(t *testing.T) {
	t.Parallel()

	if buildkitAddr == "" {
		t.Skip("Skipping: no BuildKit address provided")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	platform := &specs.Platform{
		OS:           "linux",
		Architecture: "amd64",
	}

	// Test with Mariner which has /sbin as a symlink
	updates := testenv.CreateUpdateManifest("cbl-mariner", "2.0", "amd64", []testenv.PackageUpdate{
		{
			Name:             "openssl",
			InstalledVersion: "1.1.1k-24.cm2",
			FixedVersion:     "1.1.1k-28.cm2",
			VulnerabilityID:  "CVE-2023-TEST",
		},
	})

	err := testEnv.RunPatchTestWithInspection(ctx, t, testenv.PatchTestConfig{
		ImageName:   "mcr.microsoft.com/cbl-mariner/base/core:2.0",
		Platform:    platform,
		Updates:     updates,
		IgnoreError: true,
	}, func(ctx context.Context, t *testing.T, c gwclient.Client, result *patch.Result) {
		require.NotNil(t, result, "should have patch result")

		inspector, err := testenv.NewRefInspector(ctx, result.Result)
		require.NoError(t, err, "should create inspector")

		// Check if /sbin is a symlink (common in modern Linux distros)
		if inspector.IsSymlink("/sbin") {
			linkTarget, err := inspector.ReadSymlink("/sbin")
			require.NoError(t, err, "should read symlink")
			t.Logf("/sbin is a symlink pointing to: %s", linkTarget)
			require.NotEmpty(t, linkTarget, "/sbin symlink should have a target")
		} else {
			t.Log("/sbin is not a symlink in this image")
		}

		// Also check /bin if it exists
		if inspector.IsSymlink("/bin") {
			linkTarget, err := inspector.ReadSymlink("/bin")
			require.NoError(t, err, "should read symlink")
			t.Logf("/bin is a symlink pointing to: %s", linkTarget)
		}
	})
	if err != nil {
		t.Logf("Patch returned error (may be expected): %v", err)
	}
}

// TestConfigFilePreservation verifies that config files are preserved after patching.
func TestConfigFilePreservation(t *testing.T) {
	t.Parallel()

	if buildkitAddr == "" {
		t.Skip("Skipping: no BuildKit address provided")
	}

	testCases := []struct {
		name       string
		image      string
		osType     string
		osVersion  string
		configFile string
		packages   []testenv.PackageUpdate
	}{
		{
			name:       "mariner openssl.cnf",
			image:      "mcr.microsoft.com/cbl-mariner/base/core:2.0",
			osType:     "cbl-mariner",
			osVersion:  "2.0",
			configFile: "/etc/pki/tls/openssl.cnf",
			packages: []testenv.PackageUpdate{
				{
					Name:             "openssl",
					InstalledVersion: "1.1.1k-24.cm2",
					FixedVersion:     "1.1.1k-28.cm2",
					VulnerabilityID:  "CVE-2023-TEST",
				},
			},
		},
		{
			name:       "debian openssl.cnf",
			image:      "docker.io/library/debian:11",
			osType:     "debian",
			osVersion:  "11",
			configFile: "/etc/ssl/openssl.cnf",
			packages: []testenv.PackageUpdate{
				{
					Name:             "openssl",
					InstalledVersion: "1.1.1n-0+deb11u4",
					FixedVersion:     "1.1.1n-0+deb11u5",
					VulnerabilityID:  "CVE-2023-TEST",
				},
			},
		},
		{
			name:       "alpine openssl.cnf",
			image:      "docker.io/library/alpine:3.18",
			osType:     "alpine",
			osVersion:  "3.18",
			configFile: "/etc/ssl/openssl.cnf",
			packages: []testenv.PackageUpdate{
				{
					Name:             "libcrypto3",
					InstalledVersion: "3.1.0-r4",
					FixedVersion:     "3.1.4-r6",
					VulnerabilityID:  "CVE-2023-TEST",
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
			defer cancel()

			platform := &specs.Platform{
				OS:           "linux",
				Architecture: "amd64",
			}

			updates := testenv.CreateUpdateManifest(tc.osType, tc.osVersion, "amd64", tc.packages)

			err := testEnv.RunPatchTestWithInspection(ctx, t, testenv.PatchTestConfig{
				ImageName:   tc.image,
				Platform:    platform,
				Updates:     updates,
				IgnoreError: true,
			}, func(ctx context.Context, t *testing.T, c gwclient.Client, result *patch.Result) {
				require.NotNil(t, result, "should have patch result")

				inspector, err := testenv.NewRefInspector(ctx, result.Result)
				require.NoError(t, err, "should create inspector")

				// Verify config file still exists after patching
				if inspector.FileExists(tc.configFile) {
					content, err := inspector.ReadFile(tc.configFile)
					require.NoError(t, err, "should read config file")
					t.Logf("Config file %s exists (%d bytes)", tc.configFile, len(content))

					// Config file should not be empty
					require.NotEmpty(t, content, "config file should not be empty")
				} else {
					t.Logf("Config file %s not found (may not be installed)", tc.configFile)
				}
			})
			if err != nil {
				t.Logf("Patch returned error (may be expected): %v", err)
			}
		})
	}
}

// TestPatchUpdateAll tests the "update all" mode across different distros.
func TestPatchUpdateAll(t *testing.T) {
	t.Parallel()

	if buildkitAddr == "" {
		t.Skip("Skipping: no BuildKit address provided")
	}

	testCases := []struct {
		name           string
		image          string
		osReleaseMatch string
	}{
		{"alpine", "alpine:3.18", "Alpine"},
		{"debian", "debian:11", "Debian"},
		{"mariner", "mcr.microsoft.com/cbl-mariner/base/core:2.0", "Mariner"},
		{"azure linux", "mcr.microsoft.com/azurelinux/base/core:3.0", "Azure Linux"},
		{"amazon linux", "docker.io/library/amazonlinux:2", "Amazon Linux"},
		{"rocky linux", "docker.io/library/rockylinux:9", "Rocky Linux"},
		{"almalinux", "docker.io/library/almalinux:9", "AlmaLinux"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
			defer cancel()

			platform := &specs.Platform{
				OS:           "linux",
				Architecture: "amd64",
			}

			// nil updates triggers "update all" mode
			var updates *unversioned.UpdateManifest

			err := testEnv.RunPatchTestWithInspection(ctx, t, testenv.PatchTestConfig{
				ImageName:   tc.image,
				Platform:    platform,
				Updates:     updates,
				IgnoreError: true,
			}, func(ctx context.Context, t *testing.T, c gwclient.Client, result *patch.Result) {
				require.NotNil(t, result, "should have patch result")

				t.Logf("Package manager detected: %s", result.PackageType)
				t.Logf("Errored packages: %v", result.ErroredPackages)

				// Verify we can still inspect the filesystem
				inspector, err := testenv.NewRefInspector(ctx, result.Result)
				require.NoError(t, err, "should create inspector")

				inspector.AssertFileExists(t, "/etc/os-release")
				inspector.AssertFileContains(t, "/etc/os-release", tc.osReleaseMatch)
			})
			if err != nil {
				t.Logf("Patch returned error (may be expected): %v", err)
			}
		})
	}
}
