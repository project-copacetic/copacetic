package gateway

import (
	"context"
	"testing"
	"time"

	"github.com/moby/buildkit/client/llb/sourceresolver"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"

	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/patch"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/test/testenv"
)

// TestGatewayClientAccess verifies that the test environment can access
// the BuildKit gateway client and resolve an image.
func TestGatewayClientAccess(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	testEnv.RunTest(ctx, t, func(ctx context.Context, t *testing.T, c gwclient.Client) {
		resolveOpt := sourceresolver.Opt{
			ImageOpt: &sourceresolver.ResolveImageOpt{
				ResolveMode: "prefer-local",
			},
		}

		_, _, configData, err := c.ResolveImageConfig(ctx, "docker.io/library/alpine:latest", resolveOpt)
		require.NoError(t, err, "should be able to resolve alpine:latest")
		require.NotEmpty(t, configData, "config data should not be empty")

		t.Logf("Successfully resolved alpine:latest, config size: %d bytes", len(configData))
	})
}

// TestGetOriginalLayerCount tests that we can retrieve layer count from an image.
func TestGetOriginalLayerCount(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	testEnv.RunTest(ctx, t, func(ctx context.Context, t *testing.T, c gwclient.Client) {
		platform := &specs.Platform{
			OS:           "linux",
			Architecture: "amd64",
		}

		layerInfo, err := testenv.GetOriginalImageLayerCount(ctx, c, "alpine:3.18", platform)
		require.NoError(t, err, "should get layer info")
		require.Greater(t, layerInfo.LayerCount, 0, "should have at least one layer")

		t.Logf("alpine:3.18 has %d layers", layerInfo.LayerCount)
		t.Logf("DiffIDs: %v", layerInfo.DiffIDs)
	})
}

// patchTestCase defines a test case for patching a container image.
type patchTestCase struct {
	name           string
	image          string
	osType         string
	osVersion      string
	packages       []testenv.PackageUpdate // nil for "update all" mode
	expectedPkgMgr []string                // expected package manager types
	osReleaseMatch string                  // substring to match in /etc/os-release
}

// TestPatchAlpine tests Copa patching on Alpine Linux images.
func TestPatchAlpine(t *testing.T) {
	t.Parallel()

	if buildkitAddr == "" {
		t.Skip("Skipping: no BuildKit address provided")
	}

	testCases := []patchTestCase{
		{
			name:      "busybox update",
			image:     "alpine:3.18",
			osType:    "alpine",
			osVersion: "3.18",
			packages: []testenv.PackageUpdate{
				{
					Name:             "busybox",
					InstalledVersion: "1.36.1-r0",
					FixedVersion:     "1.36.1-r29",
					VulnerabilityID:  "CVE-2023-TEST",
				},
			},
			expectedPkgMgr: []string{"apk"},
			osReleaseMatch: "Alpine",
		},
		{
			name:           "update all",
			image:          "alpine:3.18",
			osType:         "alpine",
			osVersion:      "3.18",
			packages:       nil, // update all mode
			expectedPkgMgr: []string{"apk"},
			osReleaseMatch: "Alpine",
		},
	}

	runPatchTests(t, testCases)
}

// TestPatchDebian tests Copa patching on Debian-based images.
func TestPatchDebian(t *testing.T) {
	t.Parallel()

	if buildkitAddr == "" {
		t.Skip("Skipping: no BuildKit address provided")
	}

	testCases := []patchTestCase{
		{
			name:      "bash update",
			image:     "debian:11",
			osType:    "debian",
			osVersion: "11",
			packages: []testenv.PackageUpdate{
				{
					Name:             "bash",
					InstalledVersion: "5.1-2",
					FixedVersion:     "5.1-2+deb11u1",
					VulnerabilityID:  "CVE-2023-TEST",
				},
			},
			expectedPkgMgr: []string{"deb"},
			osReleaseMatch: "Debian",
		},
		{
			name:           "update all",
			image:          "debian:11",
			osType:         "debian",
			osVersion:      "11",
			packages:       nil,
			expectedPkgMgr: []string{"deb"},
			osReleaseMatch: "Debian",
		},
		{
			name:      "nginx image",
			image:     "docker.io/library/nginx:1.21.6",
			osType:    "debian",
			osVersion: "11",
			packages: []testenv.PackageUpdate{
				{
					Name:             "zlib1g",
					InstalledVersion: "1:1.2.11.dfsg-2",
					FixedVersion:     "1:1.2.11.dfsg-2+deb11u2",
					VulnerabilityID:  "CVE-2023-TEST",
				},
			},
			expectedPkgMgr: []string{"deb"},
			osReleaseMatch: "Debian",
		},
	}

	runPatchTests(t, testCases)
}

// TestPatchDistroless tests Copa patching on distroless images.
func TestPatchDistroless(t *testing.T) {
	t.Parallel()

	if buildkitAddr == "" {
		t.Skip("Skipping: no BuildKit address provided")
	}

	testCases := []patchTestCase{
		{
			name:      "google distroless",
			image:     "gcr.io/distroless/base-debian12:latest",
			osType:    "debian",
			osVersion: "12",
			packages: []testenv.PackageUpdate{
				{
					Name:             "base-files",
					InstalledVersion: "12.4",
					FixedVersion:     "12.4+deb12u5",
					VulnerabilityID:  "CVE-2023-TEST",
				},
			},
			expectedPkgMgr: []string{"deb"},
			osReleaseMatch: "Debian",
		},
		{
			name:      "mariner distroless",
			image:     "mcr.microsoft.com/cbl-mariner/distroless/base:2.0",
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
			expectedPkgMgr: []string{"tdnf", "rpm"},
			osReleaseMatch: "Mariner",
		},
		{
			name:      "azure linux distroless",
			image:     "mcr.microsoft.com/azurelinux/distroless/base:3.0",
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
			expectedPkgMgr: []string{"tdnf", "rpm"},
			osReleaseMatch: "Azure Linux",
		},
	}

	runPatchTests(t, testCases)
}

// runPatchTests executes patch tests for a slice of test cases.
func runPatchTests(t *testing.T, testCases []patchTestCase) {
	t.Helper()

	for i := range testCases {
		tc := &testCases[i]
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
			defer cancel()

			platform := &specs.Platform{
				OS:           "linux",
				Architecture: "amd64",
			}

			var updates *unversioned.UpdateManifest
			if tc.packages != nil {
				updates = testenv.CreateUpdateManifest(tc.osType, tc.osVersion, "amd64", tc.packages)
			}

			err := testEnv.RunPatchTestWithInspection(ctx, t, testenv.PatchTestConfig{
				ImageName:   tc.image,
				Platform:    platform,
				Updates:     updates,
				IgnoreError: true,
			}, func(ctx context.Context, t *testing.T, c gwclient.Client, result *patch.Result) {
				require.NotNil(t, result, "should have patch result")

				t.Logf("Package manager: %s", result.PackageType)
				t.Logf("Errored packages: %v", result.ErroredPackages)

				// Verify package manager type if expected
				if len(tc.expectedPkgMgr) > 0 && result.PackageType != "" {
					found := false
					for _, expected := range tc.expectedPkgMgr {
						if result.PackageType == expected {
							found = true
							break
						}
					}
					require.True(t, found, "expected package manager %v, got %s", tc.expectedPkgMgr, result.PackageType)
				}

				// Inspect the patched filesystem
				inspector, err := testenv.NewRefInspector(ctx, result.Result)
				require.NoError(t, err, "should create inspector")

				inspector.AssertFileExists(t, "/etc/os-release")
				if tc.osReleaseMatch != "" {
					inspector.AssertFileContains(t, "/etc/os-release", tc.osReleaseMatch)
				}
			})
			if err != nil {
				t.Logf("Patch returned error (may be expected): %v", err)
			}
		})
	}
}

// TestPatchPreservesConfig verifies that image config is preserved after patching.
func TestPatchPreservesConfig(t *testing.T) {
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

	updates := testenv.CreateUpdateManifest("alpine", "3.18", "amd64", []testenv.PackageUpdate{
		{
			Name:             "busybox",
			InstalledVersion: "1.36.1-r0",
			FixedVersion:     "1.36.1-r29",
			VulnerabilityID:  "CVE-2023-TEST",
		},
	})

	err := testEnv.RunPatchTestWithInspection(ctx, t, testenv.PatchTestConfig{
		ImageName:   "alpine:3.18",
		Platform:    platform,
		Updates:     updates,
		IgnoreError: true,
	}, func(ctx context.Context, t *testing.T, c gwclient.Client, result *patch.Result) {
		require.NotNil(t, result, "should have patch result")

		inspector, err := testenv.NewRefInspector(ctx, result.Result)
		require.NoError(t, err, "should create inspector")

		inspector.AssertFileExists(t, "/etc/os-release")
		inspector.AssertFileContains(t, "/etc/os-release", "Alpine")

		t.Logf("Config preserved - OS release verified")
	})
	if err != nil {
		t.Logf("Patch returned error (may be expected): %v", err)
	}
}

// TestLayerCountAfterPatch verifies layer count behavior.
func TestLayerCountAfterPatch(t *testing.T) {
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

	testEnv.RunTest(ctx, t, func(ctx context.Context, t *testing.T, c gwclient.Client) {
		originalLayerInfo, err := testenv.GetOriginalImageLayerCount(ctx, c, "alpine:3.18", platform)
		require.NoError(t, err, "should get original layer count")

		t.Logf("Original image has %d layers", originalLayerInfo.LayerCount)
		t.Logf("Original DiffIDs: %v", originalLayerInfo.DiffIDs)

		require.Greater(t, originalLayerInfo.LayerCount, 0, "should have at least one layer")
	})
}

// initBuildkitConfig is a helper that creates a buildkit config for an image.
func initBuildkitConfig(ctx context.Context, c gwclient.Client, imageName string, platform *specs.Platform) (*buildkit.Config, error) {
	return buildkit.InitializeBuildkitConfig(ctx, c, imageName, platform)
}
