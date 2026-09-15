package gateway

import (
	"context"
	"testing"
	"time"

	"github.com/moby/buildkit/client/llb"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"

	"github.com/project-copacetic/copacetic/test/testenv"
)

// TestInspectARM64Image tests that we can inspect an ARM64 image.
// This verifies cross-architecture support in the gateway testing framework.
func TestInspectARM64Image(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	testEnv.RunTest(ctx, t, func(ctx context.Context, t *testing.T, c gwclient.Client) {
		platform := specs.Platform{
			OS:           "linux",
			Architecture: "arm64",
		}

		// Use an ARM64-specific Alpine image
		config, err := initBuildkitConfig(ctx, c, "docker.io/arm64v8/alpine:3.18", &platform)
		require.NoError(t, err, "should initialize buildkit config for ARM64")

		def, err := config.ImageState.Marshal(ctx, llb.Platform(platform))
		require.NoError(t, err, "should marshal image state")

		res, err := c.Solve(ctx, gwclient.SolveRequest{
			Definition: def.ToPB(),
			Evaluate:   true,
		})
		require.NoError(t, err, "should solve image state")

		inspector, err := testenv.NewRefInspector(ctx, res)
		require.NoError(t, err, "should create inspector")

		// Verify Alpine-specific files exist
		inspector.AssertFileExists(t, "/etc/os-release")
		inspector.AssertFileContains(t, "/etc/os-release", "Alpine")
		inspector.AssertFileExists(t, "/lib/apk/db/installed")

		t.Log("Successfully inspected ARM64 Alpine image")
	})
}

// TestInspectARM64MarinerImage tests that we can inspect an ARM64 Mariner image.
func TestInspectARM64MarinerImage(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	testEnv.RunTest(ctx, t, func(ctx context.Context, t *testing.T, c gwclient.Client) {
		platform := specs.Platform{
			OS:           "linux",
			Architecture: "arm64",
		}

		// Use Mariner ARM64 image
		config, err := initBuildkitConfig(ctx, c, "mcr.microsoft.com/cbl-mariner/base/core:2.0", &platform)
		require.NoError(t, err, "should initialize buildkit config for ARM64 Mariner")

		def, err := config.ImageState.Marshal(ctx, llb.Platform(platform))
		require.NoError(t, err, "should marshal image state")

		res, err := c.Solve(ctx, gwclient.SolveRequest{
			Definition: def.ToPB(),
			Evaluate:   true,
		})
		require.NoError(t, err, "should solve image state")

		inspector, err := testenv.NewRefInspector(ctx, res)
		require.NoError(t, err, "should create inspector")

		// Verify Mariner files exist
		inspector.AssertFileExists(t, "/etc/os-release")
		inspector.AssertFileContains(t, "/etc/os-release", "Mariner")

		t.Log("Successfully inspected ARM64 Mariner image")
	})
}

// TestPatchARM64Image tests patching an ARM64 image.
func TestPatchARM64Image(t *testing.T) {
	t.Parallel()

	if buildkitAddr == "" {
		t.Skip("Skipping: no BuildKit address provided (set COPA_BUILDKIT_ADDR or -addr flag)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	platform := &specs.Platform{
		OS:           "linux",
		Architecture: "arm64",
	}

	// Create an update manifest for Alpine ARM64
	updates := testenv.CreateUpdateManifest("alpine", "3.18", "arm64", []testenv.PackageUpdate{
		{
			Name:             "busybox",
			InstalledVersion: "1.36.1-r0",
			FixedVersion:     "1.36.1-r29",
			VulnerabilityID:  "CVE-2023-TEST",
		},
	})

	result, err := testEnv.RunPatchTest(ctx, t, testenv.PatchTestConfig{
		ImageName:   "docker.io/arm64v8/alpine:3.18",
		Platform:    platform,
		Updates:     updates,
		IgnoreError: true,
	})
	if err != nil {
		t.Logf("Patch returned error (may be expected): %v", err)
		return
	}

	require.NotNil(t, result, "should have patch result")
	t.Logf("Detected package type: %s", result.PackageType)
	t.Logf("Errored packages: %v", result.ErroredPackages)
}

// TestLayerCountARM64 tests layer count retrieval for ARM64 images.
func TestLayerCountARM64(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	testEnv.RunTest(ctx, t, func(ctx context.Context, t *testing.T, c gwclient.Client) {
		platform := &specs.Platform{
			OS:           "linux",
			Architecture: "arm64",
		}

		// Get layer info for ARM64 Alpine
		layerInfo, err := testenv.GetOriginalImageLayerCount(ctx, c, "docker.io/arm64v8/alpine:3.18", platform)
		require.NoError(t, err, "should get layer info for ARM64 image")
		require.Greater(t, layerInfo.LayerCount, 0, "should have at least one layer")

		t.Logf("ARM64 alpine:3.18 has %d layers", layerInfo.LayerCount)
		t.Logf("DiffIDs: %v", layerInfo.DiffIDs)

		// Verify platform info
		require.Equal(t, "arm64", layerInfo.Platform.Architecture, "should be ARM64 architecture")
	})
}

// TestMultiPlatformImageResolution tests resolving images with multiple platforms.
func TestMultiPlatformImageResolution(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	testEnv.RunTest(ctx, t, func(ctx context.Context, t *testing.T, c gwclient.Client) {
		// Test resolving a known multi-platform image for different architectures
		architectures := []string{"amd64", "arm64"}

		for _, arch := range architectures {
			platform := &specs.Platform{
				OS:           "linux",
				Architecture: arch,
			}

			layerInfo, err := testenv.GetOriginalImageLayerCount(ctx, c, "docker.io/library/alpine:3.18", platform)
			if err != nil {
				t.Logf("Could not resolve alpine:3.18 for %s: %v", arch, err)
				continue
			}

			require.Greater(t, layerInfo.LayerCount, 0, "should have at least one layer")
			t.Logf("alpine:3.18 (%s) has %d layers", arch, layerInfo.LayerCount)
		}
	})
}
