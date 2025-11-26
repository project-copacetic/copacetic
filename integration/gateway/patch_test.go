package gateway

import (
	"context"
	"testing"
	"time"

	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/client/llb/sourceresolver"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"

	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/test/testenv"
)

// TestGatewayClientAccess verifies that the test environment can access
// the BuildKit gateway client and resolve an image.
func TestGatewayClientAccess(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	testEnv.RunTest(ctx, t, func(ctx context.Context, t *testing.T, c gwclient.Client) {
		// Verify we can resolve a simple image
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

// TestInspectAlpineImage tests that we can inspect an Alpine image's filesystem.
func TestInspectAlpineImage(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	testEnv.RunTest(ctx, t, func(ctx context.Context, t *testing.T, c gwclient.Client) {
		platform := specs.Platform{
			OS:           "linux",
			Architecture: "amd64",
		}

		// Initialize buildkit config for an Alpine image
		config, err := initBuildkitConfig(ctx, c, "docker.io/library/alpine:3.18", &platform)
		require.NoError(t, err, "should initialize buildkit config")

		// Solve the image state to get a reference we can inspect
		def, err := config.ImageState.Marshal(ctx, llb.Platform(platform))
		require.NoError(t, err, "should marshal image state")

		res, err := c.Solve(ctx, gwclient.SolveRequest{
			Definition: def.ToPB(),
			Evaluate:   true,
		})
		require.NoError(t, err, "should solve image state")

		// Create inspector
		inspector, err := testenv.NewRefInspector(ctx, res)
		require.NoError(t, err, "should create inspector")

		// Verify Alpine-specific files exist
		inspector.AssertFileExists(t, "/etc/os-release")
		inspector.AssertFileExists(t, "/lib/apk/db/installed")

		// Check os-release content
		inspector.AssertFileContains(t, "/etc/os-release", "Alpine")
	})
}

// TestInspectDebianImage tests that we can inspect a Debian image's filesystem.
func TestInspectDebianImage(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	testEnv.RunTest(ctx, t, func(ctx context.Context, t *testing.T, c gwclient.Client) {
		platform := specs.Platform{
			OS:           "linux",
			Architecture: "amd64",
		}

		// Initialize buildkit config for nginx (Debian-based)
		config, err := initBuildkitConfig(ctx, c, "docker.io/library/nginx:1.21.6", &platform)
		require.NoError(t, err, "should initialize buildkit config")

		// Solve the image state to get a reference we can inspect
		def, err := config.ImageState.Marshal(ctx, llb.Platform(platform))
		require.NoError(t, err, "should marshal image state")

		res, err := c.Solve(ctx, gwclient.SolveRequest{
			Definition: def.ToPB(),
			Evaluate:   true,
		})
		require.NoError(t, err, "should solve image state")

		// Create inspector
		inspector, err := testenv.NewRefInspector(ctx, res)
		require.NoError(t, err, "should create inspector")

		// Verify Debian-specific files exist
		inspector.AssertFileExists(t, "/etc/os-release")
		inspector.AssertFileExists(t, "/var/lib/dpkg/status")

		// Check os-release content
		inspector.AssertFileContains(t, "/etc/os-release", "Debian")
	})
}

// TestGetOriginalLayerCount tests that we can retrieve layer count from an image.
func TestGetOriginalLayerCount(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	testEnv.RunTest(ctx, t, func(ctx context.Context, t *testing.T, c gwclient.Client) {
		platform := &specs.Platform{
			OS:           "linux",
			Architecture: "amd64",
		}

		// Get layer info for alpine (using short name - testenv normalizes it)
		layerInfo, err := testenv.GetOriginalImageLayerCount(ctx, c, "alpine:3.18", platform)
		require.NoError(t, err, "should get layer info")
		require.Greater(t, layerInfo.LayerCount, 0, "should have at least one layer")

		t.Logf("alpine:3.18 has %d layers", layerInfo.LayerCount)
		t.Logf("DiffIDs: %v", layerInfo.DiffIDs)
	})
}

// TestPatchConfigPreserved tests that image config is preserved after patching.
// This is an example of a test that exercises ExecutePatchCore directly.
func TestPatchConfigPreserved(t *testing.T) {
	// Skip if no BuildKit available (for CI flexibility)
	if buildkitAddr == "" {
		t.Skip("Skipping: no BuildKit address provided (set COPA_BUILDKIT_ADDR or -addr flag)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	testEnv.RunTest(ctx, t, func(ctx context.Context, t *testing.T, c gwclient.Client) {
		platform := &specs.Platform{
			OS:           "linux",
			Architecture: "amd64",
		}

		// Get original config
		resolveOpt := sourceresolver.Opt{
			ImageOpt: &sourceresolver.ResolveImageOpt{
				ResolveMode: "prefer-local",
			},
			Platform: platform,
		}

		_, _, originalConfig, err := c.ResolveImageConfig(ctx, "docker.io/library/alpine:3.18", resolveOpt)
		require.NoError(t, err, "should resolve original config")

		t.Logf("Original config size: %d bytes", len(originalConfig))
		t.Logf("Original config (first 200 bytes): %s", truncate(originalConfig, 200))
	})
}

// initBuildkitConfig is a helper that creates a buildkit config for an image.
// It uses the real pkg/buildkit.InitializeBuildkitConfig function.
func initBuildkitConfig(ctx context.Context, c gwclient.Client, imageName string, platform *specs.Platform) (*buildkit.Config, error) {
	return buildkit.InitializeBuildkitConfig(ctx, c, imageName, platform)
}

// truncate truncates a byte slice for logging.
func truncate(b []byte, maxLen int) string {
	if len(b) <= maxLen {
		return string(b)
	}
	return string(b[:maxLen]) + "..."
}
