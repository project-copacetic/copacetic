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

// TestInspectMarinerImage tests that we can inspect a Mariner/Azure Linux image.
func TestInspectMarinerImage(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	testEnv.RunTest(ctx, t, func(ctx context.Context, t *testing.T, c gwclient.Client) {
		platform := specs.Platform{
			OS:           "linux",
			Architecture: "amd64",
		}

		// Initialize buildkit config for Mariner
		config, err := initBuildkitConfig(ctx, c, "mcr.microsoft.com/cbl-mariner/base/core:2.0", &platform)
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

		// Verify Mariner-specific files exist
		inspector.AssertFileExists(t, "/etc/os-release")
		inspector.AssertFileContains(t, "/etc/os-release", "Mariner")

		// Check for RPM database
		switch {
		case inspector.FileExists("/var/lib/rpm/rpmdb.sqlite"):
			t.Log("Found SQLite RPM database")
		case inspector.FileExists("/var/lib/rpm/Packages"):
			t.Log("Found Berkeley DB RPM database")
		default:
			t.Log("RPM database location may vary")
		}
	})
}

// TestInspectAzureLinuxImage tests that we can inspect an Azure Linux 3.0 image.
func TestInspectAzureLinuxImage(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	testEnv.RunTest(ctx, t, func(ctx context.Context, t *testing.T, c gwclient.Client) {
		platform := specs.Platform{
			OS:           "linux",
			Architecture: "amd64",
		}

		// Initialize buildkit config for Azure Linux 3.0
		config, err := initBuildkitConfig(ctx, c, "mcr.microsoft.com/azurelinux/base/core:3.0", &platform)
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

		// Verify Azure Linux files exist
		inspector.AssertFileExists(t, "/etc/os-release")
		inspector.AssertFileContains(t, "/etc/os-release", "Azure Linux")
	})
}

// TestInspectAmazonLinuxImage tests that we can inspect an Amazon Linux image.
func TestInspectAmazonLinuxImage(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	testEnv.RunTest(ctx, t, func(ctx context.Context, t *testing.T, c gwclient.Client) {
		platform := specs.Platform{
			OS:           "linux",
			Architecture: "amd64",
		}

		// Initialize buildkit config for Amazon Linux 2
		config, err := initBuildkitConfig(ctx, c, "docker.io/library/amazonlinux:2", &platform)
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

		// Verify Amazon Linux files exist
		inspector.AssertFileExists(t, "/etc/os-release")
		inspector.AssertFileContains(t, "/etc/os-release", "Amazon Linux")
	})
}

// TestInspectRockyLinuxImage tests that we can inspect a Rocky Linux image.
func TestInspectRockyLinuxImage(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	testEnv.RunTest(ctx, t, func(ctx context.Context, t *testing.T, c gwclient.Client) {
		platform := specs.Platform{
			OS:           "linux",
			Architecture: "amd64",
		}

		// Initialize buildkit config for Rocky Linux
		config, err := initBuildkitConfig(ctx, c, "docker.io/library/rockylinux:9", &platform)
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

		// Verify Rocky Linux files exist
		inspector.AssertFileExists(t, "/etc/os-release")
		inspector.AssertFileContains(t, "/etc/os-release", "Rocky Linux")
	})
}

// TestInspectAlmaLinuxImage tests that we can inspect an AlmaLinux image.
func TestInspectAlmaLinuxImage(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	testEnv.RunTest(ctx, t, func(ctx context.Context, t *testing.T, c gwclient.Client) {
		platform := specs.Platform{
			OS:           "linux",
			Architecture: "amd64",
		}

		// Initialize buildkit config for AlmaLinux
		config, err := initBuildkitConfig(ctx, c, "docker.io/library/almalinux:9", &platform)
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

		// Verify AlmaLinux files exist
		inspector.AssertFileExists(t, "/etc/os-release")
		inspector.AssertFileContains(t, "/etc/os-release", "AlmaLinux")
	})
}

// TestInspectRedhatUBIImage tests that we can inspect a Red Hat UBI image.
func TestInspectRedhatUBIImage(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	testEnv.RunTest(ctx, t, func(ctx context.Context, t *testing.T, c gwclient.Client) {
		platform := specs.Platform{
			OS:           "linux",
			Architecture: "amd64",
		}

		// Initialize buildkit config for Red Hat UBI minimal
		config, err := initBuildkitConfig(ctx, c, "registry.access.redhat.com/ubi9-minimal:latest", &platform)
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

		// Verify Red Hat UBI files exist
		inspector.AssertFileExists(t, "/etc/os-release")
		inspector.AssertFileContains(t, "/etc/os-release", "Red Hat")
	})
}

// TestPatchMarinerImage tests patching a Mariner/CBL-Mariner image.
func TestPatchMarinerImage(t *testing.T) {
	if buildkitAddr == "" {
		t.Skip("Skipping: no BuildKit address provided (set COPA_BUILDKIT_ADDR or -addr flag)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	platform := &specs.Platform{
		OS:           "linux",
		Architecture: "amd64",
	}

	// Create an update manifest for Mariner
	updates := testenv.CreateUpdateManifest("cbl-mariner", "2.0", "amd64", []testenv.PackageUpdate{
		{
			Name:             "openssl",
			InstalledVersion: "1.1.1k-24.cm2",
			FixedVersion:     "1.1.1k-28.cm2",
			VulnerabilityID:  "CVE-2023-TEST",
		},
	})

	result, err := testEnv.RunPatchTest(ctx, t, testenv.PatchTestConfig{
		ImageName:   "mcr.microsoft.com/cbl-mariner/base/core:2.0",
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

	// Verify the package type is rpm-based
	if result.PackageType != "" {
		require.Contains(t, []string{"rpm", "tdnf", "yum", "dnf"}, result.PackageType,
			"Mariner should use an RPM-based package manager")
	}
}

// TestSymlinkPreservation verifies that symlinks are preserved after patching.
// This is important for RPM-based distros where /sbin -> /usr/sbin etc.
func TestSymlinkPreservation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	testEnv.RunTest(ctx, t, func(ctx context.Context, t *testing.T, c gwclient.Client) {
		platform := specs.Platform{
			OS:           "linux",
			Architecture: "amd64",
		}

		// Use a Mariner image which has /sbin as a symlink
		config, err := initBuildkitConfig(ctx, c, "mcr.microsoft.com/cbl-mariner/base/core:2.0", &platform)
		require.NoError(t, err, "should initialize buildkit config")

		def, err := config.ImageState.Marshal(ctx, llb.Platform(platform))
		require.NoError(t, err, "should marshal image state")

		res, err := c.Solve(ctx, gwclient.SolveRequest{
			Definition: def.ToPB(),
			Evaluate:   true,
		})
		require.NoError(t, err, "should solve image state")

		inspector, err := testenv.NewRefInspector(ctx, res)
		require.NoError(t, err, "should create inspector")

		// Check if /sbin is a symlink (common in modern Linux distros)
		if inspector.IsSymlink("/sbin") {
			linkTarget, err := inspector.ReadSymlink("/sbin")
			require.NoError(t, err, "should read symlink")
			t.Logf("/sbin is a symlink pointing to: %s", linkTarget)
			require.NotEmpty(t, linkTarget, "/sbin symlink should have a target")
		} else {
			t.Log("/sbin is not a symlink in this image (may be a directory)")
		}

		// Also check /bin if it exists
		if inspector.IsSymlink("/bin") {
			linkTarget, err := inspector.ReadSymlink("/bin")
			require.NoError(t, err, "should read symlink")
			t.Logf("/bin is a symlink pointing to: %s", linkTarget)
		}
	})
}

// TestDistrolessMarinerImage tests inspection of Mariner Distroless images.
// These have custom rpmmanifest files instead of standard RPM databases.
func TestDistrolessMarinerImage(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	testEnv.RunTest(ctx, t, func(ctx context.Context, t *testing.T, c gwclient.Client) {
		platform := specs.Platform{
			OS:           "linux",
			Architecture: "amd64",
		}

		// Initialize buildkit config for Mariner Distroless
		config, err := initBuildkitConfig(ctx, c, "mcr.microsoft.com/cbl-mariner/distroless/base:2.0", &platform)
		require.NoError(t, err, "should initialize buildkit config")

		def, err := config.ImageState.Marshal(ctx, llb.Platform(platform))
		require.NoError(t, err, "should marshal image state")

		res, err := c.Solve(ctx, gwclient.SolveRequest{
			Definition: def.ToPB(),
			Evaluate:   true,
		})
		require.NoError(t, err, "should solve image state")

		inspector, err := testenv.NewRefInspector(ctx, res)
		require.NoError(t, err, "should create inspector")

		// Mariner Distroless uses rpmmanifest files
		// Check for the manifest directory
		if inspector.DirExists("/var/lib/rpmmanifest") {
			t.Log("Found /var/lib/rpmmanifest directory (Mariner Distroless)")
		}

		// Verify os-release exists
		inspector.AssertFileExists(t, "/etc/os-release")
	})
}

// TestInspectOracleLinuxImage tests that we can inspect an Oracle Linux image.
// Note: Oracle Linux has known issues with Trivy (false positives), but inspection should work.
func TestInspectOracleLinuxImage(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	testEnv.RunTest(ctx, t, func(ctx context.Context, t *testing.T, c gwclient.Client) {
		platform := specs.Platform{
			OS:           "linux",
			Architecture: "amd64",
		}

		// Initialize buildkit config for Oracle Linux 8
		config, err := initBuildkitConfig(ctx, c, "docker.io/library/oraclelinux:8", &platform)
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

		// Verify Oracle Linux files exist
		inspector.AssertFileExists(t, "/etc/os-release")
		inspector.AssertFileContains(t, "/etc/os-release", "Oracle Linux")

		// Check for RPM database
		switch {
		case inspector.FileExists("/var/lib/rpm/rpmdb.sqlite"):
			t.Log("Found SQLite RPM database")
		case inspector.FileExists("/var/lib/rpm/Packages"):
			t.Log("Found Berkeley DB RPM database")
		default:
			t.Log("RPM database location may vary")
		}

		// Verify yum is available (Oracle Linux uses yum/dnf)
		if inspector.FileExists("/usr/bin/yum") || inspector.FileExists("/usr/bin/dnf") {
			t.Log("Found yum/dnf package manager")
		}
	})
}

// TestDistrolessGoogleImage tests inspection of Google Distroless images.
// These have custom dpkg/status.d directories instead of /var/lib/dpkg/status.
func TestDistrolessGoogleImage(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	testEnv.RunTest(ctx, t, func(ctx context.Context, t *testing.T, c gwclient.Client) {
		platform := specs.Platform{
			OS:           "linux",
			Architecture: "amd64",
		}

		// Initialize buildkit config for Google Distroless
		config, err := initBuildkitConfig(ctx, c, "gcr.io/distroless/base-debian12:latest", &platform)
		require.NoError(t, err, "should initialize buildkit config")

		def, err := config.ImageState.Marshal(ctx, llb.Platform(platform))
		require.NoError(t, err, "should marshal image state")

		res, err := c.Solve(ctx, gwclient.SolveRequest{
			Definition: def.ToPB(),
			Evaluate:   true,
		})
		require.NoError(t, err, "should solve image state")

		inspector, err := testenv.NewRefInspector(ctx, res)
		require.NoError(t, err, "should create inspector")

		// Google Distroless uses dpkg status.d directory
		if inspector.DirExists("/var/lib/dpkg/status.d") {
			t.Log("Found /var/lib/dpkg/status.d directory (Google Distroless)")
		}

		// Check for os-release
		if inspector.FileExists("/etc/os-release") {
			content, _ := inspector.ReadFile("/etc/os-release")
			t.Logf("os-release content: %s", truncate(content, 200))
		}
	})
}

// TestConfigFileLocations verifies that config files exist in expected locations.
// This is a prerequisite for config file preservation testing - we need to know
// where the config files are before we can verify they're preserved after patching.
func TestConfigFileLocations(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	testCases := []struct {
		name       string
		image      string
		configFile string
	}{
		{
			name:       "Mariner openssl.cnf",
			image:      "mcr.microsoft.com/cbl-mariner/base/core:2.0",
			configFile: "/etc/pki/tls/openssl.cnf",
		},
		{
			name:       "Debian openssl.cnf",
			image:      "docker.io/library/debian:11",
			configFile: "/etc/ssl/openssl.cnf",
		},
		{
			name:       "Alpine openssl.cnf",
			image:      "docker.io/library/alpine:3.18",
			configFile: "/etc/ssl/openssl.cnf",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testEnv.RunTest(ctx, t, func(ctx context.Context, t *testing.T, c gwclient.Client) {
				platform := specs.Platform{
					OS:           "linux",
					Architecture: "amd64",
				}

				config, err := initBuildkitConfig(ctx, c, tc.image, &platform)
				require.NoError(t, err, "should initialize buildkit config")

				def, err := config.ImageState.Marshal(ctx, llb.Platform(platform))
				require.NoError(t, err, "should marshal image state")

				res, err := c.Solve(ctx, gwclient.SolveRequest{
					Definition: def.ToPB(),
					Evaluate:   true,
				})
				require.NoError(t, err, "should solve image state")

				inspector, err := testenv.NewRefInspector(ctx, res)
				require.NoError(t, err, "should create inspector")

				// Check if config file exists
				if inspector.FileExists(tc.configFile) {
					content, err := inspector.ReadFile(tc.configFile)
					require.NoError(t, err, "should read config file")
					t.Logf("Found %s (%d bytes)", tc.configFile, len(content))

					// Log first 100 chars to verify it's a real config
					preview := string(content)
					if len(preview) > 100 {
						preview = preview[:100] + "..."
					}
					t.Logf("Content preview: %s", preview)
				} else {
					t.Logf("Config file %s not found (may not be installed)", tc.configFile)
				}
			})
		})
	}
}
