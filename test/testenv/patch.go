package testenv

import (
	"context"
	"testing"

	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	specs "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/project-copacetic/copacetic/pkg/patch"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
)

// PatchTestConfig holds configuration for patch tests.
type PatchTestConfig struct {
	// ImageName is the name of the image to patch (e.g., "alpine:3.18")
	ImageName string

	// Platform specifies the target platform for patching.
	// If nil, the default platform is used.
	Platform *specs.Platform

	// Updates is the vulnerability update manifest.
	// This specifies which packages to update and to what versions.
	Updates *unversioned.UpdateManifest

	// WorkingFolder is the temporary working directory.
	// If empty, a system temp directory is used.
	WorkingFolder string

	// IgnoreError continues patching even if some packages fail.
	IgnoreError bool

	// ExitOnEOL exits if the OS is end-of-life.
	ExitOnEOL bool
}

// PatchTestResult holds the result of a patch test.
type PatchTestResult struct {
	// Result is the underlying patch.Result from ExecutePatchCore.
	Result *patch.Result

	// Inspector provides filesystem inspection capabilities for the patched image.
	Inspector *RefInspector

	// PackageType is the detected package manager type (e.g., "deb", "apk", "rpm").
	PackageType string

	// ErroredPackages is the list of packages that failed to patch.
	ErroredPackages []string
}

// RunPatchTest executes a patch operation and returns results.
// This is a convenience wrapper around RunTest and ExecutePatchCore.
//
// WARNING: The Inspector field in the returned PatchTestResult will have an
// invalid reference after this function returns, because the BuildKit job
// is cleaned up when the Build callback completes. If you need to inspect
// the patched filesystem, use RunPatchTestWithInspection instead, which
// performs inspection inside the Build callback where the reference is valid.
//
// This function is still useful for tests that only need to check metadata
// like PackageType and ErroredPackages, but NOT for filesystem inspection.
//
// Example usage (metadata only - DO NOT use Inspector):
//
//	result, err := env.RunPatchTest(ctx, t, testenv.PatchTestConfig{
//	    ImageName: "alpine:3.18",
//	    Platform:  &specs.Platform{OS: "linux", Architecture: "amd64"},
//	    Updates:   updates,
//	})
//	require.NoError(t, err)
//	t.Logf("Package type: %s", result.PackageType)
//	// NOTE: result.Inspector methods will fail with "no such job" error!
func (e *TestEnv) RunPatchTest(ctx context.Context, t *testing.T, cfg PatchTestConfig) (*PatchTestResult, error) {
	t.Helper()

	var testResult *PatchTestResult
	var testErr error

	e.RunTest(ctx, t, func(ctx context.Context, t *testing.T, c gwclient.Client) {
		// Create patch context with gateway client
		patchCtx := &patch.Context{
			Context: ctx,
			Client:  c,
		}

		// Build target platform
		var targetPlatform *types.PatchPlatform
		if cfg.Platform != nil {
			targetPlatform = &types.PatchPlatform{
				Platform: *cfg.Platform,
			}
		} else {
			// Default to linux/amd64
			targetPlatform = &types.PatchPlatform{
				Platform: specs.Platform{
					OS:           "linux",
					Architecture: "amd64",
				},
			}
		}

		// Normalize the image name to prevent URL parsing errors in BuildKit
		normalizedImageName := NormalizeImageRef(cfg.ImageName)

		// Create patch options
		patchOpts := &patch.Options{
			ImageName:      normalizedImageName,
			TargetPlatform: targetPlatform,
			Updates:        cfg.Updates,
			WorkingFolder:  cfg.WorkingFolder,
			IgnoreError:    cfg.IgnoreError,
			ReturnState:    false, // We want the solved result for inspection
			ExitOnEOL:      cfg.ExitOnEOL,
		}

		// Execute the patch
		result, err := patch.ExecutePatchCore(patchCtx, patchOpts)
		if err != nil {
			testErr = err
			return
		}

		// Create inspector from result
		inspector, err := NewRefInspector(ctx, result.Result)
		if err != nil {
			testErr = err
			return
		}

		testResult = &PatchTestResult{
			Result:          result,
			Inspector:       inspector,
			PackageType:     result.PackageType,
			ErroredPackages: result.ErroredPackages,
		}
	}, WithSkipExport())

	if testErr != nil {
		return nil, testErr
	}

	return testResult, nil
}

// RunPatchTestWithInspection is similar to RunPatchTest but allows custom
// inspection logic within the gateway client context.
// This is useful when you need to perform multiple operations with the same
// gateway client, such as comparing pre/post patch states.
//
// Example usage:
//
//	err := env.RunPatchTestWithInspection(ctx, t, cfg, func(ctx context.Context, t *testing.T, c gwclient.Client, result *patch.Result) {
//	    // Inspect the patched result
//	    inspector, _ := testenv.NewRefInspector(ctx, result.Result)
//	    inspector.AssertFileExists(t, "/etc/os-release")
//
//	    // You can also perform additional operations with the gateway client here
//	})
func (e *TestEnv) RunPatchTestWithInspection(
	ctx context.Context,
	t *testing.T,
	cfg PatchTestConfig,
	inspect func(ctx context.Context, t *testing.T, c gwclient.Client, result *patch.Result),
) error {
	t.Helper()

	var testErr error

	e.RunTest(ctx, t, func(ctx context.Context, t *testing.T, c gwclient.Client) {
		// Create patch context with gateway client
		patchCtx := &patch.Context{
			Context: ctx,
			Client:  c,
		}

		// Build target platform
		var targetPlatform *types.PatchPlatform
		if cfg.Platform != nil {
			targetPlatform = &types.PatchPlatform{
				Platform: *cfg.Platform,
			}
		} else {
			targetPlatform = &types.PatchPlatform{
				Platform: specs.Platform{
					OS:           "linux",
					Architecture: "amd64",
				},
			}
		}

		// Normalize the image name to prevent URL parsing errors in BuildKit
		normalizedImageName := NormalizeImageRef(cfg.ImageName)

		// Create patch options
		patchOpts := &patch.Options{
			ImageName:      normalizedImageName,
			TargetPlatform: targetPlatform,
			Updates:        cfg.Updates,
			WorkingFolder:  cfg.WorkingFolder,
			IgnoreError:    cfg.IgnoreError,
			ReturnState:    false,
			ExitOnEOL:      cfg.ExitOnEOL,
		}

		// Execute the patch
		result, err := patch.ExecutePatchCore(patchCtx, patchOpts)
		if err != nil {
			testErr = err
			return
		}

		// Call the custom inspection function
		inspect(ctx, t, c, result)
	}, WithSkipExport())

	return testErr
}

// CreateUpdateManifest is a helper to create a simple UpdateManifest for testing.
// This is useful when you want to test patching specific packages.
//
// Example:
//
//	updates := testenv.CreateUpdateManifest("debian", "11", "amd64", []testenv.PackageUpdate{
//	    {Name: "openssl", InstalledVersion: "1.1.1k-1", FixedVersion: "1.1.1n-0+deb11u5"},
//	})
func CreateUpdateManifest(osType, osVersion, arch string, packages []PackageUpdate) *unversioned.UpdateManifest {
	updates := make([]unversioned.UpdatePackage, len(packages))
	for i, pkg := range packages {
		updates[i] = unversioned.UpdatePackage{
			Name:             pkg.Name,
			InstalledVersion: pkg.InstalledVersion,
			FixedVersion:     pkg.FixedVersion,
			VulnerabilityID:  pkg.VulnerabilityID,
		}
	}

	return &unversioned.UpdateManifest{
		Metadata: unversioned.Metadata{
			OS: unversioned.OS{
				Type:    osType,
				Version: osVersion,
			},
			Config: unversioned.Config{
				Arch: arch,
			},
		},
		OSUpdates: updates,
	}
}

// PackageUpdate represents a package that needs to be updated.
type PackageUpdate struct {
	Name             string
	InstalledVersion string
	FixedVersion     string
	VulnerabilityID  string
}
