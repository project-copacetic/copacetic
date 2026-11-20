package gateway

import (
	"context"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	rpmver "github.com/knqyf263/go-rpm-version"
	"github.com/moby/buildkit/client/llb"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"

	"github.com/project-copacetic/copacetic/integration/common"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/patch"
	"github.com/project-copacetic/copacetic/pkg/pkgmgr"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/test/testenv"
)

// fedora45Image returns the pinned Fedora 45 image, whose release package must
// actually be upgraded. CI sets COPA_TEST_FEDORA45_IMAGE to a linux/amd64 copy
// whose repositories use a fixed server instead of the Fedora metalink, so the
// tests don't depend on which mirror dnf is given; see
// .github/workflows/scripts/singlearch-fixture.sh.
func fedora45Image() string {
	if image := os.Getenv("COPA_TEST_FEDORA45_IMAGE"); image != "" {
		return image
	}
	return common.Fedora45Image
}

func TestPatchFedora45(t *testing.T) {
	t.Parallel()
	if buildkitAddr == "" {
		t.Skip("Skipping: no BuildKit address provided")
	}

	image := fedora45Image()
	tests := []struct {
		name                     string
		missingTools, reportless bool
	}{
		{name: "report"},
		{name: "reportless", reportless: true},
		{name: "missing tools", missingTools: true},
		{name: "missing tools reportless", missingTools: true, reportless: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
			defer cancel()
			platform := specs.Platform{OS: "linux", Architecture: runtime.GOARCH}
			testEnv.RunTest(ctx, t, func(ctx context.Context, t *testing.T, c gwclient.Client) {
				cfg, err := buildkit.InitializeBuildkitConfig(ctx, c, image, &platform)
				require.NoError(t, err)
				if tt.missingTools {
					cfg.ImageState = cfg.ImageState.File(llb.Rm("/usr/bin/dnf5")).File(llb.Rm("/usr/bin/rpm"))
				}
				before := fedoraReleaseVersion(ctx, t, c, &cfg.ImageState, &platform)
				require.Equal(t, "45-0.10", before, "fixture must contain the old release package")
				var updates *unversioned.UpdateManifest
				if !tt.reportless {
					updates = testenv.CreateUpdateManifest("fedora", "45", platform.Architecture, []testenv.PackageUpdate{{
						Name: "fedora-release-container", InstalledVersion: before, FixedVersion: "45-14", VulnerabilityID: "CVE-2023-TEST",
					}})
				}
				var patched *llb.State
				if tt.missingTools {
					manager, err := pkgmgr.GetPackageManager("fedora", "45", cfg, t.TempDir())
					require.NoError(t, err)
					var failed []string
					patched, failed, err = manager.InstallUpdates(ctx, updates, false)
					require.NoError(t, err)
					require.Empty(t, failed)
				} else {
					result, err := patch.ExecutePatchCore(&patch.Context{Context: ctx, Client: c}, &patch.Options{
						ImageName: image, TargetPlatform: &types.PatchPlatform{Platform: platform},
						Updates: updates, WorkingFolder: t.TempDir(), ReturnState: true,
					})
					require.NoError(t, err)
					require.Equal(t, "rpm", result.PackageType)
					require.Empty(t, result.ErroredPackages)
					patched = result.PatchedState
				}
				require.NotNil(t, patched)
				after := fedoraReleaseVersion(ctx, t, c, patched, &platform)
				oldVersion, newVersion := rpmver.NewVersion(before), rpmver.NewVersion(after)
				require.True(t, oldVersion.LessThan(newVersion), "RPM must change: before=%s after=%s", before, after)
				minimum := rpmver.NewVersion("45-14")
				require.False(t, newVersion.LessThan(minimum), "patched RPM %s must meet the fixed version", after)
				t.Logf("fedora-release-container: %s -> %s", before, after)
			}, testenv.WithSkipExport())
		})
	}
}

// Query with external tooling so this also inspects images without their own rpm binary.
func fedoraReleaseVersion(ctx context.Context, t *testing.T, c gwclient.Client, state *llb.State, platform *specs.Platform) string {
	t.Helper()
	query := llb.Image(common.Fedora45Image, llb.Platform(*platform)).Run(buildkit.Sh(
		`rpm --root=/target -q --qf '%{VERSION}-%{RELEASE}' fedora-release-container > /results/version`,
	))
	query.AddMount("/target", *state, llb.Readonly)
	output := query.AddMount("/results", llb.Scratch())
	version, err := buildkit.ExtractFileFromState(ctx, c, &output, "version")
	require.NoError(t, err)
	return strings.TrimSpace(string(version))
}
