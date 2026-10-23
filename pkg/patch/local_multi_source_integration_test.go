package patch

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/utils"
	"github.com/stretchr/testify/require"
)

func testLocallyBuiltMultiSource(t *testing.T, ctx context.Context, application map[string]string) {
	t.Helper()
	t.Run("locally-built-multi-source", func(t *testing.T) {
		repo := fmt.Sprintf("registry.invalid/project/copa-1678-multi-built-%d", time.Now().UnixNano())
		input, output := repo+":source", repo+":patched"
		var dockerfile strings.Builder
		fmt.Fprintf(&dockerfile, "FROM alpine:3.20.0\nLABEL com.example.built-source=%q\n", input)
		for key, value := range application {
			fmt.Fprintf(&dockerfile, "LABEL %s=%q\n", key, value)
		}
		//nolint:gosec // Generated fixture image names and fixed platform list.
		cmd := exec.CommandContext(ctx, "docker", "build", "--builder", "default", "--platform", "linux/amd64,linux/386", "--load", "-t", input, "-")
		cmd.Stdin = strings.NewReader(dockerfile.String())
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, string(out))
		t.Cleanup(func() {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			//nolint:gosec // Remove only this fixture's generated tags.
			out, err := exec.CommandContext(cleanupCtx, "docker", "image", "rm", input, output+"-amd64", output+"-386").CombinedOutput()
			t.Logf("owned multi-built cleanup: %v %s", err, out)
		})
		index, top, complete, found, err := utils.LocalImageIndex(ctx, input)
		require.NoError(t, err)
		require.True(t, found)
		require.True(t, complete)
		require.NotNil(t, top)
		source := &buildkit.ImageSource{Index: index}
		reports := t.TempDir()
		for _, arch := range []string{originAMD64, "386"} {
			report, err := os.ReadFile(originTestReport(t, arch))
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(filepath.Join(reports, arch+".json"), report, 0o600))
		}
		// Inspect only Docker's descriptors before Patch; resolving the parent
		// through BuildKit here would warm the missing child associations.
		require.NoError(t, Patch(ctx, &types.Options{
			Image: input, Report: reports, Scanner: "trivy", PatchedTag: output, BkAddr: "docker://",
			PkgTypes: "os", Progress: "quiet", Timeout: 3 * time.Minute,
		}))
		for _, arch := range []string{originAMD64, "386"} {
			platform := platformSpec("linux", arch, "")
			child, err := source.PlatformDescriptor(&platform)
			require.NoError(t, err)
			verifyLocalBuiltOutput(t, ctx, input, output+"-"+arch, child.Digest, application)
		}
	})
}
