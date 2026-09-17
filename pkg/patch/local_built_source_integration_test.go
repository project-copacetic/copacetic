package patch

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/opencontainers/go-digest"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/utils"
	"github.com/stretchr/testify/require"
)

func testLocallyBuiltSource(t *testing.T, ctx context.Context, application map[string]string) {
	t.Helper()
	t.Run("locally-built-source", func(t *testing.T) {
		repo := fmt.Sprintf("registry.invalid/project/copa-1678-built-%d", time.Now().UnixNano())
		input, output := repo+":source", repo+":patched"
		var dockerfile strings.Builder
		fmt.Fprintf(&dockerfile, "FROM alpine:3.20.0\nLABEL com.example.built-source=%q\n", input)
		for key, value := range application {
			fmt.Fprintf(&dockerfile, "LABEL %s=%q\n", key, value)
		}
		//nolint:gosec // Generated task-owned image names; no caller-controlled command.
		command := exec.CommandContext(ctx, "docker", "build", "--builder", "default", "--load", "-t", input, "-")
		command.Stdin = strings.NewReader(dockerfile.String())
		out, err := command.CombinedOutput()
		require.NoError(t, err, string(out))
		t.Cleanup(func() {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			//nolint:gosec // Remove only the two generated fixture tags.
			out, err := exec.CommandContext(cleanupCtx, "docker", "image", "rm", input, output).CombinedOutput()
			t.Logf("owned built-image cleanup: %v %s", err, out)
		})
		index, top, complete, found, err := utils.LocalImageIndex(ctx, input)
		require.NoError(t, err)
		require.True(t, found)
		require.True(t, complete)
		require.NotNil(t, top)
		platform := platformSpec("linux", originAMD64, "")
		child, err := (&buildkit.ImageSource{Index: index}).PlatformDescriptor(&platform)
		require.NoError(t, err)
		// Do not resolve the parent's config here: that would prime BuildKit's
		// content metadata and hide the cold unnamed-child lookup regression.
		require.NoError(t, Patch(ctx, &types.Options{
			Image: input, Report: originTestReport(t, originAMD64), Scanner: "trivy", PatchedTag: output,
			BkAddr: "docker://", PkgTypes: "os", Progress: "quiet", Timeout: 2 * time.Minute,
		}))
		archive := filepath.Join(t.TempDir(), "patched.tar")
		//nolint:gosec // Save only the generated output tag into the fixture directory.
		out, err = exec.CommandContext(ctx, "docker", "image", "save", "--output", archive, output).CombinedOutput()
		require.NoError(t, err, string(out))
		patched, err := tarball.ImageFromPath(archive, nil)
		require.NoError(t, err)
		config, err := patched.ConfigFile()
		require.NoError(t, err)
		require.Equal(t, child.Digest.String(), config.Config.Labels[types.AnnotationPatchOriginDigest])
		require.Equal(t, input, config.Config.Labels["com.example.built-source"])
		for key, value := range application {
			require.Equal(t, value, config.Config.Labels[key])
		}
		// Docker save reconstructs manifest bytes, so verify the loaded config
		// and uncompressed layer content against its RootFS identities instead.
		rawConfig, err := patched.RawConfigFile()
		require.NoError(t, err)
		configDigest, err := patched.ConfigName()
		require.NoError(t, err)
		require.Equal(t, configDigest.String(), digest.FromBytes(rawConfig).String())
		layers, err := patched.Layers()
		require.NoError(t, err)
		require.Len(t, layers, len(config.RootFS.DiffIDs))
		for i, layer := range layers {
			reader, err := layer.Uncompressed()
			require.NoError(t, err)
			digester := digest.SHA256.Digester()
			_, err = io.Copy(digester.Hash(), reader)
			require.NoError(t, err)
			require.NoError(t, reader.Close())
			require.Equal(t, config.RootFS.DiffIDs[i].String(), digester.Digest().String())
		}
	})
}
