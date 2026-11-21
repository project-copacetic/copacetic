package patch

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/moby/buildkit/client"
	"github.com/opencontainers/go-digest"
	"github.com/project-copacetic/copacetic/pkg/ocilayout"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A named multi-platform --oci-dir export is published atomically only to a
// new directory. An existing directory, empty or not, is written in place,
// and layout input keeps its own atomic export.
func TestCheckOCIDir(t *testing.T) {
	if runtime.GOOS != LINUX && runtime.GOOS != "darwin" {
		t.Skip("no-replace rename is supported only on Linux and macOS")
	}
	root := t.TempDir()
	empty := filepath.Join(root, "empty")
	require.NoError(t, os.Mkdir(empty, 0o755))
	nonEmpty := filepath.Join(root, "non-empty")
	require.NoError(t, os.Mkdir(nonEmpty, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(nonEmpty, "index.json"), nil, 0o600))
	output := filepath.Join(root, "output")

	for _, tc := range []struct {
		name string
		opts types.Options
		want bool
	}{
		{name: "new directory", opts: types.Options{Image: "app:1.0", OCIDir: output}, want: true},
		{name: "existing empty directory", opts: types.Options{Image: "app:1.0", OCIDir: empty}},
		{name: "existing non-empty directory", opts: types.Options{Image: "app:1.0", OCIDir: nonEmpty}},
		{name: "no --oci-dir", opts: types.Options{Image: "app:1.0"}},
		{name: "pushing", opts: types.Options{Image: "app:1.0", OCIDir: output, Push: true}},
		{name: "layout input", opts: types.Options{OCISource: &ocilayout.Source{}, OCIDir: output}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := checkOCIDir(&tc.opts)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
			assert.NoDirExists(t, output, "the check must not create --oci-dir")
			entries, err := os.ReadDir(root)
			require.NoError(t, err)
			assert.Len(t, entries, 2, "the check must remove its probe")
		})
	}
}

// An --oci-dir that is not a directory of its own, such as the current
// directory or one of its parents, is rejected before any platform is
// patched, since the export writes its layout files there.
func TestMultiPlatformPatchRejectsInvalidOCIDirBeforePatching(t *testing.T) {
	originalPatchPlatformImage := patchPlatformImage
	t.Cleanup(func() { patchPlatformImage = originalPatchPlatformImage })
	patchPlatformImage = func(
		context.Context, *types.Options, types.PatchPlatform, bool, chan<- *client.SolveStatus,
		*unversioned.UpdateManifest, string, string, map[string]string, digest.Digest,
	) (*types.PatchResult, error) {
		t.Error("no platform may be patched with an invalid --oci-dir")
		return nil, nil
	}

	cwd, err := os.Getwd()
	require.NoError(t, err)
	link := filepath.Join(t.TempDir(), "link")
	require.NoError(t, os.Symlink(cwd, link))
	for name, path := range map[string]string{
		"current directory":               ".",
		"current directory with slash":    "./",
		"parent directory":                "..",
		"name then parent":                "x/..",
		"absolute current directory":      cwd,
		"absolute parent directory":       filepath.Dir(cwd),
		"current directory through ..":    filepath.Join("..", filepath.Base(cwd)),
		"grandparent directory":           "../..",
		"link to the current directory":   link,
		"filesystem root":                 string(filepath.Separator),
		"parent of a directory with dots": "./x/../..",
	} {
		t.Run(name, func(t *testing.T) {
			err := patchPreparedMultiPlatformImage(t.Context(), &types.Options{Image: "example.com/acme/app:1.0", OCIDir: path},
				[]types.PatchPlatform{
					{Platform: platformSpec("linux", "amd64", "")},
					{Platform: platformSpec("linux", "arm64", "")},
				})
			require.ErrorContains(t, err, "invalid OCI layout output directory")
		})
	}
	assert.NoDirExists(t, filepath.Join(cwd, "x"))
}

// The layout-input export options are unchanged: always atomic.
func TestOCIExportOptionsAtomicOnlyForLayoutInput(t *testing.T) {
	t.Setenv("EXPERIMENTAL_BUILDKIT_SOURCE_POLICY", "")
	named, err := ociExportOptions(t.Context(), &types.Options{Image: "example.com/acme/app:1.0"}, "example.com/acme/app:1.0-patched")
	require.NoError(t, err)
	assert.False(t, named.Atomic, "the named export decides atomic publication from the --oci-dir check")
	layout, err := ociExportOptions(t.Context(), &types.Options{OCISource: &ocilayout.Source{}}, "example.com/acme/app:1.0-patched")
	require.NoError(t, err)
	assert.True(t, layout.Atomic)
}
