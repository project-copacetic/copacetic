package patch

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/project-copacetic/copacetic/pkg/ocilayout"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A named multi-platform --oci-dir export is published atomically only to a
// new directory. An existing directory, empty or not, is written in place as
// before, and layout input keeps its own atomic export.
func TestCanPublishOCIDirAtomically(t *testing.T) {
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
		{name: "current directory", opts: types.Options{Image: "app:1.0", OCIDir: "."}},
		{name: "no --oci-dir", opts: types.Options{Image: "app:1.0"}},
		{name: "pushing", opts: types.Options{Image: "app:1.0", OCIDir: output, Push: true}},
		{name: "layout input", opts: types.Options{OCISource: &ocilayout.Source{}, OCIDir: output}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, canPublishOCIDirAtomically(&tc.opts))
			assert.NoDirExists(t, output, "the check must not create --oci-dir")
			entries, err := os.ReadDir(root)
			require.NoError(t, err)
			assert.Len(t, entries, 2, "the check must remove its probe")
		})
	}
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
