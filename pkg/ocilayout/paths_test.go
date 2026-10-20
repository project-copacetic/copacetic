package ocilayout

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// linkParentFixture makes base/work/link point to base/images/child, so that
// base/work/link/../X names base/images/X while lexical cleaning would give
// base/work/X. Paths with link/.. are built by concatenation because
// filepath.Join cleans them.
func linkParentFixture(t *testing.T) string {
	t.Helper()
	base := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(base, "images", "child"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(base, "work"), 0o755))
	require.NoError(t, os.Symlink(filepath.Join(base, "images", "child"), filepath.Join(base, "work", "link")))
	return base
}

func TestOpenResolvesLinksBeforeParentDirectory(t *testing.T) {
	base := linkParentFixture(t)
	selected := newSingleLayout(t, map[string]string{"example.layout": "selected"})
	decoy := newSingleLayout(t, map[string]string{"example.layout": "decoy"})
	require.NoError(t, os.Rename(selected.path, filepath.Join(base, "images", "layout")))
	require.NoError(t, os.Rename(decoy.path, filepath.Join(base, "work", "layout")))

	source, err := Open(t.Context(), base+"/work/link/../layout", "", "")
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(base, "images", "layout"), source.Path)
	assert.Equal(t, "selected", source.Descriptor.Annotations["example.layout"], "link/.. names the link target's parent")

	_, err = Open(t.Context(), filepath.Join(base, "work", "missing"), "", "")
	require.ErrorContains(t, err, "invalid OCI layout input")
}

func TestCanonicalNewPath(t *testing.T) {
	base := linkParentFixture(t)
	require.NoError(t, os.Symlink(filepath.Join(base, "elsewhere"), filepath.Join(base, "images", "existing-link")))
	for _, test := range []struct {
		name      string
		path      string
		want      string
		wantError string
	}{
		{name: "link parent", path: base + "/work/link/../output", want: filepath.Join(base, "images", "output")},
		{name: "trailing separator", path: base + "/work/link/../output/", want: filepath.Join(base, "images", "output")},
		{name: "missing parents", path: base + "/work/link/../new/deeper/output", want: filepath.Join(base, "images", "new", "deeper", "output")},
		{name: "final link is kept", path: base + "/work/link/../existing-link", want: filepath.Join(base, "images", "existing-link")},
		{name: "dot", path: base + "/work/.", wantError: "must name a new file or directory"},
		{name: "dot dot", path: base + "/work/link/..", wantError: "must name a new file or directory"},
		{name: "empty", path: "", wantError: "must name a new file or directory"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := CanonicalNewPath(test.path)
			if test.wantError != "" {
				require.ErrorContains(t, err, test.wantError)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.want, got)
		})
	}

	t.Chdir(filepath.Join(base, "work"))
	got, err := CanonicalNewPath("link/../relative")
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(base, "images", "relative"), got)
}
