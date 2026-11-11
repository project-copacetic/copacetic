package ocilayout

import (
	"os"
	"path/filepath"
	"testing"
	"unicode"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// linkParentFixture makes base/work/link point to base/images/child, so that
// base/work/link/../X names base/images/X while lexical cleaning would give
// base/work/X. Paths with link/.. are built by concatenation because
// filepath.Join cleans them.
func linkParentFixture(t *testing.T) string {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
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

// TestPathWithinComparesIdentity covers aliases that a lexical comparison
// misses. Callers pass canonical paths, so this calls pathWithin directly
// with a symlink alias that canonicalization would otherwise resolve; on
// Linux it stands in for case variants and bind mounts.
func TestPathWithinComparesIdentity(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	root := filepath.Join(base, "layout")
	require.NoError(t, os.MkdirAll(filepath.Join(root, "blobs"), 0o755))
	alias := filepath.Join(base, "alias")
	require.NoError(t, os.Symlink(root, alias))
	require.NoError(t, os.MkdirAll(filepath.Join(base, "sibling"), 0o755))

	for _, test := range []struct {
		name   string
		root   string
		target string
		want   bool
	}{
		{name: "same path", root: root, target: root, want: true},
		{name: "lexical child", root: root, target: filepath.Join(root, "new"), want: true},
		{name: "alias of root", root: root, target: alias, want: true},
		{name: "existing child via alias", root: root, target: filepath.Join(alias, "blobs"), want: true},
		{name: "missing child via alias", root: root, target: filepath.Join(alias, "new", "deeper"), want: true},
		{name: "sibling", root: root, target: filepath.Join(base, "sibling", "out"), want: false},
		{name: "parent", root: root, target: base, want: false},
		{name: "missing root", root: filepath.Join(base, "missing"), target: filepath.Join(alias, "out"), want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, pathWithin(test.root, test.target))
		})
	}
}

// TestCaseVariantPathsOverlapInput runs only on case-insensitive filesystems,
// such as the default macOS APFS volume, where a case variant of the input
// path names the input itself.
func TestCaseVariantPathsOverlapInput(t *testing.T) {
	fixture := newSingleLayout(t, nil)
	base, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	input := filepath.Join(base, "Layout")
	require.NoError(t, os.Rename(fixture.path, input))
	fixture.path = input
	variant := filepath.Join(base, swapCase("Layout"))
	if !sameExistingFile(fixture.path, variant) {
		t.Skip("temporary directory is on a case-sensitive filesystem")
	}

	_, err = Open(t.Context(), fixture.path, filepath.Join(variant, "out"), "")
	require.ErrorContains(t, err, "must be distinct, non-overlapping directories")
	_, err = Open(t.Context(), variant, filepath.Join(fixture.path, "out"), "")
	require.ErrorContains(t, err, "must be distinct, non-overlapping directories")

	source, err := Open(t.Context(), fixture.path, "", "")
	require.NoError(t, err)
	require.ErrorContains(t, source.ValidateWritePath(filepath.Join(variant, "vex.json")), "must not overlap OCI layout input")
	require.ErrorContains(t, source.ValidateTempDir(filepath.Join(variant, "blobs")), "must not be inside OCI layout input")
	require.ErrorContains(t, ValidateOutputWritePath(variant, filepath.Join(fixture.path, "vex.json")), "must not be inside OCI layout output")
}

func swapCase(s string) string {
	out := []rune(s)
	for i, r := range out {
		switch {
		case unicode.IsLower(r):
			out[i] = unicode.ToUpper(r)
		case unicode.IsUpper(r):
			out[i] = unicode.ToLower(r)
		}
	}
	return string(out)
}

func sameExistingFile(left, right string) bool {
	leftInfo, err := os.Stat(left)
	if err != nil {
		return false
	}
	rightInfo, err := os.Stat(right)
	return err == nil && os.SameFile(leftInfo, rightInfo)
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
