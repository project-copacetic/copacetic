package ocilayout_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/moby/buildkit/util/progress/progressui"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/project-copacetic/copacetic/pkg/patch"
	"github.com/project-copacetic/copacetic/pkg/types"
)

// TestOCILayoutRejectsHardLinkedVEXOutput uses VEX destinations outside the
// input that are hard links to input files. Writing them would truncate the
// shared inode. The unreachable BuildKit address shows that rejection happens
// before any solve.
func TestOCILayoutRejectsHardLinkedVEXOutput(t *testing.T) {
	input := writeLayout(t, map[string]v1.Image{amd64Arch: markedTestImage(t, amd64Arch, nil)}, false, false)
	external := t.TempDir()
	indexLink := filepath.Join(external, "index-link.json")
	require.NoError(t, os.Link(filepath.Join(input, "index.json"), indexLink))
	symlinkToLink := filepath.Join(external, "vex-link.json")
	require.NoError(t, os.Symlink(indexLink, symlinkToLink))
	before := snapshot(t, input)
	for _, vexPath := range []string{indexLink, symlinkToLink} {
		output := filepath.Join(t.TempDir(), "output")
		err := patch.Patch(t.Context(), &types.Options{
			InputOCILayout: input, OCIDir: output, PatchedTag: outputName, Output: vexPath,
			Report: writeReport(t, amd64Arch), Scanner: "trivy", Format: "openvex",
			BkAddr: "tcp://127.0.0.1:1", Timeout: 2 * time.Second, Progress: progressui.QuietMode,
			PkgTypes: "os", LibraryPatchLevel: "patch",
		})
		require.ErrorContains(t, err, "is the same file as OCI layout input file", vexPath)
		_, statErr := os.Stat(output)
		assert.True(t, os.IsNotExist(statErr))
	}
	assert.Equal(t, before, snapshot(t, input))
}
