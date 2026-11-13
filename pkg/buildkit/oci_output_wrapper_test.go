package buildkit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWrapOCIOutputIndexDropsSourcePatchOrigin(t *testing.T) {
	dir := t.TempDir()
	index := specs.Index{MediaType: specs.MediaTypeImageIndex}
	index.SchemaVersion = 2
	data, err := json.Marshal(index)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, specs.ImageIndexFile), data, 0o600))

	source := map[string]string{
		types.AnnotationPatchOriginKind:   types.PatchOriginImage,
		types.AnnotationPatchOriginName:   "registry.example.com/team/app:1.0",
		types.AnnotationPatchOriginDigest: digest.FromString("original").String(),
		specs.AnnotationRefName:           "1.0",
		"org.example.kept":                "value",
	}
	require.NoError(t, wrapOCIOutputIndex(dir, "registry.example.com/team/app:1.0-patched", source))

	rootData, err := os.ReadFile(filepath.Join(dir, specs.ImageIndexFile))
	require.NoError(t, err)
	var root specs.Index
	require.NoError(t, json.Unmarshal(rootData, &root))
	require.Len(t, root.Manifests, 1)
	got := root.Manifests[0].Annotations
	assert.NotContains(t, got, types.AnnotationPatchOriginKind)
	assert.NotContains(t, got, types.AnnotationPatchOriginName)
	assert.NotContains(t, got, types.AnnotationPatchOriginDigest)
	assert.Equal(t, "value", got["org.example.kept"])
	assert.Equal(t, "1.0-patched", got[specs.AnnotationRefName])
	assert.Contains(t, source, types.AnnotationPatchOriginKind, "source annotations must not be mutated")
}
