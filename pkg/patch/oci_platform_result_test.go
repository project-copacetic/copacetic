package patch

import (
	"encoding/json"
	"testing"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/project-copacetic/copacetic/pkg/ocilayout"
	"github.com/project-copacetic/copacetic/pkg/types"
)

func TestOCIResultRecordsInferredPlatformWithoutChangingSource(t *testing.T) {
	source := openSolveTestSource(t)
	indexData, err := json.Marshal(map[string]any{
		"schemaVersion": 2,
		"mediaType":     ispec.MediaTypeImageIndex,
		"manifests":     []ispec.Descriptor{source.Descriptor},
	})
	require.NoError(t, err)
	index := writeSolveTestBlob(t, source.Path, ispec.MediaTypeImageIndex, indexData)
	writeRepatchLayout(t, source.Path, &index)
	source, err = ocilayout.Open(t.Context(), source.Path, "", "")
	require.NoError(t, err)
	target := types.PatchPlatform{Platform: ispec.Platform{OS: "linux", Architecture: "amd64"}}
	desc, err := source.PlatformDescriptor(t.Context(), &target.Platform)
	require.NoError(t, err)
	require.Nil(t, desc.Platform)

	result, err := createPatchResultWithStates(t.Context(), nil, "example.com/acme/app:patched", &target, nil, "", &Result{}, source)
	require.NoError(t, err)
	require.NotNil(t, result.PatchedDesc.Platform)
	assert.Equal(t, target.Platform, *result.PatchedDesc.Platform)
	assert.Empty(t, result.PatchedDesc.Digest)
	desc, err = source.PlatformDescriptor(t.Context(), &target.Platform)
	require.NoError(t, err)
	assert.Nil(t, desc.Platform, "only the patched result gains inferred metadata")
}
