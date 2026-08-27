package patch

import (
	"testing"
	"time"

	"github.com/distribution/reference"
	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMultiPlatformIndexAnnotationsLineagePrecedence(t *testing.T) {
	imageName, err := reference.ParseNormalizedNamed("registry.example.com/team/app:1.0-patched")
	require.NoError(t, err)
	tagged, ok := imageName.(reference.NamedTagged)
	require.True(t, ok)

	original := map[string]string{
		ispec.AnnotationVersion:         "1.0",
		ispec.AnnotationBaseImageName:   "registry.example.com/stale:latest",
		ispec.AnnotationBaseImageDigest: digest.FromString("stale").String(),
		"com.example.preserved":         "value",
	}
	lineage := &types.SourceLineage{
		Name:   "registry.example.com/team/app:1.0",
		Digest: digest.FromString("source-index"),
	}
	created := time.Date(2026, time.August, 26, 8, 30, 0, 0, time.UTC)

	annotations := multiPlatformIndexAnnotations(tagged, original, lineage, created)

	assert.Equal(t, lineage.Name, annotations[ispec.AnnotationBaseImageName])
	assert.Equal(t, lineage.Digest.String(), annotations[ispec.AnnotationBaseImageDigest])
	assert.Equal(t, created.Format(time.RFC3339), annotations[ispec.AnnotationCreated])
	assert.Equal(t, created.Format(time.RFC3339), annotations[copaAnnotationKeyPrefix+".patched"])
	assert.Equal(t, "1.0-patched", annotations[ispec.AnnotationVersion])
	assert.Equal(t, "value", annotations["com.example.preserved"])
	assert.Equal(t, "registry.example.com/stale:latest", original[ispec.AnnotationBaseImageName], "source annotations must not be mutated")
}

func TestMultiPlatformIndexAnnotationsOmitUnknownLineage(t *testing.T) {
	imageName, err := reference.ParseNormalizedNamed("registry.example.com/team/app:patched")
	require.NoError(t, err)
	tagged, ok := imageName.(reference.NamedTagged)
	require.True(t, ok)

	annotations := multiPlatformIndexAnnotations(tagged, map[string]string{
		ispec.AnnotationBaseImageName:   "registry.example.com/stale:latest",
		ispec.AnnotationBaseImageDigest: digest.FromString("stale").String(),
	}, nil, time.Unix(0, 0))

	assert.NotContains(t, annotations, ispec.AnnotationBaseImageName)
	assert.NotContains(t, annotations, ispec.AnnotationBaseImageDigest)
}
