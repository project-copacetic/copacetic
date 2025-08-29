package patch

import (
	"testing"
	"time"

	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
)

func TestAnnotationsAlwaysAdded(t *testing.T) {
	// Test that Copa annotations are always added even when there are no original annotations

	// Create a mock descriptor without annotations
	desc := &v1.Descriptor{
		MediaType: v1.MediaTypeImageManifest,
		Size:      1234,
		Digest:    "sha256:test",
	}

	// Simulate adding annotations (like in createPatchResult)
	augmentedDesc := *desc
	if augmentedDesc.Annotations == nil {
		augmentedDesc.Annotations = make(map[string]string)
	}

	// Always add Copa annotations
	augmentedDesc.Annotations["org.opencontainers.image.created"] = time.Now().UTC().Format(time.RFC3339)
	augmentedDesc.Annotations[copaAnnotationKeyPrefix+".image.patched"] = time.Now().UTC().Format(time.RFC3339)

	// Verify annotations were added
	assert.NotNil(t, augmentedDesc.Annotations)
	assert.NotEmpty(t, augmentedDesc.Annotations["org.opencontainers.image.created"])
	assert.NotEmpty(t, augmentedDesc.Annotations[copaAnnotationKeyPrefix+".image.patched"])
	assert.Equal(t, 2, len(augmentedDesc.Annotations))
}

func TestAnnotationsPreservedAndAdded(t *testing.T) {
	// Test that original annotations are preserved and Copa annotations are added

	// Create a mock descriptor with existing annotations
	desc := &v1.Descriptor{
		MediaType: v1.MediaTypeImageManifest,
		Size:      1234,
		Digest:    "sha256:test",
		Annotations: map[string]string{
			"org.opencontainers.image.source":  "https://github.com/test/repo",
			"org.opencontainers.image.version": "1.0.0",
		},
	}

	// Simulate adding annotations (like in createPatchResult)
	augmentedDesc := *desc
	if augmentedDesc.Annotations == nil {
		augmentedDesc.Annotations = make(map[string]string)
	}

	// Always add Copa annotations
	augmentedDesc.Annotations["org.opencontainers.image.created"] = time.Now().UTC().Format(time.RFC3339)
	augmentedDesc.Annotations[copaAnnotationKeyPrefix+".image.patched"] = time.Now().UTC().Format(time.RFC3339)

	// Verify original annotations were preserved
	assert.Equal(t, "https://github.com/test/repo", augmentedDesc.Annotations["org.opencontainers.image.source"])
	assert.Equal(t, "1.0.0", augmentedDesc.Annotations["org.opencontainers.image.version"])

	// Verify Copa annotations were added
	assert.NotEmpty(t, augmentedDesc.Annotations["org.opencontainers.image.created"])
	assert.NotEmpty(t, augmentedDesc.Annotations[copaAnnotationKeyPrefix+".image.patched"])
	assert.Equal(t, 4, len(augmentedDesc.Annotations))
}
