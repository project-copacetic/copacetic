package utils

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetSinglePlatformManifestAnnotations(t *testing.T) {
	// This test can't actually run without a registry, but we can test the function exists
	// and handles bad input gracefully

	ctx := context.Background()

	// Test with truly invalid image reference (malformed)
	_, err := GetSinglePlatformManifestAnnotations(ctx, ":::invalid:::")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse image reference")

	// Test with empty reference
	_, err = GetSinglePlatformManifestAnnotations(ctx, "")
	assert.Error(t, err)
}
