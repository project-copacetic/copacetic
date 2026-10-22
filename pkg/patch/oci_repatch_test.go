package patch

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/project-copacetic/copacetic/pkg/ocilayout"
	"github.com/project-copacetic/copacetic/pkg/types"
)

type repatchChild struct {
	arch                  string
	manifestAnnotations   map[string]string
	descriptorAnnotations map[string]string
}

func writeRepatchManifest(t *testing.T, root string, child repatchChild, labels map[string]string) ispec.Descriptor {
	t.Helper()
	configData, err := json.Marshal(map[string]any{
		"architecture": child.arch,
		"os":           "linux",
		"config":       map[string]any{"Labels": labels},
		"rootfs":       map[string]any{"type": "layers", "diff_ids": []string{}},
	})
	require.NoError(t, err)
	config := writeSolveTestBlob(t, root, ispec.MediaTypeImageConfig, configData)
	manifestData, err := json.Marshal(map[string]any{
		"schemaVersion": 2,
		"mediaType":     ispec.MediaTypeImageManifest,
		"config":        config,
		"layers":        []ispec.Descriptor{},
		"annotations":   child.manifestAnnotations,
	})
	require.NoError(t, err)
	desc := writeSolveTestBlob(t, root, ispec.MediaTypeImageManifest, manifestData)
	desc.Platform = &ispec.Platform{OS: "linux", Architecture: child.arch}
	desc.Annotations = child.descriptorAnnotations
	return desc
}

func writeRepatchLayout(t *testing.T, root string, top *ispec.Descriptor) {
	t.Helper()
	indexData, err := json.Marshal(map[string]any{
		"schemaVersion": 2,
		"mediaType":     ispec.MediaTypeImageIndex,
		"manifests":     []ispec.Descriptor{*top},
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(root, ispec.ImageLayoutFile), []byte(`{"imageLayoutVersion":"1.0.0"}`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, ispec.ImageIndexFile), indexData, 0o600))
}

// openRepatchIndex writes an image index with the given children. The index
// body and its descriptor both carry Copa's index-level markers.
func openRepatchIndex(t *testing.T, children []repatchChild, labels map[string]string) *ocilayout.Source {
	t.Helper()
	root := t.TempDir()
	var manifests []ispec.Descriptor
	for _, child := range children {
		manifests = append(manifests, writeRepatchManifest(t, root, child, labels))
	}
	indexData, err := json.Marshal(map[string]any{
		"schemaVersion": 2,
		"mediaType":     ispec.MediaTypeImageIndex,
		"manifests":     manifests,
		"annotations":   map[string]string{"sh.copa.patched": "2026-10-19T00:00:00Z"},
	})
	require.NoError(t, err)
	top := writeSolveTestBlob(t, root, ispec.MediaTypeImageIndex, indexData)
	top.Annotations = map[string]string{copaPatchedAnnotation: "2026-10-19T00:00:00Z"}
	writeRepatchLayout(t, root, &top)
	source, err := ocilayout.Open(t.Context(), root, "", "")
	require.NoError(t, err)
	return source
}

func openRepatchManifest(t *testing.T, child repatchChild, labels map[string]string) *ocilayout.Source {
	t.Helper()
	root := t.TempDir()
	desc := writeRepatchManifest(t, root, child, labels)
	writeRepatchLayout(t, root, &desc)
	source, err := ocilayout.Open(t.Context(), root, "", "")
	require.NoError(t, err)
	return source
}

func TestRejectPatchedOCITargets(t *testing.T) {
	marker := map[string]string{copaPatchedAnnotation: "2026-10-19T00:00:00Z"}
	amd64 := types.PatchPlatform{Platform: ispec.Platform{OS: "linux", Architecture: "amd64"}}
	preserved386 := types.PatchPlatform{Platform: ispec.Platform{OS: "linux", Architecture: "386"}, ShouldPreserve: true}
	// Labels a derived application inherits from a patched base image.
	inherited := map[string]string{
		"BaseImage":                  "example.com/acme/base:1.0",
		"sh.copa.patch.origin.kind":  "image-ref",
		"sh.copa.patch.origin.name":  "example.com/acme/base:1.0",
		"sh.copa.image.patched":      "2026-10-19T00:00:00Z",
		"org.opencontainers.example": "kept",
	}

	for _, test := range []struct {
		name      string
		source    func(*testing.T) *ocilayout.Source
		platforms []types.PatchPlatform
		wantError string
	}{
		{
			name: "single manifest body marker",
			source: func(t *testing.T) *ocilayout.Source {
				return openRepatchManifest(t, repatchChild{arch: "amd64", manifestAnnotations: marker}, nil)
			},
			platforms: []types.PatchPlatform{amd64},
			wantError: "manifest annotation sh.copa.image.patched",
		},
		{
			name: "single manifest descriptor marker",
			source: func(t *testing.T) *ocilayout.Source {
				return openRepatchManifest(t, repatchChild{arch: "amd64", descriptorAnnotations: marker}, nil)
			},
			platforms: []types.PatchPlatform{amd64},
			wantError: "descriptor annotation sh.copa.image.patched",
		},
		{
			name: "targeted index child body marker",
			source: func(t *testing.T) *ocilayout.Source {
				return openRepatchIndex(t, []repatchChild{{arch: "amd64", manifestAnnotations: marker}, {arch: "386"}}, nil)
			},
			platforms: []types.PatchPlatform{amd64, preserved386},
			wantError: "manifest annotation sh.copa.image.patched",
		},
		{
			name: "targeted index child descriptor marker",
			source: func(t *testing.T) *ocilayout.Source {
				return openRepatchIndex(t, []repatchChild{{arch: "amd64", descriptorAnnotations: marker}, {arch: "386"}}, nil)
			},
			platforms: []types.PatchPlatform{amd64, preserved386},
			wantError: "descriptor annotation sh.copa.image.patched",
		},
		{
			name: "preserved sibling marker and index-level markers",
			source: func(t *testing.T) *ocilayout.Source {
				return openRepatchIndex(t, []repatchChild{{arch: "amd64"}, {arch: "386", manifestAnnotations: marker, descriptorAnnotations: marker}}, nil)
			},
			platforms: []types.PatchPlatform{amd64, preserved386},
		},
		{
			name: "inherited config labels only",
			source: func(t *testing.T) *ocilayout.Source {
				return openRepatchManifest(t, repatchChild{arch: "amd64"}, inherited)
			},
			platforms: []types.PatchPlatform{amd64},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := rejectPatchedOCITargets(t.Context(), test.source(t), test.platforms)
			if test.wantError == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, test.wantError)
			assert.ErrorContains(t, err, "linux/amd64")
			assert.ErrorContains(t, err, "Patch the original, unpatched layout")
			assert.ErrorContains(t, err, "rescan that original image rather than reusing a report scanned from the patched image")
		})
	}

	require.NoError(t, rejectPatchedOCITargets(t.Context(), nil, []types.PatchPlatform{amd64}), "named images are not checked")
}
