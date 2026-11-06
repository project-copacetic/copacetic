package ocilayout_test

import (
	"archive/tar"
	"bytes"
	"maps"
	"os"
	"path/filepath"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/static"
	v1types "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/moby/buildkit/util/progress/progressui"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/project-copacetic/copacetic/pkg/patch"
	"github.com/project-copacetic/copacetic/pkg/types"
)

const copaPatchedAnnotation = "sh.copa.image.patched"

// inheritedLabels are config labels an application inherits FROM a patched
// base. The base names cannot be resolved, so following them would fail.
var inheritedLabels = map[string]string{
	"BaseImage":                 "registry.invalid/copa-1677/unreachable-base:1.0",
	"sh.copa.patch.origin.kind": "image-ref",
	"sh.copa.patch.origin.name": "registry.invalid/copa-1677/unreachable-base:1.0",
}

// derivedApplication builds an image FROM the amd64 image in a patched layout
// the way an image build does: the layers and config are reused, one
// application layer is added, and the new manifest has no annotations.
func derivedApplication(t *testing.T, patchedLayout string) v1.Image {
	t.Helper()
	base := exportedImage(t, patchedLayout)
	layers, err := base.Layers()
	require.NoError(t, err)
	baseConfig, err := base.ConfigFile()
	require.NoError(t, err)
	config := baseConfig.DeepCopy()
	config.RootFS.DiffIDs = nil
	config.History = nil
	if config.Config.Labels == nil {
		config.Config.Labels = make(map[string]string)
	}
	maps.Copy(config.Config.Labels, inheritedLabels)
	image, err := mutate.ConfigFile(mutate.MediaType(empty.Image, v1types.OCIManifestSchema1), config)
	require.NoError(t, err)
	image = mutate.ConfigMediaType(image, v1types.OCIConfigJSON)

	var buf bytes.Buffer
	archive := tar.NewWriter(&buf)
	content := []byte("derived application\n")
	require.NoError(t, archive.WriteHeader(&tar.Header{Name: "app/", Typeflag: tar.TypeDir, Mode: 0o755}))
	require.NoError(t, archive.WriteHeader(&tar.Header{Name: "app/derived.txt", Mode: 0o644, Size: int64(len(content))}))
	_, err = archive.Write(content)
	require.NoError(t, err)
	require.NoError(t, archive.Close())
	image, err = mutate.AppendLayers(image, append(layers, static.NewLayer(buf.Bytes(), v1types.OCIUncompressedLayer))...)
	require.NoError(t, err)
	manifest, err := image.Manifest()
	require.NoError(t, err)
	require.Empty(t, manifest.Annotations, "a derived image does not inherit manifest annotations")
	return image
}

func markedTestImage(t *testing.T, arch string, annotations map[string]string) v1.Image {
	t.Helper()
	config, err := empty.Image.ConfigFile()
	require.NoError(t, err)
	config.OS, config.Architecture = linuxOS, arch
	image, err := mutate.ConfigFile(mutate.MediaType(empty.Image, v1types.OCIManifestSchema1), config)
	require.NoError(t, err)
	image = mutate.ConfigMediaType(image, v1types.OCIConfigJSON)
	if annotations != nil {
		var ok bool
		image, ok = mutate.Annotations(image, annotations).(v1.Image)
		require.True(t, ok)
	}
	return image
}

// TestOCILayoutRejectsPatchedInput covers each public dispatch path. The
// unreachable BuildKit address shows that rejection happens before any solve.
func TestOCILayoutRejectsPatchedInput(t *testing.T) {
	marker := map[string]string{copaPatchedAnnotation: "2026-10-19T00:00:00Z"}
	images := map[string]v1.Image{amd64Arch: markedTestImage(t, amd64Arch, marker), "386": markedTestImage(t, "386", nil)}
	for _, test := range []struct {
		name      string
		multi     bool
		report    func(t *testing.T) string
		platforms []string
		rejected  bool
	}{
		{name: "single manifest without report", rejected: true},
		{name: "single manifest with report", report: func(t *testing.T) string { return writeReport(t, amd64Arch) }, rejected: true},
		{name: "index patching all platforms", multi: true, rejected: true},
		{name: "index with single report", multi: true, report: func(t *testing.T) string { return writeReport(t, amd64Arch) }, rejected: true},
		{name: "index with report directory", multi: true, report: func(t *testing.T) string { return filepath.Dir(writeReport(t, amd64Arch)) }, rejected: true},
		{name: "index targeting only the unpatched sibling", multi: true, platforms: []string{"linux/386"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := writeLayout(t, images, test.multi, false)
			before := snapshot(t, input)
			output := filepath.Join(t.TempDir(), "output")
			opts := &types.Options{
				InputOCILayout: input, OCIDir: output, PatchedTag: outputName, Platforms: test.platforms,
				BkAddr: "tcp://127.0.0.1:1", Timeout: 2 * time.Second, Progress: progressui.QuietMode,
				PkgTypes: "os", LibraryPatchLevel: "patch", Scanner: "trivy",
			}
			if test.report != nil {
				opts.Report = test.report(t)
			}
			err := patch.Patch(t.Context(), opts)
			require.Error(t, err, "the unreachable BuildKit address must fail any patch attempt")
			if test.rejected {
				assert.ErrorContains(t, err, "already patched by Copa (manifest annotation "+copaPatchedAnnotation+")")
				assert.ErrorContains(t, err, "Patch the original, unpatched layout instead")
				assert.ErrorContains(t, err, "rather than reusing a report scanned from the patched image")
			} else {
				assert.NotContains(t, err.Error(), "already patched by Copa", "a patched preserved sibling must not block patching another platform")
			}
			assert.Equal(t, before, snapshot(t, input))
			_, statErr := os.Stat(output)
			assert.True(t, os.IsNotExist(statErr))
		})
	}
}
