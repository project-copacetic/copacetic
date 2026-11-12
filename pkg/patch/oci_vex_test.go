package patch

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/distribution/reference"
	"github.com/moby/buildkit/client"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/project-copacetic/copacetic/pkg/ocilayout"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
)

// writeTwoPlatformLayout writes an index with linux/amd64 and linux/arm64
// manifests and returns the layout root and both manifest descriptors.
func writeTwoPlatformLayout(t *testing.T) (root string, amd64, arm64 ispec.Descriptor) {
	t.Helper()
	root = t.TempDir()
	amd64 = writeRepatchManifest(t, root, repatchChild{arch: "amd64"}, nil)
	arm64 = writeRepatchManifest(t, root, repatchChild{arch: "arm64"}, nil)
	indexData, err := json.Marshal(map[string]any{
		"schemaVersion": 2,
		"mediaType":     ispec.MediaTypeImageIndex,
		"manifests":     []ispec.Descriptor{amd64, arm64},
	})
	require.NoError(t, err)
	top := writeSolveTestBlob(t, root, ispec.MediaTypeImageIndex, indexData)
	writeRepatchLayout(t, root, &top)
	return root, amd64, arm64
}

// ociVEXResult is a patched OCI-source result for one platform. Its VEX has
// no product name because the final export has not assigned a digest yet.
func ociVEXResult(t *testing.T, arch string) types.PatchResult {
	t.Helper()
	vexData := platformVEX(t, "", arch)
	return types.PatchResult{
		PatchedDesc: &ispec.Descriptor{Platform: &ispec.Platform{OS: "linux", Architecture: arch}},
		VEX:         vexData,
	}
}

type vexProducts struct {
	Statements []struct {
		Products []struct {
			ID string `json:"@id"`
		} `json:"products"`
	} `json:"statements"`
}

// Each OCI-source product is named from the manifest in the final layout, and
// a CVE fixed on both platforms is one statement listing both products.
func TestWriteOCIVEXNamesProductsFromFinalOutput(t *testing.T) {
	root, amd64, arm64 := writeTwoPlatformLayout(t)
	vexPath := filepath.Join(t.TempDir(), "vex.json")
	opts := &types.Options{OCISource: &ocilayout.Source{}, OCIDir: root, Output: vexPath, Format: "openvex"}
	results := []types.PatchResult{ociVEXResult(t, "amd64"), ociVEXResult(t, "arm64")}

	require.NoError(t, writeOCIVEX(t.Context(), opts, results, "registry.invalid/acme/output:patched"))

	body, err := os.ReadFile(vexPath)
	require.NoError(t, err)
	var doc vexProducts
	require.NoError(t, json.Unmarshal(body, &doc))
	require.Len(t, doc.Statements, 1)
	require.Len(t, doc.Statements[0].Products, 2)
	assert.Equal(t, "pkg:oci/output@"+amd64.Digest.String(), doc.Statements[0].Products[0].ID)
	assert.Equal(t, "pkg:oci/output@"+arm64.Digest.String(), doc.Statements[0].Products[1].ID)
}

func TestResultsInPlatformOrder(t *testing.T) {
	platforms := []types.PatchPlatform{
		{Platform: platformSpec("linux", "amd64", "")},
		{Platform: platformSpec("linux", "arm64", "")},
	}
	result := func(label string, platform *ispec.Platform) types.PatchResult {
		return types.PatchResult{PatchedDesc: &ispec.Descriptor{MediaType: label, Platform: platform}}
	}
	ordered := resultsInPlatformOrder(platforms, []types.PatchResult{
		result("unknown", nil),
		result("arm64", &ispec.Platform{OS: "linux", Architecture: "arm64"}),
		{},
		result("amd64", &ispec.Platform{OS: "linux", Architecture: "amd64"}),
	})
	labels := make([]string, 0, len(ordered))
	for _, r := range ordered {
		if r.PatchedDesc == nil {
			labels = append(labels, "nil")
			continue
		}
		labels = append(labels, r.PatchedDesc.MediaType)
	}
	assert.Equal(t, []string{"amd64", "arm64", "unknown", "nil"}, labels)
}

// OCI layout input must not write the shared VEX document from per-platform
// results: their digests are not final until the OCI export, and writeOCIVEX
// writes the document after it. Without --oci-dir nothing is exported, so no
// VEX may appear.
func TestPatchPreparedMultiPlatformImageDefersOCISourceVEX(t *testing.T) {
	originalPatchPlatformImage := patchPlatformImage
	t.Cleanup(func() { patchPlatformImage = originalPatchPlatformImage })

	root, _, _ := writeTwoPlatformLayout(t)
	source, err := ocilayout.Open(t.Context(), root, "", "")
	require.NoError(t, err)

	const image = "registry.invalid/acme/output:patched"
	patchPlatformImage = func(_ context.Context, opts *types.Options, p types.PatchPlatform, _ bool, _ chan<- *client.SolveStatus) (*types.PatchResult, error) {
		assert.Empty(t, opts.Output, "a platform build must not write the shared VEX file")
		ref, err := reference.ParseNormalizedNamed(image)
		if err != nil {
			return nil, err
		}
		result := ociVEXResult(t, p.Architecture)
		result.OriginalRef = ref
		result.PatchedRef = ref
		return &result, nil
	}

	vexPath := filepath.Join(t.TempDir(), "vex.json")
	err = patchPreparedMultiPlatformImage(t.Context(), &types.Options{
		Image:      image,
		PatchedTag: image,
		OCISource:  source,
		Format:     "openvex",
		Output:     vexPath,
	}, []types.PatchPlatform{
		{Platform: platformSpec("linux", "amd64", "")},
		{Platform: platformSpec("linux", "arm64", "")},
	})
	require.NoError(t, err)
	assert.NoFileExists(t, vexPath)
}

// The output path does not exist, so any attempt to read it fails. VEX output
// must only read the exported layout when a result has updates to report.
func TestWriteOCIVEXReadsOutputOnlyForEligibleResults(t *testing.T) {
	vexPath := filepath.Join(t.TempDir(), "vex.json")
	opts := &types.Options{
		OCISource: &ocilayout.Source{},
		OCIDir:    filepath.Join(t.TempDir(), "missing-output"),
		Output:    vexPath,
		Format:    "openvex",
	}
	platform := &ispec.Platform{OS: "linux", Architecture: "amd64"}
	ineligible := []types.PatchResult{
		{PatchedDesc: &ispec.Descriptor{Platform: platform}},
		{PatchedDesc: &ispec.Descriptor{Platform: platform}, VEX: &types.PlatformVEX{}},
		{PatchedDesc: &ispec.Descriptor{Platform: platform}, VEX: &types.PlatformVEX{Updates: &unversioned.UpdateManifest{}}},
	}
	require.NoError(t, writeOCIVEX(t.Context(), opts, ineligible, "example.com/app:patched"))
	assert.NoFileExists(t, vexPath)

	eligible := append(slices.Clone(ineligible), types.PatchResult{
		PatchedDesc: &ispec.Descriptor{Platform: platform},
		VEX: &types.PlatformVEX{Updates: &unversioned.UpdateManifest{
			OSUpdates: []unversioned.UpdatePackage{{Name: "busybox", InstalledVersion: "1.0", FixedVersion: "1.1", VulnerabilityID: "CVE-0000-0000"}},
		}},
	})
	require.ErrorContains(t, writeOCIVEX(t.Context(), opts, eligible, "example.com/app:patched"), "read final OCI output for VEX")
}

// Before the export, Patch can only compare the VEX path with the output path
// it names, because the output does not exist yet. Once the output exists,
// writeOCIVEX checks again, so a VEX path that reaches the output through an
// alias, here a link to it, cannot add a file to the finished layout.
func TestWriteOCIVEXRejectsOutputAlias(t *testing.T) {
	root, _, _ := writeTwoPlatformLayout(t)
	alias := filepath.Join(t.TempDir(), "alias")
	require.NoError(t, os.Symlink(root, alias))
	indexBefore, err := os.ReadFile(filepath.Join(root, "index.json"))
	require.NoError(t, err)

	opts := &types.Options{
		OCISource: &ocilayout.Source{},
		OCIDir:    root,
		Output:    filepath.Join(alias, "vex.json"),
		Format:    "openvex",
	}
	results := []types.PatchResult{ociVEXResult(t, "amd64")}
	require.ErrorContains(t, writeOCIVEX(t.Context(), opts, results, "registry.invalid/acme/output:patched"),
		"must not be inside OCI layout output")

	assert.NoFileExists(t, filepath.Join(root, "vex.json"))
	indexAfter, err := os.ReadFile(filepath.Join(root, "index.json"))
	require.NoError(t, err)
	assert.Equal(t, indexBefore, indexAfter)
}

func TestValidateOCIVEXDestination(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "existing.json")
	require.NoError(t, os.WriteFile(existing, []byte("{}"), 0o600))
	subdir := filepath.Join(dir, "subdir")
	require.NoError(t, os.Mkdir(subdir, 0o755))
	fileLink := filepath.Join(dir, "file-link.json")
	require.NoError(t, os.Symlink(existing, fileLink))
	dirLink := filepath.Join(dir, "dir-link")
	require.NoError(t, os.Symlink(subdir, dirLink))
	danglingLink := filepath.Join(dir, "dangling-link.json")
	require.NoError(t, os.Symlink(filepath.Join(dir, "missing", "vex.json"), danglingLink))

	tests := []struct {
		name    string
		path    string
		format  string
		wantErr string
	}{
		{name: "new file", path: filepath.Join(dir, "vex.json"), format: "openvex"},
		{name: "existing file", path: existing, format: "openvex"},
		{name: "link to existing file", path: fileLink, format: "openvex"},
		{name: "existing directory", path: subdir, format: "openvex", wantErr: "exists and is not a regular file"},
		{name: "link to directory", path: dirLink, format: "openvex", wantErr: "exists and is not a regular file"},
		{name: "link to missing file", path: danglingLink, format: "openvex", wantErr: "is a link to a missing or unreadable file"},
		{name: "missing parent", path: filepath.Join(dir, "missing", "vex.json"), format: "openvex", wantErr: "parent directory"},
		{name: "parent is a file", path: filepath.Join(existing, "vex.json"), format: "openvex", wantErr: "stat VEX output"},
		{name: "unsupported format", path: filepath.Join(dir, "vex.json"), format: "csaf", wantErr: "unsupported output format csaf"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateOCIVEXDestination(tt.path, tt.format)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

// With OCI layout input, VEX is written after the output layout is published.
// A destination the VEX writer cannot use must fail before anything is
// exported, rather than leaving a published layout without its VEX document.
func TestPatchRejectsUnusableOCIVEXDestinationBeforeExport(t *testing.T) {
	input, _, _ := writeTwoPlatformLayout(t)
	dir := t.TempDir()
	tests := []struct {
		name    string
		output  string
		format  string
		wantErr string
	}{
		{name: "existing directory", output: dir, format: "openvex", wantErr: "exists and is not a regular file"},
		{name: "missing parent", output: filepath.Join(dir, "missing", "vex.json"), format: "openvex", wantErr: "parent directory"},
		{name: "unsupported format", output: filepath.Join(dir, "vex.json"), format: "csaf", wantErr: "unsupported output format"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ociDir := filepath.Join(t.TempDir(), "output")
			err := patchWithContext(t.Context(), &types.Options{
				InputOCILayout: input,
				OCIDir:         ociDir,
				PatchedTag:     "registry.invalid/acme/output:patched",
				Output:         tt.output,
				Format:         tt.format,
				BkAddr:         "tcp://127.0.0.1:1",
			})
			require.ErrorContains(t, err, tt.wantErr)
			assert.NoDirExists(t, ociDir)
		})
	}
}

func TestOCIExportOptionsCarrySourcePolicy(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "policy.json")
	require.NoError(t, os.WriteFile(policyPath, []byte(`{"rules":[{"action":"CONVERT","selector":{"identifier":"docker-image://example.invalid/tooling:1"},`+
		`"updates":{"identifier":"docker-image://example.com/mirror/tooling:1"}}]}`), 0o600))
	opts := &types.Options{OCISource: &ocilayout.Source{}, BkAddr: "tcp://127.0.0.1:1"}

	t.Setenv("EXPERIMENTAL_BUILDKIT_SOURCE_POLICY", policyPath)
	exportOpts, err := ociExportOptions(t.Context(), opts, "example.com/app:patched")
	require.NoError(t, err)
	require.NotNil(t, exportOpts.SourcePolicy)
	require.Len(t, exportOpts.SourcePolicy.Rules, 1)
	assert.Equal(t, "docker-image://example.com/mirror/tooling:1", exportOpts.SourcePolicy.Rules[0].Updates.Identifier)
	assert.Equal(t, "tcp://127.0.0.1:1", exportOpts.BuildkitOpts.Addr)
	assert.True(t, exportOpts.Atomic)
	assert.Equal(t, DefaultLocalExportCompression, exportOpts.Compression)

	t.Setenv("EXPERIMENTAL_BUILDKIT_SOURCE_POLICY", filepath.Join(t.TempDir(), "missing.json"))
	_, err = ociExportOptions(t.Context(), opts, "example.com/app:patched")
	require.ErrorContains(t, err, "failed to read source policy file")

	t.Setenv("EXPERIMENTAL_BUILDKIT_SOURCE_POLICY", "")
	exportOpts, err = ociExportOptions(t.Context(), opts, "example.com/app:patched")
	require.NoError(t, err)
	assert.Nil(t, exportOpts.SourcePolicy)
}
