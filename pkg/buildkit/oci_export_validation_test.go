package buildkit

import (
	"archive/tar"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/moby/buildkit/client"
	"github.com/moby/buildkit/client/llb"
	sourcepolicy "github.com/moby/buildkit/sourcepolicy/pb"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/project-copacetic/copacetic/pkg/ocilayout"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeOCIExport describes the OCI layout tar that a fake BuildKit OCI exporter
// writes for one platform. The edit hooks corrupt it the way a malformed or
// incomplete export would.
type fakeOCIExport struct {
	editManifests func([]ispec.Descriptor) []ispec.Descriptor
	omitLayerBlob bool
	// attestation adds an attestation manifest after the image manifest, in
	// the shape BuildKit writes when a solve requests attestations.
	attestation bool
}

// ociExportFile is one file in a fake OCI exporter tar, a blob or layout metadata.
type ociExportFile struct {
	name string
	data []byte
	desc ispec.Descriptor
}

func newOCIExportBlob(mediaType string, data []byte) ociExportFile {
	dgst := digest.FromBytes(data)
	return ociExportFile{
		name: "blobs/" + dgst.Algorithm().String() + "/" + dgst.Encoded(),
		data: data,
		desc: ispec.Descriptor{MediaType: mediaType, Digest: dgst, Size: int64(len(data))},
	}
}

func mustMarshalJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	require.NoError(t, err)
	return data
}

// writeFakeOCIExport writes what BuildKit's OCI exporter would write for one
// platform image to the export's output, so the real extraction, index
// assembly, wrapping and publication code runs on it.
func writeFakeOCIExport(t *testing.T, solveOpt *client.SolveOpt, platform *ispec.Platform, export fakeOCIExport) error {
	t.Helper()
	layer := newOCIExportBlob(ispec.MediaTypeImageLayer, []byte("layer for "+platform.Architecture))
	config := newOCIExportBlob(ispec.MediaTypeImageConfig, mustMarshalJSON(t, ispec.Image{
		Platform: ispec.Platform{OS: platform.OS, Architecture: platform.Architecture, Variant: platform.Variant},
		RootFS:   ispec.RootFS{Type: "layers", DiffIDs: []digest.Digest{layer.desc.Digest}},
	}))
	manifest := newOCIExportBlob(ispec.MediaTypeImageManifest, mustMarshalJSON(t, ispec.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ispec.MediaTypeImageManifest,
		Config:    config.desc,
		Layers:    []ispec.Descriptor{layer.desc},
	}))
	manifests := []ispec.Descriptor{manifest.desc}
	var attestationFiles []ociExportFile
	if export.attestation {
		statement := newOCIExportBlob("application/vnd.in-toto+json", []byte(`{"_type":"https://in-toto.io/Statement/v0.1"}`))
		attestationConfig := newOCIExportBlob(ispec.MediaTypeImageConfig, mustMarshalJSON(t, ispec.Image{
			Platform: ispec.Platform{OS: "unknown", Architecture: "unknown"},
			RootFS:   ispec.RootFS{Type: "layers", DiffIDs: []digest.Digest{statement.desc.Digest}},
		}))
		attestationManifest := newOCIExportBlob(ispec.MediaTypeImageManifest, mustMarshalJSON(t, ispec.Manifest{
			Versioned: specs.Versioned{SchemaVersion: 2},
			MediaType: ispec.MediaTypeImageManifest,
			Config:    attestationConfig.desc,
			Layers:    []ispec.Descriptor{statement.desc},
		}))
		desc := attestationManifest.desc
		desc.Platform = &ispec.Platform{OS: "unknown", Architecture: "unknown"}
		desc.Annotations = map[string]string{
			"vnd.docker.reference.type":   "attestation-manifest",
			"vnd.docker.reference.digest": manifest.desc.Digest.String(),
		}
		manifests = append(manifests, desc)
		attestationFiles = []ociExportFile{statement, attestationConfig, attestationManifest}
	}
	if export.editManifests != nil {
		manifests = export.editManifests(manifests)
	}

	files := []ociExportFile{
		{name: ispec.ImageLayoutFile, data: []byte(`{"imageLayoutVersion":"1.0.0"}`)},
		{name: ispec.ImageIndexFile, data: mustMarshalJSON(t, ispec.Index{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ispec.MediaTypeImageIndex, Manifests: manifests})},
		manifest,
		config,
	}
	files = append(files, attestationFiles...)
	if !export.omitLayerBlob {
		files = append(files, layer)
	}

	require.Len(t, solveOpt.Exports, 1)
	output, err := solveOpt.Exports[0].Output(nil)
	if err != nil {
		return err
	}
	archive := tar.NewWriter(output)
	for i := range files {
		file := &files[i]
		require.NoError(t, archive.WriteHeader(&tar.Header{Name: file.name, Mode: 0o644, Size: int64(len(file.data)), Typeflag: tar.TypeReg}))
		_, err := archive.Write(file.data)
		require.NoError(t, err)
	}
	require.NoError(t, archive.Close())
	return output.Close()
}

// stubOCIExporter replaces the BuildKit solve with a fake OCI exporter and
// records each solve's options. Each platform gets the export from exports,
// keyed by PlatformKey, or a valid one if it has no entry.
func stubOCIExporter(t *testing.T, exports map[string]fakeOCIExport) *[]client.SolveOpt {
	t.Helper()
	original := solveOCIPlatform
	t.Cleanup(func() { solveOCIPlatform = original })
	var solves []client.SolveOpt
	solveOCIPlatform = func(_ context.Context, _ *client.Client, _ *llb.State, platform *ispec.Platform, _ platformExportMetadata, solveOpt *client.SolveOpt) error {
		solves = append(solves, *solveOpt)
		return writeFakeOCIExport(t, solveOpt, platform, exports[PlatformKey(*platform)])
	}
	return &solves
}

// newMultiPlatformOCIInputTestSource opens a layout input whose index points
// to a child index holding one image per platform, each with a config that
// declares that platform.
func newMultiPlatformOCIInputTestSource(t *testing.T, platforms ...ispec.Platform) (*ocilayout.Source, map[string]ispec.Descriptor, map[string][]byte) {
	t.Helper()
	root := t.TempDir()
	descriptors := make(map[string]ispec.Descriptor)
	configs := make(map[string][]byte)
	var manifests []ispec.Descriptor
	for _, platform := range platforms {
		configData, err := json.Marshal(ispec.Image{Platform: platform, RootFS: ispec.RootFS{Type: "layers"}})
		require.NoError(t, err)
		configDesc := writeOCIInputTestBlob(t, root, ispec.MediaTypeImageConfig, configData)
		manifestData, err := json.Marshal(ispec.Manifest{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ispec.MediaTypeImageManifest, Config: configDesc, Layers: []ispec.Descriptor{}})
		require.NoError(t, err)
		manifestDesc := writeOCIInputTestBlob(t, root, ispec.MediaTypeImageManifest, manifestData)
		manifestDesc.Platform = &platform
		manifests = append(manifests, manifestDesc)
		descriptors[PlatformKey(platform)] = manifestDesc
		configs[PlatformKey(platform)] = configData
	}
	childData, err := json.Marshal(ispec.Index{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ispec.MediaTypeImageIndex, Manifests: manifests})
	require.NoError(t, err)
	childDesc := writeOCIInputTestBlob(t, root, ispec.MediaTypeImageIndex, childData)
	indexData, err := json.Marshal(ispec.Index{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ispec.MediaTypeImageIndex, Manifests: []ispec.Descriptor{childDesc}})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(root, ispec.ImageLayoutFile), []byte(`{"imageLayoutVersion":"1.0.0"}`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, ispec.ImageIndexFile), indexData, 0o600))

	source, err := ocilayout.Open(t.Context(), root, filepath.Join(t.TempDir(), "output"), "")
	require.NoError(t, err)
	return source, descriptors, configs
}

var (
	ociExportAMD64 = ispec.Platform{OS: "linux", Architecture: "amd64"}
	ociExportARM64 = ispec.Platform{OS: "linux", Architecture: "arm64"}
)

type ociExportRun struct {
	output string
	source *ocilayout.Source
	policy *sourcepolicy.Policy
	solves []client.SolveOpt
}

// runOCIExport exports patched results for patched and preserved results for
// preserved through the atomic OCI layout path with the fake exporter.
func runOCIExport(t *testing.T, patched, preserved []ispec.Platform, exports map[string]fakeOCIExport) (ociExportRun, error) {
	t.Helper()
	all := append(append([]ispec.Platform{}, patched...), preserved...)
	source, descriptors, configs := newMultiPlatformOCIInputTestSource(t, all...)
	solves := stubOCIExporter(t, exports)
	policy := &sourcepolicy.Policy{Rules: []*sourcepolicy.Rule{{
		Action:   sourcepolicy.PolicyAction_DENY,
		Selector: &sourcepolicy.Selector{Identifier: "docker-image://registry.invalid/denied:*", MatchType: sourcepolicy.MatchType_WILDCARD},
	}}}

	var results []types.PatchResult
	var platforms []types.PatchPlatform
	for _, platform := range patched {
		desc := descriptors[PlatformKey(platform)]
		state := llb.Scratch()
		results = append(results, types.PatchResult{OCISource: source, PatchedDesc: &desc, PatchedState: &state, ConfigData: configs[PlatformKey(platform)]})
		platforms = append(platforms, types.PatchPlatform{Platform: platform})
	}
	for _, platform := range preserved {
		platforms = append(platforms, types.PatchPlatform{Platform: platform, ShouldPreserve: true})
	}

	parent := t.TempDir()
	output := filepath.Join(parent, "output")
	err := CreateOCILayoutFromResultsWithOptions(output, results, platforms, OCILayoutExportOptions{
		Atomic:          true,
		OutputReference: "registry.invalid/output:patched",
		BuildkitOpts:    &Opts{Addr: "tcp://127.0.0.1:1"},
		SourcePolicy:    policy,
	})
	return ociExportRun{output: output, source: source, policy: policy, solves: *solves}, err
}

func assertOCIExportPublished(t *testing.T, output string, platforms ...ispec.Platform) {
	t.Helper()
	published, err := ocilayout.Open(t.Context(), output, "", "")
	require.NoError(t, err)
	for i := range platforms {
		_, err := published.PlatformDescriptor(t.Context(), &platforms[i])
		require.NoError(t, err, "published layout must contain %s", FormatPlatform(platforms[i]))
	}
}

func assertOCIExportNotPublished(t *testing.T, output string, err error) {
	t.Helper()
	require.ErrorContains(t, err, "validate staged OCI layout output")
	assert.NoDirExists(t, output)
	staged, globErr := filepath.Glob(filepath.Join(filepath.Dir(output), ".copa-oci-output-*"))
	require.NoError(t, globErr)
	assert.Empty(t, staged, "the staging directory must be removed")
}

func TestOCIExportPublishesValidatedLayoutWithPatchSolveSources(t *testing.T) {
	for _, tc := range []struct {
		name      string
		patched   []ispec.Platform
		preserved []ispec.Platform
	}{
		{name: "single platform", patched: []ispec.Platform{ociExportAMD64}},
		{name: "multiple platforms", patched: []ispec.Platform{ociExportAMD64, ociExportARM64}},
		{name: "patched and preserved platforms", patched: []ispec.Platform{ociExportAMD64}, preserved: []ispec.Platform{ociExportARM64}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run, err := runOCIExport(t, tc.patched, tc.preserved, nil)
			require.NoError(t, err)
			assertOCIExportPublished(t, run.output, append(append([]ispec.Platform{}, tc.patched...), tc.preserved...)...)

			// Each export re-solves a patched state, so it needs the layout's
			// content store and the source policy that the patch solve used.
			// It must not request attestations, which the staged layout check
			// would reject.
			require.Len(t, run.solves, len(tc.patched))
			for _, solve := range run.solves {
				assert.Same(t, run.policy, solve.SourcePolicy)
				assert.Contains(t, solve.OCIStores, run.source.StoreID)
				for key := range solve.FrontendAttrs {
					assert.False(t, strings.HasPrefix(key, "attest:"), "export solve requests attestation %s", key)
				}
			}
		})
	}
}

// BuildKit writes attestation manifests only for solves that request them,
// which the export solves do not. If one appears anyway it must not be
// published: the single and multi-platform paths stamp the exported platform
// on every index entry, so it would claim a platform its config does not
// declare. The mixed path keeps only the first manifest of each export, which
// is the image manifest, so the attestation is dropped.
func TestOCIExportDoesNotPublishAttestationManifests(t *testing.T) {
	attested := fakeOCIExport{attestation: true}
	t.Run("single platform export", func(t *testing.T) {
		run, err := runOCIExport(t, []ispec.Platform{ociExportAMD64}, nil, map[string]fakeOCIExport{PlatformKey(ociExportAMD64): attested})
		assertOCIExportNotPublished(t, run.output, err)
	})
	t.Run("multi-platform export", func(t *testing.T) {
		run, err := runOCIExport(t, []ispec.Platform{ociExportAMD64, ociExportARM64}, nil, map[string]fakeOCIExport{PlatformKey(ociExportARM64): attested})
		assertOCIExportNotPublished(t, run.output, err)
	})
	t.Run("mixed export", func(t *testing.T) {
		run, err := runOCIExport(t, []ispec.Platform{ociExportAMD64}, []ispec.Platform{ociExportARM64}, map[string]fakeOCIExport{PlatformKey(ociExportAMD64): attested})
		require.NoError(t, err)
		assertOCIExportPublished(t, run.output, ociExportAMD64, ociExportARM64)
		published, err := ocilayout.Open(t.Context(), run.output, "", "")
		require.NoError(t, err)
		listed, err := published.Manifests(t.Context())
		require.NoError(t, err)
		assert.Len(t, listed, 2, "the published index must list only the platform manifests")
	})
}

func TestOCIExportRejectsMalformedStagedLayout(t *testing.T) {
	noManifests := fakeOCIExport{editManifests: func([]ispec.Descriptor) []ispec.Descriptor { return []ispec.Descriptor{} }}
	unexpectedMediaType := fakeOCIExport{editManifests: func(manifests []ispec.Descriptor) []ispec.Descriptor {
		manifests[0].MediaType = "application/vnd.example.unknown+json"
		return manifests
	}}
	missingManifestBlob := fakeOCIExport{editManifests: func(manifests []ispec.Descriptor) []ispec.Descriptor {
		manifests[0].Digest = digest.FromString("manifest that the export does not contain")
		return manifests
	}}
	// Layout reads skip entries that are not image manifests without opening
	// them, so each of these sits beside a valid manifest unverified.
	unknownBesideManifest := fakeOCIExport{editManifests: func(manifests []ispec.Descriptor) []ispec.Descriptor {
		return append(manifests, ispec.Descriptor{MediaType: "application/vnd.example.unknown+json", Digest: digest.FromString("blob that the export does not contain"), Size: 37})
	}}
	artifactBesideManifest := fakeOCIExport{editManifests: func(manifests []ispec.Descriptor) []ispec.Descriptor {
		return append(manifests, ispec.Descriptor{
			MediaType:    ispec.MediaTypeImageManifest,
			ArtifactType: "application/vnd.example.sbom",
			Digest:       digest.FromString("artifact that the export does not contain"),
			Size:         41,
		})
	}}
	manifestListedAgain := fakeOCIExport{editManifests: func(manifests []ispec.Descriptor) []ispec.Descriptor {
		again := manifests[0]
		again.MediaType = "application/vnd.example.unknown+json"
		return append(manifests, again)
	}}
	for _, tc := range []struct {
		name      string
		patched   []ispec.Platform
		preserved []ispec.Platform
		exports   map[string]fakeOCIExport
	}{
		{
			name:    "single platform export with no manifests",
			patched: []ispec.Platform{ociExportAMD64},
			exports: map[string]fakeOCIExport{PlatformKey(ociExportAMD64): noManifests},
		},
		{
			name:    "single platform export with an unexpected manifest media type",
			patched: []ispec.Platform{ociExportAMD64},
			exports: map[string]fakeOCIExport{PlatformKey(ociExportAMD64): unexpectedMediaType},
		},
		{
			name:    "single platform export missing a layer blob",
			patched: []ispec.Platform{ociExportAMD64},
			exports: map[string]fakeOCIExport{PlatformKey(ociExportAMD64): {omitLayerBlob: true}},
		},
		{
			name:    "multi-platform export with no manifests for one platform",
			patched: []ispec.Platform{ociExportAMD64, ociExportARM64},
			exports: map[string]fakeOCIExport{PlatformKey(ociExportARM64): noManifests},
		},
		{
			name:    "single platform export with an unknown descriptor beside its manifest",
			patched: []ispec.Platform{ociExportAMD64},
			exports: map[string]fakeOCIExport{PlatformKey(ociExportAMD64): unknownBesideManifest},
		},
		{
			name:    "single platform export listing its manifest again under another media type",
			patched: []ispec.Platform{ociExportAMD64},
			exports: map[string]fakeOCIExport{PlatformKey(ociExportAMD64): manifestListedAgain},
		},
		{
			name:    "multi-platform export with an artifact beside a manifest",
			patched: []ispec.Platform{ociExportAMD64, ociExportARM64},
			exports: map[string]fakeOCIExport{PlatformKey(ociExportARM64): artifactBesideManifest},
		},
		{
			name:      "mixed export whose patched manifest blob is missing",
			patched:   []ispec.Platform{ociExportAMD64},
			preserved: []ispec.Platform{ociExportARM64},
			exports:   map[string]fakeOCIExport{PlatformKey(ociExportAMD64): missingManifestBlob},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run, err := runOCIExport(t, tc.patched, tc.preserved, tc.exports)
			assertOCIExportNotPublished(t, run.output, err)
		})
	}
}

// Results for layout input are matched to platforms by their descriptor's
// platform. One without a platform cannot be placed, and two for one platform
// would let the later result silently replace the earlier one.
func TestOCIExportRejectsUnplaceableResults(t *testing.T) {
	source, descriptors, configs := newMultiPlatformOCIInputTestSource(t, ociExportAMD64, ociExportARM64)
	stubOCIExporter(t, nil)
	result := func(platform ispec.Platform, withPlatform bool) types.PatchResult {
		desc := descriptors[PlatformKey(platform)]
		if !withPlatform {
			desc.Platform = nil
		}
		state := llb.Scratch()
		return types.PatchResult{OCISource: source, PatchedDesc: &desc, PatchedState: &state, ConfigData: configs[PlatformKey(platform)]}
	}
	for _, tc := range []struct {
		name    string
		results []types.PatchResult
		wantErr string
	}{
		{
			name:    "result without a platform",
			results: []types.PatchResult{result(ociExportAMD64, true), result(ociExportARM64, false)},
			wantErr: "OCI patch result is missing its source platform",
		},
		{
			name:    "two results for one platform",
			results: []types.PatchResult{result(ociExportAMD64, true), result(ociExportARM64, true), result(ociExportAMD64, true)},
			wantErr: "multiple OCI patch results for platform linux/amd64",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "output")
			err := CreateOCILayoutFromResultsWithOptions(output, tc.results,
				[]types.PatchPlatform{{Platform: ociExportAMD64}, {Platform: ociExportARM64}},
				OCILayoutExportOptions{Atomic: true, OutputReference: "registry.invalid/output:patched", BuildkitOpts: &Opts{Addr: "tcp://127.0.0.1:1"}},
			)
			require.ErrorContains(t, err, tc.wantErr)
			assert.NoDirExists(t, output)
		})
	}
}
