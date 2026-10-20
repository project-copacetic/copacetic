package patch

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/project-copacetic/copacetic/pkg/ocilayout"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
)

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
		{PatchedDesc: &ispec.Descriptor{Platform: platform}, VEX: &types.VEXData{}},
		{PatchedDesc: &ispec.Descriptor{Platform: platform}, VEX: &types.VEXData{Updates: &unversioned.UpdateManifest{}}},
	}
	require.NoError(t, writeOCIVEX(t.Context(), opts, ineligible, "example.com/app:patched"))
	assert.NoFileExists(t, vexPath)

	eligible := append(slices.Clone(ineligible), types.PatchResult{
		PatchedDesc: &ispec.Descriptor{Platform: platform},
		VEX: &types.VEXData{Updates: &unversioned.UpdateManifest{
			OSUpdates: []unversioned.UpdatePackage{{Name: "busybox", InstalledVersion: "1.0", FixedVersion: "1.1", VulnerabilityID: "CVE-0000-0000"}},
		}},
	})
	require.ErrorContains(t, writeOCIVEX(t.Context(), opts, eligible, "example.com/app:patched"), "read final OCI output for VEX")
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
