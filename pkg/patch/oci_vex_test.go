package patch

import (
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
