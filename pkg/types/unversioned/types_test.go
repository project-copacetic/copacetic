package unversioned

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCombinedSummary_BothSet(t *testing.T) {
	m := &UpdateManifest{
		OSSummary:      &PatchSummary{Total: 10, Patched: 6, Skipped: 4},
		LibrarySummary: &PatchSummary{Total: 5, Patched: 3, Skipped: 2},
	}
	s := m.CombinedSummary()
	assert.NotNil(t, s)
	assert.Equal(t, 15, s.Total)
	assert.Equal(t, 9, s.Patched)
	assert.Equal(t, 6, s.Skipped)
}

func TestCombinedSummary_OnlyOS(t *testing.T) {
	m := &UpdateManifest{
		OSSummary: &PatchSummary{Total: 3, Patched: 2, Skipped: 1},
	}
	s := m.CombinedSummary()
	assert.NotNil(t, s)
	assert.Equal(t, 3, s.Total)
	assert.Equal(t, 2, s.Patched)
	assert.Equal(t, 1, s.Skipped)
}

func TestCombinedSummary_Neither(t *testing.T) {
	m := &UpdateManifest{}
	assert.Nil(t, m.CombinedSummary())
}

func TestCombinedSummaryAfterPatch(t *testing.T) {
	m := &UpdateManifest{
		OSSummary:      &PatchSummary{Total: 2, Patched: 2},
		LibrarySummary: &PatchSummary{Total: 6, Patched: 5, Skipped: 1},
		LangUpdates: LangUpdatePackages{
			{Name: "minimatch", FixedVersion: "11.0.1", VulnerabilityID: "CVE-1"},
			{Name: "minimatch", FixedVersion: "11.0.1", VulnerabilityID: "CVE-2"},
			{Name: "glob", FixedVersion: "14.0.2", VulnerabilityID: "CVE-3"},
			{Name: "tar", FixedVersion: "7.5.21", VulnerabilityID: "CVE-4"},
			{Name: "ms", FixedVersion: "2.1.3", VulnerabilityID: "CVE-5"},
			{Name: "diff", FixedVersion: "", VulnerabilityID: "CVE-6"}, // no applicable fix: already skipped
		},
	}
	s := m.CombinedSummaryAfterPatch([]string{"minimatch", "diff", "tar"})
	assert.Equal(t, &PatchSummary{Total: 8, Patched: 4, Skipped: 4}, s)

	// Unchanged without errored packages, and the manifest's own summary is untouched.
	assert.Equal(t, m.CombinedSummary(), m.CombinedSummaryAfterPatch(nil))
	assert.Equal(t, 5, m.LibrarySummary.Patched)
	assert.Nil(t, (&UpdateManifest{}).CombinedSummaryAfterPatch([]string{"minimatch"}))
}
