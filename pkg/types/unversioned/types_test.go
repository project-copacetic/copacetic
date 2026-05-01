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
