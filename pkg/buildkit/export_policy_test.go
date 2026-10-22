package buildkit

import (
	"testing"

	"github.com/moby/buildkit/client"
	sourcepolicy "github.com/moby/buildkit/sourcepolicy/pb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/project-copacetic/copacetic/pkg/ocilayout"
)

func TestPrepareExportSolveOptCarriesSourcePolicy(t *testing.T) {
	source, _, _ := newOCIInputTestSource(t)
	policy := &sourcepolicy.Policy{Rules: []*sourcepolicy.Rule{{
		Action:   sourcepolicy.PolicyAction_CONVERT,
		Selector: &sourcepolicy.Selector{Identifier: "docker-image://example.invalid/tooling:1"},
		Updates:  &sourcepolicy.Update{Identifier: "docker-image://example.com/mirror/tooling:1"},
	}}}
	exportOpts := OCILayoutExportOptions{SourcePolicy: policy, state: &ociLayoutExportState{sources: []*ocilayout.Source{source}}}

	var solveOpt client.SolveOpt
	prepareExportSolveOpt(&solveOpt, exportOpts)
	require.Same(t, policy, solveOpt.SourcePolicy, "export solves use the patch solve's source policy")
	assert.Contains(t, solveOpt.OCIStores, source.StoreID)

	var withoutPolicy client.SolveOpt
	prepareExportSolveOpt(&withoutPolicy, OCILayoutExportOptions{})
	assert.Nil(t, withoutPolicy.SourcePolicy)
	assert.Empty(t, withoutPolicy.OCIStores)
}
