package ocilayout_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/moby/buildkit/client/llb"
	sourcepolicy "github.com/moby/buildkit/sourcepolicy/pb"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types"
)

// TestOCILayoutExportAppliesSourcePolicy exports an OCI-backed state that also
// reads a tooling image which only the source policy can resolve, as a patch
// using tooling-image replacement does. The export re-solve must apply the
// same policy as the patch solve.
func TestOCILayoutExportAppliesSourcePolicy(t *testing.T) {
	addr := os.Getenv("COPA_OCI_TEST_ADDR")
	if addr == "" {
		t.Skip("set COPA_OCI_TEST_ADDR to an isolated BuildKit endpoint")
	}
	ref, err := name.ParseReference(alpineIndex)
	require.NoError(t, err)
	base, err := remote.Image(ref, remote.WithPlatform(v1.Platform{OS: linuxOS, Architecture: amd64Arch}), remote.WithContext(t.Context()))
	require.NoError(t, err)
	input := writeLayout(t, map[string]v1.Image{amd64Arch: base}, false, false)
	before := snapshot(t, input)
	source := openLayout(t, input)
	platform := ocispec.Platform{OS: linuxOS, Architecture: amd64Arch}
	config, err := base.RawConfigFile()
	require.NoError(t, err)
	state, err := source.State(t.Context(), &platform, config)
	require.NoError(t, err)
	const tooling = "registry.invalid/copa-1688/tooling:1"
	state = state.File(llb.Copy(llb.Image(tooling, llb.Platform(platform)), "/etc/alpine-release", "/copa-tooling-release"))
	desc, err := source.PlatformDescriptor(t.Context(), &platform)
	require.NoError(t, err)
	policy := &sourcepolicy.Policy{Rules: []*sourcepolicy.Rule{{
		Action:   sourcepolicy.PolicyAction_CONVERT,
		Selector: &sourcepolicy.Selector{Identifier: "docker-image://" + tooling},
		Updates:  &sourcepolicy.Update{Identifier: "docker-image://" + alpineIndex},
	}}}

	output := filepath.Join(t.TempDir(), "output")
	require.NoError(t, buildkit.CreateOCILayoutFromResultsWithOptions(output,
		[]types.PatchResult{{OCISource: source, PatchedState: &state, PatchedDesc: desc, ConfigData: config}},
		[]types.PatchPlatform{{Platform: platform}},
		buildkit.OCILayoutExportOptions{
			BuildkitOpts: &buildkit.Opts{Addr: addr}, Atomic: true, OutputReference: outputName, SourcePolicy: policy,
		}.WithContext(t.Context()),
	), "the export must resolve the tooling image through the source policy")
	release := readImageFile(t, exportedImage(t, output), "copa-tooling-release")
	assert.NotEmpty(t, strings.TrimSpace(release), "the policy-resolved tooling image supplied the file")
	assert.Equal(t, before, snapshot(t, input))
}
