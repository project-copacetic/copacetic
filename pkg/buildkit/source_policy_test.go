package buildkit

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/moby/buildkit/client/llb/sourceresolver"
	"github.com/moby/buildkit/solver/pb"
	"github.com/moby/buildkit/sourcepolicy"
	policytypes "github.com/moby/buildkit/sourcepolicy/pb"
	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/stretchr/testify/require"
)

const policyImageScheme = "docker-image://"

type policyLocatorGateway struct {
	locatorGateway
	policy *policytypes.Policy
}

func (g *policyLocatorGateway) ResolveSourceMetadata(ctx context.Context, op *pb.SourceOp, opt sourceresolver.Opt) (*sourceresolver.MetaResponse, error) {
	op = op.CloneVT()
	if _, err := sourcepolicy.NewEngine([]*policytypes.Policy{g.policy}).Evaluate(ctx, op); err != nil {
		return nil, err
	}
	if _, found := g.images[strings.TrimPrefix(op.Identifier, policyImageScheme)]; !found {
		return nil, fmt.Errorf("unexpected source locator %s", op.Identifier)
	}
	return g.locatorGateway.ResolveSourceMetadata(ctx, op, opt)
}

func TestInitializeBuildkitConfigPolicySelectedSource(t *testing.T) {
	const requested = "registry-a.example/app:requested"
	const destination = "registry-b.example/app"
	original, patched := digest.FromString("policy-selected original"), digest.FromString("policy-selected patch")
	platform := &specs.Platform{OS: "linux", Architecture: "amd64"}
	originalConfig := []byte(`{"os":"linux","architecture":"amd64","config":{"Labels":{}}}`)
	for _, tc := range []struct {
		name     string
		selected string
		repatch  bool
	}{
		{name: "mirror tag", selected: destination + ":original"},
		{name: "mirror digest", selected: destination + "@" + original.String()},
		{name: "retag", selected: "registry-a.example/app:approved"},
		{name: "repatch", selected: destination + ":patched", repatch: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lineage := &types.SourceLineage{Kind: types.PatchOriginImage, Name: tc.selected, Digest: original}
			selectedDigest, selectedConfig := original, originalConfig
			originalLocator := tc.selected
			if tc.repatch {
				originalLocator = destination + ":original"
				lineage.Name = originalLocator
				labels := lineage.Annotations()
				labels["BaseImage"] = originalLocator
				var err error
				selectedConfig, err = json.Marshal(specs.Image{Platform: *platform, Config: specs.ImageConfig{Labels: labels}})
				require.NoError(t, err)
				selectedDigest = patched
			}
			originalRef, err := resolvedImageReference(originalLocator, original)
			require.NoError(t, err)
			selectedRef, err := resolvedImageReference(tc.selected, selectedDigest)
			require.NoError(t, err)
			gateway := &policyLocatorGateway{
				locatorGateway: locatorGateway{t: t, images: map[string]locatorMetadata{
					originalLocator: {original, originalConfig},
					originalRef:     {original, originalConfig},
					selectedRef:     {selectedDigest, selectedConfig},
				}},
				policy: &policytypes.Policy{Rules: []*policytypes.Rule{{
					Action:   policytypes.PolicyAction_CONVERT,
					Selector: &policytypes.Selector{Identifier: policyImageScheme + requested},
					Updates:  &policytypes.Update{Identifier: policyImageScheme + tc.selected},
				}}},
			}
			gateway.images[tc.selected] = locatorMetadata{selectedDigest, selectedConfig}
			cfg, err := InitializeBuildkitConfig(t.Context(), gateway, requested, platform)
			require.NoError(t, err)
			require.Equal(t, lineage, cfg.SourceLineage)
			require.Equal(t, originalLocator, configLabels(t, cfg.ConfigData)["BaseImage"])
			require.Equal(t, originalRef, stateSource(t, &cfg.ImageState, platform))
			if tc.repatch {
				require.True(t, cfg.SourceLineageValidated)
				require.Equal(t, selectedRef, stateSource(t, &cfg.PatchedImageState, platform))
			}

			// Digest pinning must not bypass a policy denial of the selected source.
			gateway.policy.Rules = append(gateway.policy.Rules, &policytypes.Rule{
				Action:   policytypes.PolicyAction_DENY,
				Selector: &policytypes.Selector{Identifier: policyImageScheme + originalRef},
			})
			denied, err := InitializeBuildkitConfig(t.Context(), gateway, requested, platform)
			if err == nil {
				_, err = denied.ImageState.Marshal(t.Context())
			}
			require.ErrorIs(t, err, sourcepolicy.ErrSourceDenied)
		})
	}
}

func TestInitializeBuildkitConfigNormalizationKeepsLocator(t *testing.T) {
	const supplied = "alpine:3.20"
	const normalized = "docker.io/library/" + supplied
	original := digest.FromString("normalized source")
	platform := &specs.Platform{OS: "linux", Architecture: "amd64"}
	config := []byte(`{"os":"linux","architecture":"amd64","config":{"Labels":{}}}`)
	pinned, err := resolvedImageReference(normalized, original)
	require.NoError(t, err)
	gateway := &locatorGateway{t: t, images: map[string]locatorMetadata{
		normalized: {original, config},
		pinned:     {original, config},
	}}
	cfg, err := InitializeBuildkitConfig(t.Context(), gateway, supplied, platform)
	require.NoError(t, err)
	require.Equal(t, supplied, configLabels(t, cfg.ConfigData)["BaseImage"])
	require.Equal(t, normalized, cfg.SourceLineage.Name)
	require.Equal(t, pinned, stateSource(t, &cfg.ImageState, platform))
}
