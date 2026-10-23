package buildkit

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/client/llb/sourceresolver"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/solver/pb"
	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/stretchr/testify/require"
)

type (
	locatorMetadata struct {
		digest digest.Digest
		config []byte
	}
	locatorGateway struct {
		gwclient.Client
		t      *testing.T
		images map[string]locatorMetadata
	}
)

func (g *locatorGateway) ResolveSourceMetadata(_ context.Context, op *pb.SourceOp, opt sourceresolver.Opt) (*sourceresolver.MetaResponse, error) {
	require.Equal(g.t, llb.ResolveModePreferLocal.String(), opt.ImageOpt.ResolveMode)
	image, found := g.images[strings.TrimPrefix(op.Identifier, "docker-image://")]
	require.True(g.t, found, "unexpected source locator %s", op.Identifier)
	return &sourceresolver.MetaResponse{Op: op, Image: &sourceresolver.ResolveImageResponse{Digest: image.digest, Config: image.config}}, nil
}

func TestInitializedStatesPinResolvedContent(t *testing.T) {
	const repository = "example.com/app"
	original, patched := digest.FromString("original A"), digest.FromString("patched P1")
	platform := &specs.Platform{OS: "linux", Architecture: "amd64"}
	originalConfig := []byte(`{"os":"linux","architecture":"amd64","config":{"Labels":{}}}`)
	for _, repatch := range []bool{false, true} {
		name := "first patch"
		if repatch {
			name = "repatch"
		}
		t.Run(name, func(t *testing.T) {
			images := map[string]locatorMetadata{
				repository + ":original":             {original, originalConfig},
				repository + "@" + original.String(): {original, originalConfig},
			}
			input := repository + ":original"
			if repatch {
				labels := (&types.SourceLineage{Kind: types.PatchOriginImage, Name: input, Digest: original}).Annotations()
				labels["BaseImage"] = input
				config, err := json.Marshal(map[string]interface{}{"os": "linux", "architecture": "amd64", "config": map[string]interface{}{"Labels": labels}})
				require.NoError(t, err)
				input = repository + ":patched"
				images[input] = locatorMetadata{patched, config}
				images[repository+"@"+patched.String()] = locatorMetadata{patched, config}
			}
			cfg, err := InitializeBuildkitConfig(t.Context(), &locatorGateway{t: t, images: images}, input, platform)
			require.NoError(t, err)
			states := map[string]llb.State{original.String(): cfg.ImageState}
			if repatch {
				states[patched.String()] = cfg.PatchedImageState
			}
			for expected, state := range states {
				definition, err := state.Marshal(t.Context(), llb.Platform(*platform))
				require.NoError(t, err)
				sources := 0
				for _, data := range definition.Def {
					var op pb.Op
					require.NoError(t, op.UnmarshalVT(data))
					if source := op.GetSource(); source != nil {
						sources++
						require.Equal(t, "docker-image://"+repository+"@"+expected, source.Identifier, "resolved metadata must not leave a mutable state locator")
					}
				}
				require.Equal(t, 1, sources)
			}
		})
	}
}
