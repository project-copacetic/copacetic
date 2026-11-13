package buildkit

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	ggcrtypes "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/moby/buildkit/client/llb"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/solver/pb"
	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/stretchr/testify/require"
)

// locatorGatewayWithoutBlobs is a gateway without image-blob support, which
// makes index recovery use the client-side compatibility path.
type locatorGatewayWithoutBlobs struct{ locatorGateway }

func (g *locatorGatewayWithoutBlobs) BuildOpts() gwclient.BuildOpts {
	return gwclient.BuildOpts{LLBCaps: pb.Caps.CapSet(nil)}
}

// BaseImage is the locator older Copa versions resolve to re-patch. A first
// patch records the locator the user supplied, and a re-patch keeps the
// recorded one, for each locator spelling. Content is always read through the
// digest-pinned original, even when a mutable tag has since moved.
func TestBaseImageKeepsSuppliedLocator(t *testing.T) {
	const repository = "example.com/app"
	child, index, moved := digest.FromString("original child A"), digest.FromString("original index"), digest.FromString("moved tag")
	patched := digest.FromString("patched P1")
	platform := &specs.Platform{OS: "linux", Architecture: "amd64"}
	originalConfig := []byte(`{"os":"linux","architecture":"amd64","config":{"Labels":{"org.opencontainers.image.base.name":"example.com/os:base"}}}`)
	movedConfig := []byte(`{"os":"linux","architecture":"amd64","config":{"Labels":{"com.example.moved":"true"}}}`)
	childRef := repository + "@" + child.String()
	indexRaw, err := json.Marshal(specs.Index{Manifests: []specs.Descriptor{{MediaType: specs.MediaTypeImageManifest, Digest: child, Platform: platform}}})
	require.NoError(t, err)
	oldLocal, oldRemote := tryGetManifestFromLocal, getRemoteImageDescriptor
	t.Cleanup(func() { tryGetManifestFromLocal, getRemoteImageDescriptor = oldLocal, oldRemote })
	tryGetManifestFromLocal = func(context.Context, name.Reference) (*remote.Descriptor, ggcrv1.Hash, bool, error) {
		return nil, ggcrv1.Hash{}, false, errors.New("no local image")
	}
	getRemoteImageDescriptor = func(ref name.Reference, _ ...remote.Option) (*remote.Descriptor, error) {
		require.Equal(t, repository+"@"+index.String(), ref.Name())
		hash, err := ggcrv1.NewHash(index.String())
		require.NoError(t, err)
		return &remote.Descriptor{Descriptor: ggcrv1.Descriptor{Digest: hash, MediaType: ggcrtypes.OCIImageIndex}, Manifest: indexRaw}, nil
	}

	for _, locator := range []string{repository, repository + ":stable", repository + ":stable@" + index.String()} {
		t.Run("first patch/"+locator, func(t *testing.T) {
			gateway := &locatorGatewayWithoutBlobs{locatorGateway{t: t, images: map[string]locatorMetadata{childRef: {child, originalConfig}}}}
			cfg, err := InitializeBuildkitConfigWithBaseImage(t.Context(), gateway, childRef, locator, platform)
			require.NoError(t, err)
			require.Nil(t, cfg.PatchedConfigData)
			labels := configLabels(t, cfg.ConfigData)
			require.Equal(t, locator, labels["BaseImage"])
			require.Equal(t, "example.com/os:base", labels[specs.AnnotationBaseImageName])
			require.Equal(t, child, cfg.SourceLineage.Digest)
			require.Equal(t, childRef, stateSource(t, &cfg.ImageState, platform))
		})

		t.Run("re-patch/"+locator, func(t *testing.T) {
			p1Labels := (&types.SourceLineage{Kind: types.PatchOriginImage, Name: childRef, Digest: child}).Annotations()
			p1Labels["BaseImage"] = locator
			p1Config, err := json.Marshal(map[string]interface{}{"os": "linux", "architecture": "amd64", "config": map[string]interface{}{"Labels": p1Labels}})
			require.NoError(t, err)
			p1Ref := repository + "@" + patched.String()
			images := map[string]locatorMetadata{
				p1Ref:    {patched, p1Config},
				childRef: {child, originalConfig},
				// The tag has moved since P1; an immutable index locator still
				// returns its index digest with the selected child's config.
				locator: {moved, movedConfig},
			}
			if locator == repository+":stable@"+index.String() {
				images[locator] = locatorMetadata{index, originalConfig}
			}
			gateway := &locatorGatewayWithoutBlobs{locatorGateway{t: t, images: images}}
			cfg, err := InitializeBuildkitConfigWithBaseImage(t.Context(), gateway, p1Ref, repository+":p1", platform)
			require.NoError(t, err)
			require.NotNil(t, cfg.PatchedConfigData)
			require.True(t, cfg.SourceLineageValidated)
			require.Equal(t, child, cfg.SourceLineage.Digest)
			labels := configLabels(t, cfg.ConfigData)
			require.Equal(t, locator, labels["BaseImage"], "a re-patch keeps the recorded locator")
			require.NotContains(t, labels, "com.example.moved", "a moved tag must not supply the original config")
			require.Equal(t, childRef, stateSource(t, &cfg.ImageState, platform), "the original is read by its recorded digest")
			require.Equal(t, p1Ref, stateSource(t, &cfg.PatchedImageState, platform))
		})
	}

	t.Run("default locator", func(t *testing.T) {
		gateway := &locatorGatewayWithoutBlobs{locatorGateway{t: t, images: map[string]locatorMetadata{childRef: {child, originalConfig}}}}
		cfg, err := InitializeBuildkitConfig(t.Context(), gateway, childRef, platform)
		require.NoError(t, err)
		require.Equal(t, childRef, configLabels(t, cfg.ConfigData)["BaseImage"])
	})
}

func configLabels(t *testing.T, config []byte) map[string]string {
	t.Helper()
	var image specs.Image
	require.NoError(t, json.Unmarshal(config, &image))
	return image.Config.Labels
}

func stateSource(t *testing.T, state *llb.State, platform *specs.Platform) string {
	t.Helper()
	definition, err := state.Marshal(t.Context(), llb.Platform(*platform))
	require.NoError(t, err)
	var sources []string
	for _, data := range definition.Def {
		var op pb.Op
		require.NoError(t, op.UnmarshalVT(data))
		if source := op.GetSource(); source != nil {
			sources = append(sources, source.Identifier)
		}
	}
	require.Len(t, sources, 1)
	return sources[0][len("docker-image://"):]
}
