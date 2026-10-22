package buildkit

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/containerd/platforms"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/client/llb/sourceresolver"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/opencontainers/go-digest"
	specsgo "github.com/opencontainers/image-spec/specs-go"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/project-copacetic/copacetic/mocks"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type recordedPlatformResolver struct {
	sourceresolver.ImageMetaResolver
	source *ImageSource
}

func (r *recordedPlatformResolver) resolveSourceIndex(context.Context, string) (*ImageSource, error) {
	return r.source, nil
}

func TestRecordedIndexOriginInfersPlatform(t *testing.T) {
	child := digest.FromString("original child")
	root := digest.FromString("original index")
	baseRef := "example.com/app@" + root.String()
	childRef := "example.com/app@" + child.String()
	lineage := &types.SourceLineage{Kind: types.PatchOriginImage, Name: childRef, Digest: child}
	expected := specs.Platform{OS: linux, Architecture: arm64}
	validConfig := []byte(`{"os":"linux","architecture":"aarch64","variant":"v8","config":{"Labels":{}}}`)
	for _, tc := range []struct {
		name     string
		config   []byte
		noOpt    bool
		explicit bool
		wantErr  bool
	}{
		{name: "nil platform", config: validConfig},
		{name: "nil ImageOpt", config: validConfig, noOpt: true},
		{name: "explicit platform still works without config platform", config: []byte(`{"config":{"Labels":{}}}`), explicit: true},
		{name: "missing platform", config: []byte(`{"config":{}}`), wantErr: true},
		{name: "missing OS", config: []byte(`{"architecture":"arm64","config":{}}`), wantErr: true},
		{name: "missing architecture", config: []byte(`{"os":"linux","config":{}}`), wantErr: true},
		{name: "null platform", config: []byte(`null`), wantErr: true},
		{name: "malformed config", config: []byte(`{"os":`), wantErr: true},
		{name: "malformed architecture", config: []byte(`{"os":"linux","architecture":42}`), wantErr: true},
		{name: "malformed OS features", config: []byte(`{"os":"linux","architecture":"arm64","os.features":"invalid"}`), wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opt := sourceresolver.Opt{LogName: "recorded origin", ImageOpt: &sourceresolver.ResolveImageOpt{
				ResolveMode: llb.ResolveModePreferLocal.String(), AttestationChain: true, ResolveAttestations: []string{"provenance"},
			}}
			if tc.noOpt {
				opt.ImageOpt = nil
			} else if tc.explicit {
				opt.ImageOpt.Platform = &expected
			}
			var originalImageOpt sourceresolver.ResolveImageOpt
			if opt.ImageOpt != nil {
				originalImageOpt = *opt.ImageOpt
			}
			client := &mocks.MockGWClient{}
			client.On("ResolveImageConfig", mock.Anything, baseRef, opt).Return(baseRef, root, tc.config, nil).Once()
			if !tc.wantErr {
				client.On("ResolveImageConfig", mock.Anything, childRef, mock.Anything).
					Run(func(args mock.Arguments) {
						childOpt, ok := args.Get(2).(sourceresolver.Opt)
						require.True(t, ok)
						require.NotNil(t, childOpt.ImageOpt)
						require.Equal(t, expected, *childOpt.ImageOpt.Platform)
						want := opt
						wantImageOpt := originalImageOpt
						wantImageOpt.Platform = &expected
						want.ImageOpt = &wantImageOpt
						require.Equal(t, want, childOpt, "all other resolver options must be preserved")
					}).Return(childRef, child, tc.config, nil).Once()
			}
			resolver := &recordedPlatformResolver{ImageMetaResolver: client, source: &ImageSource{
				Descriptor: specs.Descriptor{Digest: root},
				Index:      &specs.Index{Manifests: []specs.Descriptor{{MediaType: specs.MediaTypeImageManifest, Digest: child, Platform: &expected}}},
			}}
			ref, selected, got, err := resolveRecordedOrigin(t.Context(), resolver, baseRef, lineage, opt)
			if tc.wantErr {
				require.ErrorContains(t, err, "platform")
			} else {
				require.NoError(t, err)
				require.Equal(t, baseRef, ref)
				require.Equal(t, child, selected)
				require.Equal(t, tc.config, got)
			}
			if tc.noOpt {
				require.Nil(t, opt.ImageOpt)
			} else {
				require.Equal(t, originalImageOpt, *opt.ImageOpt, "inference must not mutate caller-owned ImageOpt")
			}
			client.AssertExpectations(t)
		})
	}
}

func TestRecordedIndexOriginInferenceKeepsVerification(t *testing.T) {
	child := digest.FromString("original child")
	root := digest.FromString("original index")
	other := digest.FromString("different content")
	baseRef := "example.com/app@" + root.String()
	childRef := "example.com/app@" + child.String()
	lineage := &types.SourceLineage{Kind: types.PatchOriginImage, Name: childRef, Digest: child}
	platform := specs.Platform{OS: linux, Architecture: arm64}
	config := originIntegrityConfig(t, nil)
	for _, scenario := range []string{"index digest", "platform", "ambiguous selection", "child descriptor digest", "child media type", "child resolved digest", "child config"} {
		t.Run(scenario, func(t *testing.T) {
			source := &ImageSource{
				Descriptor: specs.Descriptor{Digest: root},
				Index:      &specs.Index{Manifests: []specs.Descriptor{{MediaType: specs.MediaTypeImageManifest, Digest: child, Platform: &platform}}},
			}
			switch scenario {
			case "index digest":
				source.Descriptor.Digest = other
			case "platform":
				source.Index.Manifests[0].Platform = &specs.Platform{OS: linux, Architecture: cancellationAMD64}
			case "ambiguous selection":
				source.Index.Manifests = append(source.Index.Manifests, source.Index.Manifests[0])
			case "child descriptor digest":
				source.Index.Manifests[0].Digest = other
			case "child media type":
				source.Index.Manifests[0].MediaType = specs.MediaTypeImageIndex
			}
			client := &mocks.MockGWClient{}
			opt := sourceresolver.Opt{ImageOpt: &sourceresolver.ResolveImageOpt{ResolveMode: llb.ResolveModePreferLocal.String()}}
			client.On("ResolveImageConfig", mock.Anything, baseRef, opt).Return(baseRef, root, config, nil).Once()
			switch scenario {
			case "child resolved digest":
				client.On("ResolveImageConfig", mock.Anything, childRef, mock.Anything).Return(childRef, other, config, nil).Once()
			case "child config":
				client.On("ResolveImageConfig", mock.Anything, childRef, mock.Anything).
					Return(childRef, child, originIntegrityConfig(t, map[string]string{"different": "child configuration"}), nil).Once()
			}
			resolver := &recordedPlatformResolver{ImageMetaResolver: client, source: source}
			_, _, _, err := resolveRecordedOrigin(t.Context(), resolver, baseRef, lineage, opt)
			require.Error(t, err)
			client.AssertExpectations(t)
		})
	}
}

func TestInitializeDefaultPlatformPinnedIndexRecovery(t *testing.T) {
	for _, platform := range []specs.Platform{
		{OS: linux, Architecture: arm64, Variant: "v8"},
		{OS: goosWindows, Architecture: cancellationAMD64, OSVersion: "10.0.26100.1", OSFeatures: []string{descriptorWindowsFeature}},
	} {
		t.Run(platforms.Format(platform), func(t *testing.T) {
			const input = "example.com/app:patched"
			child := digest.FromString("original child")
			patched := digest.FromString("patched child")
			childRef := "example.com/app@" + child.String()
			original := specs.Image{Platform: platform, Config: specs.ImageConfig{
				Env: []string{"ORIGINAL=true"}, Labels: map[string]string{"com.example.original": "retained"},
			}}
			originalConfig, err := json.Marshal(original)
			require.NoError(t, err)
			index := specs.Index{
				Versioned: specsgo.Versioned{SchemaVersion: 2}, MediaType: specs.MediaTypeImageIndex,
				Manifests: []specs.Descriptor{{MediaType: specs.MediaTypeImageManifest, Digest: child, Platform: &platform}},
			}
			indexConfig, err := json.Marshal(index)
			require.NoError(t, err)
			root := digest.FromBytes(indexConfig)
			baseRef := "example.com/app@" + root.String()
			lineage := &types.SourceLineage{Kind: types.PatchOriginImage, Name: childRef, Digest: child}
			labels := lineage.Annotations()
			labels["BaseImage"] = baseRef
			patchedConfig, err := AddImageConfigLabels(originalConfig, labels)
			require.NoError(t, err)
			gateway := &originIntegrityGateway{t: t, images: map[string]originIntegrityMetadata{
				input:    {digest: patched, config: patchedConfig},
				baseRef:  {digest: root, config: originalConfig},
				childRef: {digest: child, config: originalConfig},
			}}
			gateway.solve = func(context.Context, gwclient.SolveRequest) (*gwclient.Result, error) {
				return &gwclient.Result{Ref: &originIndexReference{read: func(context.Context, gwclient.ReadRequest) ([]byte, error) {
					return indexConfig, nil
				}}}, nil
			}
			gateway.resolve = func(ref string, opt sourceresolver.Opt) {
				if ref == childRef {
					normalized := platforms.Normalize(platform)
					require.Equal(t, &normalized, opt.ImageOpt.Platform)
				} else {
					require.Nil(t, opt.ImageOpt.Platform, "initial default-platform resolution must remain unchanged")
				}
			}
			cfg, err := InitializeBuildkitConfig(t.Context(), gateway, input, nil)
			require.NoError(t, err)
			require.Nil(t, cfg.Platform)
			require.True(t, cfg.SourceLineageValidated)
			require.Equal(t, lineage, cfg.SourceLineage)
			require.Equal(t, patchedConfig, cfg.PatchedConfigData)
			require.Equal(t, []string{input, baseRef, childRef}, gateway.calls)
			var got specs.Image
			require.NoError(t, json.Unmarshal(cfg.ConfigData, &got))
			original.Config.Labels["BaseImage"] = baseRef
			require.Equal(t, original, got, "re-patching must use the exact recorded original, only adding BaseImage")
			// Verify the final LLB source is the original child, not the index or patched input.
			gateway.resolve = nil
			require.Equal(t, childRef, stateSource(t, &cfg.ImageState, &platform))
		})
	}
}
