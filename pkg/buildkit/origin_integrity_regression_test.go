package buildkit

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/client/llb/sourceresolver"
	"github.com/moby/buildkit/solver/pb"
	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/stretchr/testify/require"
)

type originIntegrityMetadata struct {
	digest digest.Digest
	config []byte
	err    error
}

type originIntegrityGateway struct {
	originIndexGateway
	t       *testing.T
	images  map[string]originIntegrityMetadata
	resolve func(string, sourceresolver.Opt)
	calls   []string
}

func (g *originIntegrityGateway) ResolveSourceMetadata(_ context.Context, op *pb.SourceOp, opt sourceresolver.Opt) (*sourceresolver.MetaResponse, error) {
	ref := strings.TrimPrefix(op.Identifier, "docker-image://")
	g.calls = append(g.calls, ref)
	require.NotNil(g.t, opt.ImageOpt)
	require.Equal(g.t, llb.ResolveModePreferLocal.String(), opt.ImageOpt.ResolveMode)
	image, ok := g.images[ref]
	require.True(g.t, ok, "unexpected image resolution: %s", ref)
	if g.resolve != nil {
		g.resolve(ref, opt)
	}
	if image.err != nil {
		return nil, image.err
	}
	return &sourceresolver.MetaResponse{Op: op, Image: &sourceresolver.ResolveImageResponse{Digest: image.digest, Config: image.config}}, nil
}

func originIntegrityConfig(t *testing.T, labels map[string]string) []byte {
	t.Helper()
	config, err := json.Marshal(specs.Image{
		Platform: specs.Platform{OS: linux, Architecture: arm64},
		Config:   specs.ImageConfig{Labels: labels},
	})
	require.NoError(t, err)
	return config
}

func TestOriginIntegrityErrorClassification(t *testing.T) {
	require.Equal(t, "patch origin integrity validation failed", ErrOriginIntegrity.Error())
	const input = "example.com/app:patched"
	const base = "example.com/app:original"
	original := digest.FromString("recorded original")
	originalRef := "example.com/app@" + original.String()
	patched := digest.FromString("patched input")
	ioErr := errors.New("registry connection reset")
	originalConfig := originIntegrityConfig(t, map[string]string{"com.example.original": "unchanged"})
	labels := (&types.SourceLineage{Kind: types.PatchOriginImage, Name: originalRef, Digest: original}).Annotations()
	labels["BaseImage"] = base
	patchedConfig := originIntegrityConfig(t, labels)
	withLabel := func(key, value string) []byte {
		updated, err := AddImageConfigLabels(patchedConfig, map[string]string{key: value})
		require.NoError(t, err)
		return updated
	}
	invalidLLBConfig := []byte(`{"os":"linux","architecture":"arm64","config":{"Env":"not an array"}}`)
	invalidPatchedLLBConfig := []byte(strings.Replace(string(patchedConfig), `"config":{`, `"config":{"Env":"not an array",`, 1))

	for _, tc := range []struct {
		name        string
		config      []byte
		sourceErr   error
		base        originIntegrityMetadata
		recovery    originIntegrityMetadata
		wantMarked  bool
		wantCause   error
		wantMessage string
	}{
		{name: "fresh source IO error", sourceErr: ioErr, wantCause: ioErr},
		{name: "ordinary source cancellation", sourceErr: context.Canceled, wantCause: context.Canceled},
		{name: "ordinary source timeout", sourceErr: context.DeadlineExceeded, wantCause: context.DeadlineExceeded},
		{name: "ordinary malformed JSON", config: []byte(`{"config":`), wantMessage: "parse image config"},
		{name: "ordinary missing config", config: []byte(`{}`), wantMessage: "config field"},
		{name: "ordinary malformed labels", config: []byte(`{"config":{"Labels":42}}`), wantMessage: "labels field"},
		{name: "unrelated LLB config error", config: invalidLLBConfig, wantMessage: "cannot unmarshal string"},
		{
			name: "partial tuple", wantMarked: true, wantMessage: "invalid patch origin metadata",
			config: originIntegrityConfig(t, map[string]string{"BaseImage": base, types.AnnotationPatchOriginKind: types.PatchOriginImage}),
		},
		{name: "missing BaseImage", config: withLabel("BaseImage", ""), wantMarked: true},
		{name: "invalid digest", config: withLabel(types.AnnotationPatchOriginDigest, "not a digest"), wantMarked: true},
		{name: "unsupported kind", config: withLabel(types.AnnotationPatchOriginKind, "unknown"), wantMarked: true},
		{
			name: "contradictory tuple", wantMarked: true,
			config: withLabel(types.AnnotationPatchOriginName, "example.com/app@"+digest.FromString("different original").String()),
		},
		{
			name: "different repository", config: withLabel("BaseImage", "other.example.com/app:original"),
			wantMarked: true, wantMessage: "repository does not match BaseImage",
		},
		{
			name: "recorded original recovery IO error", config: patchedConfig, wantMarked: true,
			base:     originIntegrityMetadata{digest: patched, config: originalConfig},
			recovery: originIntegrityMetadata{err: ioErr}, wantCause: ioErr, wantMessage: "restore the original image",
		},
		{
			name: "missing original recovery canceled", config: patchedConfig, wantMarked: true,
			base: originIntegrityMetadata{err: ioErr}, recovery: originIntegrityMetadata{err: context.Canceled}, wantCause: context.Canceled,
		},
		{
			name: "recovery digest mismatch", config: patchedConfig, wantMarked: true,
			base:     originIntegrityMetadata{digest: patched, config: originalConfig},
			recovery: originIntegrityMetadata{digest: patched, config: originalConfig}, wantMessage: "unexpected digest",
		},
		{
			name: "malformed recorded original", config: patchedConfig, wantMarked: true,
			base: originIntegrityMetadata{digest: original, config: []byte(`{}`)}, wantMessage: "parse recorded patch origin config",
		},
		{
			name: "recorded original is patched", config: patchedConfig, wantMarked: true,
			base: originIntegrityMetadata{digest: original, config: patchedConfig}, wantMessage: "itself a Copa-patched image",
		},
		{
			name: "unrelated patched LLB config error", config: invalidPatchedLLBConfig,
			base: originIntegrityMetadata{digest: original, config: originalConfig}, wantMessage: "cannot unmarshal string",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gateway := &originIntegrityGateway{t: t, images: map[string]originIntegrityMetadata{
				input: {digest: patched, config: tc.config, err: tc.sourceErr}, base: tc.base, originalRef: tc.recovery,
			}}
			cfg, err := InitializeBuildkitConfig(t.Context(), gateway, input, nil)
			require.Error(t, err)
			require.Nil(t, cfg, "integrity failures must not fall back to the patched input")
			require.Equal(t, tc.wantMarked, errors.Is(err, ErrOriginIntegrity), "%v", err)
			if tc.wantCause != nil {
				require.ErrorIs(t, err, tc.wantCause, "marking must preserve the underlying error")
			}
			if tc.wantMessage != "" {
				require.ErrorContains(t, err, tc.wantMessage)
			}
		})
	}
}

func TestOriginIntegrityLegacyRecoveryRemainsBestEffort(t *testing.T) {
	const input = "example.com/app:patched"
	const base = "example.com/app:original"
	gateway := &originIntegrityGateway{t: t, images: map[string]originIntegrityMetadata{
		input: {digest: digest.FromString("legacy patched input"), config: originIntegrityConfig(t, map[string]string{"BaseImage": base})},
		base:  {err: errors.New("registry unavailable")},
	}}
	cfg, err := InitializeBuildkitConfig(t.Context(), gateway, input, nil)
	require.NoError(t, err)
	require.Nil(t, cfg.SourceLineage)
	require.Nil(t, cfg.PatchedConfigData)
	require.False(t, cfg.SourceLineageValidated)
}
