package buildkit

import (
	"context"
	"errors"
	"testing"

	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/client/llb/sourceresolver"
	"github.com/opencontainers/go-digest"
	"github.com/project-copacetic/copacetic/mocks"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestRecordedOriginRecoveryParentCancellation(t *testing.T) {
	const base = "example.com/app:original"
	const input = "example.com/app:patched"
	original := digest.FromString("original before patching")
	patched := digest.FromString("patched layers")
	originalRef := "example.com/app@" + original.String()
	labels := (&types.SourceLineage{Kind: types.PatchOriginImage, Name: originalRef, Digest: original}).Annotations()
	labels["BaseImage"] = base
	config := originIntegrityConfig(t, labels)
	loaderErr := errors.New("loader failed")
	ioErr := errors.New("original registry connection reset")

	for _, tc := range []struct {
		name         string
		cancelParent bool
		recoveryErr  error
	}{
		{name: "loader cancellation during recovery", cancelParent: true, recoveryErr: context.Canceled},
		{name: "parent cancellation with concurrent IO error", cancelParent: true, recoveryErr: ioErr},
		{name: "live parent with recovery IO error", recoveryErr: ioErr},
		{name: "live parent with resolver cancellation", recoveryErr: context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancelCause(t.Context())
			defer cancel(nil)
			opt := sourceresolver.Opt{ImageOpt: &sourceresolver.ResolveImageOpt{ResolveMode: llb.ResolveModePreferLocal.String()}}
			resolver := &mocks.MockGWClient{}
			resolver.On("ResolveImageConfig", mock.Anything, base, opt).Return(base, patched, config, nil).Once()
			resolver.On("ResolveImageConfig", mock.Anything, originalRef, opt).
				Run(func(mock.Arguments) {
					if tc.cancelParent {
						cancel(loaderErr)
					}
				}).Return("", digest.Digest(""), []byte(nil), tc.recoveryErr).Once()

			_, _, _, _, _, err := updateImageConfigData(ctx, resolver, config, input, input, patched, nil)
			if tc.cancelParent {
				require.ErrorIs(t, err, ctx.Err())
				require.NotErrorIs(t, err, ErrOriginIntegrity, "canceled sibling recovery must not mask the loader failure")
				require.ErrorIs(t, context.Cause(ctx), loaderErr)
			} else {
				require.NoError(t, ctx.Err())
				require.ErrorIs(t, err, ErrOriginIntegrity, "recovery failures with a live parent must remain fatal")
				require.ErrorIs(t, err, tc.recoveryErr)
			}
			resolver.AssertExpectations(t)
		})
	}
}
