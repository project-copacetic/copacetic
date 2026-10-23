package patch

import (
	"context"
	"errors"
	"testing"

	"github.com/moby/buildkit/client"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/stretchr/testify/require"
)

const originPreflightPreserved = "preserved"

func TestOriginPreflightRequiresOnlyPatchingPlatforms(t *testing.T) {
	previous := bkNewClient
	t.Cleanup(func() { bkNewClient = previous })
	unavailable := errors.New("builder unavailable")
	platform := types.PatchPlatform{Platform: platformSpec("linux", "amd64", "")}
	for _, scenario := range []string{originPreflightPreserved, "empty-report", "report-error", "no-report", "os-update", "library-update"} {
		t.Run(scenario, func(t *testing.T) {
			input := platformPatchInput{updates: &unversioned.UpdateManifest{}}
			switch scenario {
			case "report-error":
				input.reportErr = errors.New("invalid report")
			case "no-report":
				input.updates = nil
			case "os-update":
				input.updates.OSUpdates = []unversioned.UpdatePackage{{Name: "busybox"}}
			case "library-update":
				input.updates.LangUpdates = []unversioned.UpdatePackage{{Name: "library"}}
			}
			inputs := map[string]platformPatchInput{buildkit.PlatformKey(platform.Platform): input}
			if scenario == originPreflightPreserved {
				inputs = nil
			}
			calls := 0
			bkNewClient = func(context.Context, buildkit.Opts) (*client.Client, error) {
				calls++
				return nil, unavailable
			}
			err := preflightMultiPlatformOrigins(t.Context(), &types.Options{}, []types.PatchPlatform{platform}, inputs, "")
			if scenario == "no-report" || scenario == "os-update" || scenario == "library-update" {
				require.ErrorIs(t, err, unavailable)
				require.Equal(t, 1, calls)
			} else {
				require.NoError(t, err)
				require.Zero(t, calls, "no new builder requirement for a platform that cannot patch")
			}
		})
	}
}

func TestOriginIntegrityWinsConcurrentErrors(t *testing.T) {
	cause := errors.New("recorded original vanished")
	integrity := errors.Join(errOriginIntegrity, cause)
	for _, other := range []error{context.Canceled, errors.New("loader stream failed"), types.ErrNoUpdatesFound, nil} {
		got := selectPatchWaitError(other, integrity)
		require.ErrorIs(t, got, errOriginIntegrity)
		require.ErrorIs(t, got, cause)
		got = selectPatchWaitError(integrity, other)
		require.ErrorIs(t, got, errOriginIntegrity)
	}
	ordinary := errors.New("package update failed")
	require.Same(t, ordinary, selectPatchWaitError(ordinary, nil))
}
